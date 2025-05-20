#!/usr/bin/env python3
"""
DiddySec Scheduled Network Monitor

This script runs in the background, capturing and analyzing network traffic at regular intervals
and sending the results to the DiddySec API. It can be set up as a system service
to run continuously.

Usage:
    python capture_client.py --interface en0 --interval 10 --api-key "this-is-api-key-lol" --api-url "https://web-production-8fe18.up.railway.app"
"""

import os
import sys
import time
import uuid
import argparse
import requests
import tempfile
import pyshark
import logging
import csv
import json
import datetime
import socket
import platform
from pathlib import Path
from collections import defaultdict
import threading
import signal
import configparser

# Try to import tabulate for better display
try:
    from tabulate import tabulate

    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# Setup logging
log_dir = os.path.join(os.path.expanduser("~"), ".diddysec")
os.makedirs(log_dir, exist_ok=True)
log_path = os.path.join(log_dir, "diddysec_monitor.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DiddySec-Monitor")

# Configuration file path
config_path = os.path.join(log_dir, "config.ini")

# Default config values
DEFAULT_CONFIG = {
    "interface": "auto",
    "interval": "10",  # minutes
    "api_key": "",
    "api_url": "",
    "hostname": socket.gethostname(),
    "location": "Default Location",
    "last_run": "",
    "last_capture_id": ""
}

# Status file to keep track of the most recent detection results
status_file = os.path.join(log_dir, "status.json")

# Global variable to track if the service should continue running
running = True


def signal_handler(sig, frame):
    """Handle interrupt signals to gracefully shut down the service"""
    global running
    logger.info("Received signal to terminate. Shutting down...")
    running = False


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def load_config():
    """Load configuration from config file, create if it doesn't exist"""
    config = configparser.ConfigParser()

    # Create default config if not exists
    if not os.path.exists(config_path):
        config['DEFAULT'] = DEFAULT_CONFIG
        with open(config_path, 'w') as config_file:
            config.write(config_file)
        logger.info(f"Created default configuration at {config_path}")

    config.read(config_path)
    return config['DEFAULT']


def save_config(config_dict):
    """Save configuration to config file"""
    config = configparser.ConfigParser()
    config['DEFAULT'] = config_dict
    with open(config_path, 'w') as config_file:
        config.write(config_file)
    logger.info(f"Configuration saved to {config_path}")


def save_status(status_data):
    """Save status data to status file"""
    with open(status_file, 'w') as f:
        json.dump(status_data, f, indent=2)
    logger.info(f"Status saved to {status_file}")


def load_status():
    """Load status data from status file"""
    if os.path.exists(status_file):
        try:
            with open(status_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Error decoding status file, creating new status")

    # Default status data
    return {
        "last_run_time": "",
        "last_capture_id": "",
        "last_result": None,
        "history": []
    }


def detect_best_interface():
    """Detect the best network interface to use based on OS"""
    try:
        import netifaces

        # Get all network interfaces
        interfaces = netifaces.interfaces()

        # Filter out loopback and non-active interfaces
        active_interfaces = []

        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            # Check if interface has IPv4 address and is not loopback
            if netifaces.AF_INET in addrs and not iface.startswith('lo'):
                ip = addrs[netifaces.AF_INET][0]['addr']
                if not ip.startswith('127.'):
                    active_interfaces.append((iface, ip))

        if active_interfaces:
            # Return the first active interface
            logger.info(f"Detected active interface: {active_interfaces[0][0]} ({active_interfaces[0][1]})")
            return active_interfaces[0][0]

        # Fallback to common interface names
        os_name = platform.system().lower()
        if os_name == "darwin":  # macOS
            return "en0"
        elif os_name == "windows":
            return "Ethernet"
        else:  # Linux and others
            return "eth0"

    except ImportError:
        logger.warning("netifaces package not installed. Using default interface.")

        # OS-based fallback
        os_name = platform.system().lower()
        if os_name == "darwin":  # macOS
            return "en0"
        elif os_name == "windows":
            return "Ethernet"
        else:  # Linux and others
            return "eth0"


def live_capture_flow_features(interface, csv_file, duration=60):
    """Capture network traffic and extract flow features"""
    try:
        logger.info(f"Starting live capture on interface {interface} for {duration} seconds...")

        # Check if interface exists
        try:
            cap = pyshark.LiveCapture(interface=interface, display_filter='ip')
        except Exception as e:
            if "Interface doesn't exist" in str(e):
                logger.error(f"Interface '{interface}' doesn't exist. Trying to detect best interface...")
                interface = detect_best_interface()
                logger.info(f"Detected interface: {interface}")
                cap = pyshark.LiveCapture(interface=interface, display_filter='ip')
            else:
                raise

        flows = defaultdict(lambda: defaultdict(int))
        src_dport_tracker = defaultdict(dict)
        start_time = time.time()
        processed_packets = 0

        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
                "state", "sttl", "ct_state_ttl", "dload", "ct_dst_sport_ltm",
                "rate", "swin", "dwin", "dmean", "ct_src_dport_ltm"
            ])

            # Create a timer to force stopping after the duration
            stop_time = start_time + duration

            # Start packet capture with a timeout
            for pkt in cap.sniff_continuously():
                current_time = time.time()
                if current_time >= stop_time:
                    logger.info(f"Reached duration limit of {duration} seconds. Stopping capture.")
                    break

                # Progress update every 50 packets
                processed_packets += 1
                if processed_packets % 50 == 0:
                    elapsed = current_time - start_time
                    progress = min(100, int((elapsed / duration) * 100))
                    logger.info(f"Processing... {progress}% complete, {processed_packets} packets processed")

                try:
                    if 'IP' not in pkt or pkt.transport_layer is None:
                        continue

                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    protocol = pkt.transport_layer
                    src_port = pkt[protocol].srcport
                    dst_port = pkt[protocol].dstport
                    length = int(pkt.length)
                    timestamp = float(pkt.sniff_time.timestamp())
                    ttl = int(pkt.ip.ttl) if hasattr(pkt.ip, 'ttl') else 0

                    flow_key = (src_ip, dst_ip, protocol, src_port, dst_port)
                    flow = flows[flow_key]

                    if 'first_time' not in flow:
                        flow['first_time'] = timestamp
                        flow['first_ttl'] = ttl
                        flow['byte_count'] = 0
                        flow['packet_count'] = 0
                        flow['swin'] = 0
                        flow['dwin'] = 0
                        flow['swin_count'] = 0
                        flow['dwin_count'] = 0
                        flow['flags_seen'] = set()
                        flow['packet_directions'] = set()
                        flow['state'] = 'INT'
                        flow['last_time_port'] = timestamp

                    flow['last_time'] = timestamp
                    flow['last_ttl'] = ttl
                    flow['byte_count'] += length
                    flow['packet_count'] += 1

                    duration_flow = timestamp - flow['first_time']
                    if duration_flow > 0:
                        flow['ct_state_ttl'] = abs(flow['first_ttl'] - ttl) * duration_flow
                        flow['dload'] = flow['byte_count'] / duration_flow
                        flow['rate'] = flow['byte_count'] / duration_flow
                    else:
                        flow['ct_state_ttl'] = 0
                        flow['dload'] = 0
                        flow['rate'] = 0

                    flow['dmean'] = flow['byte_count'] / flow['packet_count']

                    if protocol == 'TCP' and 'TCP' in pkt:
                        try:
                            flags = int(pkt.tcp.flags, 16)
                            flow['flags_seen'].add(flags)

                            if flags & 0x04:
                                flow['state'] = 'RST'
                            elif flags & 0x01:
                                flow['state'] = 'FIN'
                            elif flags & 0x02 and not (flags & 0x10):
                                flow['state'] = 'REQ'
                            elif flags & 0x12 == 0x12:
                                flow['state'] = 'CON'
                            elif flags & 0x10:
                                flow['state'] = 'CON'

                            # Check for two-way communication
                            dir_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                            flow['packet_directions'].add(dir_str)
                            reverse_dir = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                            if reverse_dir in flow['packet_directions']:
                                flow['state'] = 'CLO'
                        except:
                            pass

                        if hasattr(pkt.tcp, 'window_size_value'):
                            flow['swin'] += int(pkt.tcp.window_size_value)
                            flow['swin_count'] += 1

                        if hasattr(pkt.tcp, 'window_size_scalefactor'):
                            flow['dwin'] += int(pkt.tcp.window_size_scalefactor)
                            flow['dwin_count'] += 1

                        flow['ct_dst_sport_ltm'] = timestamp - flow.get('last_time_port', timestamp)
                        flow['last_time_port'] = timestamp

                    elif protocol == 'ICMP' and hasattr(pkt, 'icmp'):
                        icmp_type = int(pkt.icmp.type)
                        if icmp_type == 8:
                            flow['state'] = 'ECO'
                        elif icmp_type == 0:
                            flow['state'] = 'ECR'

                    last_seen_dport_time = src_dport_tracker[src_ip].get(dst_port, timestamp)
                    flow['ct_src_dport_ltm'] = timestamp - last_seen_dport_time
                    src_dport_tracker[src_ip][dst_port] = timestamp

                    # Write to CSV
                    swin_avg = flow['swin'] / flow['swin_count'] if flow['swin_count'] else 0
                    dwin_avg = flow['dwin'] / flow['dwin_count'] if flow['dwin_count'] else 0

                    # Prepare row and write it
                    row = [
                        flow_key[0], flow_key[1], flow_key[2].lower(), flow_key[3], flow_key[4],
                        flow.get('state', '-'),
                        flow.get('first_ttl', 0),
                        flow.get('ct_state_ttl', 0),
                        flow.get('dload', 0),
                        flow.get('ct_dst_sport_ltm', 0),
                        flow.get('rate', 0),
                        swin_avg,
                        dwin_avg,
                        flow.get('dmean', 0),
                        flow.get('ct_src_dport_ltm', 0)
                    ]
                    writer.writerow(row)

                except Exception as e:
                    logger.error(f"Error processing packet: {str(e)}")
                    continue

        logger.info(f"Capture completed. Processed {processed_packets} packets. Output file: {csv_file}")
        return True

    except Exception as e:
        logger.error(f"Error in live capture: {str(e)}")
        raise


def send_csv_to_api(csv_file, api_url, api_key, hostname, location):
    """Send the captured CSV data to the API for processing"""
    try:
        logger.info(f"Sending captured data to API at {api_url}...")

        with open(csv_file, 'rb') as f:
            files = {'file': (os.path.basename(csv_file), f, 'text/csv')}
            headers = {'X-API-Key': api_key}

            # Include metadata about the client
            data = {
                'hostname': hostname,
                'location': location,
                'os': platform.system(),
                'capture_time': datetime.datetime.now().isoformat()
            }

            response = requests.post(
                f"{api_url}/predict_csv",
                headers=headers,
                files=files,
                data=data
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"API response received. Capture ID: {result.get('capture_id')}")
                return result
            else:
                logger.error(f"API error: {response.status_code} - {response.text}")
                return None

    except Exception as e:
        logger.error(f"Error sending data to API: {str(e)}")
        return None


def check_status(api_url, api_key, capture_id, max_attempts=15, delay=2):
    """Poll the API for the status of the analysis"""
    logger.info(f"Checking status of capture {capture_id}...")

    for attempt in range(max_attempts):
        try:
            response = requests.get(
                f"{api_url}/status/{capture_id}",
                headers={'X-API-Key': api_key}
            )

            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get('status')

                if status == 'completed':
                    logger.info("Analysis completed successfully!")
                    return status_data
                elif status == 'error':
                    logger.error(f"Analysis failed: {status_data.get('message')}")
                    return None
                else:
                    logger.info(f"Status: {status} - {status_data.get('message')} ({status_data.get('progress')}%)")
            else:
                logger.error(f"Error checking status: {response.status_code} - {response.text}")

            time.sleep(delay)

        except Exception as e:
            logger.error(f"Error checking status: {str(e)}")
            time.sleep(delay)

    logger.error(f"Gave up waiting for results after {max_attempts} attempts")
    return None


def get_detection_history(api_url, api_key, limit=10, critical_only=False, hostname=None):
    """Get the detection history from the API"""
    try:
        logger.info(f"Fetching detection history from API...")

        # Build query parameters
        params = {'limit': limit}
        if critical_only:
            params['critical_only'] = 'true'
        if hostname:
            params['hostname'] = hostname

        response = requests.get(
            f"{api_url}/results",
            headers={'X-API-Key': api_key},
            params=params
        )

        if response.status_code == 200:
            results = response.json()
            logger.info(f"Received {len(results)} detection history records")
            return results
        else:
            logger.error(f"API error fetching history: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error fetching detection history: {str(e)}")
        return None


def get_statistics(api_url, api_key):
    """Get detection statistics from the API"""
    try:
        logger.info(f"Fetching detection statistics from API...")

        response = requests.get(
            f"{api_url}/stats",
            headers={'X-API-Key': api_key}
        )

        if response.status_code == 200:
            stats = response.json()
            logger.info(f"Received detection statistics")
            return stats
        else:
            logger.error(f"API error fetching statistics: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error fetching statistics: {str(e)}")
        return None


def display_detection_history(results):
    """Format and display detection history in a table"""
    if not results:
        print("\nNo detection history available.")
        return

    print(f"\n===== DiddySec Detection History ({len(results)} records) =====\n")

    # Prepare table data
    table_data = []
    for result in results:
        timestamp = result.get('timestamp', '')
        if timestamp:
            # Format the timestamp for display
            try:
                dt = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass

        # Calculate intrusion percentage
        normal = result.get('normal_count', 0)
        intrusion = result.get('intrusion_count', 0)
        total = normal + intrusion
        percentage = (intrusion / total * 100) if total > 0 else 0

        # Format the row
        row = [
            timestamp,
            result.get('hostname', 'Unknown'),
            result.get('location', 'Unknown'),
            normal,
            intrusion,
            f"{percentage:.1f}%",
            "CRITICAL" if result.get('is_critical', False) else "Normal"
        ]
        table_data.append(row)

    # Print the table
    headers = ["Timestamp", "Hostname", "Location", "Normal", "Intrusion", "Intrusion %", "Status"]

    if HAS_TABULATE:
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    else:
        # Simple table format if tabulate is not available
        print(" | ".join(headers))
        print("-" * 100)
        for row in table_data:
            print(" | ".join(str(item) for item in row))

    print("\n")


def display_statistics(stats):
    """Format and display detection statistics"""
    if not stats:
        print("\nNo statistics available.")
        return

    print("\n===== DiddySec Monitoring Statistics =====\n")

    print(f"Total Detections: {stats.get('total_detections', 0)}")
    print(f"Critical Detections: {stats.get('critical_detections', 0)}")

    last_24h = stats.get('last_24h', {})
    normal_24h = last_24h.get('normal', 0)
    intrusion_24h = last_24h.get('intrusion', 0)
    total_24h = normal_24h + intrusion_24h
    percent_24h = (intrusion_24h / total_24h * 100) if total_24h > 0 else 0

    print("\n--- Last 24 Hours ---")
    print(f"Normal Connections: {normal_24h}")
    print(f"Intrusion Detections: {intrusion_24h}")
    print(f"Intrusion Percentage: {percent_24h:.1f}%")

    hosts = stats.get('hosts', [])
    if hosts:
        print("\n--- Hosts Summary ---")
        if HAS_TABULATE:
            host_data = [(h.get('hostname', 'Unknown'), h.get('count', 0)) for h in hosts]
            print(tabulate(host_data, headers=["Hostname", "Detections"], tablefmt="simple"))
        else:
            print("Hostname | Detections")
            print("-----------------")
            for h in hosts:
                print(f"{h.get('hostname', 'Unknown')} | {h.get('count', 0)}")

    print("\n")


def perform_detection_cycle(config):
    """Complete one detection cycle: capture, send to API, get results"""
    try:
        interface = config.get('interface')
        api_url = config.get('api_url')
        api_key = config.get('api_key')
        hostname = config.get('hostname', socket.gethostname())
        location = config.get('location', 'Default Location')

        if interface == 'auto':
            interface = detect_best_interface()
            logger.info(f"Using auto-detected interface: {interface}")

        logger.info(f"Starting detection cycle with interface {interface}")

        # Create temp file for CSV
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        temp_dir = os.path.join(log_dir, "captures")
        os.makedirs(temp_dir, exist_ok=True)
        csv_file = os.path.join(temp_dir, f"ddos_capture_{timestamp}.csv")

        # Capture network traffic (30 seconds by default)
        success = live_capture_flow_features(interface, csv_file, 30)

        if not success:
            logger.error("Capture failed. Skipping this cycle.")
            return False, None

        # Send to API
        result = send_csv_to_api(csv_file, api_url, api_key, hostname, location)

        if not result:
            logger.error("Failed to send data to API. Skipping this cycle.")
            return False, None

        capture_id = result.get('capture_id')

        # Poll for results
        status_data = check_status(api_url, api_key, capture_id)

        if status_data and status_data.get('result_counts'):
            counts = status_data.get('result_counts')
            normal = counts.get('Normal', 0)
            intrusion = counts.get('Intrusion', 0)
            total = normal + intrusion

            # Log detection result
            if intrusion > 0:
                intrusion_pct = (intrusion / total) * 100 if total > 0 else 0
                if intrusion_pct > 50:
                    logger.warning(
                        f"CRITICAL: Major DDoS attack detected! {intrusion}/{total} suspicious connections ({intrusion_pct:.1f}%)")
                elif intrusion_pct > 20:
                    logger.warning(
                        f"WARNING: Significant DDoS activity detected! {intrusion}/{total} suspicious connections ({intrusion_pct:.1f}%)")
                else:
                    logger.warning(
                        f"ALERT: Minor DDoS activity detected. {intrusion}/{total} suspicious connections ({intrusion_pct:.1f}%)")
            else:
                logger.info("No DDoS activity detected. Network appears normal.")

            # Save the results for history
            status_data['timestamp'] = datetime.datetime.now().isoformat()
            status_data['hostname'] = hostname
            status_data['location'] = location

            return True, status_data

        return False, None

    except Exception as e:
        logger.error(f"Error in detection cycle: {str(e)}")
        return False, None


def update_status_with_results(success, status_data):
    """Update the status file with detection results"""
    current_status = load_status()

    if success and status_data:
        # Add to history (most recent first)
        current_status['last_run_time'] = datetime.datetime.now().isoformat()
        current_status['last_capture_id'] = status_data.get('capture_id', '')
        current_status['last_result'] = status_data

        # Limit history to 50 entries
        if 'history' not in current_status:
            current_status['history'] = []

        current_status['history'].insert(0, status_data)
        if len(current_status['history']) > 50:
            current_status['history'] = current_status['history'][:50]

    save_status(current_status)
    return current_status


def run_scheduled_detection(config):
    """Run detection on a schedule"""
    global running

    interval_minutes = int(config.get('interval', 10))
    logger.info(f"Starting scheduled detection every {interval_minutes} minutes")

    while running:
        try:
            # Run a detection cycle
            success, status_data = perform_detection_cycle(config)

            # Update status file with results
            update_status_with_results(success, status_data)

            # Update config with last run time
            config_dict = dict(config)
            config_dict['last_run'] = datetime.datetime.now().isoformat()
            if status_data and 'capture_id' in status_data:
                config_dict['last_capture_id'] = status_data['capture_id']
            save_config(config_dict)

            # Sleep until next interval
            logger.info(f"Sleeping for {interval_minutes} minutes until next detection cycle")

            # Check every second if we should continue running
            for _ in range(interval_minutes * 60):
                if not running:
                    break
                time.sleep(1)

        except Exception as e:
            logger.error(f"Error in scheduled detection: {str(e)}")
            # Sleep for a minute before trying again
            time.sleep(60)


def main():
    parser = argparse.ArgumentParser(description='DiddySec Scheduled Network Monitor')
    parser.add_argument('--interface', '-i', type=str, help='Network interface to capture on')
    parser.add_argument('--interval', '-n', type=int, default=10, help='Interval in minutes between detection cycles')
    parser.add_argument('--api-key', '-k', type=str, help='API key for authentication')
    parser.add_argument('--api-url', '-u', type=str, help='API URL (e.g., https://your-api.railway.app)')
    parser.add_argument('--hostname', type=str, help='Hostname for this monitoring client')
    parser.add_argument('--location', type=str, help='Location description for this monitoring client')
    parser.add_argument('--run-once', action='store_true', help='Run once and exit instead of scheduling')
    parser.add_argument('--config', action='store_true', help='Update config file with provided arguments')

    # Add database-related commands
    parser.add_argument('--history', action='store_true', help='Show detection history')
    parser.add_argument('--stats', action='store_true', help='Show detection statistics')
    parser.add_argument('--limit', type=int, default=10, help='Limit number of history records')
    parser.add_argument('--critical-only', action='store_true', help='Show only critical detections')

    args = parser.parse_args()

    # Load existing config
    config = load_config()

    # Update config with command line arguments if provided
    if args.interface:
        config['interface'] = args.interface
    if args.interval:
        config['interval'] = str(args.interval)
    if args.api_key:
        config['api_key'] = args.api_key
    if args.api_url:
        config['api_url'] = args.api_url
    if args.hostname:
        config['hostname'] = args.hostname
    if args.location:
        config['location'] = args.location

    # Save the updated config if requested
    if args.config:
        save_config(dict(config))
        logger.info("Configuration updated successfully")
        return

    # Handle database-related commands
    if args.history:
        if not config.get('api_key') or not config.get('api_url'):
            logger.error(
                "API key and URL are required for history. Please set them using --api-key and --api-url or --config")
            return

        results = get_detection_history(
            config.get('api_url'),
            config.get('api_key'),
            limit=args.limit,
            critical_only=args.critical_only,
            hostname=args.hostname
        )
        display_detection_history(results)
        return

    if args.stats:
        if not config.get('api_key') or not config.get('api_url'):
            logger.error(
                "API key and URL are required for statistics. Please set them using --api-key and --api-url or --config")
            return

        stats = get_statistics(config.get('api_url'), config.get('api_key'))
        display_statistics(stats)
        return

    # Validate required configuration
    if not config.get('api_key') or not config.get('api_url'):
        logger.error("API key and URL are required. Please set them using --api-key and --api-url or --config")
        return

    logger.info("Starting DiddySec Network Monitor")
    logger.info(f"Configuration: interface={config.get('interface')}, interval={config.get('interval')} minutes")
    logger.info(f"API URL: {config.get('api_url')}")

    if args.run_once:
        # Run detection once and exit
        logger.info("Running single detection cycle...")
        success, status_data = perform_detection_cycle(config)
        update_status_with_results(success, status_data)
    else:
        # Run scheduled detection
        run_scheduled_detection(config)

    logger.info("DiddySec Network Monitor shutting down")


if __name__ == "__main__":
    main()