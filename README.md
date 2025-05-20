# DiddySec Network Monitor

## Table of Contents

* [Introduction](#introduction)
* [System Requirements](#system-requirements)
* [Installation](#installation)
* [Basic Usage](#basic-usage)
* [Configuration](#configuration)
* [Command-Line Options](#command-line-options)
* [Viewing Results](#viewing-results)
* [Running as a Service](#running-as-a-service)

  * [On Linux (systemd)](#on-linux-systemd)
  * [On Windows](#on-windows)
* [Troubleshooting](#troubleshooting)
* [FAQ](#faq)

---

## Introduction

DiddySec Network Monitor is a powerful tool designed to detect and analyze potential DDoS attacks on your network in real-time. It captures network traffic at regular intervals, analyzes traffic patterns, and sends the results to the DiddySec API for intelligent threat analysis.

**Key Features:**

* Scheduled network monitoring with configurable intervals
* Automatic network interface detection
* Detection of various DDoS attack types (SYN Flood, UDP Flood, HTTP Flood, etc.)
* Traffic flow analysis with sophisticated ML-based detection
* Comprehensive reporting of suspicious activities
* Historical data tracking and trend analysis

---

## System Requirements

* Python 3.7 or higher
* Operating System: Linux, macOS, or Windows
* Network interface with sufficient access permissions
* Internet connection to DiddySec API servers
* Minimum 2 GB RAM recommended

---

## Installation

### Step 1: Install Python Dependencies

```bash
# Create a virtual environment (recommended)
python -m venv diddysec-env
source diddysec-env/bin/activate  # On Windows: diddysec-env\Scripts\activate

# Install required packages
pip install pyshark requests configparser tabulate netifaces
```

### Step 2: Download the Monitoring Script

Save the `capture_client.py` script to your preferred location.

### Step 3: Initial Configuration

Run the script once to generate the default configuration file:

```bash
python capture_client.py --config
```

This will create `~/.diddysec/config.ini` with default settings.

---

## Basic Usage

### Start Monitoring

```bash
python capture_client.py --api-key YOUR_API_KEY --api-url YOUR_API_URL
```

### Run Once without Scheduling

```bash
python capture_client.py --api-key YOUR_API_KEY --api-url YOUR_API_URL --run-once
```

### View Recent Detection History

```bash
python capture_client.py --history
```

### View Detection Statistics

```bash
python capture_client.py --stats
```

---

## Configuration

The configuration file is located at `~/.diddysec/config.ini` and contains:

```ini
[DEFAULT]
interface      = auto
interval       = 10
api_key        = YOUR_API_KEY
api_url        = YOUR_API_URL
hostname       = your-hostname
location       = Default Location
```

| Option    | Description                                             | Default            |
| --------- | ------------------------------------------------------- | ------------------ |
| interface | Network interface to monitor (`auto` for detection)     | `auto`             |
| interval  | Monitoring interval in minutes                          | `10`               |
| api\_key  | Your DiddySec API key                                   | (from config)      |
| api\_url  | The DiddySec API URL (e.g., `https://api.diddysec.com`) | (from config)      |
| hostname  | Hostname for identification in reports                  | System hostname    |
| location  | Physical or logical location description                | `Default Location` |

### Updating Configuration

1. **Edit the file directly:**

   ```bash
   nano ~/.diddysec/config.ini
   ```
2. **Using the `--config` flag:**

   ```bash
   python capture_client.py --interface eth0 --interval 5 --config
   ```
3. **Providing options on each run:**

   ```bash
   python capture_client.py --interface eth0 --interval 5
   ```

---

## Command-Line Options

```text
Usage:
  python capture_client.py --interface eth0 --interval 10 --api-key YOUR_API_KEY --api-url YOUR_API_URL
  python capture_client.py --history --limit 20
  python capture_client.py --stats
```

| Option              | Description                                     | Default            |
| ------------------- | ----------------------------------------------- | ------------------ |
| `--interface`, `-i` | Network interface to capture on                 | `auto`             |
| `--interval`, `-n`  | Minutes between detection cycles                | `10`               |
| `--api-key`, `-k`   | API key for authentication                      | (from config)      |
| `--api-url`, `-u`   | API URL                                         | (from config)      |
| `--hostname`        | Hostname for this monitoring client             | System hostname    |
| `--location`        | Location description for this monitoring client | `Default Location` |
| `--run-once`        | Run one detection cycle and exit                | `false`            |
| `--config`          | Update config file with provided arguments      | `false`            |
| `--history`         | Show detection history                          | `false`            |
| `--stats`           | Show detection statistics                       | `false`            |
| `--limit`           | Limit number of history records                 | `10`               |
| `--critical-only`   | Show only critical detections                   | `false`            |

---

## Viewing Results

### Live Console Output

When running the script, results display in real-time:

```
===== DiddySec Detection History (5 records) =====

Timestamp           | Hostname     | Location      | Normal | Intrusion | Intrusion % | Status   
--------------------|--------------|--------------| ------|-----------| -----------|----------
2025-05-19 19:44:22 | server-east  | Jakarta      | 593    | 30        | 4.8%        | Normal   
2025-05-19 19:33:47 | server-west  | Singapore    | 481    | 11        | 2.2%        | Normal   
...
```

### History Command

```bash
python capture_client.py --history
```

### Statistics Command

```bash
python capture_client.py --stats
```

---

## Running as a Service

### On Linux (systemd)

1. Create `/etc/systemd/system/diddysec-monitor.service`:

   ```ini
   [Unit]
   Description=DiddySec Network Monitor
   After=network.target

   [Service]
   Type=simple
   User=YOUR_USERNAME
   WorkingDirectory=/path/to/script
   ExecStart=/usr/bin/python3 /path/to/script/capture_client.py
   Restart=on-failure
   RestartSec=5s

   [Install]
   WantedBy=multi-user.target
   ```
2. Enable and start:

   ```bash
   sudo systemctl enable diddysec-monitor
   sudo systemctl start diddysec-monitor
   ```
3. Check status:

   ```bash
   sudo systemctl status diddysec-monitor
   ```

### On Windows

1. Create `diddysec-monitor.bat`:

   ```batch
   @echo off
   cd /d C:\path\to\script
   python capture_client.py
   ```
2. Use Task Scheduler:

   * Create a new task
   * Trigger: At system startup
   * Action: Start `diddysec-monitor.bat`

---

## Troubleshooting

### Common Issues

* **Interface Not Found**: `Error: Interface 'eth0' doesn't exist`

  * Use automatic detection:

    ```bash
    python capture_client.py --interface auto
    ```
* **API Connection Errors**: `ConnectionError`

  * Verify internet, API URL, and API key
* **Permission Errors**: `Permission denied`

  * Run with elevated privileges (`sudo`/Admin) or grant capture permissions
* **ModuleNotFoundError**: `No module named 'pyshark'`

  * Install missing package:

    ```bash
    pip install pyshark
    ```

### Log File

Inspect detailed logs:

```bash
cat ~/.diddysec/diddysec_monitor.log
```

---

## FAQ

*For common questions and answers, visit our [FAQ page](#).*
