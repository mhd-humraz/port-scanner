# Bash Port Scanner

A lightweight TCP port scanner written in Bash for Linux systems. Designed for learning networking fundamentals and performing basic, authorized security testing.

## Features

- Scan individual ports, comma-separated ports, or port ranges.
- Detect and report open, closed, filtered (timeout), and unexpected error results.
- Identify common services associated with well-known ports.
- Configure connection timeout.
- Save scan results to a text report.
- Validate port numbers, ranges, hostnames, and IP resolution.
- Remove duplicate ports automatically.
- Display a scan summary with result counts.
- Lightweight implementation using Bash and standard Linux utilities.

## Requirements

- Linux or WSL with Bash.
- `timeout` command.
- `getent` command.

## Installation

Clone the repository:

```bash
https://github.com/mhd-humraz/port-scanner.git
cd port-scanner
```

Make the script executable:

```bash
chmod +x portscan.sh
```

## Usage

```bash
./portscan.sh -t TARGET [OPTIONS]
```

### Options

| Option | Description |
|---|---|
| `-t TARGET` | Target IP address or hostname (required) |
| `-p PORTS` | Comma-separated ports or ranges |
| `-T SECONDS` | Connection timeout (1–10 seconds, default: 1) |
| `-o FILE` | Save results to a text file |
| `-h` | Display help |

### Examples

Scan the default ports:

```bash
./portscan.sh -t 127.0.0.1
```

Scan selected ports:

```bash
./portscan.sh -t 127.0.0.1 -p 22,80,443
```

Scan a port range:

```bash
./portscan.sh -t 127.0.0.1 -p 8000-8100
```

Combine individual ports and ranges:

```bash
./portscan.sh -t localhost -p 22,80,443,8000-8010
```

Set a custom timeout:

```bash
./portscan.sh -t 127.0.0.1 -p 1-100 -T 2
```

Save results to a report:

```bash
./portscan.sh -t 127.0.0.1 -p 22,80,443 -o report.txt
```

## Sample Output

```text
========================================
       BASH PORT SCANNER v1.0.0
========================================
Target       : 127.0.0.1
Port Count   : 4
Timeout      : 1s
----------------------------------------
Scanning started...

[OPEN] Port 22 - SSH
[OPEN] Port 80 - HTTP
[CLOSED] Port 443 - HTTPS
[CLOSED] Port 3306 - MySQL

========================================
              SCAN SUMMARY
========================================
Total Ports  : 4
Open Ports   : 2
Closed Ports : 2
Filtered     : 0
Errors       : 0
========================================
```

## Result Classification

| Status | Meaning |
|---|---|
| OPEN | TCP connection succeeded |
| CLOSED | Connection attempt was refused |
| FILTERED | Connection attempt timed out |
| ERROR | An unexpected connection error occurred |

**Note:** These classifications are based on Bash TCP connection attempts. A timeout does not prove that a firewall is blocking a port, and connection failures may not always indicate that a port is closed.

## Limitations

- Supports TCP scanning only.
- Scans ports sequentially rather than concurrently.
- Uses connection attempts rather than raw packet inspection.
- Service names are based on a built-in list of common ports, not protocol fingerprinting.

## Responsible Use

This tool is intended for educational purposes and authorized security testing.

Only scan systems you own or have explicit permission to test. Unauthorized scanning may violate applicable laws or network policies.

## Author

**Humraz**

GitHub: https://github.com/YOUR_USERNAME

---

If you find this project useful, consider giving it a star!
