# 🔍 Network Packet Analyzer & Sniffer

> A Python-based network traffic analysis tool that captures, dissects, and analyzes packets in real-time to detect suspicious network activity and potential security threats.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Category](https://img.shields.io/badge/Category-Network%20Security-red)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Cybersecurity Concepts](#cybersecurity-concepts)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Capabilities](#detection-capabilities)
- [Project Structure](#project-structure)
- [Sample Output](#sample-output)
- [Interview Talking Points](#interview-talking-points)
- [Disclaimer](#disclaimer)

---

## Overview

This project demonstrates core **network security** and **traffic analysis** skills by building a packet sniffer from scratch using raw sockets and Scapy. It captures live network traffic, decodes protocol layers (Ethernet, IP, TCP, UDP, DNS, HTTP, ARP, ICMP), and applies threat detection rules to identify:

- **Port scanning** (SYN scans, connect scans)
- **ARP spoofing / poisoning** attacks
- **DNS tunneling** attempts
- **Suspicious DNS queries** (DGA detection)
- **Brute force login attempts** (repeated connections)
- **Large data exfiltration** patterns
- **ICMP flood / Ping of Death**

This is the type of tool a **SOC analyst** or **network security engineer** works with daily, and building one demonstrates deep understanding of how networks operate at the packet level.

---

## Cybersecurity Concepts

### What is Packet Sniffing?
Packet sniffing is the process of capturing data packets as they travel across a network. Every piece of data sent over a network (emails, web requests, file transfers) is broken into packets. Each packet contains:
- **Headers**: Source/destination addresses, protocol info, flags
- **Payload**: The actual data being transmitted

### Why It Matters in Security
- **Intrusion Detection**: Detect malicious activity by analyzing traffic patterns
- **Forensics**: Investigate security incidents by examining captured packets
- **Compliance**: Monitor network traffic to ensure policy compliance
- **Vulnerability Assessment**: Identify unencrypted sensitive data on the wire

### Key Protocols Analyzed
| Protocol | Layer | Purpose | Security Relevance |
|----------|-------|---------|-------------------|
| ARP | 2 (Data Link) | MAC-to-IP resolution | ARP spoofing/poisoning |
| ICMP | 3 (Network) | Error reporting, ping | Ping floods, tunneling |
| IP | 3 (Network) | Addressing & routing | IP spoofing |
| TCP | 4 (Transport) | Reliable delivery | Port scans, SYN floods |
| UDP | 4 (Transport) | Fast delivery | DNS attacks, amplification |
| DNS | 7 (Application) | Name resolution | DNS tunneling, DGA |
| HTTP | 7 (Application) | Web traffic | Data leaks, injections |

### OSI Model Relevance
This tool operates across **Layers 2-7** of the OSI model, giving you visibility into:
- **Layer 2**: Ethernet frames, MAC addresses, ARP
- **Layer 3**: IP addresses, routing, ICMP
- **Layer 4**: TCP/UDP ports, connection states, flags
- **Layer 7**: DNS queries, HTTP requests, application data

---

## Features

- **Real-time packet capture** with configurable filters
- **Multi-protocol dissection** (Ethernet, IP, TCP, UDP, ARP, ICMP, DNS, HTTP)
- **Threat detection engine** with 7+ detection modules
- **Statistical dashboard** showing traffic breakdown
- **Alert system** with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- **PCAP export** for further analysis in Wireshark
- **Logging** with structured JSON output
- **Configurable** via YAML configuration file
- **Colored terminal output** for easy reading

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MAIN CONTROLLER                       │
│                   (packet_sniffer.py)                     │
├──────────┬──────────┬───────────┬───────────┬───────────┤
│  Capture │  Parser  │ Detector  │  Logger   │  Stats    │
│  Engine  │  Engine  │  Engine   │  Engine   │  Engine   │
│          │          │           │           │           │
│ Scapy    │ Protocol │ Port Scan │ JSON Log  │ Traffic   │
│ Raw Sock │ Decoders │ ARP Spoof │ Alerts    │ Counters  │
│ BPF Filt │ Headers  │ DNS Tunnel│ PCAP Save │ Dashboard │
│          │ Payloads │ BruteForce│           │           │
└──────────┴──────────┴───────────┴───────────┴───────────┘
```

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Linux/macOS (raw sockets require Unix-like OS)
- Root/sudo privileges (required for packet capture)

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-packet-analyzer.git
cd network-packet-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Basic Capture
```bash
# Capture all traffic (requires sudo)
sudo python3 packet_sniffer.py

# Capture with specific interface
sudo python3 packet_sniffer.py --interface eth0

# Capture with BPF filter
sudo python3 packet_sniffer.py --filter "tcp port 80"

# Capture specific number of packets
sudo python3 packet_sniffer.py --count 100

# Save capture to PCAP file
sudo python3 packet_sniffer.py --output captures/capture.pcap

# Enable verbose mode with full payload display
sudo python3 packet_sniffer.py --verbose

# Run with all options
sudo python3 packet_sniffer.py --interface eth0 --filter "tcp" --count 500 --output captures/session.pcap --verbose
```

### Configuration
Edit `config.yaml` to customize detection thresholds:
```yaml
detection:
  port_scan_threshold: 15       # Unique ports before alert
  port_scan_window: 30          # Time window in seconds
  arp_spoof_detection: true
  dns_tunnel_detection: true
  brute_force_threshold: 10     # Connection attempts before alert
```

---

## Detection Capabilities

### 1. Port Scan Detection
Identifies when a single source IP probes multiple ports on a target within a time window. Detects SYN scans (half-open), connect scans, and FIN/NULL/XMAS scans.

### 2. ARP Spoofing Detection
Maintains an ARP table and alerts when a MAC address is seen claiming multiple IP addresses, or when an IP-to-MAC mapping changes unexpectedly.

### 3. DNS Tunneling Detection
Flags DNS queries with abnormally long subdomain labels or unusually high query volumes from a single source — indicators of data exfiltration through DNS.

### 4. DGA Domain Detection
Uses entropy analysis to detect randomly generated domain names, which are commonly used by malware to contact command-and-control (C2) servers.

### 5. Brute Force Detection
Tracks repeated connection attempts to the same service (e.g., SSH on port 22) from a single source IP within a short time window.

### 6. Data Exfiltration Detection
Monitors for unusually large outbound data transfers that could indicate data theft.

### 7. ICMP Anomaly Detection
Detects ICMP floods (ping floods) and oversized ICMP packets (Ping of Death attempts).

---

## Project Structure

```
network-packet-analyzer/
│
├── README.md                  # This file
├── requirements.txt           # Python dependencies
├── config.yaml               # Configuration file
├── packet_sniffer.py         # Main entry point
│
├── modules/
│   ├── __init__.py
│   ├── capture.py            # Packet capture engine
│   ├── parser.py             # Protocol parser/dissector
│   ├── detector.py           # Threat detection engine
│   ├── logger.py             # Logging and alerting
│   ├── stats.py              # Traffic statistics
│   └── utils.py              # Utility functions
│
├── tests/
│   ├── __init__.py
│   └── test_detector.py      # Unit tests for detection logic
│
├── logs/                     # Alert and event logs
├── captures/                 # Saved PCAP files
└── LICENSE
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║            NETWORK PACKET ANALYZER & SNIFFER                 ║
║                    v1.0.0                                    ║
╚══════════════════════════════════════════════════════════════╝

[*] Interface: eth0
[*] Filter: None
[*] Starting capture... Press Ctrl+C to stop.

────────────────────────────────────────────────────────────────
[14:23:01] TCP | 192.168.1.105:48291 → 93.184.216.34:443 | SYN | Len:0
[14:23:01] TCP | 93.184.216.34:443 → 192.168.1.105:48291 | SYN-ACK | Len:0
[14:23:01] TCP | 192.168.1.105:48291 → 93.184.216.34:443 | ACK | Len:0
[14:23:02] DNS | 192.168.1.105 → 8.8.8.8 | Query: example.com (A)
[14:23:02] DNS | 8.8.8.8 → 192.168.1.105 | Response: 93.184.216.34

⚠️  [ALERT][HIGH] Port Scan Detected!
    Source: 10.0.0.50 → Target: 192.168.1.1
    Ports scanned: 22, 23, 25, 53, 80, 110, 143, 443, 993, 995...
    Scan type: SYN Scan | Duration: 4.2s

🚨 [ALERT][CRITICAL] ARP Spoofing Detected!
    Attacker MAC: aa:bb:cc:dd:ee:ff
    Claimed IP: 192.168.1.1 (Gateway)
    Original MAC: 11:22:33:44:55:66

────────────────────────────── STATISTICS ──────────────────────
Total Packets: 1,247  |  Duration: 60.0s
TCP: 856 (68.6%)  |  UDP: 289 (23.2%)  |  ARP: 67 (5.4%)  |  ICMP: 23 (1.8%)  |  Other: 12 (1.0%)
Unique Sources: 14  |  Unique Destinations: 47  |  Alerts: 3
```

---

## Interview Talking Points

When discussing this project in interviews, be prepared to explain:

1. **"How does your tool capture packets?"**
   - Uses Scapy's `sniff()` function which leverages raw sockets and libpcap under the hood
   - Supports BPF (Berkeley Packet Filter) for efficient kernel-level filtering
   - Operates in promiscuous mode to capture all traffic on the segment

2. **"How do you detect a SYN scan?"**
   - Track unique destination ports per source IP within a rolling time window
   - SYN scans send SYN packets without completing the three-way handshake
   - Threshold-based detection: alert when ports exceed configurable limit

3. **"What's the difference between this and Wireshark?"**
   - Wireshark is a GUI-based analyzer; this is programmatic and scriptable
   - This tool has built-in automated threat detection rules
   - Can be integrated into larger security pipelines and SIEM systems

4. **"How would you improve this tool?"**
   - Add ML-based anomaly detection for unknown threats
   - Implement distributed capture across multiple network segments
   - Add protocol-specific deep inspection (TLS fingerprinting, JA3 hashes)
   - Integrate with threat intelligence feeds for known-bad IP correlation

5. **"What are the limitations?"**
   - Cannot inspect encrypted (TLS/SSL) traffic payload
   - Signature-based detection can be evaded by novel attacks
   - Single-point capture misses traffic on other network segments
   - Requires root privileges which is a security consideration

---

## Disclaimer

⚠️ **This tool is built for educational and authorized security testing purposes only.** Unauthorized network sniffing is illegal in most jurisdictions. Always obtain explicit permission before capturing network traffic. Use responsibly and ethically.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Zishnendu Sarker** - Built as part of a hands-on cybersecurity learning path covering network security, threat detection, and traffic analysis.
