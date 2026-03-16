"""
detector.py - Threat Detection Engine
=======================================
Analyzes parsed packets against security rules to detect
malicious activity and generate alerts.

CYBERSECURITY CONCEPTS:
-----------------------
This module implements a rule-based Intrusion Detection System (IDS).
IDS systems fall into two categories:

1. Signature-based: Match traffic against known attack patterns (what we build here)
2. Anomaly-based: Detect deviations from normal behavior (requires ML, more advanced)

Our detection engine uses STATEFUL analysis — it tracks network activity
over time in memory to detect patterns that span multiple packets.
A single SYN packet is normal; 100 SYN packets to different ports in
5 seconds is a port scan.

DETECTION METHODOLOGY:
Each detector follows the same pattern:
1. OBSERVE: Extract relevant fields from the parsed packet
2. TRACK: Update internal state (counters, timers, mappings)
3. EVALUATE: Check if tracked state exceeds thresholds
4. ALERT: Generate an alert if a rule triggers
5. EXPIRE: Clean up old tracking data to prevent memory leaks
"""

import time
from collections import defaultdict
from modules.utils import (
    calculate_entropy, is_suspicious_domain,
    get_tcp_flags, Colors, colorize
)


class ThreatDetector:
    """
    Main threat detection engine.
    
    Maintains internal state to track:
    - Port access patterns per source IP (port scan detection)
    - ARP IP-to-MAC mappings (ARP spoof detection)
    - DNS query patterns (tunneling/DGA detection)
    - Connection attempt counts (brute force detection)
    - Data transfer volumes (exfiltration detection)
    - ICMP packet rates (flood detection)
    """

    def __init__(self, config):
        """
        Initialize detector with configuration thresholds.
        
        Args:
            config (dict): Detection configuration from config.yaml
        """
        self.config = config.get("detection", {})
        
        # ─── State Tracking Structures ───
        
        # Port Scan Detection
        # Tracks: {source_ip: {destination_ip: {port: timestamp}}}
        # When unique ports exceed threshold in time window → alert
        self.port_access = defaultdict(lambda: defaultdict(dict))
        self.port_scan_alerts = {}  # Track when we last alerted for each IP
        
        # ARP Spoof Detection
        # Tracks: {ip_address: mac_address}
        # When an IP maps to a different MAC than before → alert
        self.arp_table = {}
        # Trusted mappings from config (e.g., your gateway)
        self.trusted_arp = self.config.get("arp_spoof", {}).get("trusted_mappings", {})
        
        # DNS Analysis
        # Tracks: {source_ip: [timestamps]} for query volume
        self.dns_queries = defaultdict(list)
        # Tracks unique domains queried per source
        self.dns_domains = defaultdict(set)
        
        # Brute Force Detection
        # Tracks: {source_ip: {destination_ip:port: [timestamps]}}
        self.connection_attempts = defaultdict(lambda: defaultdict(list))
        self.brute_force_alerts = {}
        
        # Data Exfiltration Detection
        # Tracks: {source_ip: {destination_ip: total_bytes}}
        self.data_transfers = defaultdict(lambda: defaultdict(int))
        self.transfer_start_times = defaultdict(lambda: defaultdict(float))
        
        # ICMP Flood Detection
        # Tracks: {source_ip: [timestamps]}
        self.icmp_packets = defaultdict(list)
        
        # Alert deduplication — avoid flooding with repeated alerts
        # Tracks: {alert_key: last_alert_timestamp}
        self.alert_cooldowns = {}
        self.COOLDOWN_PERIOD = 60  # Seconds between duplicate alerts

    def analyze(self, parsed_packet):
        """
        Run all applicable detectors against a parsed packet.
        
        Args:
            parsed_packet (dict): Output from PacketParser.parse()
            
        Returns:
            list: List of alert dictionaries, empty if no threats detected
        """
        alerts = []
        
        if not parsed_packet or "ERROR" in parsed_packet.get("layers", []):
            return alerts
        
        # Run each detector based on what protocol layers are present
        layers = parsed_packet.get("layers", [])
        
        # ARP Spoofing Detection
        if "ARP" in layers and self.config.get("arp_spoof", {}).get("enabled", True):
            alert = self._detect_arp_spoof(parsed_packet)
            if alert:
                alerts.append(alert)
        
        # Port Scan Detection (TCP traffic)
        if "TCP" in layers and self.config.get("port_scan", {}).get("enabled", True):
            alert = self._detect_port_scan(parsed_packet)
            if alert:
                alerts.append(alert)
        
        # DNS Analysis (DNS queries)
        if "DNS" in layers and self.config.get("dns_analysis", {}).get("enabled", True):
            dns_alerts = self._detect_dns_threats(parsed_packet)
            alerts.extend(dns_alerts)
        
        # Brute Force Detection
        if ("TCP" in layers and
                self.config.get("brute_force", {}).get("enabled", True)):
            alert = self._detect_brute_force(parsed_packet)
            if alert:
                alerts.append(alert)
        
        # Data Exfiltration Detection
        if "IP" in layers and self.config.get("data_exfiltration", {}).get("enabled", True):
            alert = self._detect_data_exfiltration(parsed_packet)
            if alert:
                alerts.append(alert)
        
        # ICMP Anomaly Detection
        if "ICMP" in layers and self.config.get("icmp_anomaly", {}).get("enabled", True):
            icmp_alerts = self._detect_icmp_anomaly(parsed_packet)
            alerts.extend(icmp_alerts)
        
        # Periodic cleanup of old tracking data
        self._cleanup_expired_state()
        
        return alerts

    # ──────────────────────────────────────────────────────────
    # DETECTOR 1: PORT SCAN DETECTION
    # ──────────────────────────────────────────────────────────

    def _detect_port_scan(self, parsed):
        """
        Detect port scanning activity.
        
        TECHNIQUE:
        Port scanning is a reconnaissance technique where an attacker
        probes multiple ports on a target to find open services.
        
        Types of port scans we detect:
        
        1. SYN Scan (Half-open / Stealth scan):
           - Attacker sends SYN packets but never completes handshake
           - Fast and less likely to be logged by the target
           - Nmap command: nmap -sS target
        
        2. Connect Scan:
           - Attacker completes full TCP handshake
           - Slower but works without root privileges
           - Nmap command: nmap -sT target
        
        3. FIN/NULL/XMAS Scans:
           - Send packets with unusual flag combinations
           - Exploit RFC 793: closed ports respond with RST, open ports don't
           - Very stealthy but unreliable on some OS
        
        DETECTION LOGIC:
        Track unique destination ports per (source_ip → destination_ip) pair.
        If unique ports exceed threshold within time window → alert.
        """
        ip_data = parsed.get("ip", {})
        transport = parsed.get("transport", {})
        
        if not ip_data or not transport:
            return None
        
        src_ip = ip_data.get("src", "")
        dst_ip = ip_data.get("dst", "")
        dst_port = transport.get("dst_port", 0)
        flags = transport.get("flags", "")
        now = time.time()
        
        # Record the port access with timestamp
        self.port_access[src_ip][dst_ip][dst_port] = now
        
        # Get configuration
        ps_config = self.config.get("port_scan", {})
        threshold = ps_config.get("threshold", 15)
        window = ps_config.get("time_window", 30)
        
        # Count unique ports accessed within the time window
        ports = self.port_access[src_ip][dst_ip]
        recent_ports = {
            port: ts for port, ts in ports.items()
            if now - ts < window
        }
        self.port_access[src_ip][dst_ip] = recent_ports  # Clean old entries
        
        unique_port_count = len(recent_ports)
        
        if unique_port_count >= threshold:
            # Check cooldown to avoid alert flooding
            alert_key = f"portscan_{src_ip}_{dst_ip}"
            if self._is_on_cooldown(alert_key):
                return None
            
            # Determine scan type based on TCP flags observed
            scan_type = self._identify_scan_type(flags)
            
            return {
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "timestamp": parsed.get("timestamp"),
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "details": {
                    "unique_ports_scanned": unique_port_count,
                    "ports": sorted(recent_ports.keys()),
                    "scan_type": scan_type,
                    "time_window": window,
                    "flags_observed": flags
                },
                "description": (
                    f"Port scan detected from {src_ip} → {dst_ip}: "
                    f"{unique_port_count} unique ports in {window}s "
                    f"(Type: {scan_type})"
                )
            }
        
        return None

    def _identify_scan_type(self, flags):
        """
        Identify the type of port scan based on TCP flags.
        
        Flag patterns:
        - "SYN" only (no ACK) → SYN Scan / Half-open scan
        - "SYN-ACK" present → Connect Scan (full handshake)
        - "FIN" only → FIN Scan
        - "NONE" → NULL Scan
        - "FIN-PSH-URG" → XMAS Scan
        """
        if "SYN" in flags and "ACK" not in flags:
            return "SYN Scan (Half-open)"
        elif "FIN" in flags and "SYN" not in flags and "ACK" not in flags:
            return "FIN Scan (Stealth)"
        elif flags == "NONE" or not flags:
            return "NULL Scan (Stealth)"
        elif all(f in flags for f in ["FIN", "PSH", "URG"]):
            return "XMAS Scan (Stealth)"
        else:
            return "Connect Scan"

    # ──────────────────────────────────────────────────────────
    # DETECTOR 2: ARP SPOOFING DETECTION
    # ──────────────────────────────────────────────────────────

    def _detect_arp_spoof(self, parsed):
        """
        Detect ARP spoofing/poisoning attacks.
        
        ATTACK EXPLAINED:
        ARP has no authentication — any device can claim to be any IP.
        An attacker exploits this by:
        
        1. Attacker sends: "192.168.1.1 (gateway) is at ATTACKER_MAC"
        2. Victim updates ARP cache with fake mapping
        3. Victim sends all internet traffic to attacker instead of gateway
        4. Attacker forwards traffic to real gateway (Man-in-the-Middle)
        5. Attacker can now read/modify all victim's traffic
        
        DETECTION LOGIC:
        Maintain our own ARP table. If we see an ARP reply where:
        - An IP address is now associated with a different MAC than before
        - OR a trusted IP-MAC mapping is contradicted
        → Generate alert
        """
        arp_data = parsed.get("arp", {})
        
        if not arp_data or arp_data.get("operation") != "reply":
            return None  # We only analyze ARP replies (is-at)
        
        sender_ip = arp_data.get("sender_ip", "")
        sender_mac = arp_data.get("sender_mac", "")
        
        if not sender_ip or not sender_mac:
            return None
        
        # Check against trusted mappings first (highest priority)
        if sender_ip in self.trusted_arp:
            trusted_mac = self.trusted_arp[sender_ip].lower()
            if sender_mac != trusted_mac:
                alert_key = f"arpspoof_trusted_{sender_ip}"
                if self._is_on_cooldown(alert_key):
                    return None
                
                return {
                    "type": "ARP_SPOOF",
                    "severity": "CRITICAL",
                    "timestamp": parsed.get("timestamp"),
                    "source_ip": sender_ip,
                    "details": {
                        "claimed_ip": sender_ip,
                        "attacker_mac": sender_mac,
                        "trusted_mac": trusted_mac,
                        "reason": "Trusted ARP mapping violated"
                    },
                    "description": (
                        f"ARP Spoofing: {sender_mac} claims to be {sender_ip} "
                        f"(trusted MAC: {trusted_mac})"
                    )
                }
        
        # Check against our observed ARP table
        if sender_ip in self.arp_table:
            known_mac = self.arp_table[sender_ip]
            if sender_mac != known_mac:
                alert_key = f"arpspoof_{sender_ip}"
                if self._is_on_cooldown(alert_key):
                    # Still update the table
                    self.arp_table[sender_ip] = sender_mac
                    return None
                
                alert = {
                    "type": "ARP_SPOOF",
                    "severity": "CRITICAL",
                    "timestamp": parsed.get("timestamp"),
                    "source_ip": sender_ip,
                    "details": {
                        "claimed_ip": sender_ip,
                        "new_mac": sender_mac,
                        "original_mac": known_mac,
                        "reason": "IP-to-MAC mapping changed"
                    },
                    "description": (
                        f"ARP Spoofing: MAC for {sender_ip} changed "
                        f"from {known_mac} to {sender_mac}"
                    )
                }
                
                self.arp_table[sender_ip] = sender_mac
                return alert
        
        # First time seeing this IP — record it
        self.arp_table[sender_ip] = sender_mac
        return None

    # ──────────────────────────────────────────────────────────
    # DETECTOR 3: DNS THREAT DETECTION
    # ──────────────────────────────────────────────────────────

    def _detect_dns_threats(self, parsed):
        """
        Detect DNS-based threats including tunneling and DGA domains.
        
        DNS TUNNELING EXPLAINED:
        Firewalls often allow DNS traffic (port 53) freely.
        Attackers exploit this by encoding data in DNS queries:
        
        Normal query: "google.com"
        Tunnel query: "dGhpcyBpcyBzZWNyZXQgZGF0YQ.evil.com"
                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                       Base64-encoded exfiltrated data
        
        The attacker's DNS server decodes the subdomain to extract data.
        
        DGA (Domain Generation Algorithm) EXPLAINED:
        Malware generates random domain names to contact C2 servers:
        - Day 1: "xk4mq9v2.com"
        - Day 2: "p3nw8jf1.com"
        - Day 3: "a7bz2yq5.com"
        
        The attacker registers these domains in advance.
        This makes blocking individual domains ineffective.
        We detect DGAs using entropy analysis (random strings have high entropy).
        """
        alerts = []
        dns_data = parsed.get("application", {}).get("dns", {})
        ip_data = parsed.get("ip", {})
        
        if not dns_data or not ip_data:
            return alerts
        
        src_ip = ip_data.get("src", "")
        dns_config = self.config.get("dns_analysis", {})
        now = time.time()
        
        # Track query volume
        self.dns_queries[src_ip].append(now)
        
        # Analyze each DNS query in the packet
        for query in dns_data.get("queries", []):
            domain = query.get("name", "")
            
            if not domain:
                continue
            
            self.dns_domains[src_ip].add(domain)
            
            # ─── Check 1: DNS Tunneling Detection ───
            # Look for abnormally long subdomains (encoded data)
            if dns_config.get("tunnel_detection", True):
                parts = domain.split(".")
                if len(parts) > 2:
                    subdomain = ".".join(parts[:-2])
                    max_length = dns_config.get("max_subdomain_length", 50)
                    
                    if len(subdomain) > max_length:
                        alert_key = f"dnstunnel_{src_ip}_{parts[-2]}.{parts[-1]}"
                        if not self._is_on_cooldown(alert_key):
                            alerts.append({
                                "type": "DNS_TUNNELING",
                                "severity": "HIGH",
                                "timestamp": parsed.get("timestamp"),
                                "source_ip": src_ip,
                                "details": {
                                    "domain": domain,
                                    "subdomain_length": len(subdomain),
                                    "threshold": max_length,
                                    "base_domain": f"{parts[-2]}.{parts[-1]}"
                                },
                                "description": (
                                    f"Possible DNS tunneling from {src_ip}: "
                                    f"subdomain length {len(subdomain)} chars "
                                    f"in query to {domain}"
                                )
                            })
            
            # ─── Check 2: DGA Domain Detection ───
            # Use entropy to detect randomly generated domains
            entropy_threshold = dns_config.get("entropy_threshold", 3.5)
            suspicious, reasons = is_suspicious_domain(
                domain, entropy_threshold=entropy_threshold
            )
            
            if suspicious:
                alert_key = f"dga_{src_ip}_{domain}"
                if not self._is_on_cooldown(alert_key):
                    alerts.append({
                        "type": "DGA_DOMAIN",
                        "severity": "MEDIUM",
                        "timestamp": parsed.get("timestamp"),
                        "source_ip": src_ip,
                        "details": {
                            "domain": domain,
                            "reasons": reasons,
                            "entropy": calculate_entropy(domain.split(".")[0])
                        },
                        "description": (
                            f"Possible DGA domain from {src_ip}: {domain} "
                            f"({', '.join(reasons)})"
                        )
                    })
        
        # ─── Check 3: DNS Query Volume Anomaly ───
        # Excessive DNS queries from one source may indicate tunneling
        volume_threshold = dns_config.get("query_volume_threshold", 50)
        volume_window = dns_config.get("query_volume_window", 60)
        
        # Clean old timestamps
        self.dns_queries[src_ip] = [
            ts for ts in self.dns_queries[src_ip]
            if now - ts < volume_window
        ]
        
        if len(self.dns_queries[src_ip]) >= volume_threshold:
            alert_key = f"dnsvolume_{src_ip}"
            if not self._is_on_cooldown(alert_key):
                alerts.append({
                    "type": "DNS_VOLUME_ANOMALY",
                    "severity": "MEDIUM",
                    "timestamp": parsed.get("timestamp"),
                    "source_ip": src_ip,
                    "details": {
                        "query_count": len(self.dns_queries[src_ip]),
                        "time_window": volume_window,
                        "unique_domains": len(self.dns_domains[src_ip])
                    },
                    "description": (
                        f"High DNS query volume from {src_ip}: "
                        f"{len(self.dns_queries[src_ip])} queries in {volume_window}s"
                    )
                })
        
        return alerts

    # ──────────────────────────────────────────────────────────
    # DETECTOR 4: BRUTE FORCE DETECTION
    # ──────────────────────────────────────────────────────────

    def _detect_brute_force(self, parsed):
        """
        Detect brute force login attempts.
        
        ATTACK EXPLAINED:
        Brute force attacks try many username/password combinations
        to gain unauthorized access to a service. Signs include:
        - Rapid repeated connections to authentication services
        - Many connections from one source to one destination port
        - Targeting common services: SSH(22), RDP(3389), FTP(21)
        
        DETECTION LOGIC:
        Track connection attempts (SYN packets) to monitored ports.
        If attempts from one source exceed threshold → alert.
        
        WHY MONITOR THESE PORTS:
        - 22 (SSH): Remote shell access — gold mine for attackers
        - 23 (Telnet): Unencrypted remote access — legacy but still seen
        - 3389 (RDP): Windows Remote Desktop — common ransomware entry point
        - 21 (FTP): File transfer — may contain sensitive data
        - 3306 (MySQL): Database — direct data access
        - 5432 (PostgreSQL): Database — direct data access
        """
        ip_data = parsed.get("ip", {})
        transport = parsed.get("transport", {})
        
        if not ip_data or not transport:
            return None
        
        src_ip = ip_data.get("src", "")
        dst_ip = ip_data.get("dst", "")
        dst_port = transport.get("dst_port", 0)
        flags = transport.get("flags", "")
        
        # Only track SYN packets (new connection attempts)
        if "SYN" not in flags or "ACK" in flags:
            return None
        
        # Only monitor configured ports
        bf_config = self.config.get("brute_force", {})
        monitored_ports = bf_config.get("monitored_ports", [22, 23, 3389, 21])
        
        if dst_port not in monitored_ports:
            return None
        
        now = time.time()
        target_key = f"{dst_ip}:{dst_port}"
        
        # Record the connection attempt
        self.connection_attempts[src_ip][target_key].append(now)
        
        # Clean old attempts outside the time window
        window = bf_config.get("time_window", 60)
        self.connection_attempts[src_ip][target_key] = [
            ts for ts in self.connection_attempts[src_ip][target_key]
            if now - ts < window
        ]
        
        threshold = bf_config.get("threshold", 10)
        attempt_count = len(self.connection_attempts[src_ip][target_key])
        
        if attempt_count >= threshold:
            alert_key = f"bruteforce_{src_ip}_{target_key}"
            if self._is_on_cooldown(alert_key):
                return None
            
            service_names = {
                22: "SSH", 23: "Telnet", 3389: "RDP",
                21: "FTP", 3306: "MySQL", 5432: "PostgreSQL"
            }
            
            return {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "timestamp": parsed.get("timestamp"),
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "details": {
                    "target_port": dst_port,
                    "service": service_names.get(dst_port, f"Port-{dst_port}"),
                    "attempt_count": attempt_count,
                    "time_window": window
                },
                "description": (
                    f"Brute force detected: {src_ip} → {dst_ip}:"
                    f"{dst_port} ({service_names.get(dst_port, 'Unknown')}) "
                    f"— {attempt_count} attempts in {window}s"
                )
            }
        
        return None

    # ──────────────────────────────────────────────────────────
    # DETECTOR 5: DATA EXFILTRATION DETECTION
    # ──────────────────────────────────────────────────────────

    def _detect_data_exfiltration(self, parsed):
        """
        Detect potential data exfiltration based on transfer volume.
        
        DATA EXFILTRATION EXPLAINED:
        The unauthorized transfer of data from an organization.
        Common methods:
        - Direct transfer to external servers
        - Cloud storage uploads
        - Encrypted channels to attacker infrastructure
        - Steganography (hiding data in images/files)
        
        DETECTION LOGIC:
        Track cumulative bytes transferred from each source to each
        destination within a time window. Alert if threshold exceeded.
        
        LIMITATIONS:
        - Cannot inspect encrypted traffic content
        - Legitimate large transfers (backups, uploads) will trigger alerts
        - Should be tuned per network environment
        """
        ip_data = parsed.get("ip", {})
        transport = parsed.get("transport", {})
        
        if not ip_data:
            return None
        
        src_ip = ip_data.get("src", "")
        dst_ip = ip_data.get("dst", "")
        packet_size = parsed.get("size", 0)
        payload_size = transport.get("payload_size", 0)
        
        now = time.time()
        exfil_config = self.config.get("data_exfiltration", {})
        window = exfil_config.get("time_window", 300)
        
        # Initialize tracking for new pairs
        if self.transfer_start_times[src_ip][dst_ip] == 0:
            self.transfer_start_times[src_ip][dst_ip] = now
        
        # Reset if outside time window
        if now - self.transfer_start_times[src_ip][dst_ip] > window:
            self.data_transfers[src_ip][dst_ip] = 0
            self.transfer_start_times[src_ip][dst_ip] = now
        
        # Accumulate transferred bytes
        self.data_transfers[src_ip][dst_ip] += payload_size if payload_size else packet_size
        
        threshold = exfil_config.get("threshold_bytes", 10485760)  # 10MB
        total_bytes = self.data_transfers[src_ip][dst_ip]
        
        if total_bytes >= threshold:
            alert_key = f"exfil_{src_ip}_{dst_ip}"
            if self._is_on_cooldown(alert_key):
                return None
            
            from modules.utils import format_bytes
            return {
                "type": "DATA_EXFILTRATION",
                "severity": "HIGH",
                "timestamp": parsed.get("timestamp"),
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "details": {
                    "bytes_transferred": total_bytes,
                    "formatted_size": format_bytes(total_bytes),
                    "threshold": format_bytes(threshold),
                    "time_window": window,
                    "duration": round(now - self.transfer_start_times[src_ip][dst_ip], 1)
                },
                "description": (
                    f"Possible data exfiltration: {src_ip} → {dst_ip} "
                    f"transferred {format_bytes(total_bytes)} in "
                    f"{round(now - self.transfer_start_times[src_ip][dst_ip], 1)}s"
                )
            }
        
        return None

    # ──────────────────────────────────────────────────────────
    # DETECTOR 6: ICMP ANOMALY DETECTION
    # ──────────────────────────────────────────────────────────

    def _detect_icmp_anomaly(self, parsed):
        """
        Detect ICMP-based attacks.
        
        ICMP FLOOD (Ping Flood):
        Overwhelm a target with ICMP echo requests, consuming bandwidth
        and processing resources. Simple but effective DDoS technique.
        
        PING OF DEATH:
        Send an oversized ICMP packet (>65,535 bytes) that causes a buffer
        overflow in vulnerable systems. Historic attack — most modern OS are
        patched, but oversized ICMP is still suspicious.
        
        ICMP TUNNELING:
        Hide data in ICMP payload fields. Normal pings have small, predictable
        payloads. Large or high-entropy ICMP payloads are suspicious.
        """
        alerts = []
        icmp_data = parsed.get("icmp", {})
        ip_data = parsed.get("ip", {})
        
        if not icmp_data or not ip_data:
            return alerts
        
        src_ip = ip_data.get("src", "")
        now = time.time()
        icmp_config = self.config.get("icmp_anomaly", {})
        
        # Track ICMP packets from this source
        self.icmp_packets[src_ip].append(now)
        
        # ─── Check 1: ICMP Flood Detection ───
        flood_threshold = icmp_config.get("flood_threshold", 100)
        flood_window = icmp_config.get("flood_window", 10)
        
        # Clean old entries
        self.icmp_packets[src_ip] = [
            ts for ts in self.icmp_packets[src_ip]
            if now - ts < flood_window
        ]
        
        if len(self.icmp_packets[src_ip]) >= flood_threshold:
            alert_key = f"icmpflood_{src_ip}"
            if not self._is_on_cooldown(alert_key):
                alerts.append({
                    "type": "ICMP_FLOOD",
                    "severity": "HIGH",
                    "timestamp": parsed.get("timestamp"),
                    "source_ip": src_ip,
                    "details": {
                        "packet_count": len(self.icmp_packets[src_ip]),
                        "time_window": flood_window,
                        "icmp_type": icmp_data.get("type_name")
                    },
                    "description": (
                        f"ICMP flood from {src_ip}: "
                        f"{len(self.icmp_packets[src_ip])} packets in {flood_window}s"
                    )
                })
        
        # ─── Check 2: Oversized ICMP Packet ───
        max_size = icmp_config.get("max_packet_size", 1000)
        payload_size = icmp_data.get("payload_size", 0)
        
        if payload_size > max_size:
            alert_key = f"icmpsize_{src_ip}"
            if not self._is_on_cooldown(alert_key):
                alerts.append({
                    "type": "ICMP_OVERSIZED",
                    "severity": "MEDIUM",
                    "timestamp": parsed.get("timestamp"),
                    "source_ip": src_ip,
                    "details": {
                        "payload_size": payload_size,
                        "threshold": max_size,
                        "icmp_type": icmp_data.get("type_name")
                    },
                    "description": (
                        f"Oversized ICMP from {src_ip}: "
                        f"{payload_size} bytes (threshold: {max_size})"
                    )
                })
        
        return alerts

    # ──────────────────────────────────────────────────────────
    # UTILITY METHODS
    # ──────────────────────────────────────────────────────────

    def _is_on_cooldown(self, alert_key):
        """
        Check if an alert is on cooldown to prevent flooding.
        Returns True if we should suppress the alert.
        """
        now = time.time()
        if alert_key in self.alert_cooldowns:
            if now - self.alert_cooldowns[alert_key] < self.COOLDOWN_PERIOD:
                return True
        
        self.alert_cooldowns[alert_key] = now
        return False

    def _cleanup_expired_state(self):
        """
        Periodically clean up tracking data structures to prevent
        memory leaks during long-running captures.
        
        Called automatically on every packet analysis.
        Only performs cleanup every 100 calls to avoid overhead.
        """
        if not hasattr(self, '_cleanup_counter'):
            self._cleanup_counter = 0
        
        self._cleanup_counter += 1
        if self._cleanup_counter < 100:
            return
        
        self._cleanup_counter = 0
        now = time.time()
        
        # Clean port scan tracking (older than 2x window)
        max_age = self.config.get("port_scan", {}).get("time_window", 30) * 2
        for src_ip in list(self.port_access.keys()):
            for dst_ip in list(self.port_access[src_ip].keys()):
                ports = self.port_access[src_ip][dst_ip]
                self.port_access[src_ip][dst_ip] = {
                    p: ts for p, ts in ports.items()
                    if now - ts < max_age
                }
                if not self.port_access[src_ip][dst_ip]:
                    del self.port_access[src_ip][dst_ip]
            if not self.port_access[src_ip]:
                del self.port_access[src_ip]
        
        # Clean alert cooldowns (older than cooldown period)
        self.alert_cooldowns = {
            key: ts for key, ts in self.alert_cooldowns.items()
            if now - ts < self.COOLDOWN_PERIOD * 2
        }

    def get_detection_stats(self):
        """
        Return current detection engine statistics.
        Useful for debugging and dashboard display.
        """
        return {
            "tracked_sources_portscan": len(self.port_access),
            "arp_table_size": len(self.arp_table),
            "tracked_dns_sources": len(self.dns_queries),
            "tracked_brute_force_sources": len(self.connection_attempts),
            "active_cooldowns": len(self.alert_cooldowns)
        }
