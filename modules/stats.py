"""
stats.py - Traffic Statistics Engine
=====================================
Tracks and reports network traffic statistics including
protocol distribution, top talkers, and traffic volume.

CYBERSECURITY CONCEPTS:
-----------------------
Traffic baselining is essential for anomaly detection:
- Knowing "normal" helps you spot "abnormal"
- Sudden protocol shifts may indicate attacks
- New top talkers could be compromised hosts
- Traffic volume spikes may signal DDoS or exfiltration

SOC analysts use traffic statistics dashboards daily to:
- Monitor network health and utilization
- Identify performance bottlenecks
- Spot unusual patterns that warrant investigation
- Generate reports for management and compliance
"""

import time
from collections import defaultdict, Counter
from modules.utils import Colors, format_bytes
from tabulate import tabulate


class TrafficStats:
    """
    Collects and reports traffic statistics from captured packets.
    
    Tracks:
    - Total packet and byte counts
    - Protocol distribution (TCP, UDP, ARP, ICMP, DNS, HTTP)
    - Top source and destination IPs (top talkers)
    - Top destination ports (most accessed services)
    - Packets per second rate
    - Capture duration
    """

    def __init__(self, config):
        """
        Initialize statistics tracking.
        
        Args:
            config (dict): Stats configuration section from config.yaml
        """
        self.config = config.get("stats", {})
        self.display_interval = self.config.get("display_interval", 30)
        self.track_top_talkers = self.config.get("track_top_talkers", True)
        self.top_count = self.config.get("top_talkers_count", 10)
        
        # ─── Counters ───
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.last_display_time = time.time()
        
        # Protocol counters
        self.protocol_counts = Counter()
        
        # IP tracking
        self.source_ips = Counter()
        self.dest_ips = Counter()
        
        # Port tracking
        self.dest_ports = Counter()
        
        # Bytes per source IP (useful for finding data-heavy hosts)
        self.bytes_per_source = Counter()
        
        # Time-series data (packets per second)
        self.pps_history = []
        self._pps_counter = 0
        self._pps_last_check = time.time()

    def update(self, parsed_packet):
        """
        Update statistics with a new parsed packet.
        
        Args:
            parsed_packet (dict): Output from PacketParser.parse()
        """
        if not parsed_packet or "ERROR" in parsed_packet.get("layers", []):
            return
        
        self.total_packets += 1
        packet_size = parsed_packet.get("size", 0)
        self.total_bytes += packet_size
        
        # Count protocols
        layers = parsed_packet.get("layers", [])
        for layer in layers:
            if layer in ("TCP", "UDP", "ARP", "ICMP", "DNS", "HTTP"):
                self.protocol_counts[layer] += 1
        
        # Track IPs
        ip_data = parsed_packet.get("ip", {})
        if ip_data:
            src = ip_data.get("src", "")
            dst = ip_data.get("dst", "")
            if src:
                self.source_ips[src] += 1
                self.bytes_per_source[src] += packet_size
            if dst:
                self.dest_ips[dst] += 1
        
        # Track ARP IPs too
        if "ARP" in layers:
            arp = parsed_packet.get("arp", {})
            if arp.get("sender_ip"):
                self.source_ips[arp["sender_ip"]] += 1
        
        # Track destination ports
        transport = parsed_packet.get("transport", {})
        if transport.get("dst_port"):
            self.dest_ports[transport["dst_port"]] += 1
        
        # Update PPS (packets per second) tracking
        self._pps_counter += 1
        now = time.time()
        if now - self._pps_last_check >= 1.0:
            self.pps_history.append(self._pps_counter)
            self._pps_counter = 0
            self._pps_last_check = now
            # Keep last 300 seconds of PPS data
            if len(self.pps_history) > 300:
                self.pps_history = self.pps_history[-300:]

    def should_display(self):
        """Check if it's time to display periodic statistics."""
        now = time.time()
        if now - self.last_display_time >= self.display_interval:
            self.last_display_time = now
            return True
        return False

    def display_periodic(self):
        """Display periodic inline statistics summary."""
        duration = time.time() - self.start_time
        avg_pps = self.total_packets / duration if duration > 0 else 0
        
        # Protocol breakdown string
        proto_parts = []
        for proto in ["TCP", "UDP", "ARP", "ICMP", "DNS", "HTTP"]:
            count = self.protocol_counts.get(proto, 0)
            if count > 0:
                pct = (count / self.total_packets * 100) if self.total_packets > 0 else 0
                proto_parts.append(f"{proto}: {count} ({pct:.1f}%)")
        
        other = self.total_packets - sum(
            self.protocol_counts.get(p, 0) 
            for p in ["TCP", "UDP", "ARP", "ICMP"]
        )
        if other > 0 and self.total_packets > 0:
            proto_parts.append(f"Other: {other} ({other/self.total_packets*100:.1f}%)")
        
        separator = f"{Colors.WHITE}{'─' * 70}{Colors.RESET}"
        
        print(f"\n{separator}")
        print(
            f"{Colors.BRIGHT}{Colors.WHITE}"
            f"  📊 Packets: {self.total_packets:,}  |  "
            f"Duration: {duration:.0f}s  |  "
            f"Rate: {avg_pps:.1f} pps  |  "
            f"Data: {format_bytes(self.total_bytes)}"
            f"{Colors.RESET}"
        )
        print(f"  {' | '.join(proto_parts)}")
        
        # Unique hosts
        print(
            f"  Unique Sources: {len(self.source_ips)}  |  "
            f"Unique Destinations: {len(self.dest_ips)}"
        )
        print(separator)
        print()

    def display_final_report(self, alert_summary=None):
        """
        Display comprehensive final statistics report.
        Called when capture stops (Ctrl+C).
        
        Args:
            alert_summary (dict): Alert statistics from AlertLogger
        """
        duration = time.time() - self.start_time
        avg_pps = self.total_packets / duration if duration > 0 else 0
        
        print(f"\n{'═' * 70}")
        print(f"{Colors.BRIGHT}{Colors.CYAN}  CAPTURE SUMMARY REPORT{Colors.RESET}")
        print(f"{'═' * 70}\n")
        
        # ─── General Stats ───
        print(f"{Colors.BRIGHT}  General Statistics{Colors.RESET}")
        print(f"  {'─' * 40}")
        print(f"  Total Packets:     {self.total_packets:,}")
        print(f"  Total Data:        {format_bytes(self.total_bytes)}")
        print(f"  Duration:          {duration:.1f} seconds")
        print(f"  Average Rate:      {avg_pps:.1f} packets/second")
        
        if self.pps_history:
            print(f"  Peak Rate:         {max(self.pps_history)} packets/second")
        
        print(f"  Unique Sources:    {len(self.source_ips)}")
        print(f"  Unique Destinations: {len(self.dest_ips)}")
        print()
        
        # ─── Protocol Distribution ───
        print(f"{Colors.BRIGHT}  Protocol Distribution{Colors.RESET}")
        print(f"  {'─' * 40}")
        
        if self.total_packets > 0:
            proto_table = []
            for proto, count in self.protocol_counts.most_common():
                pct = count / self.total_packets * 100
                bar = "█" * int(pct / 2) + "░" * (50 - int(pct / 2))
                proto_table.append([proto, f"{count:,}", f"{pct:.1f}%", bar])
            
            if proto_table:
                print(tabulate(
                    proto_table,
                    headers=["Protocol", "Packets", "Percentage", "Distribution"],
                    tablefmt="simple",
                    stralign="right"
                ))
        print()
        
        # ─── Top Source IPs ───
        if self.track_top_talkers and self.source_ips:
            print(f"{Colors.BRIGHT}  Top Source IPs (Talkers){Colors.RESET}")
            print(f"  {'─' * 40}")
            
            src_table = []
            for ip, count in self.source_ips.most_common(self.top_count):
                bytes_sent = self.bytes_per_source.get(ip, 0)
                src_table.append([ip, f"{count:,}", format_bytes(bytes_sent)])
            
            print(tabulate(
                src_table,
                headers=["Source IP", "Packets", "Bytes Sent"],
                tablefmt="simple"
            ))
            print()
        
        # ─── Top Destination IPs ───
        if self.track_top_talkers and self.dest_ips:
            print(f"{Colors.BRIGHT}  Top Destination IPs{Colors.RESET}")
            print(f"  {'─' * 40}")
            
            dst_table = []
            for ip, count in self.dest_ips.most_common(self.top_count):
                dst_table.append([ip, f"{count:,}"])
            
            print(tabulate(
                dst_table,
                headers=["Destination IP", "Packets"],
                tablefmt="simple"
            ))
            print()
        
        # ─── Top Destination Ports ───
        if self.dest_ports:
            print(f"{Colors.BRIGHT}  Top Destination Ports (Services){Colors.RESET}")
            print(f"  {'─' * 40}")
            
            well_known_ports = {
                20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
                25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                993: "IMAPS", 995: "POP3S", 3306: "MySQL",
                3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
                8443: "HTTPS-Alt"
            }
            
            port_table = []
            for port, count in self.dest_ports.most_common(self.top_count):
                service = well_known_ports.get(port, "")
                port_table.append([port, service, f"{count:,}"])
            
            print(tabulate(
                port_table,
                headers=["Port", "Service", "Connections"],
                tablefmt="simple"
            ))
            print()
        
        # ─── Alert Summary ───
        if alert_summary:
            print(f"{Colors.BRIGHT}{Colors.RED}  Security Alert Summary{Colors.RESET}")
            print(f"  {'─' * 40}")
            print(f"  Total Alerts: {alert_summary.get('total_alerts', 0)}")
            
            by_severity = alert_summary.get("by_severity", {})
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = by_severity.get(sev, 0)
                if count > 0:
                    print(f"  {sev}: {count}")
            
            by_type = alert_summary.get("by_type", {})
            if by_type:
                print(f"\n  Alerts by Type:")
                for atype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                    print(f"    {atype}: {count}")
            print()
        
        print(f"{'═' * 70}\n")

    def get_stats_dict(self):
        """Return current statistics as a dictionary."""
        duration = time.time() - self.start_time
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration": duration,
            "avg_pps": self.total_packets / duration if duration > 0 else 0,
            "protocols": dict(self.protocol_counts),
            "unique_sources": len(self.source_ips),
            "unique_destinations": len(self.dest_ips)
        }
