"""
capture.py - Packet Capture Engine
====================================
Handles the actual packet capture using Scapy's sniff() function,
which leverages libpcap underneath for efficient packet capture.

CYBERSECURITY CONCEPTS:
-----------------------
Packet capture happens at the DATA LINK LAYER (Layer 2) of the OSI model.
The network interface card (NIC) is put into "promiscuous mode," which
means it captures ALL packets on the network segment — not just those
addressed to this machine.

How capture works under the hood:
1. NIC in promiscuous mode receives all frames on the wire
2. libpcap (via BPF) applies kernel-level filters for efficiency
3. Matching packets are copied to userspace (our Python program)
4. Scapy wraps each packet in a rich object for easy manipulation

BPF (Berkeley Packet Filter):
Filters packets in the kernel before copying to userspace.
This is critical for performance — without BPF, capturing on
a busy network would overwhelm the CPU.

Examples:
- "tcp port 80" — only HTTP traffic
- "host 192.168.1.100" — traffic to/from specific host
- "tcp and port 22" — only SSH traffic
- "not arp" — everything except ARP

LEGAL NOTE:
Packet capture on networks you don't own or have explicit permission
to monitor is illegal in most jurisdictions. Always get authorization.
"""

import sys
import threading

# Try importing Scapy
try:
    from scapy.all import sniff, wrpcap, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from modules.parser import PacketParser
from modules.detector import ThreatDetector
from modules.logger import AlertLogger
from modules.stats import TrafficStats
from modules.utils import Colors


class PacketCaptureEngine:
    """
    Main capture engine that orchestrates:
    1. Packet capture (via Scapy)
    2. Protocol parsing
    3. Threat detection
    4. Logging and alerting
    5. Statistics collection
    
    This is the central coordinator — the "brain" of the sniffer.
    """

    def __init__(self, config, interface=None, bpf_filter=None,
                 packet_count=0, output_file=None, verbose=False):
        """
        Initialize the capture engine.
        
        Args:
            config (dict): Full configuration dictionary
            interface (str): Network interface to capture on (None = default)
            bpf_filter (str): BPF filter expression
            packet_count (int): Max packets to capture (0 = unlimited)
            output_file (str): Path to save PCAP file (None = don't save)
            verbose (bool): Show detailed packet information
        """
        if not SCAPY_AVAILABLE:
            print(f"{Colors.RED}[ERROR] Scapy is not installed. "
                  f"Run: pip install scapy{Colors.RESET}")
            sys.exit(1)
        
        self.config = config
        self.interface = interface or config.get("capture", {}).get("interface")
        self.bpf_filter = bpf_filter or config.get("capture", {}).get("bpf_filter")
        self.packet_count = packet_count or config.get("capture", {}).get("packet_count", 0)
        self.output_file = output_file
        self.verbose = verbose
        
        # Initialize sub-components
        self.parser = PacketParser()
        self.detector = ThreatDetector(config)
        self.logger = AlertLogger(config)
        self.stats = TrafficStats(config)
        
        # Packet storage for PCAP export
        self.captured_packets = []
        self.save_pcap = output_file is not None or config.get("output", {}).get("save_pcap", False)
        
        # Control flags
        self.running = False
        self.packet_counter = 0

    def start(self):
        """
        Start packet capture.
        
        This method blocks until capture is stopped (Ctrl+C or packet limit).
        The capture runs in the main thread because Scapy's sniff()
        needs to handle signals for clean shutdown.
        """
        self.running = True
        
        # Display capture configuration
        self._print_capture_info()
        
        self.logger.log_event("info", 
            f"Starting capture on {self.interface or 'default interface'}")
        
        try:
            # Scapy's sniff() function
            # - iface: Network interface (None = default)
            # - prn: Callback function called for EACH packet
            # - filter: BPF filter string for kernel-level filtering
            # - count: Number of packets (0 = infinite)
            # - store: Whether to keep packets in memory (needed for PCAP)
            # - stop_filter: Function that returns True to stop capture
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.bpf_filter if self.bpf_filter else None,
                count=self.packet_count if self.packet_count > 0 else 0,
                store=False,  # We handle storage ourselves
                stop_filter=lambda p: not self.running
            )
            
        except PermissionError:
            print(f"\n{Colors.RED}[ERROR] Permission denied! "
                  f"Packet capture requires root/sudo privileges.")
            print(f"Run with: sudo python3 packet_sniffer.py{Colors.RESET}")
            sys.exit(1)
            
        except KeyboardInterrupt:
            self.stop()
            
        except Exception as e:
            self.logger.log_event("error", f"Capture error: {e}")
            self.stop()

    def stop(self):
        """
        Stop capture and generate final report.
        Called when user presses Ctrl+C or packet limit is reached.
        """
        self.running = False
        
        print(f"\n{Colors.YELLOW}[*] Stopping capture...{Colors.RESET}")
        
        # Save PCAP if configured
        if self.save_pcap and self.captured_packets:
            pcap_path = self.output_file or "captures/capture.pcap"
            try:
                wrpcap(pcap_path, self.captured_packets)
                print(f"{Colors.GREEN}[✓] Saved {len(self.captured_packets)} "
                      f"packets to {pcap_path}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[✗] Failed to save PCAP: {e}{Colors.RESET}")
        
        # Display final report
        alert_summary = self.logger.get_alert_summary()
        self.stats.display_final_report(alert_summary)
        
        self.logger.log_event("info", 
            f"Capture stopped. {self.stats.total_packets} packets captured.")

    def _process_packet(self, packet):
        """
        Callback for each captured packet.
        This is the MAIN PROCESSING PIPELINE for every packet:
        
        Raw Packet → Parse → Detect → Log → Stats
        
        Args:
            packet: Raw Scapy packet object
        """
        self.packet_counter += 1
        
        # Store raw packet if saving PCAP
        if self.save_pcap:
            self.captured_packets.append(packet)
        
        # STEP 1: PARSE — Decode all protocol layers
        parsed = self.parser.parse(packet)
        
        if not parsed:
            return
        
        # STEP 2: DETECT — Run threat detection rules
        alerts = self.detector.analyze(parsed)
        
        # STEP 3: LOG — Display packet and any alerts
        self.logger.log_packet(parsed)
        
        for alert in alerts:
            self.logger.log_alert(alert)
        
        # STEP 4: STATS — Update traffic statistics
        self.stats.update(parsed)
        
        # Show verbose details if requested
        if self.verbose:
            self._print_verbose(parsed)
        
        # Periodic statistics display
        if self.stats.should_display():
            self.stats.display_periodic()

    def _print_capture_info(self):
        """Display capture configuration at startup."""
        print(f"{Colors.GREEN}[*] Interface: "
              f"{self.interface or 'default'}{Colors.RESET}")
        print(f"{Colors.GREEN}[*] Filter: "
              f"{self.bpf_filter or 'None (all traffic)'}{Colors.RESET}")
        if self.packet_count > 0:
            print(f"{Colors.GREEN}[*] Packet limit: "
                  f"{self.packet_count}{Colors.RESET}")
        if self.save_pcap:
            print(f"{Colors.GREEN}[*] Saving to: "
                  f"{self.output_file or 'captures/capture.pcap'}{Colors.RESET}")
        
        print(f"{Colors.GREEN}[*] Starting capture... "
              f"Press Ctrl+C to stop.{Colors.RESET}")
        print(f"{'─' * 70}\n")

    def _print_verbose(self, parsed):
        """Print detailed packet information in verbose mode."""
        if "ERROR" in parsed.get("layers", []):
            return
        
        ip = parsed.get("ip", {})
        transport = parsed.get("transport", {})
        
        # Show TTL (useful for OS fingerprinting)
        if ip.get("ttl"):
            os_guess = self._guess_os_by_ttl(ip["ttl"])
            print(f"    TTL: {ip['ttl']} (likely {os_guess})")
        
        # Show payload preview if present
        payload = parsed.get("raw_payload")
        if payload:
            max_display = self.config.get("output", {}).get("max_payload_display", 256)
            preview = payload[:max_display]
            if len(payload) > max_display:
                preview += f"... ({len(payload)} bytes total)"
            print(f"    Payload: {preview}")

    @staticmethod
    def _guess_os_by_ttl(ttl):
        """
        Guess the operating system based on initial TTL value.
        
        OS FINGERPRINTING via TTL:
        Different operating systems use different default TTL values.
        By looking at the TTL in received packets (which decrements
        by 1 at each router hop), we can estimate the original TTL
        and thus the source OS.
        
        Common defaults:
        - Linux/macOS: TTL = 64
        - Windows: TTL = 128
        - Cisco/Network devices: TTL = 255
        - Solaris: TTL = 254
        
        Note: TTL decrements per hop, so a Windows machine 3 hops away
        shows TTL=125. We round up to the nearest known default.
        """
        if ttl <= 64:
            return "Linux/macOS"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Device/Solaris"
        return "Unknown"

    @staticmethod
    def list_interfaces():
        """List available network interfaces."""
        if not SCAPY_AVAILABLE:
            print("Scapy not available. Cannot list interfaces.")
            return []
        
        interfaces = get_if_list()
        print(f"\n{Colors.BRIGHT}Available Network Interfaces:{Colors.RESET}")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        print()
        return interfaces
