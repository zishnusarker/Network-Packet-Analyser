#!/usr/bin/env python3
"""
packet_sniffer.py - Network Packet Analyzer & Sniffer
======================================================

Main entry point for the Network Packet Analyzer.

USAGE:
    sudo python3 packet_sniffer.py [options]

OPTIONS:
    --interface, -i    Network interface (default: auto-detect)
    --filter, -f       BPF filter expression
    --count, -c        Number of packets to capture (0 = unlimited)
    --output, -o       Output PCAP file path
    --verbose, -v      Show detailed packet information
    --list-interfaces  List available network interfaces
    --config           Path to configuration file
    --help, -h         Show this help message

EXAMPLES:
    sudo python3 packet_sniffer.py
    sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80" -c 100
    sudo python3 packet_sniffer.py -o captures/session.pcap -v
    python3 packet_sniffer.py --list-interfaces

REQUIRES: Root/sudo privileges for packet capture.

Author: Cybersecurity Portfolio Project
License: MIT
"""

import sys
import os
import argparse
import signal

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import load_config, print_banner, Colors
from modules.capture import PacketCaptureEngine


def parse_arguments():
    """
    Parse command-line arguments using argparse.
    
    argparse is Python's standard library for building CLI tools.
    In cybersecurity, most professional tools are CLI-based because:
    - They can be scripted and automated
    - They work over SSH on remote systems
    - They can be chained with other tools via pipes
    - No GUI dependency = runs on any server
    """
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer & Sniffer - "
                    "Capture and analyze network traffic with threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  sudo python3 packet_sniffer.py                          # Basic capture
  sudo python3 packet_sniffer.py -i eth0                  # Specific interface
  sudo python3 packet_sniffer.py -f "tcp port 80"         # HTTP only
  sudo python3 packet_sniffer.py -c 1000 -o capture.pcap  # Save 1000 packets
  sudo python3 packet_sniffer.py -v                       # Verbose mode
  python3 packet_sniffer.py --list-interfaces              # Show interfaces

BPF FILTER EXAMPLES:
  "tcp"                    - Only TCP traffic
  "udp port 53"            - Only DNS traffic
  "host 192.168.1.100"     - Traffic to/from specific host
  "tcp port 80 or port 443" - HTTP and HTTPS
  "not arp"                - Everything except ARP
  "src net 192.168.1.0/24" - Traffic from specific subnet
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to capture on (default: auto-detect)',
        default=None
    )
    
    parser.add_argument(
        '-f', '--filter',
        help='BPF (Berkeley Packet Filter) expression',
        default=None
    )
    
    parser.add_argument(
        '-c', '--count',
        help='Number of packets to capture (0 = unlimited)',
        type=int,
        default=0
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Save captured packets to PCAP file',
        default=None
    )
    
    parser.add_argument(
        '-v', '--verbose',
        help='Show detailed packet information (TTL, payload preview)',
        action='store_true'
    )
    
    parser.add_argument(
        '--list-interfaces',
        help='List available network interfaces and exit',
        action='store_true'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file (default: config.yaml)',
        default='config.yaml'
    )
    
    return parser.parse_args()


def check_root():
    """
    Check if running with root/sudo privileges.
    
    WHY ROOT IS REQUIRED:
    Packet capture requires access to raw sockets, which is a privileged
    operation. This is a security feature of the OS — you don't want
    any unprivileged process to be able to sniff network traffic.
    
    On Linux: uid 0 = root
    Alternative: Use Linux capabilities (CAP_NET_RAW) instead of full root
    """
    if os.geteuid() != 0:
        return False
    return True


def setup_signal_handlers(engine):
    """
    Set up graceful shutdown on SIGINT (Ctrl+C) and SIGTERM.
    
    Signal handling ensures:
    1. PCAP file is properly saved
    2. Final statistics are displayed
    3. Log files are properly closed
    4. No data corruption from abrupt termination
    """
    def signal_handler(signum, frame):
        print(f"\n{Colors.YELLOW}[*] Signal received. Shutting down...{Colors.RESET}")
        engine.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def ensure_directories():
    """Create necessary directories if they don't exist."""
    dirs = ['logs', 'captures']
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def main():
    """
    Main entry point.
    
    Pipeline:
    1. Parse CLI arguments
    2. Load configuration
    3. Check privileges
    4. Initialize capture engine
    5. Start capture loop
    6. On exit: save PCAP, show report
    """
    # Parse command-line arguments
    args = parse_arguments()
    
    # Handle --list-interfaces (doesn't require root)
    if args.list_interfaces:
        PacketCaptureEngine.list_interfaces()
        sys.exit(0)
    
    # Display banner
    print_banner()
    
    # Create necessary directories
    ensure_directories()
    
    # Load configuration
    config = load_config(args.config)
    print(f"{Colors.GREEN}[✓] Configuration loaded from {args.config}{Colors.RESET}")
    
    # Check root privileges
    if not check_root():
        print(f"{Colors.YELLOW}[!] WARNING: Not running as root. "
              f"Packet capture may fail.{Colors.RESET}")
        print(f"{Colors.YELLOW}    Run with: sudo python3 packet_sniffer.py{Colors.RESET}")
        print(f"{Colors.YELLOW}    Continuing anyway (some features may be limited)...{Colors.RESET}\n")
    
    # Create output directory for PCAP if needed
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
    
    # Initialize the capture engine
    engine = PacketCaptureEngine(
        config=config,
        interface=args.interface,
        bpf_filter=args.filter,
        packet_count=args.count,
        output_file=args.output,
        verbose=args.verbose
    )
    
    # Set up graceful shutdown handlers
    setup_signal_handlers(engine)
    
    # Start capture
    print(f"{Colors.GREEN}[✓] Capture engine initialized{Colors.RESET}")
    print(f"{Colors.GREEN}[✓] Threat detection engine loaded "
          f"(7 detection modules active){Colors.RESET}\n")
    
    try:
        engine.start()
    except KeyboardInterrupt:
        engine.stop()
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Fatal error: {e}{Colors.RESET}")
        engine.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
