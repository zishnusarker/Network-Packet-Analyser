"""
parser.py - Protocol Parser & Dissector
=========================================
Decodes captured packets into structured data by extracting
information from each protocol layer.

CYBERSECURITY CONCEPTS:
-----------------------
Protocol Dissection: The process of breaking down a network packet into
its component layers and extracting meaningful fields. This is what tools
like Wireshark do visually — we do it programmatically.

Packet Encapsulation: Each layer wraps the layer above it.
An HTTP request looks like this on the wire:

┌─────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                   │
│  └─ src_mac, dst_mac, type                   │
│  ┌───────────────────────────────────────┐   │
│  │ IP Header (20+ bytes)                  │   │
│  │  └─ src_ip, dst_ip, protocol, ttl      │   │
│  │  ┌─────────────────────────────────┐   │   │
│  │  │ TCP Header (20+ bytes)           │   │   │
│  │  │  └─ src_port, dst_port, flags    │   │   │
│  │  │  ┌───────────────────────────┐   │   │   │
│  │  │  │ HTTP Data (variable)      │   │   │   │
│  │  │  │  └─ method, url, headers  │   │   │   │
│  │  │  └───────────────────────────┘   │   │   │
│  │  └─────────────────────────────────┘   │   │
│  └───────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
"""

from datetime import datetime
from modules.utils import get_tcp_flags, format_mac, format_bytes

# Try importing Scapy layers
# Scapy is the de-facto Python library for packet manipulation
try:
    from scapy.all import (
        Ether, IP, TCP, UDP, ARP, ICMP, DNS, DNSQR, DNSRR, Raw
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketParser:
    """
    Parses raw packets into structured dictionaries.
    
    Each parsed packet contains:
    - timestamp: When the packet was captured
    - layers: List of protocol layers present (e.g., ["Ethernet", "IP", "TCP"])
    - ethernet: Source/destination MAC addresses
    - ip: Source/destination IPs, TTL, protocol
    - tcp/udp: Ports, flags, sequence numbers
    - dns: Query/response details
    - http: Method, URL, headers (if unencrypted)
    - arp: Operation, sender/target IPs and MACs
    - icmp: Type, code, payload size
    - raw_payload: Application layer data (if any)
    - size: Total packet size in bytes
    """

    def parse(self, packet):
        """
        Main parsing method. Takes a Scapy packet and returns
        a structured dictionary with all extracted fields.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Parsed packet data, or None if parsing fails
        """
        try:
            parsed = {
                "timestamp": datetime.now().isoformat(),
                "display_time": datetime.now().strftime("%H:%M:%S"),
                "layers": [],
                "size": len(packet),
                "ethernet": {},
                "ip": {},
                "transport": {},
                "application": {},
                "raw_payload": None,
                "alerts": []  # Any immediate alerts from parsing
            }
            
            # ─── Layer 2: Ethernet ───
            if packet.haslayer(Ether):
                parsed["layers"].append("Ethernet")
                parsed["ethernet"] = self._parse_ethernet(packet[Ether])
            
            # ─── Layer 2: ARP ───
            # ARP is special — it's Layer 2 but has its own structure
            if packet.haslayer(ARP):
                parsed["layers"].append("ARP")
                parsed["arp"] = self._parse_arp(packet[ARP])
                return parsed  # ARP packets don't have IP/TCP layers
            
            # ─── Layer 3: IP ───
            if packet.haslayer(IP):
                parsed["layers"].append("IP")
                parsed["ip"] = self._parse_ip(packet[IP])
            
            # ─── Layer 3: ICMP ───
            if packet.haslayer(ICMP):
                parsed["layers"].append("ICMP")
                parsed["icmp"] = self._parse_icmp(packet[ICMP])
            
            # ─── Layer 4: TCP ───
            if packet.haslayer(TCP):
                parsed["layers"].append("TCP")
                parsed["transport"] = self._parse_tcp(packet[TCP])
                
                # Check for HTTP (unencrypted web traffic on port 80)
                if packet.haslayer(Raw):
                    payload = self._extract_payload(packet)
                    if payload and self._is_http(payload, packet[TCP]):
                        parsed["layers"].append("HTTP")
                        parsed["application"]["http"] = self._parse_http(payload)
                    parsed["raw_payload"] = payload
            
            # ─── Layer 4: UDP ───
            elif packet.haslayer(UDP):
                parsed["layers"].append("UDP")
                parsed["transport"] = self._parse_udp(packet[UDP])
            
            # ─── Layer 7: DNS ───
            if packet.haslayer(DNS):
                parsed["layers"].append("DNS")
                parsed["application"]["dns"] = self._parse_dns(packet[DNS])
            
            return parsed
            
        except Exception as e:
            # In production, we log and skip malformed packets
            # rather than crashing the entire capture
            return {
                "timestamp": datetime.now().isoformat(),
                "display_time": datetime.now().strftime("%H:%M:%S"),
                "layers": ["ERROR"],
                "error": str(e),
                "size": len(packet) if packet else 0
            }

    # ──────────────────────────────────────────────────────────
    # LAYER-SPECIFIC PARSERS
    # ──────────────────────────────────────────────────────────

    def _parse_ethernet(self, eth_layer):
        """
        Parse Ethernet (Layer 2) header.
        
        Ethernet Frame Structure:
        ┌────────────┬────────────┬──────────┬─────────┐
        │ Dest MAC   │ Source MAC │ Type     │ Payload │
        │ (6 bytes)  │ (6 bytes)  │ (2 bytes)│ (var)   │
        └────────────┴────────────┴──────────┴─────────┘
        
        Type field tells us what's inside:
        - 0x0800: IPv4
        - 0x0806: ARP
        - 0x86DD: IPv6
        """
        return {
            "src_mac": format_mac(eth_layer.src),
            "dst_mac": format_mac(eth_layer.dst),
            "type": hex(eth_layer.type),
            "type_name": self._get_ether_type_name(eth_layer.type)
        }

    def _parse_ip(self, ip_layer):
        """
        Parse IPv4 (Layer 3) header.
        
        Key fields for security analysis:
        - src/dst: Who is talking to whom
        - TTL: Can reveal OS fingerprinting (Linux=64, Windows=128)
        - Protocol: What Layer 4 protocol is inside (6=TCP, 17=UDP, 1=ICMP)
        - Flags: Fragmentation flags (used in fragment attacks)
        """
        return {
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "protocol": ip_layer.proto,
            "protocol_name": self._get_ip_protocol_name(ip_layer.proto),
            "version": ip_layer.version,
            "header_length": ip_layer.ihl * 4,  # IHL is in 32-bit words
            "total_length": ip_layer.len,
            "identification": ip_layer.id,
            "flags": str(ip_layer.flags),
            "fragment_offset": ip_layer.frag
        }

    def _parse_tcp(self, tcp_layer):
        """
        Parse TCP (Layer 4) header.
        
        TCP is connection-oriented — it uses a three-way handshake:
        1. Client → SYN → Server          (I want to connect)
        2. Client ← SYN-ACK ← Server      (OK, I accept)
        3. Client → ACK → Server           (Great, let's talk)
        
        Security significance of flags:
        - SYN to many ports = Port scan
        - RST responses = Port is closed
        - FIN/NULL/XMAS = Stealth scan techniques
        - SYN without completing handshake = Half-open (SYN) scan
        """
        flags_int = int(tcp_layer.flags)
        return {
            "type": "TCP",
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "flags": get_tcp_flags(flags_int),
            "flags_raw": flags_int,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "window": tcp_layer.window,
            "payload_size": len(tcp_layer.payload) if tcp_layer.payload else 0
        }

    def _parse_udp(self, udp_layer):
        """
        Parse UDP (Layer 4) header.
        
        UDP is connectionless — no handshake, no guarantee of delivery.
        Used for: DNS (port 53), DHCP (67/68), NTP (123), streaming.
        
        Security relevance:
        - DNS over UDP is the primary target for DNS-based attacks
        - UDP flood attacks are common DDoS vectors
        - No connection state makes it easier to spoof source addresses
        """
        return {
            "type": "UDP",
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "length": udp_layer.len,
            "payload_size": len(udp_layer.payload) if udp_layer.payload else 0
        }

    def _parse_arp(self, arp_layer):
        """
        Parse ARP (Address Resolution Protocol) packet.
        
        ARP resolves IP addresses to MAC addresses on local networks.
        
        Operations:
        - op=1 (who-has): "Who has 192.168.1.1? Tell 192.168.1.105"
        - op=2 (is-at): "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
        
        ARP SPOOFING ATTACK:
        An attacker sends fake ARP replies claiming to be the gateway,
        causing traffic to flow through the attacker (Man-in-the-Middle).
        
        Normal: Gateway (192.168.1.1) → MAC: real_gateway_mac
        Attack: Attacker sends "192.168.1.1 is at attacker_mac"
        Result: Victim sends all traffic to attacker instead of gateway
        """
        return {
            "operation": "request" if arp_layer.op == 1 else "reply",
            "op_code": arp_layer.op,
            "sender_mac": format_mac(arp_layer.hwsrc),
            "sender_ip": arp_layer.psrc,
            "target_mac": format_mac(arp_layer.hwdst),
            "target_ip": arp_layer.pdst
        }

    def _parse_icmp(self, icmp_layer):
        """
        Parse ICMP (Internet Control Message Protocol) packet.
        
        Common ICMP types:
        - Type 0: Echo Reply (ping response)
        - Type 3: Destination Unreachable
        - Type 8: Echo Request (ping)
        - Type 11: Time Exceeded (traceroute)
        
        Security attacks using ICMP:
        - Ping flood: Overwhelming target with echo requests
        - Ping of Death: Oversized ICMP packets causing buffer overflow
        - ICMP tunneling: Hiding data in ICMP payload for exfiltration
        - Smurf attack: Spoofed broadcast pings causing amplification
        """
        type_names = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            13: "Timestamp Request",
            14: "Timestamp Reply"
        }
        
        return {
            "type": icmp_layer.type,
            "code": icmp_layer.code,
            "type_name": type_names.get(icmp_layer.type, f"Type-{icmp_layer.type}"),
            "payload_size": len(icmp_layer.payload) if icmp_layer.payload else 0
        }

    def _parse_dns(self, dns_layer):
        """
        Parse DNS (Domain Name System) packet.
        
        DNS converts human-readable names to IP addresses:
        "example.com" → 93.184.216.34
        
        DNS packet types:
        - QR=0: Query (client asking for resolution)
        - QR=1: Response (server providing answer)
        
        Security relevance:
        - DNS Tunneling: Encoding data in DNS queries to bypass firewalls
        - DGA Domains: Malware generating random domains for C2 communication
        - DNS Spoofing: Returning false DNS responses to redirect traffic
        - DNS Amplification: Using DNS for DDoS amplification attacks
        """
        dns_data = {
            "is_response": dns_layer.qr == 1,
            "query_count": dns_layer.qdcount,
            "answer_count": dns_layer.ancount,
            "queries": [],
            "answers": []
        }
        
        # Parse DNS queries
        if dns_layer.haslayer(DNSQR):
            try:
                for i in range(dns_layer.qdcount):
                    qr = dns_layer.qd
                    if qr:
                        qname = qr.qname.decode('utf-8', errors='replace').rstrip('.')
                        dns_data["queries"].append({
                            "name": qname,
                            "type": self._get_dns_type_name(qr.qtype),
                            "type_code": qr.qtype
                        })
            except Exception:
                pass  # Malformed DNS queries are common
        
        # Parse DNS answers
        if dns_layer.haslayer(DNSRR) and dns_layer.ancount > 0:
            try:
                answer = dns_layer.an
                for i in range(min(dns_layer.ancount, 10)):  # Limit to 10 answers
                    if answer:
                        rdata = str(answer.rdata)
                        if isinstance(answer.rdata, bytes):
                            rdata = answer.rdata.decode('utf-8', errors='replace')
                        dns_data["answers"].append({
                            "name": answer.rrname.decode('utf-8', errors='replace').rstrip('.'),
                            "type": self._get_dns_type_name(answer.type),
                            "data": rdata,
                            "ttl": answer.ttl
                        })
                        answer = answer.payload
                        if not hasattr(answer, 'rrname'):
                            break
            except Exception:
                pass
        
        return dns_data

    def _parse_http(self, payload):
        """
        Parse HTTP (unencrypted web traffic).
        
        NOTE: This only works for HTTP (port 80), not HTTPS (port 443).
        HTTPS traffic is encrypted with TLS and payload is not readable.
        In 2024+, most web traffic is HTTPS, so HTTP visibility is limited
        but still valuable for:
        - Internal network traffic (many internal services use HTTP)
        - Misconfigured services leaking data over HTTP
        - Detecting cleartext credential transmission
        """
        http_data = {
            "raw_header": "",
            "method": None,
            "url": None,
            "host": None,
            "user_agent": None,
            "content_type": None,
            "status_code": None
        }
        
        try:
            # HTTP messages start with either a request line or status line
            lines = payload.split("\r\n")
            if not lines:
                return http_data
            
            first_line = lines[0]
            http_data["raw_header"] = first_line
            
            # Check if it's a request (GET /path HTTP/1.1)
            http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
            for method in http_methods:
                if first_line.startswith(method):
                    parts = first_line.split(" ")
                    http_data["method"] = parts[0]
                    http_data["url"] = parts[1] if len(parts) > 1 else ""
                    break
            
            # Check if it's a response (HTTP/1.1 200 OK)
            if first_line.startswith("HTTP/"):
                parts = first_line.split(" ")
                http_data["status_code"] = int(parts[1]) if len(parts) > 1 else None
            
            # Parse headers
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    key_lower = key.lower()
                    if key_lower == "host":
                        http_data["host"] = value
                    elif key_lower == "user-agent":
                        http_data["user_agent"] = value
                    elif key_lower == "content-type":
                        http_data["content_type"] = value
                elif line == "":
                    break  # End of headers
        except Exception:
            pass
        
        return http_data

    # ──────────────────────────────────────────────────────────
    # HELPER METHODS
    # ──────────────────────────────────────────────────────────

    def _extract_payload(self, packet):
        """Extract and decode the raw payload from a packet."""
        try:
            if packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                try:
                    return raw_data.decode('utf-8', errors='replace')
                except Exception:
                    return raw_data.hex()
        except Exception:
            pass
        return None

    def _is_http(self, payload, tcp_layer):
        """
        Check if the payload looks like HTTP traffic.
        We check both the port and the content pattern.
        """
        http_ports = {80, 8080, 8000, 8888}
        if tcp_layer.sport in http_ports or tcp_layer.dport in http_ports:
            return True
        
        # Check content for HTTP signatures
        http_signatures = ["GET ", "POST ", "PUT ", "DELETE ", "HTTP/", "HEAD ", "OPTIONS "]
        return any(payload.startswith(sig) for sig in http_signatures)

    @staticmethod
    def _get_ether_type_name(ether_type):
        """Map Ethernet type code to human-readable name."""
        types = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN",
            0x8847: "MPLS"
        }
        return types.get(ether_type, f"Unknown(0x{ether_type:04x})")

    @staticmethod
    def _get_ip_protocol_name(proto):
        """Map IP protocol number to name."""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            89: "OSPF"
        }
        return protocols.get(proto, f"Proto-{proto}")

    @staticmethod
    def _get_dns_type_name(qtype):
        """Map DNS query type to name."""
        types = {
            1: "A",          # IPv4 address
            2: "NS",         # Name server
            5: "CNAME",      # Canonical name (alias)
            6: "SOA",        # Start of authority
            12: "PTR",       # Pointer (reverse DNS)
            15: "MX",        # Mail exchange
            16: "TXT",       # Text record (often used in tunneling)
            28: "AAAA",      # IPv6 address
            33: "SRV",       # Service locator
            255: "ANY"       # Any type (used in amplification attacks)
        }
        return types.get(qtype, f"Type-{qtype}")
