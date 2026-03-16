"""
utils.py - Shared Utility Functions
====================================
Contains helper functions used across multiple modules:
- Color formatting for terminal output
- Entropy calculation (used in DGA detection)
- Timestamp formatting
- Configuration loading

CYBERSECURITY CONCEPTS:
-----------------------
Shannon Entropy: A measure of randomness in data. In security, high entropy
in domain names often indicates Domain Generation Algorithms (DGAs) used by
malware to generate random C2 (Command & Control) domain names. Normal domains
like "google.com" have low entropy; DGA domains like "xk4mq9v2.com" have high entropy.
"""

import math
import yaml
import os
from datetime import datetime
from collections import Counter

# Try to import colorama for colored output; fall back to plain text if unavailable
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)  # Auto-reset color after each print
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# COLOR AND FORMATTING UTILITIES
# ─────────────────────────────────────────────────────────────

class Colors:
    """
    Centralized color constants for terminal output.
    Falls back to empty strings if colorama is not installed,
    so the code works regardless.
    """
    if COLORS_AVAILABLE:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        CYAN = Fore.CYAN
        MAGENTA = Fore.MAGENTA
        WHITE = Fore.WHITE
        BRIGHT = Style.BRIGHT
        RESET = Style.RESET_ALL
        BG_RED = Back.RED
        BG_YELLOW = Back.YELLOW
    else:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ""
        BRIGHT = RESET = BG_RED = BG_YELLOW = ""


def colorize(text, color):
    """Apply color to text string."""
    return f"{color}{text}{Colors.RESET}"


def severity_color(severity):
    """
    Map alert severity to appropriate color.
    Security alerts follow standard severity conventions:
    - CRITICAL (Red): Immediate action required
    - HIGH (Red): Significant threat detected
    - MEDIUM (Yellow): Suspicious activity, investigate
    - LOW (Cyan): Informational, low risk
    """
    severity_map = {
        "CRITICAL": Colors.BG_RED + Colors.WHITE,
        "HIGH": Colors.RED + Colors.BRIGHT,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.CYAN,
        "INFO": Colors.GREEN
    }
    return severity_map.get(severity.upper(), Colors.WHITE)


# ─────────────────────────────────────────────────────────────
# ENTROPY CALCULATION
# ─────────────────────────────────────────────────────────────

def calculate_entropy(data):
    """
    Calculate Shannon entropy of a string.
    
    THEORY:
    Shannon entropy measures the average information content per character.
    Formula: H(X) = -Σ p(x) * log2(p(x))
    
    - Low entropy (0-2): Predictable, repetitive data (e.g., "aaaaaa")
    - Medium entropy (2-3.5): Normal text/domains (e.g., "google.com")
    - High entropy (3.5+): Random-looking data (e.g., "xk4mq9v2a3.net")
    
    In cybersecurity, high entropy in domain names suggests:
    - Domain Generation Algorithms (DGAs) used by malware
    - Encoded/encrypted data being exfiltrated via DNS
    - Base64 or hex-encoded C2 communications
    
    Args:
        data (str): The string to analyze
        
    Returns:
        float: Shannon entropy value (0.0 to ~4.7 for alphanumeric)
    """
    if not data:
        return 0.0
    
    # Count frequency of each character
    # Counter({'g': 2, 'o': 3, 'l': 1, 'e': 1}) for "google"
    frequency = Counter(data)
    length = len(data)
    
    # Calculate probability and entropy for each unique character
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def is_suspicious_domain(domain, entropy_threshold=3.5, max_length=50):
    """
    Analyze a domain name for suspicious characteristics.
    
    Checks performed:
    1. Entropy analysis - high randomness suggests DGA
    2. Length analysis - unusually long subdomains suggest DNS tunneling
    3. Character distribution - excessive consonants suggest random generation
    
    Args:
        domain (str): Domain name to analyze
        entropy_threshold (float): Entropy above this is suspicious
        max_length (int): Subdomain length above this is suspicious
        
    Returns:
        tuple: (is_suspicious: bool, reasons: list[str])
    """
    reasons = []
    
    # Extract the subdomain part (everything before the last two labels)
    # For "malware.evil.example.com" → analyze "malware.evil"
    parts = domain.split(".")
    if len(parts) > 2:
        subdomain = ".".join(parts[:-2])
    else:
        subdomain = parts[0]
    
    # Check 1: Entropy analysis
    entropy = calculate_entropy(subdomain)
    if entropy > entropy_threshold:
        reasons.append(f"High entropy: {entropy:.2f} (threshold: {entropy_threshold})")
    
    # Check 2: Length analysis (DNS tunneling uses long subdomains to encode data)
    if len(subdomain) > max_length:
        reasons.append(f"Long subdomain: {len(subdomain)} chars (threshold: {max_length})")
    
    # Check 3: Numeric ratio (DGA domains often have high numbers)
    if subdomain:
        numeric_ratio = sum(c.isdigit() for c in subdomain) / len(subdomain)
        if numeric_ratio > 0.4:
            reasons.append(f"High numeric ratio: {numeric_ratio:.1%}")
    
    return (len(reasons) > 0, reasons)


# ─────────────────────────────────────────────────────────────
# CONFIGURATION MANAGEMENT
# ─────────────────────────────────────────────────────────────

def load_config(config_path="config.yaml"):
    """
    Load configuration from YAML file.
    Falls back to default values if file is missing or malformed.
    
    Args:
        config_path (str): Path to the YAML configuration file
        
    Returns:
        dict: Configuration dictionary with all settings
    """
    default_config = {
        "capture": {
            "interface": None,
            "promiscuous": True,
            "packet_count": 0,
            "bpf_filter": None,
            "snap_length": 65535
        },
        "detection": {
            "port_scan": {"enabled": True, "threshold": 15, "time_window": 30},
            "arp_spoof": {"enabled": True, "trusted_mappings": {}},
            "dns_analysis": {
                "enabled": True, "tunnel_detection": True,
                "max_subdomain_length": 50, "query_volume_threshold": 50,
                "query_volume_window": 60, "entropy_threshold": 3.5
            },
            "brute_force": {
                "enabled": True, "threshold": 10, "time_window": 60,
                "monitored_ports": [22, 23, 3389, 21, 3306, 5432]
            },
            "data_exfiltration": {
                "enabled": True, "threshold_bytes": 10485760, "time_window": 300
            },
            "icmp_anomaly": {
                "enabled": True, "flood_threshold": 100,
                "flood_window": 10, "max_packet_size": 1000
            }
        },
        "logging": {
            "log_directory": "logs",
            "log_level": "INFO",
            "log_to_file": True,
            "log_to_console": True,
            "alert_log_file": "logs/alerts.json",
            "event_log_file": "logs/events.log"
        },
        "output": {
            "save_pcap": False,
            "pcap_directory": "captures",
            "show_payload": False,
            "max_payload_display": 256,
            "colorized": True
        },
        "stats": {
            "display_interval": 30,
            "track_top_talkers": True,
            "top_talkers_count": 10
        }
    }
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
            if user_config:
                # Deep merge user config with defaults
                return deep_merge(default_config, user_config)
        except (yaml.YAMLError, IOError) as e:
            print(f"[!] Error loading config: {e}. Using defaults.")
    
    return default_config


def deep_merge(base, override):
    """
    Recursively merge two dictionaries.
    Values in 'override' take precedence over 'base'.
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ─────────────────────────────────────────────────────────────
# TIME AND FORMATTING UTILITIES
# ─────────────────────────────────────────────────────────────

def timestamp():
    """Get current timestamp formatted for display."""
    return datetime.now().strftime("%H:%M:%S")


def full_timestamp():
    """Get current timestamp formatted for logging (ISO 8601)."""
    return datetime.now().isoformat()


def format_bytes(num_bytes):
    """
    Convert bytes to human-readable format.
    Example: 1536 → "1.5 KB", 1048576 → "1.0 MB"
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_mac(mac):
    """Ensure MAC address is in standard format (lowercase with colons)."""
    if mac:
        return mac.lower()
    return "unknown"


def get_tcp_flags(flag_value):
    """
    Decode TCP flags from numeric value to human-readable string.
    
    TCP FLAGS (each is a single bit in the TCP header):
    ┌─────┬─────┬─────┬─────┬─────┬─────┐
    │ URG │ ACK │ PSH │ RST │ SYN │ FIN │
    └─────┴─────┴─────┴─────┴─────┴─────┘
    
    Common combinations:
    - SYN (0x02): Connection initiation
    - SYN-ACK (0x12): Connection acceptance
    - ACK (0x10): Acknowledgment
    - FIN (0x01): Connection termination
    - RST (0x04): Connection reset (abrupt close)
    - PSH-ACK (0x18): Data push
    
    In security context:
    - SYN without ACK from many ports = SYN scan (Nmap -sS)
    - FIN without ACK = FIN scan (stealthy)
    - No flags (0x00) = NULL scan
    - URG+PSH+FIN = XMAS scan (all lit up like a Christmas tree)
    """
    flags = []
    flag_names = [
        (0x01, "FIN"),   # Finish - terminate connection
        (0x02, "SYN"),   # Synchronize - initiate connection
        (0x04, "RST"),   # Reset - abort connection
        (0x08, "PSH"),   # Push - deliver data immediately
        (0x10, "ACK"),   # Acknowledge - confirm receipt
        (0x20, "URG"),   # Urgent - prioritize this data
    ]
    
    for bit, name in flag_names:
        if flag_value & bit:
            flags.append(name)
    
    return "-".join(flags) if flags else "NONE"


def print_banner():
    """Display the application banner."""
    banner = f"""
{Colors.CYAN}{Colors.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║          NETWORK PACKET ANALYZER & SNIFFER                   ║
║                      v1.0.0                                  ║
║                                                              ║
║   Cybersecurity Portfolio Project                            ║
║   Network Traffic Analysis & Threat Detection                ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)
