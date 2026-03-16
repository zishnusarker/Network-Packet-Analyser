"""
logger.py - Logging & Alert Management
========================================
Handles structured logging of events and alerts, both to
console (with colors) and to files (JSON format).

CYBERSECURITY CONCEPTS:
-----------------------
Logging is foundational to security operations. Without proper logs:
- You can't investigate incidents (forensics)
- You can't prove compliance (audit trails)
- You can't detect patterns across time (trend analysis)
- You can't reconstruct attack timelines (incident response)

Log best practices implemented here:
1. Structured format (JSON) — machine-parseable for SIEM ingestion
2. Timestamps in ISO 8601 — unambiguous, sortable, timezone-aware
3. Severity levels — allows filtering and prioritization
4. Contextual details — includes all relevant fields for investigation
5. Separate alert log — quick access to security events
"""

import os
import json
import logging
from datetime import datetime
from modules.utils import (
    Colors, colorize, severity_color, format_bytes,
    get_tcp_flags, full_timestamp
)


class AlertLogger:
    """
    Manages logging for the packet analyzer.
    
    Two output streams:
    1. Console: Colored, human-readable output for real-time monitoring
    2. File: JSON-structured logs for archival and SIEM integration
    """

    def __init__(self, config):
        """
        Initialize logger with configuration.
        
        Args:
            config (dict): Logging configuration section from config.yaml
        """
        self.config = config.get("logging", {})
        self.output_config = config.get("output", {})
        self.colorized = self.output_config.get("colorized", True)
        
        # Ensure log directory exists
        log_dir = self.config.get("log_directory", "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up Python's logging module for event logging
        self.event_logger = self._setup_event_logger()
        
        # Alert log file (JSON lines format)
        self.alert_log_path = self.config.get("alert_log_file", "logs/alerts.json")
        
        # Statistics
        self.alert_count = 0
        self.alerts_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.alerts_by_type = {}

    def _setup_event_logger(self):
        """Configure Python logging for event log file."""
        logger = logging.getLogger("packet_analyzer")
        logger.setLevel(
            getattr(logging, self.config.get("log_level", "INFO").upper())
        )
        
        # Avoid duplicate handlers on re-initialization
        if logger.handlers:
            logger.handlers.clear()
        
        # File handler
        if self.config.get("log_to_file", True):
            log_file = self.config.get("event_log_file", "logs/events.log")
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            logger.addHandler(file_handler)
        
        return logger

    # ──────────────────────────────────────────────────────────
    # PACKET DISPLAY (Console Output)
    # ──────────────────────────────────────────────────────────

    def log_packet(self, parsed_packet):
        """
        Display a parsed packet in the console with color coding.
        
        Format: [TIME] PROTOCOL | SRC → DST | FLAGS | Len:SIZE
        
        Color coding by protocol:
        - TCP: Cyan — most common, easy to scan
        - UDP: Green — distinct from TCP
        - DNS: Yellow — application layer, interesting for analysis
        - ARP: Magenta — layer 2, less common
        - ICMP: Blue — control messages
        - HTTP: Red (bright) — unencrypted web traffic, noteworthy
        """
        if not parsed_packet or "ERROR" in parsed_packet.get("layers", []):
            return
        
        display_time = parsed_packet.get("display_time", "??:??:??")
        layers = parsed_packet.get("layers", [])
        size = parsed_packet.get("size", 0)
        
        # ─── ARP Packets ───
        if "ARP" in layers:
            arp = parsed_packet.get("arp", {})
            op = arp.get("operation", "?")
            sender = f"{arp.get('sender_ip', '?')} ({arp.get('sender_mac', '?')})"
            target = f"{arp.get('target_ip', '?')} ({arp.get('target_mac', '?')})"
            
            line = (
                f"{Colors.MAGENTA}[{display_time}] ARP | "
                f"{op.upper()}: {sender} → {target}{Colors.RESET}"
            )
            print(line)
            return
        
        # ─── IP-based Packets ───
        ip = parsed_packet.get("ip", {})
        transport = parsed_packet.get("transport", {})
        app = parsed_packet.get("application", {})
        
        src_ip = ip.get("src", "?")
        dst_ip = ip.get("dst", "?")
        
        # DNS packets get special formatting
        if "DNS" in layers and "dns" in app:
            self._display_dns(display_time, src_ip, dst_ip, app["dns"])
            return
        
        # HTTP packets get special formatting
        if "HTTP" in layers and "http" in app:
            self._display_http(display_time, src_ip, dst_ip, transport, app["http"])
            return
        
        # ICMP packets
        if "ICMP" in layers:
            icmp = parsed_packet.get("icmp", {})
            line = (
                f"{Colors.BLUE}[{display_time}] ICMP | "
                f"{src_ip} → {dst_ip} | "
                f"{icmp.get('type_name', '?')} | "
                f"Len:{size}{Colors.RESET}"
            )
            print(line)
            return
        
        # TCP packets
        if "TCP" in layers:
            src_port = transport.get("src_port", "?")
            dst_port = transport.get("dst_port", "?")
            flags = transport.get("flags", "?")
            payload_size = transport.get("payload_size", 0)
            
            line = (
                f"{Colors.CYAN}[{display_time}] TCP | "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"{flags} | Len:{payload_size}{Colors.RESET}"
            )
            print(line)
            return
        
        # UDP packets
        if "UDP" in layers:
            src_port = transport.get("src_port", "?")
            dst_port = transport.get("dst_port", "?")
            
            line = (
                f"{Colors.GREEN}[{display_time}] UDP | "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"Len:{size}{Colors.RESET}"
            )
            print(line)
            return
        
        # Fallback for other packet types
        print(f"[{display_time}] {'/'.join(layers)} | {src_ip} → {dst_ip} | Len:{size}")

    def _display_dns(self, time_str, src, dst, dns_data):
        """Format and display DNS packet."""
        if dns_data.get("is_response"):
            # DNS Response
            answers = dns_data.get("answers", [])
            answer_str = ", ".join(
                a.get("data", "?") for a in answers[:3]  # Show first 3 answers
            ) if answers else "NXDOMAIN"
            
            queries = dns_data.get("queries", [])
            query_name = queries[0].get("name", "?") if queries else "?"
            
            print(
                f"{Colors.YELLOW}[{time_str}] DNS | "
                f"{src} → {dst} | "
                f"Response: {query_name} → {answer_str}{Colors.RESET}"
            )
        else:
            # DNS Query
            queries = dns_data.get("queries", [])
            for q in queries:
                print(
                    f"{Colors.YELLOW}[{time_str}] DNS | "
                    f"{src} → {dst} | "
                    f"Query: {q.get('name', '?')} "
                    f"({q.get('type', '?')}){Colors.RESET}"
                )

    def _display_http(self, time_str, src, dst, transport, http_data):
        """Format and display HTTP packet."""
        src_port = transport.get("src_port", "?")
        dst_port = transport.get("dst_port", "?")
        
        method = http_data.get("method", "")
        url = http_data.get("url", "")
        status = http_data.get("status_code", "")
        host = http_data.get("host", "")
        
        if method:
            print(
                f"{Colors.RED}{Colors.BRIGHT}[{time_str}] HTTP | "
                f"{src}:{src_port} → {dst}:{dst_port} | "
                f"{method} {host}{url}{Colors.RESET}"
            )
        elif status:
            print(
                f"{Colors.RED}{Colors.BRIGHT}[{time_str}] HTTP | "
                f"{src}:{src_port} → {dst}:{dst_port} | "
                f"Response: {status}{Colors.RESET}"
            )

    # ──────────────────────────────────────────────────────────
    # ALERT DISPLAY AND LOGGING
    # ──────────────────────────────────────────────────────────

    def log_alert(self, alert):
        """
        Process and display a security alert.
        
        Steps:
        1. Display colored alert in console
        2. Write to JSON alert log file
        3. Update alert statistics
        4. Log to event log
        
        Args:
            alert (dict): Alert from ThreatDetector.analyze()
        """
        if not alert:
            return
        
        # Update statistics
        self.alert_count += 1
        severity = alert.get("severity", "LOW")
        alert_type = alert.get("type", "UNKNOWN")
        self.alerts_by_severity[severity] = self.alerts_by_severity.get(severity, 0) + 1
        self.alerts_by_type[alert_type] = self.alerts_by_type.get(alert_type, 0) + 1
        
        # Console display
        self._display_alert_console(alert)
        
        # File logging (JSON lines format)
        self._write_alert_to_file(alert)
        
        # Event log
        self.event_logger.warning(
            f"ALERT [{severity}] {alert_type}: {alert.get('description', '')}"
        )

    def _display_alert_console(self, alert):
        """Display a formatted alert in the console."""
        severity = alert.get("severity", "LOW")
        alert_type = alert.get("type", "UNKNOWN")
        description = alert.get("description", "No description")
        details = alert.get("details", {})
        
        # Choose icon based on severity
        icon = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "🔔", "LOW": "ℹ️ "}.get(severity, "•")
        
        color = severity_color(severity)
        
        print(f"\n{color}{icon} [ALERT][{severity}] {alert_type}{Colors.RESET}")
        print(f"{color}    {description}{Colors.RESET}")
        
        # Print relevant details
        for key, value in details.items():
            if isinstance(value, list) and len(value) > 10:
                # Truncate long lists (e.g., port lists)
                display_val = str(value[:10]) + f"... ({len(value)} total)"
            else:
                display_val = value
            print(f"{color}    {key}: {display_val}{Colors.RESET}")
        
        print()  # Blank line after alert

    def _write_alert_to_file(self, alert):
        """
        Write alert to JSON lines file.
        
        JSON Lines format (one JSON object per line) is preferred because:
        - Easy to append without loading entire file
        - Parseable line-by-line (memory efficient)
        - Compatible with SIEM systems, ELK stack, Splunk
        - Each line is independently valid JSON
        """
        try:
            alert_record = {
                "timestamp": alert.get("timestamp", full_timestamp()),
                "severity": alert.get("severity"),
                "type": alert.get("type"),
                "source_ip": alert.get("source_ip", ""),
                "target_ip": alert.get("target_ip", ""),
                "description": alert.get("description"),
                "details": alert.get("details", {})
            }
            
            with open(self.alert_log_path, 'a') as f:
                f.write(json.dumps(alert_record) + "\n")
        except IOError as e:
            self.event_logger.error(f"Failed to write alert to file: {e}")

    # ──────────────────────────────────────────────────────────
    # LOG EVENTS
    # ──────────────────────────────────────────────────────────

    def log_event(self, level, message):
        """Log a general event (startup, shutdown, errors, etc.)."""
        log_func = getattr(self.event_logger, level.lower(), self.event_logger.info)
        log_func(message)
        
        if self.config.get("log_to_console", True):
            level_colors = {
                "debug": Colors.WHITE,
                "info": Colors.GREEN,
                "warning": Colors.YELLOW,
                "error": Colors.RED,
                "critical": Colors.BG_RED
            }
            color = level_colors.get(level.lower(), Colors.WHITE)
            print(f"{color}[{level.upper()}] {message}{Colors.RESET}")

    def get_alert_summary(self):
        """Return summary of all alerts for final report."""
        return {
            "total_alerts": self.alert_count,
            "by_severity": dict(self.alerts_by_severity),
            "by_type": dict(self.alerts_by_type)
        }
