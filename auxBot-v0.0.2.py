#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🚀 AUXBOT v2.0.0 - MULTI-PLATFORM C2                     ║
║                    Discord | Telegram | WhatsApp | SSH                       ║
║                    500+ Commands | Remote Access | Security Tool             ║
╚══════════════════════════════════════════════════════════════════════════════╝
Author: AuxBot Team
Description: Advanced command & control tool with multi-platform support
Commands: !help, !ping, !nmap, !ssh, !scan, !system, and 500+ more
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
import psutil
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import shlex
import asyncio
import uuid
import hashlib
import base64
import getpass
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
import shutil
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from collections import defaultdict

# =====================
# OPTIONAL IMPORTS WITH FALLBACKS
# =====================

# Discord
try:
    import discord
    from discord.ext import commands as discord_commands
    from discord.ext import tasks
    from discord import app_commands
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("[!] Discord module not installed. Install with: pip install discord.py")

# Telegram
try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("[!] Telethon module not installed. Install with: pip install telethon")

# WhatsApp (Selenium)
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        WEBDRIVER_MANAGER_AVAILABLE = True
    except ImportError:
        WEBDRIVER_MANAGER_AVAILABLE = False
except ImportError:
    SELENIUM_AVAILABLE = False
    WEBDRIVER_MANAGER_AVAILABLE = False
    print("[!] Selenium not installed. WhatsApp integration disabled.")

# SSH/Paramiko
try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy
    from scp import SCPClient
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("[!] Paramiko not installed. SSH features disabled. Install with: pip install paramiko scp")

# Crypto
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] Cryptography not installed. Install with: pip install cryptography")

# Colorama
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Create dummy color classes
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# =====================
# CONFIGURATION
# =====================

CONFIG_DIR = ".auxbot"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DISCORD_CONFIG = os.path.join(CONFIG_DIR, "discord.json")
TELEGRAM_CONFIG = os.path.join(CONFIG_DIR, "telegram.json")
WHATSAPP_CONFIG = os.path.join(CONFIG_DIR, "whatsapp.json")
SSH_CONFIG = os.path.join(CONFIG_DIR, "ssh.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "auxbot.db")
LOG_FILE = os.path.join(CONFIG_DIR, "auxbot.log")
WHATSAPP_SESSION_DIR = os.path.join(CONFIG_DIR, "whatsapp_session")
SSH_KEYS_DIR = os.path.join(CONFIG_DIR, "ssh_keys")

# Create directories
for directory in [CONFIG_DIR, WHATSAPP_SESSION_DIR, SSH_KEYS_DIR]:
    Path(directory).mkdir(exist_ok=True, parents=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("AuxBot")

# Colors
if COLORAMA_AVAILABLE:
    class Colors:
        RED = Fore.RED + Style.BRIGHT
        GREEN = Fore.GREEN + Style.BRIGHT
        YELLOW = Fore.YELLOW + Style.BRIGHT
        BLUE = Fore.BLUE + Style.BRIGHT
        CYAN = Fore.CYAN + Style.BRIGHT
        MAGENTA = Fore.MAGENTA + Style.BRIGHT
        WHITE = Fore.WHITE + Style.BRIGHT
        RESET = Style.RESET_ALL
else:
    class Colors:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""

# =====================
# ENCRYPTION MANAGER
# =====================

class EncryptionManager:
    """Handle encryption for sensitive data"""
    
    def __init__(self, key_file: str = os.path.join(CONFIG_DIR, "master.key")):
        self.key_file = key_file
        self.key = self._load_or_create_key()
        if CRYPTO_AVAILABLE and self.key:
            self.cipher = Fernet(self.key)
        else:
            self.cipher = None
    
    def _load_or_create_key(self) -> Optional[bytes]:
        """Load existing key or create new one"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                return key
        except Exception as e:
            logger.error(f"Failed to load/create encryption key: {e}")
            return None
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not self.cipher:
            return data
        
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data
    
    def decrypt(self, data: str) -> str:
        """Decrypt string data"""
        if not self.cipher:
            return data
        
        try:
            return self.cipher.decrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return data

# =====================
# DATABASE MANAGER
# =====================

class DatabaseManager:
    """SQLite database manager for command history and settings"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._connect()
    
    def _connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            self._init_tables()
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
    
    def _init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT NOT NULL,
                user TEXT,
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL,
                target TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS authorized_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT,
                added_by TEXT,
                added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT 0,
                permissions TEXT DEFAULT 'basic',
                UNIQUE(platform, user_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                result TEXT,
                executed_by TEXT,
                open_ports TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ssh_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT,
                created_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                active BOOLEAN DEFAULT 1
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ssh_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                command TEXT,
                output TEXT,
                executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                executed_by TEXT,
                FOREIGN KEY (session_id) REFERENCES ssh_sessions(session_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME,
                notes TEXT,
                tags TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                command TEXT,
                schedule TEXT,
                next_run DATETIME,
                created_by TEXT,
                active BOOLEAN DEFAULT 1
            )
            """
        ]
        
        for table in tables:
            try:
                self.cursor.execute(table)
            except Exception as e:
                logger.error(f"Failed to create table: {e}")
        
        self.conn.commit()
    
    def log_command(self, command: str, source: str, user: str = None, 
                   success: bool = True, output: str = "", 
                   execution_time: float = 0.0, target: str = None):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history 
                (command, source, user, success, output, execution_time, target)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (command, source, user, success, output[:5000], execution_time, target))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def get_command_history(self, limit: int = 50, source: str = None, 
                           user: str = None) -> List[Dict]:
        """Get command history"""
        try:
            query = "SELECT * FROM command_history WHERE 1=1"
            params = []
            
            if source:
                query += " AND source = ?"
                params.append(source)
            
            if user:
                query += " AND user = ?"
                params.append(user)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            self.cursor.execute(query, params)
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def is_user_authorized(self, platform: str, user_id: str) -> bool:
        """Check if user is authorized"""
        try:
            self.cursor.execute('''
                SELECT * FROM authorized_users 
                WHERE platform = ? AND user_id = ?
            ''', (platform, user_id))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check authorization: {e}")
            return False
    
    def get_user_permissions(self, platform: str, user_id: str) -> str:
        """Get user permissions"""
        try:
            self.cursor.execute('''
                SELECT permissions FROM authorized_users 
                WHERE platform = ? AND user_id = ?
            ''', (platform, user_id))
            row = self.cursor.fetchone()
            return row['permissions'] if row else 'none'
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return 'none'
    
    def add_authorized_user(self, platform: str, user_id: str, username: str = None, 
                           added_by: str = None, is_admin: bool = False,
                           permissions: str = 'basic') -> bool:
        """Add authorized user"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO authorized_users 
                (platform, user_id, username, added_by, is_admin, permissions)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (platform, user_id, username, added_by, is_admin, permissions))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add authorized user: {e}")
            return False
    
    def remove_authorized_user(self, platform: str, user_id: str) -> bool:
        """Remove authorized user"""
        try:
            self.cursor.execute('''
                DELETE FROM authorized_users WHERE platform = ? AND user_id = ?
            ''', (platform, user_id))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove authorized user: {e}")
            return False
    
    def update_user_permissions(self, platform: str, user_id: str, permissions: str) -> bool:
        """Update user permissions"""
        try:
            self.cursor.execute('''
                UPDATE authorized_users SET permissions = ? 
                WHERE platform = ? AND user_id = ?
            ''', (permissions, platform, user_id))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to update permissions: {e}")
            return False
    
    def get_authorized_users(self, platform: str = None) -> List[Dict]:
        """Get authorized users"""
        try:
            if platform:
                self.cursor.execute('''
                    SELECT * FROM authorized_users WHERE platform = ? 
                    ORDER BY added_date DESC
                ''', (platform,))
            else:
                self.cursor.execute('''
                    SELECT * FROM authorized_users ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get authorized users: {e}")
            return []
    
    def save_scan_result(self, target: str, scan_type: str, result: str, 
                        executed_by: str = None, open_ports: str = None):
        """Save scan result"""
        try:
            self.cursor.execute('''
                INSERT INTO scan_results (target, scan_type, result, executed_by, open_ports)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, scan_type, result[:5000], executed_by, open_ports))
            self.conn.commit()
            
            # Update targets table
            self.cursor.execute('''
                INSERT OR REPLACE INTO targets (target, last_seen, tags)
                VALUES (?, ?, ?)
            ''', (target, datetime.datetime.now(), f"scanned:{scan_type}"))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")
    
    def get_scan_history(self, target: str = None, limit: int = 20) -> List[Dict]:
        """Get scan history"""
        try:
            if target:
                self.cursor.execute('''
                    SELECT * FROM scan_results WHERE target = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (target, limit))
            else:
                self.cursor.execute('''
                    SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def create_ssh_session(self, session_id: str, host: str, username: str, 
                          port: int = 22, created_by: str = None) -> bool:
        """Create SSH session record"""
        try:
            self.cursor.execute('''
                INSERT INTO ssh_sessions (session_id, host, port, username, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, host, port, username, created_by))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to create SSH session: {e}")
            return False
    
    def update_ssh_session(self, session_id: str):
        """Update SSH session last used time"""
        try:
            self.cursor.execute('''
                UPDATE ssh_sessions SET last_used = CURRENT_TIMESTAMP
                WHERE session_id = ?
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update SSH session: {e}")
    
    def close_ssh_session(self, session_id: str):
        """Close SSH session"""
        try:
            self.cursor.execute('''
                UPDATE ssh_sessions SET active = 0 WHERE session_id = ?
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to close SSH session: {e}")
    
    def log_ssh_command(self, session_id: str, command: str, output: str, 
                       executed_by: str = None):
        """Log SSH command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO ssh_commands (session_id, command, output, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (session_id, command, output[:5000], executed_by))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log SSH command: {e}")
    
    def get_active_ssh_sessions(self) -> List[Dict]:
        """Get active SSH sessions"""
        try:
            self.cursor.execute('''
                SELECT * FROM ssh_sessions WHERE active = 1 
                ORDER BY created_at DESC
            ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get SSH sessions: {e}")
            return []
    
    def add_target(self, target: str, notes: str = "", tags: str = "") -> bool:
        """Add target to database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO targets (target, notes, tags, last_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (target, notes, tags))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add target: {e}")
            return False
    
    def get_targets(self, tag: str = None) -> List[Dict]:
        """Get targets"""
        try:
            if tag:
                self.cursor.execute('''
                    SELECT * FROM targets WHERE tags LIKE ? 
                    ORDER BY last_seen DESC
                ''', (f'%{tag}%',))
            else:
                self.cursor.execute('''
                    SELECT * FROM targets ORDER BY last_seen DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get targets: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# =====================
# SSH MANAGER
# =====================

class SSHManager:
    """Manage SSH connections and commands"""
    
    def __init__(self, db: DatabaseManager, encryption: EncryptionManager):
        self.db = db
        self.encryption = encryption
        self.sessions: Dict[str, SSHClient] = {}
        self.lock = threading.Lock()
    
    def connect(self, host: str, username: str = None, password: str = None,
               key_filename: str = None, port: int = 22, timeout: int = 10,
               session_id: str = None) -> Tuple[bool, str, Optional[str]]:
        """Establish SSH connection"""
        if not SSH_AVAILABLE:
            return False, "SSH module not available", None
        
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            # Try to connect
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'timeout': timeout
            }
            
            if username:
                connect_kwargs['username'] = username
            
            if password:
                connect_kwargs['password'] = password
            elif key_filename:
                connect_kwargs['key_filename'] = key_filename
            else:
                # Try auto key discovery
                connect_kwargs['look_for_keys'] = True
                connect_kwargs['allow_agent'] = True
            
            client.connect(**connect_kwargs)
            
            # Generate session ID if not provided
            if not session_id:
                session_id = str(uuid.uuid4())[:8]
            
            # Store session
            with self.lock:
                self.sessions[session_id] = client
            
            # Save to database
            self.db.create_ssh_session(session_id, host, username or 'unknown', 
                                      port, username)
            
            return True, f"Connected to {host} (Session: {session_id})", session_id
            
        except paramiko.AuthenticationException:
            return False, "Authentication failed", None
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}", None
        except Exception as e:
            return False, f"Connection failed: {e}", None
    
    def execute_command(self, session_id: str, command: str, 
                       timeout: int = 30) -> Dict[str, Any]:
        """Execute command on SSH session"""
        start_time = time.time()
        
        try:
            with self.lock:
                if session_id not in self.sessions:
                    return {
                        'success': False,
                        'output': f"Session {session_id} not found",
                        'execution_time': time.time() - start_time
                    }
                
                client = self.sessions[session_id]
            
            # Execute command
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            
            # Get output
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            if error:
                output += f"\n[STDERR]\n{error}"
            
            # Log to database
            self.db.update_ssh_session(session_id)
            self.db.log_ssh_command(session_id, command, output, 'system')
            
            return {
                'success': True,
                'output': output or "Command executed (no output)",
                'execution_time': time.time() - start_time
            }
            
        except Exception as e:
            return {
                'success': False,
                'output': str(e),
                'execution_time': time.time() - start_time
            }
    
    def upload_file(self, session_id: str, local_path: str, 
                   remote_path: str) -> Tuple[bool, str]:
        """Upload file via SCP"""
        if not SSH_AVAILABLE:
            return False, "SCP module not available"
        
        try:
            with self.lock:
                if session_id not in self.sessions:
                    return False, f"Session {session_id} not found"
                
                client = self.sessions[session_id]
            
            # Upload file
            with SCPClient(client.get_transport()) as scp:
                scp.put(local_path, remote_path)
            
            self.db.update_ssh_session(session_id)
            return True, f"File uploaded to {remote_path}"
            
        except Exception as e:
            return False, f"Upload failed: {e}"
    
    def download_file(self, session_id: str, remote_path: str, 
                     local_path: str) -> Tuple[bool, str]:
        """Download file via SCP"""
        try:
            with self.lock:
                if session_id not in self.sessions:
                    return False, f"Session {session_id} not found"
                
                client = self.sessions[session_id]
            
            # Download file
            with SCPClient(client.get_transport()) as scp:
                scp.get(remote_path, local_path)
            
            self.db.update_ssh_session(session_id)
            return True, f"File downloaded to {local_path}"
            
        except Exception as e:
            return False, f"Download failed: {e}"
    
    def list_sessions(self) -> List[Dict]:
        """List active SSH sessions"""
        sessions = []
        with self.lock:
            for session_id, client in self.sessions.items():
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        sessions.append({
                            'session_id': session_id,
                            'host': transport.getpeername()[0] if transport else 'unknown',
                            'port': transport.getpeername()[1] if transport else 22
                        })
                except:
                    pass
        return sessions
    
    def close_session(self, session_id: str) -> bool:
        """Close SSH session"""
        with self.lock:
            if session_id in self.sessions:
                try:
                    self.sessions[session_id].close()
                except:
                    pass
                del self.sessions[session_id]
                self.db.close_ssh_session(session_id)
                return True
        return False
    
    def close_all(self):
        """Close all SSH sessions"""
        with self.lock:
            for session_id in list(self.sessions.keys()):
                try:
                    self.sessions[session_id].close()
                except:
                    pass
            self.sessions.clear()

# =====================
# COMMAND EXECUTOR
# =====================

class CommandExecutor:
    """Execute system commands and return results"""
    
    # Built-in commands database
    COMMANDS = {
        # Basic Commands
        'help': 'Show this help message',
        'ping': 'ping <host> - Ping a host',
        'nmap': 'nmap <target> [options] - Run nmap scan',
        'scan': 'scan <target> - Quick port scan',
        'fullscan': 'fullscan <target> - Full port scan',
        'system': 'Show system information',
        'network': 'Show network information',
        'whoami': 'Show current user',
        'uptime': 'Show system uptime',
        'date': 'Show current date/time',
        'ps': 'Show running processes',
        'df': 'Show disk usage',
        'free': 'Show memory usage',
        'ifconfig': 'Show network interfaces',
        'netstat': 'Show network connections',
        'route': 'Show routing table',
        
        # Network Tools
        'traceroute': 'traceroute <host> - Trace route to host',
        'whois': 'whois <domain> - WHOIS lookup',
        'dig': 'dig <domain> - DNS lookup',
        'nslookup': 'nslookup <domain> - DNS lookup',
        'curl': 'curl <url> - HTTP request',
        'wget': 'wget <url> - Download file',
        'http': 'http <url> - Simple HTTP GET',
        'headers': 'headers <url> - Get HTTP headers',
        'ssl': 'ssl <host> [port] - Check SSL certificate',
        'subdomains': 'subdomains <domain> - Find subdomains',
        'dnsenum': 'dnsenum <domain> - DNS enumeration',
        'theharvester': 'theharvester <domain> - Email/subdomain harvesting',
        
        # SSH Commands
        'ssh': 'ssh <host> [username] - Connect via SSH',
        'ssh-exec': 'ssh-exec <session> <command> - Execute SSH command',
        'ssh-upload': 'ssh-upload <session> <local> <remote> - Upload file',
        'ssh-download': 'ssh-download <session> <remote> <local> - Download file',
        'ssh-list': 'List active SSH sessions',
        'ssh-close': 'ssh-close <session> - Close SSH session',
        
        # File Operations
        'ls': 'ls [path] - List directory contents',
        'cd': 'cd <path> - Change directory',
        'pwd': 'Print working directory',
        'cat': 'cat <file> - View file contents',
        'head': 'head <file> [lines] - View first lines',
        'tail': 'tail <file> [lines] - View last lines',
        'grep': 'grep <pattern> <file> - Search in file',
        'find': 'find <path> -name <pattern> - Find files',
        'mkdir': 'mkdir <directory> - Create directory',
        'rm': 'rm <file> - Remove file',
        'cp': 'cp <source> <dest> - Copy file',
        'mv': 'mv <source> <dest> - Move file',
        'chmod': 'chmod <mode> <file> - Change permissions',
        'chown': 'chown <user> <file> - Change owner',
        'tar': 'tar <options> <file> - Archive files',
        'zip': 'zip <archive> <files> - Create zip',
        'unzip': 'unzip <archive> - Extract zip',
        
        # Process Management
        'kill': 'kill <pid> - Kill process',
        'killall': 'killall <name> - Kill processes by name',
        'top': 'Show top processes',
        'htop': 'Interactive process viewer',
        'service': 'service <name> <action> - Manage service',
        'systemctl': 'systemctl <action> <service> - Systemd control',
        
        # System Info
        'uname': 'Show system information',
        'hostname': 'Show hostname',
        'dmesg': 'Show kernel messages',
        'lscpu': 'Show CPU information',
        'lsblk': 'Show block devices',
        'lspci': 'Show PCI devices',
        'lsusb': 'Show USB devices',
        'dmidecode': 'Show hardware information',
        
        # Security Tools
        'hydra': 'hydra <options> - Password cracking',
        'john': 'john <file> - Password cracking',
        'hashcat': 'hashcat <options> - Password cracking',
        'sqlmap': 'sqlmap <options> - SQL injection',
        'nikto': 'nikto -h <host> - Web scanner',
        'wpscan': 'wpscan --url <url> - WordPress scanner',
        'dirb': 'dirb <url> - Directory scanner',
        'gobuster': 'gobuster dir -u <url> - Directory scanner',
        'wfuzz': 'wfuzz <options> - Web fuzzer',
        'metasploit': 'msfconsole - Metasploit console',
        'aircrack': 'aircrack-ng <file> - WiFi cracking',
        'reaver': 'reaver -i <interface> - WPS attack',
        
        # AuxBot Commands
        'history': 'Show command history',
        'clear': 'Clear the screen',
        'targets': 'List scanned targets',
        'scan-history': 'scan-history [target] - Show scan history',
        'auth-list': 'List authorized users',
        'auth-add': 'auth-add <platform> <user_id> - Add user',
        'auth-remove': 'auth-remove <platform> <user_id> - Remove user',
        'export': 'export <format> <data> - Export data',
        'schedule': 'schedule <command> <time> - Schedule command',
        'tasks': 'List scheduled tasks',
        'stats': 'Show bot statistics',
    }
    
    @staticmethod
    def execute(command: str, timeout: int = 60) -> Dict[str, Any]:
        """Execute a shell command and return result"""
        start_time = time.time()
        
        try:
            # Handle built-in commands
            if command.startswith('cd '):
                return CommandExecutor._handle_cd(command[3:].strip())
            elif command == 'pwd':
                return CommandExecutor._handle_pwd()
            elif command == 'clear' or command == 'cls':
                return CommandExecutor._handle_clear()
            elif command == 'history':
                return CommandExecutor._handle_history()
            
            # Check if command is safe (prevent dangerous commands)
            if CommandExecutor._is_dangerous_command(command):
                return {
                    'success': False,
                    'output': "Command blocked for security reasons",
                    'execution_time': time.time() - start_time,
                    'command': command
                }
            
            # Execute system command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            execution_time = time.time() - start_time
            
            output = result.stdout + result.stderr
            if not output:
                output = "Command executed successfully (no output)"
            
            return {
                'success': result.returncode == 0,
                'output': output,
                'execution_time': execution_time,
                'command': command
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': f"Command timed out after {timeout} seconds",
                'execution_time': time.time() - start_time,
                'command': command
            }
        except Exception as e:
            return {
                'success': False,
                'output': str(e),
                'execution_time': time.time() - start_time,
                'command': command
            }
    
    @staticmethod
    def _is_dangerous_command(command: str) -> bool:
        """Check if command is potentially dangerous"""
        dangerous_patterns = [
            r'rm\s+-rf\s+/\s*$',  # rm -rf /
            r'mkfs\s+',            # Format commands
            r'dd\s+if=.*of=/dev/sd', # dd to disk
            r'>\s*/dev/sd',        # Write to disk
            r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;', # Fork bomb
            r'chmod\s+777\s+/',    # Bad permissions
            r'chown\s+.*\s+/',     # Bad ownership
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def _handle_cd(path: str) -> Dict[str, Any]:
        """Handle cd command"""
        try:
            if not path or path == '~':
                path = os.path.expanduser('~')
            os.chdir(path)
            return {
                'success': True,
                'output': f"Changed directory to: {os.getcwd()}",
                'execution_time': 0
            }
        except Exception as e:
            return {
                'success': False,
                'output': str(e),
                'execution_time': 0
            }
    
    @staticmethod
    def _handle_pwd() -> Dict[str, Any]:
        """Handle pwd command"""
        return {
            'success': True,
            'output': os.getcwd(),
            'execution_time': 0
        }
    
    @staticmethod
    def _handle_clear() -> Dict[str, Any]:
        """Handle clear command"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return {
            'success': True,
            'output': 'Screen cleared',
            'execution_time': 0
        }
    
    @staticmethod
    def _handle_history() -> Dict[str, Any]:
        """Handle history command (placeholder)"""
        return {
            'success': True,
            'output': 'Use !history to view command history',
            'execution_time': 0
        }
    
    @staticmethod
    def ping(host: str, count: int = 4) -> Dict[str, Any]:
        """Ping a host"""
        if platform.system().lower() == 'windows':
            cmd = f"ping -n {count} {host}"
        else:
            cmd = f"ping -c {count} {host}"
        return CommandExecutor.execute(cmd)
    
    @staticmethod
    def nmap_scan(target: str, options: str = "-sV") -> Dict[str, Any]:
        """Run nmap scan"""
        cmd = f"nmap {options} {target}"
        return CommandExecutor.execute(cmd, timeout=300)
    
    @staticmethod
    def quick_scan(target: str) -> Dict[str, Any]:
        """Quick port scan (common ports)"""
        cmd = f"nmap -T4 -F {target}"
        return CommandExecutor.execute(cmd, timeout=120)
    
    @staticmethod
    def full_scan(target: str) -> Dict[str, Any]:
        """Full port scan"""
        cmd = f"nmap -p- -T4 {target}"
        return CommandExecutor.execute(cmd, timeout=600)
    
    @staticmethod
    def traceroute(target: str) -> Dict[str, Any]:
        """Traceroute to target"""
        if platform.system().lower() == 'windows':
            cmd = f"tracert {target}"
        else:
            cmd = f"traceroute {target}"
        return CommandExecutor.execute(cmd, timeout=120)
    
    @staticmethod
    def whois(domain: str) -> Dict[str, Any]:
        """WHOIS lookup"""
        cmd = f"whois {domain}"
        return CommandExecutor.execute(cmd, timeout=30)
    
    @staticmethod
    def dig(domain: str, record_type: str = "ANY") -> Dict[str, Any]:
        """DNS lookup"""
        cmd = f"dig {domain} {record_type}"
        return CommandExecutor.execute(cmd, timeout=30)
    
    @staticmethod
    def curl(url: str, options: str = "") -> Dict[str, Any]:
        """HTTP request with curl"""
        cmd = f"curl {options} {url}"
        return CommandExecutor.execute(cmd, timeout=30)
    
    @staticmethod
    def http_get(url: str) -> Dict[str, Any]:
        """Simple HTTP GET using requests"""
        try:
            start_time = time.time()
            response = requests.get(url, timeout=10, verify=False)
            execution_time = time.time() - start_time
            
            output = f"HTTP/{response.raw.version/10} {response.status_code} {response.reason}\n"
            for key, value in response.headers.items():
                output += f"{key}: {value}\n"
            output += f"\n{response.text[:1000]}"
            
            return {
                'success': True,
                'output': output,
                'execution_time': execution_time
            }
        except Exception as e:
            return {
                'success': False,
                'output': str(e),
                'execution_time': time.time() - start_time
            }
    
    @staticmethod
    def get_headers(url: str) -> Dict[str, Any]:
        """Get HTTP headers"""
        try:
            start_time = time.time()
            response = requests.head(url, timeout=10, verify=False)
            execution_time = time.time() - start_time
            
            output = f"HTTP/{response.raw.version/10} {response.status_code} {response.reason}\n"
            for key, value in response.headers.items():
                output += f"{key}: {value}\n"
            
            return {
                'success': True,
                'output': output,
                'execution_time': execution_time
            }
        except Exception as e:
            return {
                'success': False,
                'output': str(e),
                'execution_time': time.time() - start_time
            }

# =====================
# COMMAND PARSER
# =====================

class CommandParser:
    """Parse and validate commands from various platforms"""
    
    @classmethod
    def parse(cls, message: str) -> Tuple[str, List[str]]:
        """Parse command and arguments"""
        parts = message.strip().split()
        if not parts:
            return '', []
        
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        return command, args
    
    @classmethod
    def get_help(cls) -> str:
        """Get help text"""
        help_text = "**🚀 AUXBOT COMMANDS**\n\n"
        
        # Group commands by category
        categories = {
            '🔧 Basic': ['help', 'ping', 'system', 'network', 'whoami', 'uptime', 'date'],
            '📡 Network': ['nmap', 'scan', 'fullscan', 'traceroute', 'whois', 'dig', 'curl'],
            '🔐 SSH': ['ssh', 'ssh-exec', 'ssh-list', 'ssh-close'],
            '📁 Files': ['ls', 'cd', 'pwd', 'cat', 'grep', 'find'],
            '🛡️ Security': ['nikto', 'sqlmap', 'hydra', 'dirb', 'wpscan'],
            '📊 Management': ['history', 'targets', 'auth-list', 'stats']
        }
        
        for category, commands in categories.items():
            help_text += f"\n**{category}**\n"
            for cmd in commands:
                if cmd in CommandExecutor.COMMANDS:
                    help_text += f"`!{cmd}` - {CommandExecutor.COMMANDS[cmd]}\n"
        
        return help_text

# =====================
# DISCORD BOT
# =====================

class DiscordBot(discord_commands.Bot):
    """Discord bot with command handling"""
    
    def __init__(self, db: DatabaseManager, ssh_manager: SSHManager):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        
        super().__init__(command_prefix='!', intents=intents, help_command=None)
        
        self.db = db
        self.ssh_manager = ssh_manager
        self.config = self.load_config()
        self.start_time = time.time()
        
        # Register commands
        self.setup_commands()
    
    def load_config(self) -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG):
                with open(DISCORD_CONFIG, 'r') as f:
                    config = json.load(f)
                    
                    # Decrypt sensitive data if needed
                    if 'token' in config and config['token'].startswith('enc:'):
                        # Would decrypt here
                        pass
                    
                    return config
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        
        return {
            "enabled": False,
            "token": "",
            "admin_role": "Admin",
            "allowed_channels": []
        }
    
    def setup_commands(self):
        """Setup bot commands"""
        
        @self.event
        async def on_ready():
            logger.info(f'Discord bot logged in as {self.user}')
            print(f"{Colors.GREEN}✅ Discord bot connected as {self.user}{Colors.RESET}")
            await self.change_presence(
                activity=discord.Activity(
                    type=discord.ActivityType.watching,
                    name="!help | AuxBot"
                )
            )
        
        @self.event
        async def on_message(message):
            # Ignore bot messages
            if message.author.bot:
                return
            
            # Check if message starts with prefix
            if not message.content.startswith('!'):
                return
            
            # Check if channel is allowed
            allowed_channels = self.config.get('allowed_channels', [])
            if allowed_channels and str(message.channel.id) not in allowed_channels:
                return
            
            # Check authorization
            if not await self.is_authorized(message):
                await message.channel.send("❌ You are not authorized to use this bot.")
                return
            
            # Process command
            await self.process_commands(message)
        
        # Basic Commands
        @self.command(name='help')
        async def help_cmd(ctx):
            """Show help message"""
            help_text = CommandParser.get_help()
            await ctx.send(help_text)
        
        @self.command(name='ping')
        async def ping_cmd(ctx, host: str):
            """Ping a host"""
            await ctx.send(f"🏓 Pinging `{host}`...")
            result = CommandExecutor.ping(host)
            await self.send_result(ctx, result)
            self.db.log_command(f"!ping {host}", 'discord', str(ctx.author), 
                              result['success'], result['output'], 
                              result['execution_time'], host)
        
        @self.command(name='system')
        async def system_cmd(ctx):
            """Show system information"""
            try:
                info = f"**💻 System Information:**\n```\n"
                info += f"System: {platform.system()} {platform.release()}\n"
                info += f"Hostname: {socket.gethostname()}\n"
                info += f"CPU: {psutil.cpu_percent()}% used ({psutil.cpu_count()} cores)\n"
                info += f"Memory: {psutil.virtual_memory().percent}% used\n"
                info += f"Disk: {psutil.disk_usage('/').percent}% used\n"
                info += f"Python: {sys.version.split()[0]}\n"
                info += f"Uptime: {self.get_uptime()}\n"
                info += f"Current Dir: {os.getcwd()}\n"
                info += "```"
                await ctx.send(info)
            except Exception as e:
                await ctx.send(f"❌ Error: {e}")
        
        @self.command(name='network')
        async def network_cmd(ctx):
            """Show network information"""
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                
                info = f"**🌐 Network Information:**\n```\n"
                info += f"Hostname: {hostname}\n"
                info += f"Local IP: {local_ip}\n"
                
                # Get interfaces
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            info += f"{interface}: {addr.address}\n"
                
                # Get external IP
                try:
                    response = requests.get('https://api.ipify.org', timeout=5)
                    info += f"External IP: {response.text}\n"
                except:
                    pass
                
                info += "```"
                await ctx.send(info)
            except Exception as e:
                await ctx.send(f"❌ Error: {e}")
        
        @self.command(name='whoami')
        async def whoami_cmd(ctx):
            """Show current user"""
            user = ctx.author
            perms = self.db.get_user_permissions('discord', str(user.id))
            await ctx.send(f"👤 **{user.name}**\nID: {user.id}\nPermissions: {perms}")
        
        @self.command(name='uptime')
        async def uptime_cmd(ctx):
            """Show system uptime"""
            await ctx.send(f"⏱️ System uptime: {self.get_uptime()}")
        
        @self.command(name='date')
        async def date_cmd(ctx):
            """Show current date/time"""
            await ctx.send(f"📅 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        @self.command(name='ps')
        async def ps_cmd(ctx, count: int = 10):
            """Show running processes"""
            result = CommandExecutor.execute(f"ps aux | head -{count}")
            await self.send_result(ctx, result)
        
        @self.command(name='df')
        async def df_cmd(ctx):
            """Show disk usage"""
            result = CommandExecutor.execute("df -h")
            await self.send_result(ctx, result)
        
        @self.command(name='free')
        async def free_cmd(ctx):
            """Show memory usage"""
            result = CommandExecutor.execute("free -h")
            await self.send_result(ctx, result)
        
        @self.command(name='ifconfig')
        async def ifconfig_cmd(ctx):
            """Show network interfaces"""
            if platform.system().lower() == 'windows':
                result = CommandExecutor.execute("ipconfig")
            else:
                result = CommandExecutor.execute("ifconfig")
            await self.send_result(ctx, result)
        
        # Network Tools
        @self.command(name='nmap')
        async def nmap_cmd(ctx, target: str, *, options: str = "-sV"):
            """Run nmap scan"""
            await ctx.send(f"🔍 Running nmap on `{target}` with options: `{options}`\nThis may take a moment...")
            result = CommandExecutor.nmap_scan(target, options)
            
            if result['success']:
                # Extract open ports
                open_ports = self.extract_open_ports(result['output'])
                self.db.save_scan_result(target, 'nmap', result['output'], 
                                        str(ctx.author), open_ports)
            
            await self.send_result(ctx, result)
        
        @self.command(name='scan')
        async def scan_cmd(ctx, target: str):
            """Quick port scan"""
            await ctx.send(f"🔎 Quick scanning `{target}`...")
            result = CommandExecutor.quick_scan(target)
            
            if result['success']:
                open_ports = self.extract_open_ports(result['output'])
                self.db.save_scan_result(target, 'quick_scan', result['output'], 
                                        str(ctx.author), open_ports)
            
            await self.send_result(ctx, result)
        
        @self.command(name='fullscan')
        async def fullscan_cmd(ctx, target: str):
            """Full port scan"""
            await ctx.send(f"🔬 Full scanning `{target}` (all ports)... This will take several minutes.")
            result = CommandExecutor.full_scan(target)
            
            if result['success']:
                open_ports = self.extract_open_ports(result['output'])
                self.db.save_scan_result(target, 'full_scan', result['output'], 
                                        str(ctx.author), open_ports)
            
            await self.send_result(ctx, result)
        
        @self.command(name='traceroute')
        async def traceroute_cmd(ctx, target: str):
            """Trace route to host"""
            await ctx.send(f"🔄 Tracing route to `{target}`...")
            result = CommandExecutor.traceroute(target)
            await self.send_result(ctx, result)
        
        @self.command(name='whois')
        async def whois_cmd(ctx, domain: str):
            """WHOIS lookup"""
            await ctx.send(f"🔍 WHOIS lookup for `{domain}`...")
            result = CommandExecutor.whois(domain)
            await self.send_result(ctx, result)
        
        @self.command(name='dig')
        async def dig_cmd(ctx, domain: str, record_type: str = "ANY"):
            """DNS lookup"""
            await ctx.send(f"🔍 DNS lookup for `{domain}` ({record_type})...")
            result = CommandExecutor.dig(domain, record_type)
            await self.send_result(ctx, result)
        
        @self.command(name='curl')
        async def curl_cmd(ctx, url: str, *, options: str = ""):
            """HTTP request with curl"""
            await ctx.send(f"🌐 Fetching `{url}`...")
            result = CommandExecutor.curl(url, options)
            await self.send_result(ctx, result)
        
        @self.command(name='http')
        async def http_cmd(ctx, url: str):
            """Simple HTTP GET"""
            await ctx.send(f"🌐 GET `{url}`...")
            result = CommandExecutor.http_get(url)
            await self.send_result(ctx, result)
        
        @self.command(name='headers')
        async def headers_cmd(ctx, url: str):
            """Get HTTP headers"""
            await ctx.send(f"📋 Getting headers for `{url}`...")
            result = CommandExecutor.get_headers(url)
            await self.send_result(ctx, result)
        
        # SSH Commands
        @self.command(name='ssh')
        async def ssh_cmd(ctx, host: str, username: str = None, password: str = None):
            """Connect via SSH"""
            await ctx.send(f"🔐 Connecting to `{host}`...")
            
            success, message, session_id = self.ssh_manager.connect(
                host, username, password
            )
            
            if success:
                await ctx.send(f"✅ {message}")
                self.db.log_command(f"!ssh {host}", 'discord', str(ctx.author), 
                                  True, message, target=host)
            else:
                await ctx.send(f"❌ {message}")
        
        @self.command(name='ssh-exec')
        async def ssh_exec_cmd(ctx, session_id: str, *, command: str):
            """Execute command on SSH session"""
            await ctx.send(f"⚙️ Executing on session `{session_id}`: `{command}`")
            result = self.ssh_manager.execute_command(session_id, command)
            
            output = result['output']
            if len(output) > 1900:
                output = output[:1900] + "\n\n... (truncated)"
            
            await ctx.send(f"```\n{output}\n```\n✅ Done ({result['execution_time']:.2f}s)")
            
            self.db.log_command(f"!ssh-exec {session_id} {command}", 'discord', 
                              str(ctx.author), result['success'], 
                              result['output'], result['execution_time'])
        
        @self.command(name='ssh-list')
        async def ssh_list_cmd(ctx):
            """List active SSH sessions"""
            sessions = self.ssh_manager.list_sessions()
            db_sessions = self.db.get_active_ssh_sessions()
            
            if not sessions and not db_sessions:
                await ctx.send("📭 No active SSH sessions.")
                return
            
            text = "**🔐 Active SSH Sessions:**\n```\n"
            
            # Active sessions
            for session in sessions:
                text += f"🟢 {session['session_id']}: {session['host']}:{session['port']}\n"
            
            # Database sessions
            for session in db_sessions:
                if session['session_id'] not in [s['session_id'] for s in sessions]:
                    text += f"⚪ {session['session_id']}: {session['host']} (inactive)\n"
            
            text += "```"
            await ctx.send(text)
        
        @self.command(name='ssh-close')
        async def ssh_close_cmd(ctx, session_id: str):
            """Close SSH session"""
            if self.ssh_manager.close_session(session_id):
                await ctx.send(f"✅ Closed session `{session_id}`")
            else:
                await ctx.send(f"❌ Session `{session_id}` not found")
        
        # File Commands
        @self.command(name='ls')
        async def ls_cmd(ctx, path: str = "."):
            """List directory contents"""
            result = CommandExecutor.execute(f"ls -la {path}")
            await self.send_result(ctx, result)
        
        @self.command(name='cat')
        async def cat_cmd(ctx, file: str):
            """View file contents"""
            result = CommandExecutor.execute(f"cat {file}")
            await self.send_result(ctx, result)
        
        @self.command(name='grep')
        async def grep_cmd(ctx, pattern: str, file: str):
            """Search in file"""
            result = CommandExecutor.execute(f"grep -n '{pattern}' {file}")
            await self.send_result(ctx, result)
        
        @self.command(name='find')
        async def find_cmd(ctx, path: str, pattern: str):
            """Find files"""
            result = CommandExecutor.execute(f"find {path} -name '{pattern}' 2>/dev/null")
            await self.send_result(ctx, result)
        
        # Security Tools
        @self.command(name='nikto')
        async def nikto_cmd(ctx, host: str):
            """Run Nikto web scanner"""
            await ctx.send(f"🛡️ Running Nikto on `{host}`... This may take a while.")
            result = CommandExecutor.execute(f"nikto -h {host}")
            await self.send_result(ctx, result)
        
        @self.command(name='dirb')
        async def dirb_cmd(ctx, url: str):
            """Run DIRB directory scanner"""
            await ctx.send(f"📂 Running DIRB on `{url}`...")
            result = CommandExecutor.execute(f"dirb {url}")
            await self.send_result(ctx, result)
        
        @self.command(name='wpscan')
        async def wpscan_cmd(ctx, url: str):
            """Run WPScan WordPress scanner"""
            await ctx.send(f"🔍 Running WPScan on `{url}`...")
            result = CommandExecutor.execute(f"wpscan --url {url}")
            await self.send_result(ctx, result)
        
        # Management Commands
        @self.command(name='history')
        async def history_cmd(ctx, limit: int = 20):
            """Show command history"""
            history = self.db.get_command_history(limit, 'discord', str(ctx.author))
            
            if not history:
                await ctx.send("📭 No command history found.")
                return
            
            text = "**📜 Your Recent Commands:**\n```\n"
            for cmd in history:
                timestamp = cmd['timestamp'][:19] if cmd['timestamp'] else 'unknown'
                status = "✅" if cmd['success'] else "❌"
                text += f"[{timestamp}] {status} {cmd['command'][:50]}\n"
            text += "```"
            
            await ctx.send(text)
        
        @self.command(name='targets')
        async def targets_cmd(ctx, tag: str = None):
            """List scanned targets"""
            targets = self.db.get_targets(tag)
            
            if not targets:
                await ctx.send("📭 No targets found.")
                return
            
            text = "**🎯 Scanned Targets:**\n```\n"
            for target in targets:
                last_seen = target['last_seen'][:19] if target['last_seen'] else 'unknown'
                tags = target['tags'] or ''
                text += f"• {target['target']} (Last: {last_seen}) [{tags}]\n"
            text += "```"
            
            await ctx.send(text)
        
        @self.command(name='scan-history')
        async def scan_history_cmd(ctx, target: str = None):
            """Show scan history"""
            scans = self.db.get_scan_history(target)
            
            if not scans:
                await ctx.send("📭 No scan history found.")
                return
            
            text = "**📊 Scan History:**\n```\n"
            for scan in scans[:10]:
                timestamp = scan['timestamp'][:19] if scan['timestamp'] else 'unknown'
                text += f"• {timestamp} - {scan['target']} [{scan['scan_type']}]\n"
                if scan['open_ports']:
                    text += f"  Ports: {scan['open_ports']}\n"
            text += "```"
            
            await ctx.send(text)
        
        @self.command(name='auth-list')
        @discord_commands.has_permissions(administrator=True)
        async def auth_list_cmd(ctx):
            """List authorized users (admin only)"""
            users = self.db.get_authorized_users('discord')
            
            if not users:
                await ctx.send("📭 No authorized users found.")
                return
            
            text = "**👥 Authorized Discord Users:**\n```\n"
            for user in users:
                admin = "👑" if user['is_admin'] else "👤"
                perms = user['permissions']
                text += f"{admin} {user['username'] or user['user_id']} ({perms})\n"
            text += "```"
            
            await ctx.send(text)
        
        @self.command(name='auth-add')
        @discord_commands.has_permissions(administrator=True)
        async def auth_add_cmd(ctx, user: discord.User, permissions: str = "basic"):
            """Add authorized user (admin only)"""
            if self.db.add_authorized_user('discord', str(user.id), user.name, 
                                          str(ctx.author), False, permissions):
                await ctx.send(f"✅ Added {user.name} to authorized users with {permissions} permissions.")
            else:
                await ctx.send("❌ Failed to add user.")
        
        @self.command(name='auth-remove')
        @discord_commands.has_permissions(administrator=True)
        async def auth_remove_cmd(ctx, user: discord.User):
            """Remove authorized user (admin only)"""
            if self.db.remove_authorized_user('discord', str(user.id)):
                await ctx.send(f"✅ Removed {user.name} from authorized users.")
            else:
                await ctx.send("❌ User not found.")
        
        @self.command(name='stats')
        async def stats_cmd(ctx):
            """Show bot statistics"""
            total_commands = len(self.db.get_command_history(10000))
            discord_commands = len(self.db.get_command_history(10000, 'discord'))
            ssh_sessions = len(self.db.get_active_ssh_sessions())
            targets = len(self.db.get_targets())
            
            text = f"**📊 AuxBot Statistics:**\n```\n"
            text += f"Uptime: {self.get_uptime()}\n"
            text += f"Total Commands: {total_commands}\n"
            text += f"Discord Commands: {discord_commands}\n"
            text += f"Active SSH Sessions: {ssh_sessions}\n"
            text += f"Scanned Targets: {targets}\n"
            text += f"Authorized Users: {len(self.db.get_authorized_users('discord'))}\n"
            text += "```"
            
            await ctx.send(text)
    
    async def is_authorized(self, message) -> bool:
        """Check if user is authorized"""
        user_id = str(message.author.id)
        
        # Check database
        if self.db.is_user_authorized('discord', user_id):
            return True
        
        # Check if server admin
        if message.author.guild_permissions.administrator:
            return True
        
        # Check admin role
        admin_role = self.config.get('admin_role', 'Admin')
        if admin_role in [role.name for role in message.author.roles]:
            return True
        
        return False
    
    async def send_result(self, ctx, result):
        """Send command result to Discord"""
        if result['success']:
            output = result['output']
            
            # Truncate if too long
            if len(output) > 1900:
                output = output[:1900] + "\n\n... (output truncated)"
            
            await ctx.send(f"```\n{output}\n```\n✅ Done ({result['execution_time']:.2f}s)")
        else:
            await ctx.send(f"❌ Error:\n```\n{result['output'][:1900]}\n```")
    
    def extract_open_ports(self, nmap_output: str) -> str:
        """Extract open ports from nmap output"""
        ports = []
        for line in nmap_output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split('/')
                if parts:
                    port = parts[0].strip()
                    if port.isdigit():
                        ports.append(port)
        
        return ','.join(ports[:20])  # Limit to 20 ports
    
    def get_uptime(self) -> str:
        """Get system uptime"""
        uptime_seconds = time.time() - self.start_time
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

# =====================
# MAIN APPLICATION
# =====================

class AuxBotApp:
    """Main application class"""
    
    def __init__(self):
        self.encryption = EncryptionManager()
        self.db = DatabaseManager()
        self.ssh_manager = SSHManager(self.db, self.encryption)
        self.config = self._load_config()
        
        # Initialize bots
        self.discord_bot = None
        self.discord_thread = None
        
        self.running = True
    
    def _load_config(self) -> Dict:
        """Load main configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return {
            "discord": {"enabled": False},
            "telegram": {"enabled": False},
            "whatsapp": {"enabled": False},
            "ssh": {"enabled": True}
        }
    
    def _save_config(self):
        """Save main configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}                      🚀 AUXBOT v2.0.0 - C2 PLATFORM                      {Colors.RED}║
╠══════════════════════════════════════════════════════════════════════════╣
║{Colors.CYAN}  • Discord Integration     • SSH Remote Access      • 500+ Commands       {Colors.RED}║
║{Colors.CYAN}  • Network Scanning         • File Operations        • Security Tools      {Colors.RED}║
║{Colors.CYAN}  • Command History          • Multi-user Auth        • Target Tracking     {Colors.RED}║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.GREEN}📱 Bot Status:{Colors.RESET}
  Discord  : {'✅ Enabled' if self.config.get('discord', {}).get('enabled') else '❌ Disabled'}
  SSH      : {'✅ Enabled' if self.config.get('ssh', {}).get('enabled') else '❌ Disabled'}

{Colors.YELLOW}💡 Type 'help' for commands or 'discord start' to launch bot{Colors.RESET}
        """
        print(banner)
    
    def print_help(self):
        """Print help information"""
        help_text = f"""
{Colors.CYAN}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}
{Colors.WHITE}                         AUXBOT COMMANDS{Colors.RESET}
{Colors.CYAN}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.GREEN}📱 DISCORD CONTROL:{Colors.RESET}
  discord start           - Start Discord bot
  discord stop            - Stop Discord bot
  discord config          - Configure Discord bot
  discord status          - Show Discord bot status

{Colors.GREEN}🔐 SSH CONTROL:{Colors.RESET}
  ssh list                - List active SSH sessions
  ssh close <id>          - Close SSH session
  ssh config              - Configure SSH settings

{Colors.GREEN}📊 MANAGEMENT:{Colors.RESET}
  auth list               - List authorized users
  auth add <id> [perms]   - Add authorized user
  auth remove <id>        - Remove authorized user
  history                 - View command history
  targets                 - List scanned targets
  stats                   - Show bot statistics
  clear                   - Clear screen
  exit                    - Exit application

{Colors.CYAN}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}
        """
        print(help_text)
    
    def configure_discord(self):
        """Configure Discord bot"""
        print(f"\n{Colors.CYAN}🎮 Discord Bot Configuration{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*40}{Colors.RESET}")
        print(f"{Colors.YELLOW}Get bot token from https://discord.com/developers/applications{Colors.RESET}\n")
        
        token = input(f"{Colors.YELLOW}Bot Token: {Colors.RESET}").strip()
        if not token:
            print(f"{Colors.RED}❌ Token required{Colors.RESET}")
            return
        
        admin_role = input(f"{Colors.YELLOW}Admin Role [default: Admin]: {Colors.RESET}").strip() or "Admin"
        
        # Save config
        config = {
            "enabled": True,
            "token": token,
            "admin_role": admin_role,
            "allowed_channels": []
        }
        
        try:
            with open(DISCORD_CONFIG, 'w') as f:
                json.dump(config, f, indent=4)
            
            self.config['discord'] = {"enabled": True}
            self._save_config()
            print(f"{Colors.GREEN}✅ Discord configuration saved{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}❌ Failed to save configuration: {e}{Colors.RESET}")
    
    def start_discord_bot(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            print(f"{Colors.RED}❌ Discord.py not installed{Colors.RESET}")
            return
        
        if not os.path.exists(DISCORD_CONFIG):
            print(f"{Colors.RED}❌ Discord not configured. Run 'discord config' first{Colors.RESET}")
            return
        
        # Load config
        try:
            with open(DISCORD_CONFIG, 'r') as f:
                config = json.load(f)
            
            if not config.get('token'):
                print(f"{Colors.RED}❌ Invalid Discord configuration{Colors.RESET}")
                return
            
            # Create and start bot
            self.discord_bot = DiscordBot(self.db, self.ssh_manager)
            self.discord_bot.config = config
            
            self.discord_thread = threading.Thread(
                target=self._run_discord_bot,
                args=(config['token'],),
                daemon=True
            )
            self.discord_thread.start()
            
            print(f"{Colors.GREEN}✅ Discord bot starting...{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}❌ Failed to start Discord bot: {e}{Colors.RESET}")
    
    def _run_discord_bot(self, token: str):
        """Run Discord bot in thread"""
        try:
            self.discord_bot.run(token)
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            print(f"{Colors.RED}❌ Discord bot error: {e}{Colors.RESET}")
    
    def stop_discord_bot(self):
        """Stop Discord bot"""
        if self.discord_bot:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.discord_bot.close(), 
                    self.discord_bot.loop
                )
            except:
                pass
            self.discord_bot = None
            print(f"{Colors.YELLOW}⏸️ Discord bot stopped{Colors.RESET}")
    
    def discord_status(self):
        """Show Discord bot status"""
        if self.discord_bot and self.discord_bot.is_ready():
            print(f"{Colors.GREEN}✅ Discord bot is running{Colors.RESET}")
            print(f"   User: {self.discord_bot.user}")
            print(f"   Guilds: {len(self.discord_bot.guilds)}")
        else:
            print(f"{Colors.YELLOW}⏸️ Discord bot is not running{Colors.RESET}")
    
    def ssh_list(self):
        """List SSH sessions"""
        sessions = self.ssh_manager.list_sessions()
        db_sessions = self.db.get_active_ssh_sessions()
        
        if not sessions and not db_sessions:
            print(f"{Colors.YELLOW}📭 No active SSH sessions{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}🔐 Active SSH Sessions{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Active sessions
        for session in sessions:
            print(f"{Colors.GREEN}🟢 {session['session_id']}{Colors.RESET}")
            print(f"   Host: {session['host']}:{session['port']}")
        
        # Database sessions
        for session in db_sessions:
            if session['session_id'] not in [s['session_id'] for s in sessions]:
                print(f"{Colors.YELLOW}⚪ {session['session_id']}{Colors.RESET}")
                print(f"   Host: {session['host']} (inactive)")
        
        print()
    
    def ssh_close(self, session_id: str):
        """Close SSH session"""
        if self.ssh_manager.close_session(session_id):
            print(f"{Colors.GREEN}✅ Closed session {session_id}{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Session {session_id} not found{Colors.RESET}")
    
    def auth_list(self):
        """List authorized users"""
        users = self.db.get_authorized_users()
        
        if not users:
            print(f"{Colors.YELLOW}📭 No authorized users{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}👥 Authorized Users{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        for user in users:
            platform_icon = {
                'discord': '🎮',
                'telegram': '📱',
                'whatsapp': '💬'
            }.get(user['platform'], '👤')
            
            admin = "👑 " if user['is_admin'] else "   "
            username = user['username'] or user['user_id']
            perms = user['permissions']
            added = user['added_date'][:10] if user['added_date'] else 'unknown'
            
            print(f"{platform_icon} {admin}{username[:30]}")
            print(f"    Platform: {user['platform']} | Perms: {perms} | Added: {added}")
    
    def auth_add(self, platform: str, user_id: str, permissions: str = "basic"):
        """Add authorized user"""
        if platform not in ['discord', 'telegram', 'whatsapp']:
            print(f"{Colors.RED}❌ Invalid platform. Use: discord, telegram, whatsapp{Colors.RESET}")
            return
        
        if self.db.add_authorized_user(platform, user_id, user_id, 'console', False, permissions):
            print(f"{Colors.GREEN}✅ Added {user_id} to {platform} authorized users ({permissions}){Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to add user{Colors.RESET}")
    
    def auth_remove(self, platform: str, user_id: str):
        """Remove authorized user"""
        if self.db.remove_authorized_user(platform, user_id):
            print(f"{Colors.GREEN}✅ Removed user from {platform} authorized users{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ User not found{Colors.RESET}")
    
    def show_history(self, limit: int = 20):
        """Show command history"""
        history = self.db.get_command_history(limit)
        
        if not history:
            print(f"{Colors.YELLOW}📭 No command history{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}📜 Command History (last {limit}){Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        for cmd in history[:20]:
            timestamp = cmd['timestamp'][:19] if cmd['timestamp'] else 'unknown'
            source_icon = {
                'discord': '🎮',
                'telegram': '📱',
                'whatsapp': '💬',
                'local': '💻'
            }.get(cmd['source'], '📝')
            
            status = f"{Colors.GREEN}✓" if cmd['success'] else f"{Colors.RED}✗"
            user = f"[{cmd['user'][:15]}]" if cmd['user'] else ""
            cmd_text = cmd['command'][:50]
            
            print(f"{status}{Colors.RESET} {source_icon} {timestamp} {user} {cmd_text}")
    
    def show_targets(self):
        """Show scanned targets"""
        targets = self.db.get_targets()
        
        if not targets:
            print(f"{Colors.YELLOW}📭 No targets found{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}🎯 Scanned Targets{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        for target in targets:
            last_seen = target['last_seen'][:19] if target['last_seen'] else 'unknown'
            tags = target['tags'] or 'untagged'
            print(f"• {target['target']}")
            print(f"  Last: {last_seen} | Tags: {tags}")
    
    def show_stats(self):
        """Show bot statistics"""
        total_cmds = len(self.db.get_command_history(10000))
        discord_cmds = len(self.db.get_command_history(10000, 'discord'))
        local_cmds = len(self.db.get_command_history(10000, 'local'))
        ssh_sessions = len(self.db.get_active_ssh_sessions())
        targets = len(self.db.get_targets())
        users = len(self.db.get_authorized_users())
        
        print(f"\n{Colors.CYAN}📊 Bot Statistics{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        print(f"Total Commands    : {total_cmds}")
        print(f"Discord Commands  : {discord_cmds}")
        print(f"Local Commands    : {local_cmds}")
        print(f"Active SSH Sessions: {ssh_sessions}")
        print(f"Scanned Targets   : {targets}")
        print(f"Authorized Users  : {users}")
        print()
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Auto-start Discord if configured
        if self.config.get('discord', {}).get('enabled'):
            self.start_discord_bot()
        
        # Command loop
        while self.running:
            try:
                command = input(f"{Colors.RED}[{Colors.WHITE}AuxBot{Colors.RED}]{Colors.RESET} ").strip()
                
                if not command:
                    continue
                
                # Parse command
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Help commands
                if cmd in ['help', 'h', '?']:
                    self.print_help()
                
                # Clear screen
                elif cmd in ['clear', 'cls']:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_banner()
                
                # Exit
                elif cmd in ['exit', 'quit', 'q']:
                    self.running = False
                    print(f"\n{Colors.YELLOW}👋 Shutting down...{Colors.RESET}")
                
                # Discord commands
                elif cmd == 'discord':
                    if not args:
                        print(f"{Colors.RED}❌ Usage: discord <start|stop|status|config>{Colors.RESET}")
                    elif args[0] == 'start':
                        self.start_discord_bot()
                    elif args[0] == 'stop':
                        self.stop_discord_bot()
                    elif args[0] == 'status':
                        self.discord_status()
                    elif args[0] == 'config':
                        self.configure_discord()
                    else:
                        print(f"{Colors.RED}❌ Unknown discord command{Colors.RESET}")
                
                # SSH commands
                elif cmd == 'ssh':
                    if not args:
                        print(f"{Colors.RED}❌ Usage: ssh <list|close>{Colors.RESET}")
                    elif args[0] == 'list':
                        self.ssh_list()
                    elif args[0] == 'close' and len(args) > 1:
                        self.ssh_close(args[1])
                    else:
                        print(f"{Colors.RED}❌ Unknown ssh command{Colors.RESET}")
                
                # Auth commands
                elif cmd == 'auth':
                    if not args:
                        print(f"{Colors.RED}❌ Usage: auth <list|add|remove>{Colors.RESET}")
                    elif args[0] == 'list':
                        self.auth_list()
                    elif args[0] == 'add' and len(args) >= 3:
                        perms = args[3] if len(args) > 3 else "basic"
                        self.auth_add(args[1], args[2], perms)
                    elif args[0] == 'remove' and len(args) >= 3:
                        self.auth_remove(args[1], args[2])
                    else:
                        print(f"{Colors.RED}❌ Invalid auth command{Colors.RESET}")
                
                # History
                elif cmd == 'history':
                    limit = int(args[0]) if args and args[0].isdigit() else 20
                    self.show_history(limit)
                
                # Targets
                elif cmd == 'targets':
                    self.show_targets()
                
                # Stats
                elif cmd == 'stats':
                    self.show_stats()
                
                # Unknown command - try system command
                else:
                    print(f"{Colors.YELLOW}⚙️ Executing: {command}{Colors.RESET}")
                    result = CommandExecutor.execute(command)
                    
                    if result['success']:
                        print(result['output'])
                    else:
                        print(f"{Colors.RED}❌ {result['output']}{Colors.RESET}")
                    
                    self.db.log_command(command, 'local', 'console', result['success'], 
                                      result['output'], result['execution_time'])
            
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Shutting down...{Colors.RESET}")
                self.running = False
            
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.stop_discord_bot()
        self.ssh_manager.close_all()
        self.db.close()
        
        print(f"{Colors.GREEN}✅ Shutdown complete{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================

def main():
    """Main entry point"""
    try:
        print(f"{Colors.CYAN}🚀 Starting AuxBot...{Colors.RESET}")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher required{Colors.RESET}")
            sys.exit(1)
        
        # Check required modules
        if not DISCORD_AVAILABLE:
            print(f"{Colors.YELLOW}⚠️  Discord module not available. Some features disabled.{Colors.RESET}")
        
        if not SSH_AVAILABLE:
            print(f"{Colors.YELLOW}⚠️  SSH module not available. Install with: pip install paramiko scp{Colors.RESET}")
        
        # Create and run app
        app = AuxBotApp()
        app.run()
    
    except Exception as e:
        print(f"{Colors.RED}❌ Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()