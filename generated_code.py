# Cisco XR Device Audit Script

A comprehensive Python script for conducting automated audits on Cisco XR devices following organizational standards and security best practices.

## Features

- Secure SSH connectivity with error handling
- Comprehensive device information gathering
- Configuration compliance checking
- Security assessment
- Automated report generation
- Logging and audit trails

## Requirements

```bash
pip install netmiko paramiko
```

## Script

```python
#!/usr/bin/env python3
"""
Cisco XR Device Audit Script

This script automates the audit process for Cisco XR devices as outlined in the MOP.
It performs comprehensive configuration, security, and compliance assessments.

Author: Infrastructure Team
Version: 1.0
Date: 2024
"""

import json
import logging
import re
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:
    print("Error: Required modules not found. Please install: pip install netmiko")
    sys.exit(1)


class CiscoXRAuditor:
    """
    Cisco XR Device Auditor Class
    
    Handles the complete audit workflow for Cisco XR devices including
    connection management, data collection, analysis, and reporting.
    """
    
    def __init__(self, host: str, username: str, password: str, 
                 enable_password: Optional[str] = None, port: int = 22):
        """
        Initialize the auditor with device connection parameters.
        
        Args:
            host: Device IP address or hostname
            username: SSH username
            password: SSH password
            enable_password: Enable password (if required)
            port: SSH port (default: 22)
        """
        self.host = host
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.port = port
        self.connection = None
        
        # Initialize audit data storage
        self.audit_data = {
            'device_info': {},
            'configuration': {},
            'interfaces': {},
            'security': {},
            'routing': {},
            'logs': {},
            'findings': [],
            'recommendations': []
        }
        
        # Setup logging
        self._setup_logging()
        
        # Define compliance checks
        self._setup_compliance_rules()
    
    def _setup_logging(self) -> None:
        """Configure logging for audit trail."""
        log_dir = Path("audit_logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"cisco_xr_audit_{self.host}_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Audit session started for device: {self.host}")
    
    def _setup_compliance_rules(self) -> None:
        """Define compliance rules for security and best practices."""
        self.compliance_rules = {
            'security': {
                'insecure_protocols': ['telnet', 'http', 'tftp', 'snmp community'],
                'required_acls': ['management-acl', 'infrastructure-acl'],
                'password_policies': ['minimum-length', 'complexity'],
                'login_security': ['login block-for', 'login quiet-mode']
            },
            'interfaces': {
                'required_descriptions': True,
                'unused_interfaces': 'shutdown',
                'trunk_security': ['switchport trunk allowed vlan']
            },
            'routing': {
                'default_routes': 'review_required',
                'routing_protocols': ['ospf', 'bgp', 'isis']
            }
        }
    
    def connect(self) -> bool:
        """
        Establish secure SSH connection to the Cisco XR device.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        device_params = {
            'device_type': 'cisco_xr',
            'host': self.host,
            'username': self.username,
            'password': self.password,
            'port': self.port,
            'timeout': 30,
            'banner_timeout': 30,
            'conn_timeout': 10
        }
        
        if self.enable_password:
            device_params['secret'] = self.enable_password
        
        try:
            self.logger.info(f"Establishing SSH connection to {self.host}:{self.port}")
            self.connection = ConnectHandler(**device_params)
            
            # Test connection with a simple command
            test_output = self.connection.send_command("show clock")
            self.logger.info("Connection established successfully")
            self.logger.info(f"Device time: {test_output.strip()}")
            
            return True
            
        except NetmikoTimeoutException:
            self.logger.error(f"Connection timeout to {self.host}")
            return False
        except NetmikoAuthenticationException:
            self.logger.error(f"Authentication failed for {self.host}")
            return False
        except Exception as e:
            self.logger.error(f"Connection failed: {str(e)}")
            return False
    
    def disconnect(self) -> None:
        """Gracefully close the SSH connection."""
        if self.connection:
            try:
                self.connection.disconnect()
                self.logger.info("SSH connection closed successfully")
            except Exception as e:
                self.logger.warning(f"Error during disconnect: {str(e)}")
    
    def gather_device_info(self) -> Dict:
        """
        Gather basic device information.
        
        Returns:
            Dict: Device information including hostname, model, version
        """
        self.logger.info("Step 2: Gathering device information")
        
        try:
            # Get hostname
            hostname_output = self.connection.send_command("show hostname")
            hostname = hostname_output.strip()
            
            # Get version information
            version_output = self.connection.send_command("show version")
            
            # Parse version output
            device_info = self._parse_version_output(version_output)
            device_info['hostname'] = hostname
            device_info['audit_timestamp'] = datetime.now().isoformat()
            
            self.audit_data['device_info'] = device_info
            self.logger.info(f"Device: {hostname}, Model: {device_info.get('model', 'Unknown')}")
            
            return device_info
            
        except Exception as e:
            self.logger.error(f"Failed to gather device information: {str(e)}")
            return {}
    
    def _parse_version_output(self, version_output: str) -> Dict:
        """Parse the show version command output."""
        device_info = {}
        
        # Extract software version
        version_match = re.search(r'Version (\S+)', version_output)
        if version_match:
            device_info['software_version'] = version_match.group(1)
        
        # Extract hardware model
        model_patterns = [
            r'cisco (\S+)',
            r'Cisco (\S+)',
            r'Platform:\s+(\S+)'
        ]
        
        for pattern in model_patterns:
            model_match = re.search(pattern, version_output)
            if model_match:
                device_info['model'] = model_match.group(1)
                break
        
        # Extract uptime
        uptime_match = re.search(r'uptime is (.+)', version_output)
        if uptime_match:
            device_info['uptime']