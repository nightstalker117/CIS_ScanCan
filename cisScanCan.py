#!/usr/bin/env python3
"""
Universal CIS Benchmark Compliance Scanner - All Operating Systems
Comprehensive security compliance checker supporting Windows, Linux, macOS, and Unix systems
"""

import os
import sys
import subprocess
import json
import re
import platform
import socket
from datetime import datetime
from pathlib import Path
import configparser
import logging
import traceback
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Any, Optional, Set
import argparse
import tempfile

# Import OS-specific modules
try:
    import winreg
    import ctypes
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

try:
    import pwd
    import grp
    import stat
    UNIX_AVAILABLE = True
except ImportError:
    UNIX_AVAILABLE = False


def print_ascii_banner():
    """Print ASCII art banner for CIS ScanCan"""
    banner = """
    >>==========================================================<<
    ||   ______  _____   ______                                 ||
    || .' ___  ||_   _|.' ____ \                                ||
    ||/ .'   \_|  | |  | (___ \_|                               ||
    ||| |         | |   _.____`.                                ||
    ||\ `.___.'\ _| |_ | \____) |                               ||
    || `.____ .'|_____| \______.'                               ||
    ||  ______                           ______                 ||
    ||.' ____ \                        .' ___  |                ||
    ||| (___ \_| .---.  ,--.   _ .--. / .'   \_| ,--.   _ .--.  ||
    || _.____`. / /'`\]`'_\ : [ `.-. || |       `'_\ : [ `.-. | ||
    ||| \____) || \__. // | |, | | | |\ `.___.'\// | |, | | | | ||
    || \______.''.___.'\'-;__/[___||__]`.____ .'\'-;__/[___||__]||
    >>==========================================================<<
                                                                                      
   🛡️  Universal CIS Benchmark Compliance Scanner - All Operating Systems 🛡️
   ═════════════════════════════════════════════════════════════════════════
                                                     By: Nightstalker
"""
    print(banner)


class CISException(Exception):
    """Base exception class for CIS Scanner"""
    pass


class OSDetector:
    """Detect and classify operating system"""
    
    @staticmethod
    def detect_os() -> Dict[str, str]:
        """Detect operating system and return detailed information"""
        system = platform.system().lower()
        release = platform.release()
        version = platform.version()
        machine = platform.machine()
        
        os_info = {
            'system': system,
            'release': release,
            'version': version,
            'machine': machine,
            'distribution': 'unknown',
            'distribution_version': 'unknown',
            'category': 'unknown'
        }
        
        if system == 'windows':
            os_info['category'] = 'windows'
            os_info['distribution'] = 'windows'
            os_info['distribution_version'] = release
            
        elif system == 'linux':
            os_info['category'] = 'linux'
            # Detect Linux distribution
            try:
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        content = f.read()
                        for line in content.split('\n'):
                            if line.startswith('ID='):
                                os_info['distribution'] = line.split('=')[1].strip('"')
                            elif line.startswith('VERSION_ID='):
                                os_info['distribution_version'] = line.split('=')[1].strip('"')
            except Exception:
                pass
                
        elif system == 'darwin':
            os_info['category'] = 'macos'
            os_info['distribution'] = 'macos'
            os_info['distribution_version'] = release
            
        elif system in ['aix', 'sunos', 'hp-ux']:
            os_info['category'] = 'unix'
            os_info['distribution'] = system
            
        return os_info


class UniversalCISBenchmarkRegistry:
    """Registry of all CIS benchmark modules for all operating systems"""
    
    BENCHMARK_CATEGORIES = {
        # Windows CIS Benchmarks
        'windows': {
            '1': {
                'name': 'Account Policies',
                'description': 'Password policies, account lockout policies, and Kerberos policies',
                'subcategories': {
                    '1.1': 'Password Policy',
                    '1.2': 'Account Lockout Policy'
                }
            },
            '9': {
                'name': 'Windows Firewall',
                'description': 'Windows Firewall with Advanced Security',
                'subcategories': {
                    '9.1': 'Domain Profile',
                    '9.2': 'Private Profile',
                    '9.3': 'Public Profile'
                }
            }
        },
        
        # Linux CIS Benchmarks
        'linux': {
            '1': {
                'name': 'Initial Setup',
                'description': 'Filesystem configuration, software updates, mandatory access controls',
                'subcategories': {
                    '1.1': 'Filesystem Configuration',
                    '1.3': 'Filesystem Integrity Checking'
                }
            },
            '3': {
                'name': 'Network Configuration',
                'description': 'Network parameters and firewall configuration',
                'subcategories': {
                    '3.1': 'Network Parameters (Host Only)',
                    '3.5': 'Firewall Configuration'
                }
            },
            '4': {
                'name': 'Logging and Auditing',
                'description': 'System logging and audit configuration',
                'subcategories': {
                    '4.1': 'Configure System Accounting (auditd)',
                    '4.2': 'Configure Logging'
                }
            },
            '5': {
                'name': 'Access, Authentication and Authorization',
                'description': 'SSH, PAM, user accounts, and sudo configuration',
                'subcategories': {
                    '5.2': 'SSH Server Configuration',
                    '5.3': 'Configure PAM'
                }
            }
        },
        
        # macOS CIS Benchmarks
        'macos': {
            '1': {
                'name': 'Install Updates, Patches and Additional Security Software',
                'description': 'Software updates and security patches',
                'subcategories': {
                    '1.1': 'Verify all Apple provided software is current',
                    '1.2': 'Enable Auto Update'
                }
            },
            '4': {
                'name': 'Network Configurations',
                'description': 'Network security configurations',
                'subcategories': {
                    '4.1': 'Configure Firewall',
                    '4.2': 'Enable Firewall Stealth Mode'
                }
            },
            '5': {
                'name': 'System Access, Authentication and Authorization',
                'description': 'User access control and authentication',
                'subcategories': {
                    '5.2': 'Password Policy',
                    '5.8': 'Disable automatic login'
                }
            }
        },
        
        # Unix CIS Benchmarks
        'unix': {
            '1': {
                'name': 'Filesystem Configuration',
                'description': 'Configure filesystem security and partitions',
                'subcategories': {
                    '1.1': 'Create Separate Partitions',
                    '1.5': 'Set Default umask'
                }
            },
            '3': {
                'name': 'Network Configuration and Firewalls',
                'description': 'Network security and firewall configuration',
                'subcategories': {
                    '3.1': 'Network Parameters',
                    '3.4': 'Disable Standard Services'
                }
            }
        }
    }
    
    @classmethod
    def get_categories_for_os(cls, os_category: str) -> Dict[str, Dict]:
        """Get benchmark categories for specific OS"""
        return cls.BENCHMARK_CATEGORIES.get(os_category, {})


class ExceptionHandler:
    """Centralized exception handling and logging"""
    
    def __init__(self, logger):
        self.logger = logger
        self.error_counts = {
            'permission': 0,
            'timeout': 0,
            'system': 0,
            'configuration': 0,
            'general': 0
        }
    
    def handle_exception(self, exception: Exception, context: str = "") -> Dict[str, Any]:
        """Handle and categorize exceptions"""
        error_type = type(exception).__name__
        error_msg = str(exception)
        
        self.logger.error(f"{context}: {error_type} - {error_msg}")
        
        return {
            'status': 'ERROR',
            'error_type': error_type,
            'description': f'{context} failed',
            'reason': f'{error_type}: {error_msg}',
            'timestamp': datetime.now().isoformat()
        }


class SafeFileHandler:
    """Safe file operations with proper exception handling"""
    
    def __init__(self, logger, timeout: int = 10):
        self.logger = logger
        self.timeout = timeout
    
    def safe_read_file(self, filepath: str, encoding: str = 'utf-8') -> Optional[str]:
        """Safely read file contents with timeout and error handling"""
        try:
            if not os.path.exists(filepath):
                return None
            
            with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
                return f.read()
                
        except Exception as e:
            self.logger.warning(f"Failed to read {filepath}: {e}")
            return None


class CISModule(ABC):
    """Abstract base class for CIS benchmark modules"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.exception_handler = ExceptionHandler(self.logger)
    
    @abstractmethod
    def get_name(self) -> str:
        """Return module name"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Return module description"""
        pass
    
    @abstractmethod
    def get_category_id(self) -> str:
        """Return CIS category ID (e.g., '1.1', '2.2')"""
        pass
    
    @abstractmethod
    def get_supported_os(self) -> List[str]:
        """Return list of supported operating systems"""
        pass
    
    @abstractmethod
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        """Check if module is applicable to current system"""
        pass
    
    @abstractmethod
    def run_checks(self, scanner) -> Dict[str, Any]:
        """Run the CIS checks for this module"""
        pass
    
    def safe_run_checks(self, scanner) -> Dict[str, Any]:
        """Safely run checks with comprehensive error handling"""
        try:
            return self.run_checks(scanner)
        except Exception as e:
            error_result = self.exception_handler.handle_exception(e, f"{self.get_name()} module")
            return {'module_error': error_result}


# Windows-specific modules
class WindowsPasswordPolicyModule(CISModule):
    def get_name(self) -> str:
        return "Windows Password Policy"
    
    def get_description(self) -> str:
        return "Configure password complexity and aging requirements (CIS 1.1)"
    
    def get_category_id(self) -> str:
        return "1.1"
    
    def get_supported_os(self) -> List[str]:
        return ['windows']
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'windows' and WINDOWS_AVAILABLE
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        results = {}
        
        try:
            # Basic password policy checks using registry or manual verification
            results["1.1.1_password_complexity"] = {
                'status': 'MANUAL',
                'description': 'Ensure password complexity requirements are enabled',
                'reason': 'Manual verification required - check Local Security Policy (secpol.msc)'
            }
            
            results["1.1.2_minimum_password_length"] = {
                'status': 'MANUAL',
                'description': 'Ensure minimum password length is 14 characters',
                'reason': 'Manual verification required - check Local Security Policy (secpol.msc)'
            }
            
            results["1.1.3_password_history"] = {
                'status': 'MANUAL',
                'description': 'Ensure password history is set to 24 passwords',
                'reason': 'Manual verification required - check Local Security Policy (secpol.msc)'
            }

        except Exception as e:
            self.logger.error(f"Critical error in WindowsPasswordPolicy module: {e}")
            results['critical_error'] = self.exception_handler.handle_exception(e, "WindowsPasswordPolicy module")

        return results


class WindowsFirewallModule(CISModule):
    def get_name(self) -> str:
        return "Windows Firewall"
    
    def get_description(self) -> str:
        return "Configure Windows Firewall settings (CIS 9.1)"
    
    def get_category_id(self) -> str:
        return "9.1"
    
    def get_supported_os(self) -> List[str]:
        return ['windows']
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'windows'
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        results = {}
        
        try:
            profiles = ['domain', 'private', 'public']
            
            for profile in profiles:
                try:
                    cmd = f'netsh advfirewall show {profile}profile'
                    stdout, stderr, rc = scanner.run_command(cmd)
                    
                    if rc == 0:
                        firewall_enabled = 'State                                 ON' in stdout
                        
                        results[f"9.1.{profile}_firewall_enabled"] = {
                            'status': 'PASS' if firewall_enabled else 'FAIL',
                            'description': f'Ensure Windows Firewall is enabled ({profile} profile)',
                            'reason': 'Firewall enabled' if firewall_enabled else 'Firewall disabled'
                        }
                        
                    else:
                        results[f"9.1.{profile}_firewall_check"] = {
                            'status': 'ERROR',
                            'description': f'Check Windows Firewall status ({profile} profile)',
                            'reason': f'Failed to query firewall status: {stderr}'
                        }
                        
                except Exception as e:
                    results[f"9.1.{profile}_firewall_check"] = self.exception_handler.handle_exception(
                        e, f"Windows Firewall check for {profile} profile")

        except Exception as e:
            self.logger.error(f"Critical error in WindowsFirewall module: {e}")
            results['critical_error'] = self.exception_handler.handle_exception(e, "WindowsFirewall module")

        return results


# Linux-specific modules
class LinuxFilesystemModule(CISModule):
    def get_name(self) -> str:
        return "Linux Filesystem Configuration"
    
    def get_description(self) -> str:
        return "Configure filesystem security and disable unused filesystems (CIS 1.1)"
    
    def get_category_id(self) -> str:
        return "1.1"
    
    def get_supported_os(self) -> List[str]:
        return ['linux']
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'linux'
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        results = {}
        
        try:
            # Check for unused filesystems
            unused_filesystems = ['cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf']
            
            for fs in unused_filesystems:
                try:
                    stdout, stderr, rc = scanner.run_command(f"lsmod | grep {fs}")
                    results[f"1.1.1_{fs}_disabled"] = {
                        'status': 'PASS' if rc != 0 else 'FAIL',
                        'description': f'Ensure {fs} filesystem is disabled',
                        'reason': 'Module not loaded' if rc != 0 else 'Module is loaded'
                    }
                except Exception as e:
                    results[f"1.1.1_{fs}_disabled"] = self.exception_handler.handle_exception(
                        e, f"Filesystem check for {fs}")

        except Exception as e:
            self.logger.error(f"Critical error in LinuxFilesystem module: {e}")
            results['critical_error'] = self.exception_handler.handle_exception(e, "LinuxFilesystem module")

        return results


class LinuxSSHModule(CISModule):
    def get_name(self) -> str:
        return "Linux SSH Configuration"
    
    def get_description(self) -> str:
        return "SSH Security Settings - Protocol, authentication, etc. (CIS 5.2)"
    
    def get_category_id(self) -> str:
        return "5.2"
    
    def get_supported_os(self) -> List[str]:
        return ['linux']
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'linux' and os.path.exists('/etc/ssh/sshd_config')
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        results = {}
        
        try:
            ssh_config = scanner.file_handler.safe_read_file('/etc/ssh/sshd_config')
            if not ssh_config:
                results["5.2_ssh_config_read_error"] = {
                    'status': 'ERROR',
                    'description': 'SSH configuration file read error',
                    'reason': 'Could not read SSH config file'
                }
                return results

            ssh_requirements = {
                'PermitRootLogin': 'no',
                'PermitEmptyPasswords': 'no',
                'X11Forwarding': 'no',
                'MaxAuthTries': '4'
            }

            for setting, expected_value in ssh_requirements.items():
                try:
                    pattern = rf'^{setting}\s+(.+)$'
                    match = re.search(pattern, ssh_config, re.MULTILINE | re.IGNORECASE)
                    
                    if match:
                        actual_value = match.group(1).strip()
                        status = 'PASS' if actual_value.lower() == expected_value.lower() else 'FAIL'
                        reason = f'Set to {actual_value}' if status == 'PASS' else f'Set to {actual_value}, expected {expected_value}'
                    else:
                        status = 'FAIL'
                        reason = f'Setting not found, expected {expected_value}'

                    results[f"5.2.{setting.lower()}"] = {
                        'status': status,
                        'description': f'Ensure SSH {setting} is configured',
                        'reason': reason
                    }
                except Exception as e:
                    results[f"5.2.{setting.lower()}"] = self.exception_handler.handle_exception(
                        e, f"SSH setting check for {setting}")

        except Exception as e:
            self.logger.error(f"Critical error in LinuxSSH module: {e}")
            results['critical_error'] = self.exception_handler.handle_exception(e, "LinuxSSH module")

        return results


# macOS-specific modules
class MacOSUpdatesModule(CISModule):
    def get_name(self) -> str:
        return "macOS Software Updates"
    
    def get_description(self) -> str:
        return "Verify all Apple provided software is current (CIS 1.1)"
    
    def get_category_id(self) -> str:
        return "1.1"
    
    def get_supported_os(self) -> List[str]:
        return ['macos']
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'macos'
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        results = {}
        
        try:
            # Check for available updates
            stdout, stderr, rc = scanner.run_command("softwareupdate -l")
            
            if rc == 0:
                if "No new software available" in stdout:
                    status = 'PASS'
                    reason = 'No updates available - system is current'
                else:
                    status = 'FAIL'
                    reason = 'Software updates are available'
            else:
                status = 'ERROR'
                reason = f'Unable to check for updates: {stderr}'
            
            results["1.1.1_software_updates"] = {
                'status': status,
                'description': 'Ensure all Apple provided software is current',
                'reason': reason
            }

        except Exception as e:
            self.logger.error(f"Critical error in MacOSUpdates module: {e}")
            results['critical_error'] = self.exception_handler.handle_exception(e, "MacOSUpdates module")

        return results


class MacOSFirewallModule(CISModule):
    def get_name(self) -> str:
        return "macOS Firewall Configuration"
    
    def get_description(self) -> str:
        return "Configure Application Layer Firewall (CIS 4.1)"
    
    def get_category_id(self) -> str:
        return "4.1"
    
    def get_supported_os(self) -> List[str]:
        return ['macos']
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'macos'
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        results = {}
        
        try:
            # Check firewall status
            stdout, stderr, rc = scanner.run_command("defaults read /Library/Preferences/com.apple.alf globalstate")
            
            if rc == 0:
                firewall_state = stdout.strip()
                firewall_enabled = firewall_state in ['1', '2']
                
                status = 'PASS' if firewall_enabled else 'FAIL'
                reason = f'Firewall enabled (state: {firewall_state})' if firewall_enabled else f'Firewall disabled (state: {firewall_state})'
            else:
                status = 'ERROR'
                reason = f'Unable to check firewall status: {stderr}'
            
            results["4.1.1_firewall_enabled"] = {
                'status': status,
                'description': 'Ensure Application Layer Firewall is enabled',
                'reason': reason
            }

        except Exception as e:
            self.logger.error(f"Critical error in MacOSFirewall module: {e}")
            results['critical_error'] = self.exception_handler.handle_exception(e, "MacOSFirewall module")

        return results


class ModuleSelector:
    """Interactive module selection interface for all operating systems"""
    
    def __init__(self, os_info: Dict[str, str]):
        self.os_info = os_info
        self.selected_modules = set()
        self.registry = UniversalCISBenchmarkRegistry()
    
    def display_categories(self):
        """Display available benchmark categories for current OS"""
        os_category = self.os_info.get('category', 'unknown')
        categories = self.registry.get_categories_for_os(os_category)
        
        print(f"\n{'='*80}")
        print(f"🛡️  {os_category.upper()} CIS BENCHMARK CATEGORIES")
        print(f"{'='*80}")
        
        if not categories:
            print(f"No CIS benchmark categories available for {os_category}")
            return
        
        for cat_id, cat_info in categories.items():
            print(f"\n{cat_id}. {cat_info['name']}")
            print(f"   Description: {cat_info['description']}")
            
            if cat_info.get('subcategories'):
                print("   Subcategories:")
                for sub_id, sub_name in cat_info['subcategories'].items():
                    print(f"     • {sub_id}: {sub_name}")
    
    def display_selection_menu(self):
        """Display selection menu"""
        print(f"\n{'='*80}")
        print("🔧  MODULE SELECTION OPTIONS")
        print(f"{'='*80}")
        print("1. Select all modules (comprehensive scan)")
        print("2. Select by category")
        print("3. Select by subcategory")
        print("4. Interactive selection")
        print("5. Quick security assessment (recommended modules)")
        print("0. Exit")
    
    def select_all_modules(self) -> Set[str]:
        """Select all available modules for current OS"""
        os_category = self.os_info.get('category', 'unknown')
        categories = self.registry.get_categories_for_os(os_category)
        
        all_modules = set()
        for cat_id, cat_info in categories.items():
            all_modules.add(cat_id)
            if cat_info.get('subcategories'):
                all_modules.update(cat_info['subcategories'].keys())
        return all_modules
    
    def select_recommended_modules(self) -> Set[str]:
        """Select recommended modules based on OS"""
        os_category = self.os_info.get('category', 'unknown')
        
        recommended = {
            'windows': {'1.1', '9.1'},
            'linux': {'1.1', '5.2'},
            'macos': {'1.1', '4.1'},
            'unix': {'1.1', '3.1'}
        }
        
        return recommended.get(os_category, set())
    
    def get_module_selection(self, args=None) -> Set[str]:
        """Main module selection interface"""
        if args and args.modules:
            return set(args.modules.split(','))
        elif args and args.all:
            return self.select_all_modules()
        elif args and args.recommended:
            return self.select_recommended_modules()
        else:
            # Interactive selection
            self.display_categories()
            self.display_selection_menu()
            
            while True:
                try:
                    choice = input("\nSelect option (0-5): ").strip()
                    
                    if choice == '0':
                        sys.exit(0)
                    elif choice == '1':
                        return self.select_all_modules()
                    elif choice == '2':
                        cats = input("Enter categories (comma-separated): ").strip()
                        return self.select_by_category(cats.split(','))
                    elif choice == '3':
                        subcats = input("Enter subcategories (comma-separated): ").strip()
                        return set(subcats.split(','))
                    elif choice == '4':
                        return self.interactive_selection()
                    elif choice == '5':
                        return self.select_recommended_modules()
                    else:
                        print("Invalid choice. Please select 0-5.")
                except KeyboardInterrupt:
                    print("\nExiting...")
                    sys.exit(0)
    
    def select_by_category(self, categories: List[str]) -> Set[str]:
        """Select modules by category"""
        os_category = self.os_info.get('category', 'unknown')
        available_categories = self.registry.get_categories_for_os(os_category)
        
        selected = set()
        for category in categories:
            category = category.strip()
            if category in available_categories:
                selected.add(category)
                subcats = available_categories[category].get('subcategories', {})
                selected.update(subcats.keys())
        return selected
    
    def interactive_selection(self) -> Set[str]:
        """Interactive module selection"""
        os_category = self.os_info.get('category', 'unknown')
        categories = self.registry.get_categories_for_os(os_category)
        
        selected = set()
        for cat_id, cat_info in categories.items():
            print(f"\n--- {cat_id}. {cat_info['name']} ---")
            print(f"Description: {cat_info['description']}")
            
            choice = input(f"Include category {cat_id}? (y/n/s for subcategories): ").lower().strip()
            
            if choice == 'y':
                selected.add(cat_id)
                if cat_info.get('subcategories'):
                    selected.update(cat_info['subcategories'].keys())
            elif choice == 's' and cat_info.get('subcategories'):
                for sub_id, sub_name in cat_info['subcategories'].items():
                    sub_choice = input(f"  Include {sub_id} ({sub_name})? (y/n): ").lower().strip()
                    if sub_choice == 'y':
                        selected.add(sub_id)
        
        return selected


class UniversalModuleManager:
    """Manages CIS modules for all operating systems"""
    
    def __init__(self, os_info: Dict[str, str]):
        self.os_info = os_info
        self.logger = logging.getLogger(__name__)
        
        # Module mapping based on OS category and module ID
        self.module_map = {
            'windows': {
                '1.1': WindowsPasswordPolicyModule,
                '9.1': WindowsFirewallModule,
            },
            'linux': {
                '1.1': LinuxFilesystemModule,
                '5.2': LinuxSSHModule,
            },
            'macos': {
                '1.1': MacOSUpdatesModule,
                '4.1': MacOSFirewallModule,
            },
            'unix': {
                '1.1': LinuxFilesystemModule,  # Reuse Linux filesystem module
            }
        }
    
    def get_applicable_modules(self, module_ids: Set[str]) -> List[CISModule]:
        """Get modules that are applicable to the current system"""
        modules = []
        os_category = self.os_info.get('category', 'unknown')
        
        for module_id in module_ids:
            module_class = self.module_map.get(os_category, {}).get(module_id)
            
            if module_class:
                try:
                    module = module_class()
                    if module.is_applicable(self.os_info):
                        modules.append(module)
                        self.logger.info(f"Module {module_id} ({module.get_name()}) is applicable")
                    else:
                        self.logger.info(f"Module {module_id} is not applicable to this system")
                except Exception as e:
                    self.logger.error(f"Error instantiating module {module_id}: {e}")
            else:
                self.logger.warning(f"Module {module_id} not found for {os_category}")
        
        return modules


class UniversalCISScanner:
    """Universal CIS Scanner supporting all operating systems"""
    
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        self.exception_handler = ExceptionHandler(self.logger)
        self.file_handler = SafeFileHandler(self.logger, timeout)
        
        # Detect operating system
        self.os_info = OSDetector.detect_os()
        self.module_manager = UniversalModuleManager(self.os_info)
        
        self.logger.info(f"Universal CIS Scanner initialized for {self.os_info['system']} ({self.os_info['distribution']} {self.os_info['distribution_version']})")
        
        # Check privileges based on OS
        self._check_privileges()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('universal_cis_scanner.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def _check_privileges(self):
        """Check if running with appropriate privileges for the OS"""
        os_category = self.os_info.get('category', 'unknown')
        
        if os_category == 'windows' and WINDOWS_AVAILABLE:
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self.logger.warning("Scanner is not running with administrator privileges - some checks may fail")
            except:
                self.logger.warning("Unable to determine administrator status")
                
        elif os_category in ['linux', 'macos', 'unix'] and UNIX_AVAILABLE:
            if os.geteuid() != 0:
                self.logger.warning("Scanner is not running as root - some checks may fail")
    
    def run_command(self, command: str, timeout: Optional[int] = None) -> Tuple[str, str, int]:
        """Safely run shell command with timeout"""
        try:
            timeout = timeout or self.timeout
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command '{command}' timed out after {timeout} seconds")
            return "", f"Command timed out after {timeout} seconds", 1
        except Exception as e:
            self.logger.error(f"Error running command '{command}': {e}")
            return "", str(e), 1
    
    def run_scan(self, selected_modules: Set[str]) -> Dict[str, Any]:
        """Run CIS compliance scan with selected modules"""
        scan_start = datetime.now()
        
        self.logger.info(f"Starting Universal CIS compliance scan with {len(selected_modules)} modules")
        self.logger.info(f"Operating System: {self.os_info['system']} ({self.os_info['distribution']} {self.os_info['distribution_version']})")
        self.logger.info(f"Selected modules: {', '.join(sorted(selected_modules))}")
        
        # Get modules to run
        modules_to_run = self.module_manager.get_applicable_modules(selected_modules)
        
        if not modules_to_run:
            self.logger.error("No applicable modules found for the selected categories")
            return {
                'error': 'No applicable modules found',
                'scan_summary': {
                    'start_time': scan_start.isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'total_modules': 0,
                    'selected_modules': list(selected_modules),
                    'os_info': self.os_info
                }
            }
        
        scan_results = {}
        module_summaries = {}
        
        # Run each selected module
        for module in modules_to_run:
            module_start = datetime.now()
            module_id = module.get_category_id()
            
            self.logger.info(f"Running module {module_id}: {module.get_name()}")
            
            try:
                module_results = module.safe_run_checks(self)
                scan_results[module_id] = module_results
                
                # Calculate module summary
                total_checks = len([k for k in module_results.keys() if not k.endswith('_error')])
                passed_checks = len([k for k, v in module_results.items() 
                                   if isinstance(v, dict) and v.get('status') == 'PASS'])
                failed_checks = len([k for k, v in module_results.items() 
                                   if isinstance(v, dict) and v.get('status') == 'FAIL'])
                error_checks = len([k for k, v in module_results.items() 
                                  if isinstance(v, dict) and v.get('status') == 'ERROR'])
                manual_checks = len([k for k, v in module_results.items() 
                                   if isinstance(v, dict) and v.get('status') == 'MANUAL'])
                
                module_summaries[module_id] = {
                    'name': module.get_name(),
                    'description': module.get_description(),
                    'total_checks': total_checks,
                    'passed': passed_checks,
                    'failed': failed_checks,
                    'errors': error_checks,
                    'manual': manual_checks,
                    'execution_time': (datetime.now() - module_start).total_seconds()
                }
                
                self.logger.info(f"Module {module_id} completed: {passed_checks} passed, {failed_checks} failed, {error_checks} errors, {manual_checks} manual")
                
            except Exception as e:
                error_result = self.exception_handler.handle_exception(e, f"Module {module_id}")
                scan_results[module_id] = {'critical_error': error_result}
                module_summaries[module_id] = {
                    'name': module.get_name(),
                    'description': module.get_description(),
                    'total_checks': 0,
                    'passed': 0,
                    'failed': 0,
                    'errors': 1,
                    'manual': 0,
                    'execution_time': (datetime.now() - module_start).total_seconds(),
                    'critical_error': True
                }
                self.logger.error(f"Critical error in module {module_id}: {e}")
        
        scan_end = datetime.now()
        execution_time = (scan_end - scan_start).total_seconds()
        
        # Calculate overall summary
        total_checks = sum(summary['total_checks'] for summary in module_summaries.values())
        total_passed = sum(summary['passed'] for summary in module_summaries.values())
        total_failed = sum(summary['failed'] for summary in module_summaries.values())
        total_errors = sum(summary['errors'] for summary in module_summaries.values())
        total_manual = sum(summary['manual'] for summary in module_summaries.values())
        
        # Calculate compliance percentage (excluding manual checks)
        automated_checks = total_checks - total_manual
        compliance_percentage = (total_passed / automated_checks * 100) if automated_checks > 0 else 0
        
        scan_summary = {
            'start_time': scan_start.isoformat(),
            'end_time': scan_end.isoformat(),
            'execution_time_seconds': execution_time,
            'os_info': self.os_info,
            'selected_modules': list(selected_modules),
            'executed_modules': len(modules_to_run),
            'total_checks': total_checks,
            'passed_checks': total_passed,
            'failed_checks': total_failed,
            'error_checks': total_errors,
            'manual_checks': total_manual,
            'compliance_percentage': round(compliance_percentage, 2),
            'module_summaries': module_summaries,
            'error_summary': self.exception_handler.error_counts
        }
        
        self.logger.info(f"Scan completed in {execution_time:.2f} seconds")
        self.logger.info(f"Overall compliance: {compliance_percentage:.2f}% ({total_passed}/{automated_checks} automated checks)")
        
        return {
            'scan_summary': scan_summary,
            'detailed_results': scan_results
        }
    
    def generate_report(self, scan_results: Dict[str, Any], output_format: str = 'json') -> str:
        """Generate scan report in various formats"""
        if output_format.lower() == 'json':
            return json.dumps(scan_results, indent=2, sort_keys=True)
        elif output_format.lower() == 'txt':
            return self._generate_text_report(scan_results)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_text_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate plain text report"""
        summary = scan_results.get('scan_summary', {})
        os_info = summary.get('os_info', {})
        
        report = f"""
UNIVERSAL CIS COMPLIANCE SCAN REPORT
{'=' * 60}

System Information:
  Operating System: {os_info.get('system', 'Unknown').title()} ({os_info.get('distribution', 'Unknown')} {os_info.get('distribution_version', '')})
  Architecture: {os_info.get('machine', 'Unknown')}
  Hostname: {socket.gethostname()}
  Scan Date: {summary.get('start_time', 'Unknown')}
  Execution Time: {summary.get('execution_time_seconds', 0):.2f} seconds

Overall Summary:
  Compliance Percentage: {summary.get('compliance_percentage', 0):.2f}%
  Total Checks: {summary.get('total_checks', 0)}
  Passed: {summary.get('passed_checks', 0)}
  Failed: {summary.get('failed_checks', 0)}
  Errors: {summary.get('error_checks', 0)}
  Manual Review Required: {summary.get('manual_checks', 0)}

Module Results:
{'-' * 60}
"""
        
        detailed_results = scan_results.get('detailed_results', {})
        for module_id, module_results in detailed_results.items():
            module_summary = summary.get('module_summaries', {}).get(module_id, {})
            
            report += f"""
{module_id}: {module_summary.get('name', 'Unknown Module')}
Description: {module_summary.get('description', 'N/A')}
Checks: {module_summary.get('total_checks', 0)} total, {module_summary.get('passed', 0)} passed, {module_summary.get('failed', 0)} failed, {module_summary.get('errors', 0)} errors, {module_summary.get('manual', 0)} manual
Execution Time: {module_summary.get('execution_time', 0):.2f} seconds

"""
            
            for check_id, check_result in module_results.items():
                if isinstance(check_result, dict) and 'status' in check_result:
                    report += f"  {check_id}: [{check_result['status']}] {check_result.get('reason', 'N/A')}\n"
            
            report += "\n"
        
        return report


def main():
    """Main function with argument parsing and execution"""
    
    # Print ASCII banner first
    print_ascii_banner()
    
    # Detect OS early for help text
    os_info = OSDetector.detect_os()
    os_category = os_info.get('category', 'unknown')
    
    parser = argparse.ArgumentParser(
        description='Universal CIS Benchmark Compliance Scanner - All Operating Systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s --interactive                    # Interactive module selection
  %(prog)s --all                           # Run all available modules
  %(prog)s --recommended                   # Run recommended modules only
  %(prog)s --modules "1.1,9.1"            # Run specific modules
  %(prog)s --all --output report.json     # Run all modules and save JSON report
  %(prog)s --all --format txt --output report.txt  # Generate text report

Detected Operating System: {os_info.get('system', 'Unknown').title()} ({os_info.get('distribution', 'Unknown')} {os_info.get('distribution_version', '')})
Supported OS Categories: Windows, Linux, macOS, Unix

Note: Administrator/root privileges are recommended for complete security assessment.
        """
    )
    
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Use interactive module selection')
    parser.add_argument('--all', '-a', action='store_true',
                       help='Run all available modules for detected OS')
    parser.add_argument('--recommended', '-r', action='store_true',
                       help='Run recommended modules for quick assessment')
    parser.add_argument('--modules', '-m', type=str,
                       help='Comma-separated list of module IDs to run')
    parser.add_argument('--list', '-l', action='store_true',
                       help='List all available modules for detected OS and exit')
    parser.add_argument('--output', '-o', type=str,
                       help='Output file path for scan results')
    parser.add_argument('--format', '-f', choices=['json', 'txt'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--timeout', '-t', type=int, default=60,
                       help='Command timeout in seconds (default: 60)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize scanner
        scanner = UniversalCISScanner(timeout=args.timeout)
        module_selector = ModuleSelector(scanner.os_info)
        
        # Display OS information
        print(f"🖥️  Detected Operating System: {scanner.os_info['system'].title()} ({scanner.os_info['distribution']} {scanner.os_info['distribution_version']})")
        print(f"🏗️  Architecture: {scanner.os_info['machine']}")
        print(f"🏠  Hostname: {socket.gethostname()}")
        
        # List modules if requested
        if args.list:
            print(f"\n🔍 Available CIS Benchmark Modules for {os_category.upper()}:")
            print("=" * 70)
            
            categories = UniversalCISBenchmarkRegistry.get_categories_for_os(os_category)
            if not categories:
                print(f"No CIS benchmark modules available for {os_category}")
                return
                
            for cat_id, cat_info in categories.items():
                print(f"\n📂 {cat_id}. {cat_info['name']}")
                print(f"   Description: {cat_info['description']}")
                
                if cat_info.get('subcategories'):
                    for sub_id, sub_name in cat_info['subcategories'].items():
                        # Check if module is implemented
                        module_class = scanner.module_manager.module_map.get(os_category, {}).get(sub_id)
                        status = "✅" if module_class else "🚧"
                        print(f"   {status} {sub_id}: {sub_name}")
            
            print(f"\n✅ = Implemented and available")
            print(f"🚧 = Planned for future implementation")
            return
        
        # Get module selection
        selected_modules = module_selector.get_module_selection(args)
        
        if not selected_modules:
            print("No modules selected. Exiting.")
            return
        
        print(f"\n🎯 Selected {len(selected_modules)} modules: {', '.join(sorted(selected_modules))}")
        
        # Run the scan
        print(f"\n🚀 Running Universal CIS compliance scan...")
        
        scan_results = scanner.run_scan(selected_modules)
        
        # Generate and output report
        report = scanner.generate_report(scan_results, args.format)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"📄 Report saved to {args.output}")
        else:
            print(report)
        
        # Print summary to console
        summary = scan_results.get('scan_summary', {})
        print(f"\n{'=' * 70}")
        print("📊 UNIVERSAL CIS SCAN SUMMARY")
        print(f"{'=' * 70}")
        print(f"Operating System: {summary.get('os_info', {}).get('system', 'Unknown').title()} ({summary.get('os_info', {}).get('distribution', 'Unknown')} {summary.get('os_info', {}).get('distribution_version', '')})")
        print(f"Overall Compliance: {summary.get('compliance_percentage', 0):.2f}%")
        print(f"Total Checks: {summary.get('total_checks', 0)}")
        print(f"Passed: {summary.get('passed_checks', 0)}")
        print(f"Failed: {summary.get('failed_checks', 0)}")
        print(f"Errors: {summary.get('error_checks', 0)}")
        print(f"Manual Review Required: {summary.get('manual_checks', 0)}")
        print(f"Execution Time: {summary.get('execution_time_seconds', 0):.2f} seconds")
        
        # Exit with appropriate code based on compliance
        compliance = summary.get('compliance_percentage', 0)
        
        if compliance >= 90:
            sys.exit(0)  # Excellent compliance
        elif compliance >= 80:
            sys.exit(1)  # Good compliance
        elif compliance >= 60:
            sys.exit(2)  # Moderate compliance
        else:
            sys.exit(3)  # Poor compliance
        
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
