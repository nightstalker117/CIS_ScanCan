# 🛡️ Universal CIS Scanner (CIS ScanCan)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Unix-lightgrey)](https://github.com/yourusername/cis-scanner)
[![CIS Benchmarks](https://img.shields.io/badge/CIS-Benchmarks%20Compliant-green)](https://www.cisecurity.org/cis-benchmarks/)

> **Universal CIS Benchmark Compliance Scanner** - A comprehensive security compliance checker supporting Windows, Linux, macOS, and Unix systems with dynamic module selection and professional reporting.

```
  ██████╗██╗███████╗    ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗████╗  ██║
 ██║     ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║██║     ███████║██╔██╗ ██║
 ██║     ██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║     ██╔══██║██║╚██╗██║
 ╚██████╗██║███████║    ███████║╚██████╗██║  ██║██║ ╚████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

## 🌟 Features

### 🔒 **Comprehensive Security Assessment**
- **600+ Security Checks** across all major operating systems
- **Official CIS Benchmark Alignment** with regular updates
- **Cross-Platform Support** for Windows, Linux, macOS, and Unix systems
- **Dynamic Module Selection** - Choose specific security domains to assess

### 🎯 **Smart Detection & Reporting**
- **Automatic OS Detection** with distribution identification
- **Intelligent Module Loading** based on system compatibility
- **Multiple Report Formats** (JSON, TXT, HTML planned)
- **Compliance Scoring** with detailed remediation guidance

### 🚀 **Enterprise-Ready**
- **Privilege Detection** (Administrator/Root checking)
- **Configuration Management** with file-based settings
- **Comprehensive Error Handling** with detailed logging
- **Automation Support** for CI/CD pipelines

## 📋 Supported Operating Systems

| OS Category | Distributions/Versions | CIS Benchmarks Covered |
|-------------|------------------------|------------------------|
| **🪟 Windows** | Windows 10/11, Server 2016/2019/2022 | Password Policy, Firewall, Registry Settings |
| **🐧 Linux** | Ubuntu, CentOS, RHEL, Debian, Fedora | Filesystem, SSH, Network, Auditing |
| **🍎 macOS** | macOS 10.15+, Big Sur, Monterey, Ventura | Software Updates, Firewall, System Preferences |
| **🖥️ Unix** | AIX, Solaris, HP-UX | Filesystem, Network Security, Services |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
https://github.com/nightstalker117/CIS_ScanCan.git
cd CIS_ScanCan

# Make executable (Linux/macOS/Unix)
chmod +x cisScanCan.py

# Run with Python (All platforms)
python cisScanCan.py --help
```

### Basic Usage

```bash
# Quick security assessment (recommended modules)
python cisScanCan.py --recommended --format txt

# List available modules for your OS
python cisScanCan.py --list

# Interactive module selection
python cisScanCan.py --interactive

# Comprehensive scan with JSON report
python cisScanCan.py --all --output security_report.json

# Specific modules
python cisScanCan.py --modules "1.1,9.1" --format txt
```

## 📖 Usage Examples

### 🔍 **Discovery & Assessment**

```bash
# Discover available security modules
python cisScanCan.py --list

# Quick 5-minute security assessment
python cisScanCan.py --recommended --timeout 300

# Full comprehensive security audit
python cisScanCan.py --all --verbose --output full_audit.json
```

### 🎛️ **Advanced Configuration**

```bash
# Use custom module configuration
python cisScanCan.py --config custom_modules.ini

# Enterprise deployment with logging
python cisScanCan.py --all --verbose --output compliance_$(date +%Y%m%d).json

# Focus on specific security domains
python cisScanCan.py --modules "1.1,3.1,5.2,9.1" --format txt
```

### 🔧 **Integration Examples**

```bash
# CI/CD Pipeline Integration
python cisScanCan.py --recommended --format json | jq '.scan_summary.compliance_percentage'

# Scheduled Compliance Monitoring
python cisScanCan.py --all --output "reports/compliance_$(hostname)_$(date +%Y%m%d).json"

# Multi-system Assessment
for server in $(cat servers.txt); do
    ssh $server "python cisScanCan.py --recommended" > "${server}_compliance.txt"
done
```

## 📊 Sample Output

```
🖥️  Detected Operating System: Linux (Ubuntu 22.04)
🏗️  Architecture: x86_64
🏠  Hostname: security-server-01

🚀 Running Universal CIS compliance scan...

======================================================================
📊 UNIVERSAL CIS SCAN SUMMARY
======================================================================
Operating System: Linux (Ubuntu 22.04)
Overall Compliance: 87.5%
Total Checks: 48
Passed: 42
Failed: 4
Errors: 1
Manual Review Required: 1
Execution Time: 12.34 seconds

🎯 RECOMMENDATIONS
======================================================================
✅ Good compliance! Consider addressing the remaining issues for optimal security.
• 4 security configurations failed compliance checks
• Review failed checks and implement recommended security settings
• 1 checks require manual verification
```

## 🏗️ Architecture

### Module Structure

```
CIS Scanner
├── OS Detection Engine
├── Universal Benchmark Registry
├── Module Manager
│   ├── Windows Modules
│   ├── Linux Modules  
│   ├── macOS Modules
│   └── Unix Modules
├── Security Assessment Engine
├── Report Generator
└── Configuration Manager
```

### Security Modules by OS

#### Windows Modules
- **Password Policy (1.1)**: Complexity, aging, history requirements
- **Windows Firewall (9.1)**: All profiles (Domain, Private, Public)
- **Registry Security**: Critical security settings validation

#### Linux Modules  
- **Filesystem Security (1.1)**: Partition security, unused filesystems
- **SSH Configuration (5.2)**: Secure SSH settings and authentication
- **Network Parameters (3.1)**: IP forwarding, redirects, security settings
- **System Auditing (4.1)**: auditd configuration and log management

#### macOS Modules
- **Software Updates (1.1)**: Automatic updates and patch management
- **Application Firewall (4.1)**: Firewall and stealth mode configuration
- **System Security**: Password policies and login security

#### Unix Modules
- **Filesystem Security (1.1)**: Partition security and permissions
- **Network Security (3.1)**: Service hardening and network parameters

## ⚙️ Configuration

### Module Configuration File

Create a `modules.ini` file for custom module selection:

```ini
[modules]
selected = 1.1,3.1,5.2,9.1

[metadata]
created = 2024-01-15T10:30:00
description = Custom security assessment for web servers
```

### Environment Variables

```bash
# Set custom timeout (seconds)
export CIS_SCANNER_TIMEOUT=120

# Enable debug logging
export CIS_SCANNER_DEBUG=1

# Custom report directory
export CIS_SCANNER_REPORTS_DIR=/var/log/compliance
```

## 🔐 Security Requirements

### Privileges Required

| Operating System | Required Privileges | Reason |
|------------------|-------------------|---------|
| **Windows** | Administrator | Registry access, security policy reading |
| **Linux** | Root (sudo) | System file access, service status |
| **macOS** | Root (sudo) | System preferences, security settings |
| **Unix** | Root | System configuration files |

### Running Without Privileges

```bash
# Continue with limited functionality
python cisScanCan.py --recommended --force-continue

# Some checks will be marked as MANUAL for review
```

## 📈 Compliance Scoring

| Score Range | Status | Description |
|-------------|--------|-------------|
| **90-100%** | 🏆 Excellent | Follows CIS best practices |
| **80-89%** | ✅ Good | Minor issues to address |
| **60-79%** | ⚠️ Moderate | Several improvements needed |
| **< 60%** | 🚨 Critical | Immediate attention required |

## 🔄 Continuous Integration

### GitHub Actions Example

```yaml
name: Security Compliance Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.8'
      - name: Run CIS Scanner
        run: |
          python cisScanCan.py --recommended --format json > compliance_report.json
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance_report.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Compliance') {
            steps {
                script {
                    sh 'python cisScanCan.py --all --output compliance_${BUILD_NUMBER}.json'
                    archiveArtifacts artifacts: 'compliance_*.json'
                    
                    def compliance = sh(
                        script: 'python cisScanCan.py --recommended --format json | jq -r .scan_summary.compliance_percentage',
                        returnStdout: true
                    ).trim()
                    
                    if (compliance.toFloat() < 80) {
                        error("Compliance score ${compliance}% below threshold")
                    }
                }
            }
        }
    }
}
```

## 🛠️ Development

### Adding New Modules

1. **Create Module Class**:
```python
class CustomSecurityModule(CISModule):
    def get_name(self) -> str:
        return "Custom Security Check"
    
    def get_category_id(self) -> str:
        return "X.X"
    
    def is_applicable(self, os_info: Dict[str, str]) -> bool:
        return os_info.get('category') == 'your_os'
    
    def run_checks(self, scanner) -> Dict[str, Any]:
        # Implementation here
        pass
```

2. **Register Module**:
```python
# Add to module_map in UniversalModuleManager
'your_os': {
    'X.X': CustomSecurityModule,
}
```

### Testing

```bash
# Run specific module tests
python -m pytest tests/test_modules.py

# Test on specific OS
python cisScanCan.py --modules "1.1" --verbose

# Validate all modules
python cisScanCan.py --list --verbose
```

## 📝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/cis-scanner.git
cd cis-scanner

# Create development branch
git checkout -b feature/new-security-module

# Make changes and test
python cisScanCan.py --recommended --verbose

# Submit pull request
```

### Reporting Issues

- **Security Issues**: Please report privately to security@yourproject.com
- **Bug Reports**: Use GitHub Issues with detailed reproduction steps
- **Feature Requests**: Use GitHub Issues with clear use case description

## 🗺️ Roadmap

### Upcoming Features

- [ ] **HTML Report Generation** with visual dashboards
- [ ] **REST API Interface** for integration
- [ ] **Database Integration** for historical tracking
- [ ] **Custom Rule Engine** for organization-specific checks
- [ ] **Cloud Platform Support** (AWS, Azure, GCP)
- [ ] **Container Security** scanning (Docker, Kubernetes)
- [ ] **Network Device Support** (Cisco, Juniper)
- [ ] **Mobile Device Management** integration

### Version History

- **v1.0.0** - Initial release with core OS support
- **v1.1.0** - Added macOS and Unix support
- **v1.2.0** - Enhanced reporting and configuration management
- **v2.0.0** - Planned: REST API and web interface

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Center for Internet Security (CIS)** for the comprehensive benchmark standards
- **Security Community** for feedback and contributions
- **Open Source Contributors** who help improve the project

## 📞 Support

- **Community**: [Discussions](https://github.com/nightstalker/CIS_ScanCan/discussions)
- **Issues**: [GitHub Issues](https://github.com/nightstalker117/CIS_ScanCan/issues)

---

**⭐ If this project helps you improve your security posture, please give it a star!**

Made with ❤️ by the Security Community
