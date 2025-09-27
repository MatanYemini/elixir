# Extension Security Scanner

A comprehensive Python-based security tool for scanning and analyzing VS Code and Cursor extensions, providing full visibility and control over 400,000+ apps and browser extensions through AI-powered security assessment algorithms.

## Overview

This tool helps organizations and developers maintain security control over their development environments by:
- Discovering and analyzing all installed VS Code and Cursor extensions
- Performing deep security analysis using AI-driven algorithms
- Enforcing custom security policies
- Generating detailed security reports
- Managing allowlists and blocklists for extension control

## Security Analysis Logic

### 1. Extension Discovery Phase

The scanner employs a multi-stage discovery process:

```
Discovery Pipeline:
├── Editor Detection (VS Code, Cursor)
├── Path Resolution
│   ├── Default installation paths
│   ├── User-specific extension directories
│   └── Custom installation locations
├── Extension Enumeration
│   ├── Parse package.json manifests
│   ├── Extract metadata
│   └── Build extension inventory
└── File System Analysis
    ├── Source code enumeration
    ├── Resource file detection
    └── Size calculation
```

**Locations Scanned:**
- VS Code: `~/.vscode/extensions`, `~/.vscode-insiders/extensions`
- Cursor: `~/.cursor/extensions`, `~/Library/Application Support/Cursor/User/extensions`

### 2. Security Analysis Engine

The tool implements a comprehensive security analysis framework:

#### Static Code Analysis
- **Pattern Matching**: Detects dangerous code patterns using regex-based analysis
- **Obfuscation Detection**: Identifies minified, obfuscated, or encoded code
- **API Usage Analysis**: Tracks usage of dangerous VS Code APIs
- **Dependency Analysis**: Examines npm dependencies for known risks

#### Risk Scoring Algorithm

```python
Risk Score = Σ(Finding_Weight × Finding_Count)

Weights:
- Code Injection Risks: 4.0
- Obfuscation: 3.0
- Suspicious Patterns: 3.0
- Network Calls: 2.5
- Permissions: 2.0
- File Operations: 2.0
- Outdated Extensions: 1.5
- Unverified Publisher: 1.0
```

#### Security Checks Performed

1. **Permission Analysis**
   - Activation events (especially `*` activation)
   - Command registration
   - Menu contributions
   - Debug capabilities
   - Terminal access

2. **Code Quality Checks**
   - Eval/exec usage detection
   - Dynamic code execution
   - Child process spawning
   - Filesystem access patterns
   - Network communication

3. **Obfuscation Detection**
   - Hex encoding patterns
   - Base64 operations
   - Character code construction
   - Minification analysis
   - Variable name entropy

4. **Network Analysis**
   - External URL detection
   - API endpoint discovery
   - Suspicious domain checking
   - WebSocket usage

5. **Sensitive Data Access**
   - SSH key path detection
   - Environment variable access
   - Credential file patterns
   - Browser storage access

### 3. Policy Engine

The policy engine implements a rule-based decision system:

```
Policy Evaluation Flow:
├── Blocklist Check (immediate rejection)
├── Allowlist Check (immediate approval)
├── Risk Score Evaluation
├── Permission Validation
├── Publisher Verification
├── Custom Rule Application
└── Final Decision (allowed/blocked/warning)
```

**Default Policies:**
- Maximum risk score: 7.0
- Blocked permissions: configurable
- Required publisher verification: optional
- Minimum install count: configurable
- Maximum days since update: 365

### 4. AI-Powered Assessment

The tool uses intelligent algorithms to:

1. **Pattern Recognition**: Identifies malicious code patterns through heuristic analysis
2. **Anomaly Detection**: Flags extensions with unusual behavior patterns
3. **Risk Correlation**: Combines multiple risk factors for accurate assessment
4. **Behavioral Analysis**: Examines extension activation and runtime behavior

## Installation

```bash
# Clone the repository
git clone <repository>
cd extension-security-scanner

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python src/main.py
```

## Usage

### Basic Scan

```bash
# Scan all extensions
python src/main.py

# Scan only VS Code extensions
python src/main.py --target vscode

# Scan only Cursor extensions
python src/main.py --target cursor
```

### Advanced Usage

```bash
# Use custom configuration
python src/main.py --config config/custom_policy.json

# Generate HTML report
python src/main.py --format html --output report.html

# Apply custom policy file
python src/main.py --policy config/strict_policy.json

# Verbose output
python src/main.py --verbose
```

### Configuration

Create a custom configuration file:

```json
{
  "scan_locations": {
    "vscode": ["~/.vscode/extensions"],
    "cursor": ["~/.cursor/extensions"]
  },
  "policies": {
    "max_risk_score": 5,
    "blocked_permissions": ["filesystem.write", "network.all"],
    "allowed_publishers": ["microsoft", "github"],
    "blocked_publishers": [],
    "min_install_count": 1000,
    "allow_obfuscated_code": false
  },
  "analysis": {
    "check_permissions": true,
    "check_obfuscation": true,
    "check_network_calls": true,
    "check_code_injection": true
  }
}
```

### Custom Security Policies

Define custom rules in JSON:

```json
{
  "policies": {
    "max_risk_score": 3,
    "required_publisher_verification": true
  },
  "allowlist": [
    {"publisher": "microsoft"},
    {"id": "esbenp.prettier-vscode"}
  ],
  "blocklist": [
    {"pattern": ".*-china$"},
    {"publisher": "untrusted-publisher"}
  ],
  "custom_rules": [
    {
      "type": "threshold",
      "field": "risk_score",
      "operator": "gt",
      "value": 5,
      "action": "block",
      "message": "Risk score too high"
    }
  ]
}
```

## Output Formats

The scanner supports multiple output formats:

1. **JSON**: Machine-readable format with complete details
2. **HTML**: Interactive web report with visualizations
3. **CSV**: Spreadsheet-compatible format for analysis
4. **Markdown**: Documentation-friendly format

## Security Features

### Real-time Threat Detection

- **Code Injection**: Detects eval(), exec(), Function() constructor usage
- **Command Execution**: Identifies child_process and shell command execution
- **Network Communication**: Monitors external API calls and data exfiltration
- **File System Access**: Tracks file read/write operations and sensitive path access

### Extension Fingerprinting

Each extension is fingerprinted based on:
- Code patterns and signatures
- API usage profile
- Network behavior
- File access patterns
- Permission requirements

### Risk Categorization

Extensions are classified into risk levels:
- **Critical** (8-10): Immediate security threat
- **High** (6-8): Significant security concerns
- **Medium** (4-6): Moderate risk, review recommended
- **Low** (2-4): Minor concerns
- **Minimal** (0-2): Safe for use

## API Reference

### Scanner Class

```python
from extension_scanner import ExtensionScanner

scanner = ExtensionScanner()
extensions = scanner.discover_extensions('all', scan_locations)
```

### Security Analyzer

```python
from security_analyzer import SecurityAnalyzer

analyzer = SecurityAnalyzer()
results = analyzer.analyze_extension(extension_data, config)
```

### Policy Engine

```python
from policy_engine import PolicyEngine

engine = PolicyEngine(policies)
evaluation = engine.evaluate(extension, analysis_results)
```

## Best Practices

1. **Regular Scanning**: Run scans weekly or after installing new extensions
2. **Policy Updates**: Keep security policies updated with latest threats
3. **Allowlist Management**: Maintain approved extension lists
4. **Report Review**: Review all high-risk findings promptly
5. **Extension Updates**: Keep extensions updated to latest versions

## Security Recommendations

1. **Principle of Least Privilege**: Only install necessary extensions
2. **Publisher Verification**: Prefer verified publishers
3. **Source Code Review**: Check if source code is available
4. **Permission Audit**: Review requested permissions
5. **Network Monitoring**: Monitor extensions making network calls

## Architecture

```
┌─────────────────────────────────────┐
│         Main Controller             │
└────────────┬────────────────────────┘
             │
    ┌────────┴────────┬──────────────┬──────────────┐
    ▼                 ▼              ▼              ▼
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│Extension │   │Security  │   │Policy    │   │Report    │
│Scanner   │   │Analyzer  │   │Engine    │   │Generator │
└──────────┘   └──────────┘   └──────────┘   └──────────┘
    │              │              │              │
    ▼              ▼              ▼              ▼
[Discovery]   [Analysis]     [Evaluation]   [Reporting]
```

## Extension Threat Model

### Attack Vectors

1. **Data Exfiltration**: Extensions stealing code, credentials, or sensitive data
2. **Code Injection**: Malicious code execution in the development environment
3. **Supply Chain**: Compromised dependencies or updates
4. **Privilege Escalation**: Extensions gaining unauthorized system access
5. **Persistence**: Extensions maintaining backdoor access

### Defense Mechanisms

1. **Static Analysis**: Pre-execution code analysis
2. **Behavioral Monitoring**: Runtime activity tracking
3. **Sandboxing**: Isolated execution environments
4. **Policy Enforcement**: Strict security rules
5. **Continuous Monitoring**: Ongoing security assessment

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is for security assessment purposes only. Always follow your organization's security policies and procedures when evaluating extensions.

## Support

For issues, questions, or feature requests, please open an issue on the repository.