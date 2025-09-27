#!/usr/bin/env python3
"""
Basic example of using the Extension Security Scanner programmatically.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path to import the scanner modules
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from extension_scanner import ExtensionScanner
from security_analyzer import SecurityAnalyzer
from policy_engine import PolicyEngine
from report_generator import ReportGenerator


def main():
    # Initialize components
    scanner = ExtensionScanner()
    analyzer = SecurityAnalyzer()
    policy_engine = PolicyEngine()
    reporter = ReportGenerator()

    # Define scan locations
    scan_locations = {
        'vscode': [
            '~/.vscode/extensions',
            '~/.vscode-insiders/extensions'
        ],
        'cursor': [
            '~/.cursor/extensions'
        ]
    }

    # Define analysis configuration
    analysis_config = {
        'check_permissions': True,
        'check_dependencies': True,
        'check_obfuscation': True,
        'check_network_calls': True,
        'check_file_access': True,
        'check_code_injection': True
    }

    print("[*] Starting extension security scan...")

    # Discover extensions
    extensions = scanner.discover_extensions('all', scan_locations)
    print(f"[*] Found {len(extensions)} extensions")

    # Analyze each extension
    high_risk_extensions = []
    blocked_extensions = []

    for ext in extensions:
        print(f"\n[*] Analyzing: {ext['name']} (v{ext.get('version', 'unknown')})")

        # Perform security analysis
        analysis_result = analyzer.analyze_extension(ext, analysis_config)

        # Evaluate against policies
        policy_result = policy_engine.evaluate(ext, analysis_result)

        # Print summary
        print(f"    Risk Score: {analysis_result['risk_score']:.1f}/10")
        print(f"    Risk Level: {analysis_result['risk_level']}")
        print(f"    Decision: {policy_result['decision']}")

        if policy_result['violations']:
            print("    Violations:")
            for violation in policy_result['violations'][:3]:  # Show first 3 violations
                print(f"      - {violation}")

        if policy_result['warnings']:
            print("    Warnings:")
            for warning in policy_result['warnings'][:3]:  # Show first 3 warnings
                print(f"      - {warning}")

        # Track high-risk and blocked extensions
        if analysis_result['risk_score'] >= 7:
            high_risk_extensions.append(ext['name'])

        if policy_result['decision'] == 'blocked':
            blocked_extensions.append(ext['name'])

    # Print final summary
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Total Extensions Scanned: {len(extensions)}")
    print(f"High Risk Extensions: {len(high_risk_extensions)}")
    print(f"Blocked Extensions: {len(blocked_extensions)}")

    if high_risk_extensions:
        print("\nHigh Risk Extensions:")
        for ext_name in high_risk_extensions:
            print(f"  - {ext_name}")

    if blocked_extensions:
        print("\nBlocked Extensions:")
        for ext_name in blocked_extensions:
            print(f"  - {ext_name}")

    # Generate report
    print("\n[*] Generating detailed report...")
    results = {
        'scan_date': str(Path(__file__).stat().st_mtime),
        'total_extensions': len(extensions),
        'extensions': [],
        'summary': {
            'allowed': len(extensions) - len(blocked_extensions),
            'blocked': len(blocked_extensions),
            'warnings': 0,
            'high_risk': len(high_risk_extensions),
            'medium_risk': 0,
            'low_risk': 0
        }
    }

    # Save JSON report
    report_path = Path('extension_scan_report.json')
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] Report saved to: {report_path}")

    # Return exit code based on findings
    if blocked_extensions:
        print("\n[!] Security violations found. Review blocked extensions.")
        return 1
    else:
        print("\n[+] No critical security issues found.")
        return 0


if __name__ == "__main__":
    sys.exit(main())