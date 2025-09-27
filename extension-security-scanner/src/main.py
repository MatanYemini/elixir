#!/usr/bin/env python3

import argparse
import sys
import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

from extension_scanner import ExtensionScanner
from security_analyzer import SecurityAnalyzer
from policy_engine import PolicyEngine
from report_generator import ReportGenerator


class ExtensionSecurityScanner:
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.scanner = ExtensionScanner()
        self.analyzer = SecurityAnalyzer()
        self.policy_engine = PolicyEngine(self.config.get('policies', {}))
        self.reporter = ReportGenerator()
        self._load_default_allowlist()

    def _load_config(self, config_path: str) -> Dict:
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        return self._default_config()

    def _load_default_allowlist(self):
        allowlist_path = Path(__file__).parent.parent / 'config' / 'default_allowlist.json'
        if allowlist_path.exists():
            try:
                with open(allowlist_path, 'r') as f:
                    allowlist_data = json.load(f)

                for item in allowlist_data.get('allowlist', []):
                    self.policy_engine.allowlist.append(item)

                for publisher in allowlist_data.get('allowed_publishers', []):
                    if publisher.get('name') and publisher['name'] not in self.policy_engine.policies.get('allowed_publishers', []):
                        self.policy_engine.policies.setdefault('allowed_publishers', []).append(publisher['name'])
            except Exception as e:
                print(f"[!] Could not load default allowlist: {e}")

    def _default_config(self) -> Dict:
        return {
            'scan_locations': {
                'vscode': [
                    '~/.vscode/extensions',
                    '~/.vscode-insiders/extensions',
                    '~/.vscode-oss/extensions'
                ],
                'cursor': [
                    '~/.cursor/extensions',
                    '~/Library/Application Support/Cursor/User/extensions'
                ]
            },
            'policies': {
                'max_risk_score': 7,
                'required_publisher_verification': False,
                'blocked_permissions': ['filesystem.write', 'network.all'],
                'allowed_publishers': [],
                'blocked_publishers': [],
                'max_days_since_update': 365,
                'min_install_count': 100
            },
            'analysis': {
                'check_permissions': True,
                'check_dependencies': True,
                'check_obfuscation': True,
                'check_network_calls': True,
                'check_file_access': True,
                'check_code_injection': True
            }
        }

    def scan(self, target: str = 'all', output_format: str = 'json') -> Dict[str, Any]:
        print(f"[*] Starting extension security scan at {datetime.now()}")

        extensions = self.scanner.discover_extensions(
            target,
            self.config['scan_locations']
        )

        print(f"[*] Found {len(extensions)} extensions to analyze")

        results = {
            'scan_date': datetime.now().isoformat(),
            'total_extensions': len(extensions),
            'extensions': [],
            'summary': {
                'allowed': 0,
                'blocked': 0,
                'warnings': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0
            }
        }

        for ext in extensions:
            print(f"[*] Analyzing: {ext['name']} v{ext.get('version', 'unknown')}")

            analysis_result = self.analyzer.analyze_extension(ext, self.config['analysis'])

            policy_result = self.policy_engine.evaluate(ext, analysis_result)

            extension_result = {
                **ext,
                'analysis': analysis_result,
                'policy_evaluation': policy_result,
                'status': policy_result['decision'],
                'risk_score': analysis_result['risk_score']
            }

            results['extensions'].append(extension_result)

            results['summary'][policy_result['decision']] += 1

            if analysis_result['risk_score'] >= 8:
                results['summary']['high_risk'] += 1
            elif analysis_result['risk_score'] >= 5:
                results['summary']['medium_risk'] += 1
            else:
                results['summary']['low_risk'] += 1

        return results

    def generate_report(self, results: Dict, output_format: str, output_path: str = None):
        report = self.reporter.generate(results, output_format)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to: {output_path}")
        else:
            print(report)


def main():
    parser = argparse.ArgumentParser(
        description='Security scanner for VS Code and Cursor extensions'
    )
    parser.add_argument(
        '--target',
        choices=['vscode', 'cursor', 'all'],
        default='all',
        help='Target editor to scan'
    )
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--output',
        help='Output file path'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'html', 'csv', 'markdown'],
        default='json',
        help='Output format'
    )
    parser.add_argument(
        '--policy',
        help='Path to custom policy file'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    try:
        scanner = ExtensionSecurityScanner(args.config)

        if args.policy:
            scanner.policy_engine.load_custom_policy(args.policy)

        results = scanner.scan(args.target, args.format)

        scanner.generate_report(results, args.format, args.output)

        blocked_count = results['summary']['blocked']
        if blocked_count > 0:
            print(f"\n[!] Found {blocked_count} extensions that violate security policies")
            sys.exit(1)
        else:
            print("\n[+] All extensions passed security validation")

    except Exception as e:
        print(f"[!] Error during scan: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()