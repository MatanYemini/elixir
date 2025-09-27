#!/usr/bin/env python3

import re
import json
import ast
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import subprocess


class SecurityAnalyzer:
    def __init__(self):
        self.risk_weights = {
            'permissions': 0.5,
            'obfuscation': 2.5,
            'network_calls': 1.0,
            'file_operations': 0.3,
            'code_injection': 3.5,
            'suspicious_patterns': 2.0,
            'outdated': 0.5,
            'unverified_publisher': 0.2,
            'minimal_documentation': 0.1
        }

        self.suspicious_patterns = [
            (r'eval\s*\([^)]*(atob|base64|decode|unescape)', 'eval_with_decode', 4.0),
            (r'eval\s*\(\s*[\'"`]', 'eval_string', 2.0),
            (r'new\s+Function\s*\([\'"`]return', 'function_constructor_return', 3.0),
            (r'child_process.*exec[^a-zA-Z].*\$\{|child_process.*exec[^a-zA-Z].*\+', 'command_injection', 4.0),
            (r'require\s*\(\s*[\'"`]child_process[\'"`]\s*\).*exec', 'child_process_exec', 2.0),
            (r'\.execSync\s*\([^)]*\$\{|\.execSync\s*\([^)]*\+', 'dynamic_command', 3.5),
            (r'document\.cookie.*fetch\s*\(|document\.cookie.*XMLHttpRequest', 'cookie_exfiltration', 4.5),
            (r'process\.env.*\.(PRIVATE|SECRET|TOKEN|KEY|PASSWORD)', 'sensitive_env_access', 3.0),
            (r'chrome\.cookies\.getAll|browser\.cookies\.getAll', 'browser_cookie_access', 3.5),
            (r'require\([\'"`]keytar[\'"`]\)|require\([\'"`]node-keytar[\'"`]\)', 'credential_access', 4.0),
            (r'\.ssh[\/\\].*\.read|\.aws[\/\\].*\.read', 'sensitive_file_read', 4.0),
            (r'Buffer\.from\([^)]*,\s*[\'"`]hex[\'"`]\).*eval', 'hex_eval_combo', 4.5),
            (r'atob\s*\([^)]+\).*eval\s*\(', 'base64_eval_combo', 4.0),
            (r'String\.fromCharCode\.apply.*split.*map', 'obfuscated_decode', 3.0),
            (r'_0x[a-f0-9]{4,}', 'obfuscator_signature', 2.5)
        ]

        self.dangerous_apis = [
            'vscode.workspace.fs',
            'vscode.workspace.workspaceFolders',
            'vscode.env.clipboard',
            'vscode.authentication',
            'vscode.secrets',
            'vscode.workspace.onDidChangeConfiguration',
            'vscode.debug',
            'vscode.tasks',
            'vscode.extensions',
            'vscode.commands.executeCommand'
        ]

    def analyze_extension(self, extension: Dict, analysis_config: Dict) -> Dict:
        results = {
            'risk_score': 0,
            'risk_level': 'low',
            'findings': [],
            'permissions_analysis': {},
            'code_analysis': {},
            'dependency_analysis': {},
            'metadata_analysis': {},
            'recommendations': []
        }

        if analysis_config.get('check_permissions', True):
            results['permissions_analysis'] = self._analyze_permissions(extension)

        if analysis_config.get('check_obfuscation', True):
            results['code_analysis']['obfuscation'] = self._check_obfuscation(extension)

        if analysis_config.get('check_network_calls', True):
            results['code_analysis']['network_calls'] = self._check_network_calls(extension)

        if analysis_config.get('check_file_access', True):
            results['code_analysis']['file_access'] = self._check_file_access(extension)

        if analysis_config.get('check_code_injection', True):
            results['code_analysis']['injection_risks'] = self._check_injection_risks(extension)

        if analysis_config.get('check_dependencies', True):
            results['dependency_analysis'] = self._analyze_dependencies(extension)

        results['metadata_analysis'] = self._analyze_metadata(extension)

        results['risk_score'] = self._calculate_risk_score(results)
        results['risk_level'] = self._determine_risk_level(results['risk_score'])

        results['recommendations'] = self._generate_recommendations(results)

        return results

    def _analyze_permissions(self, extension: Dict) -> Dict:
        analysis = {
            'declared_permissions': extension.get('permissions', []),
            'risk_assessment': [],
            'dangerous_permissions': []
        }

        high_risk_permissions = [
            'activation.always',
            'terminal',
            'debuggers',
            'activation.filesystem',
            'activation.uri'
        ]

        for perm in extension.get('permissions', []):
            if perm in high_risk_permissions:
                analysis['dangerous_permissions'].append(perm)
                analysis['risk_assessment'].append({
                    'permission': perm,
                    'risk': 'high',
                    'description': f'Extension has access to: {perm}'
                })

        manifest = extension.get('manifest', {})
        contributes = manifest.get('contributes', {})

        if contributes.get('commands'):
            commands = contributes['commands']
            if len(commands) > 10:
                analysis['risk_assessment'].append({
                    'permission': 'commands',
                    'risk': 'medium',
                    'description': f'Extension registers {len(commands)} commands'
                })

        activation_events = manifest.get('activationEvents', [])
        if '*' in activation_events:
            analysis['risk_assessment'].append({
                'permission': 'activation',
                'risk': 'high',
                'description': 'Extension activates on all events (*)'
            })

        return analysis

    def _check_obfuscation(self, extension: Dict) -> Dict:
        obfuscation_indicators = {
            'minified_files': 0,
            'obfuscated_files': [],
            'suspicious_encoding': [],
            'packed_code': False
        }

        ext_path = Path(extension['path'])

        for file_info in extension.get('files', []):
            file_path = ext_path / file_info['path']

            if file_path.suffix in ['.js', '.ts']:
                try:
                    if file_path.exists():
                        content = file_path.read_text(encoding='utf-8', errors='ignore')

                        if self._is_minified(content):
                            obfuscation_indicators['minified_files'] += 1

                        if self._is_obfuscated(content):
                            obfuscation_indicators['obfuscated_files'].append(str(file_info['path']))

                        if self._has_suspicious_encoding(content):
                            obfuscation_indicators['suspicious_encoding'].append(str(file_info['path']))

                except Exception:
                    pass

        return obfuscation_indicators

    def _check_network_calls(self, extension: Dict) -> Dict:
        network_analysis = {
            'external_urls': [],
            'api_calls': [],
            'suspicious_domains': []
        }

        ext_path = Path(extension['path'])

        url_pattern = re.compile(
            r'https?:\/\/[^\s\'"<>]+|'
            r'wss?:\/\/[^\s\'"<>]+|'
            r'ftp:\/\/[^\s\'"<>]+'
        )

        api_patterns = [
            r'fetch\s*\([\'"`]([^\'"]+)[\'"`]',
            r'axios\.[get|post|put|delete]+\s*\([\'"`]([^\'"]+)[\'"`]',
            r'XMLHttpRequest.*open\s*\([\'"`]\w+[\'"`],\s*[\'"`]([^\'"]+)[\'"`]'
        ]

        for file_info in extension.get('files', []):
            file_path = ext_path / file_info['path']

            if file_path.suffix in ['.js', '.ts', '.json']:
                try:
                    if file_path.exists():
                        content = file_path.read_text(encoding='utf-8', errors='ignore')

                        urls = url_pattern.findall(content)
                        network_analysis['external_urls'].extend(urls)

                        for pattern in api_patterns:
                            matches = re.findall(pattern, content)
                            network_analysis['api_calls'].extend(matches)

                except Exception:
                    pass

        suspicious_domains = [
            'pastebin.com',
            'bit.ly',
            'tinyurl.com',
            'goo.gl',
            'rebrand.ly',
            'short.link',
            'grabify.link',
            'iplogger.org',
            'blasze.tk',
            'cutt.ly',
            'ow.ly'
        ]

        suspicious_patterns = [
            r'http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Direct IP addresses
            r'https?:\/\/[^\/]*\.tk[\/\s]',  # .tk domains
            r'https?:\/\/[^\/]*\.ml[\/\s]',  # .ml domains
            r'https?:\/\/[^\/]*\.ga[\/\s]'   # .ga domains
        ]

        for url in network_analysis['external_urls']:
            for domain in suspicious_domains:
                if domain in url:
                    network_analysis['suspicious_domains'].append(url)
                    break

            for pattern in suspicious_patterns:
                if re.search(pattern, url):
                    network_analysis['suspicious_domains'].append(url)
                    break

        return network_analysis

    def _check_file_access(self, extension: Dict) -> Dict:
        file_analysis = {
            'file_operations': [],
            'sensitive_paths': [],
            'api_usage': []
        }

        ext_path = Path(extension['path'])

        file_patterns = [
            (r'fs\.readFile', 'read'),
            (r'fs\.writeFile', 'write'),
            (r'fs\.unlink', 'delete'),
            (r'fs\.mkdir', 'create_dir'),
            (r'fs\.readdir', 'list_dir'),
            (r'fs\.access', 'check_access'),
            (r'fs\.chmod', 'change_permissions'),
            (r'fs\.copyFile', 'copy'),
            (r'vscode\.workspace\.fs\.readFile', 'vscode_read'),
            (r'vscode\.workspace\.fs\.writeFile', 'vscode_write')
        ]

        sensitive_paths = [
            r'\.ssh[\/\\].*private',
            r'\.ssh[\/\\]id_rsa',
            r'\.ssh[\/\\]id_ed25519',
            r'\.aws[\/\\]credentials',
            r'\.aws[\/\\]config.*secret',
            r'\.env\..*\.(prod|production)',
            r'wallet\.dat',
            r'\.gnupg[\/\\].*\.key',
            r'\.kube[\/\\]config',
            r'\.docker[\/\\]config\.json',
            r'\.npmrc.*authToken',
            r'cookies\.sqlite',
            r'Login Data',
            r'Web Data'
        ]

        for file_info in extension.get('files', []):
            file_path = ext_path / file_info['path']

            if file_path.suffix in ['.js', '.ts']:
                try:
                    if file_path.exists():
                        content = file_path.read_text(encoding='utf-8', errors='ignore')

                        for pattern, operation in file_patterns:
                            if re.search(pattern, content):
                                file_analysis['file_operations'].append({
                                    'file': str(file_info['path']),
                                    'operation': operation
                                })

                        for sensitive_pattern in sensitive_paths:
                            if re.search(sensitive_pattern, content):
                                file_analysis['sensitive_paths'].append({
                                    'file': str(file_info['path']),
                                    'pattern': sensitive_pattern
                                })

                except Exception:
                    pass

        return file_analysis

    def _check_injection_risks(self, extension: Dict) -> Dict:
        injection_analysis = {
            'eval_usage': [],
            'dynamic_code': [],
            'command_execution': [],
            'sql_patterns': []
        }

        ext_path = Path(extension['path'])

        injection_patterns = [
            (r'eval\s*\(', 'eval'),
            (r'exec\s*\(', 'exec'),
            (r'Function\s*\([\'"`]', 'function_constructor'),
            (r'setTimeout\s*\([\'"`]', 'setTimeout_string'),
            (r'setInterval\s*\([\'"`]', 'setInterval_string'),
            (r'child_process\.exec', 'exec_command'),
            (r'child_process\.spawn', 'spawn_command'),
            (r'\.execSync\s*\(', 'execSync')
        ]

        for file_info in extension.get('files', []):
            file_path = ext_path / file_info['path']

            if file_path.suffix in ['.js', '.ts']:
                try:
                    if file_path.exists():
                        content = file_path.read_text(encoding='utf-8', errors='ignore')

                        for pattern, risk_type in injection_patterns:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                injection_analysis['dynamic_code'].append({
                                    'file': str(file_info['path']),
                                    'type': risk_type,
                                    'line': line_num
                                })

                except Exception:
                    pass

        return injection_analysis

    def _analyze_dependencies(self, extension: Dict) -> Dict:
        dep_analysis = {
            'total_dependencies': 0,
            'suspicious_dependencies': [],
            'outdated_dependencies': [],
            'vulnerability_check': []
        }

        dependencies = extension.get('dependencies', {})
        dep_analysis['total_dependencies'] = len(dependencies)

        suspicious_packages = [
            'request',
            'node-fetch',
            'axios',
            'child_process',
            'shelljs',
            'node-cmd',
            'systeminformation',
            'os-utils',
            'public-ip',
            'internal-ip'
        ]

        for dep, version in dependencies.items():
            if any(susp in dep.lower() for susp in suspicious_packages):
                dep_analysis['suspicious_dependencies'].append({
                    'package': dep,
                    'version': version,
                    'reason': 'Package may have elevated permissions'
                })

        return dep_analysis

    def _analyze_metadata(self, extension: Dict) -> Dict:
        metadata = {
            'publisher_verified': False,
            'last_updated': None,
            'install_count': 0,
            'rating': 0,
            'documentation_quality': 'poor',
            'source_available': False
        }

        manifest = extension.get('manifest', {})

        if manifest.get('repository'):
            metadata['source_available'] = True

        if manifest.get('description') and len(manifest['description']) > 50:
            if manifest.get('homepage') or manifest.get('repository'):
                metadata['documentation_quality'] = 'good'
            else:
                metadata['documentation_quality'] = 'moderate'

        return metadata

    def _is_minified(self, content: str) -> bool:
        lines = content.split('\n')
        if not lines:
            return False

        avg_line_length = sum(len(line) for line in lines) / len(lines)

        long_lines = sum(1 for line in lines if len(line) > 1000)

        return avg_line_length > 500 or long_lines > len(lines) * 0.5

    def _is_obfuscated(self, content: str) -> bool:
        obfuscation_indicators = [
            r'_0x[a-f0-9]{4,}',
            r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}',
            r'String\.fromCharCode\([0-9,\s]+\).*String\.fromCharCode',
            r'atob\([\'"`][A-Za-z0-9+/=]{100,}[\'"`]\)',
            r'\[[\'"`]\\x[0-9a-fA-F]+[\'"`]\]\[[\'"`]\\x[0-9a-fA-F]+[\'"`]\]',
            r'[a-zA-Z_$][a-zA-Z0-9_$]{100,}',
            r'eval.*unescape.*eval',
            r'Function.*atob.*eval'
        ]

        indicators_found = 0
        for pattern in obfuscation_indicators:
            if re.search(pattern, content):
                indicators_found += 1

        return indicators_found >= 4

    def _has_suspicious_encoding(self, content: str) -> bool:
        encoding_patterns = [
            r'\\u[0-9a-fA-F]{4}',
            r'\\x[0-9a-fA-F]{2}',
            r'String\.fromCharCode',
            r'unescape\(',
            r'decodeURI'
        ]

        matches = 0
        for pattern in encoding_patterns:
            matches += len(re.findall(pattern, content))

        return matches > 50

    def _calculate_risk_score(self, analysis: Dict) -> float:
        score = 0.0

        perms = analysis.get('permissions_analysis', {})
        dangerous_perms = perms.get('dangerous_permissions', [])
        if 'activation.always' in dangerous_perms:
            score += 1.0
        score += min(len(dangerous_perms), 3) * self.risk_weights['permissions']

        code = analysis.get('code_analysis', {})

        obfuscated = code.get('obfuscation', {}).get('obfuscated_files', [])
        if obfuscated:
            score += min(len(obfuscated), 2) * self.risk_weights['obfuscation']

        suspicious_domains = code.get('network_calls', {}).get('suspicious_domains', [])
        if suspicious_domains:
            score += min(len(set(suspicious_domains)), 3) * self.risk_weights['network_calls']

        sensitive_paths = code.get('file_access', {}).get('sensitive_paths', [])
        if sensitive_paths:
            score += min(len(sensitive_paths), 2) * self.risk_weights['file_operations'] * 2

        injection_risks = code.get('injection_risks', {}).get('dynamic_code', [])
        if injection_risks:
            high_risk_injections = [r for r in injection_risks if r.get('type') in ['eval', 'exec', 'function_constructor_return', 'command_injection']]
            score += min(len(high_risk_injections), 2) * self.risk_weights['code_injection']

        deps = analysis.get('dependency_analysis', {})
        suspicious_deps = deps.get('suspicious_dependencies', [])
        if len(suspicious_deps) > 5:
            score += 1.0

        return min(score, 10.0)

    def _determine_risk_level(self, score: float) -> str:
        if score >= 8:
            return 'critical'
        elif score >= 6:
            return 'high'
        elif score >= 4:
            return 'medium'
        elif score >= 2:
            return 'low'
        else:
            return 'minimal'

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        recommendations = []

        if analysis['risk_score'] >= 6:
            recommendations.append('Consider removing this extension due to high security risk')

        perms = analysis.get('permissions_analysis', {})
        if perms.get('dangerous_permissions'):
            recommendations.append('Review the permissions required by this extension')

        code = analysis.get('code_analysis', {})
        if code.get('obfuscation', {}).get('obfuscated_files'):
            recommendations.append('Extension contains obfuscated code - verify publisher trustworthiness')

        if code.get('network_calls', {}).get('suspicious_domains'):
            recommendations.append('Extension connects to suspicious domains - investigate network activity')

        if code.get('file_access', {}).get('sensitive_paths'):
            recommendations.append('Extension accesses sensitive file paths - review file operations')

        if code.get('injection_risks', {}).get('dynamic_code'):
            recommendations.append('Extension uses dynamic code execution - potential code injection risk')

        return recommendations