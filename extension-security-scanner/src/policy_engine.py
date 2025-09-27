#!/usr/bin/env python3

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta


class PolicyEngine:
    def __init__(self, default_policies: Dict = None):
        self.policies = default_policies or self._get_default_policies()
        self.allowlist = []
        self.blocklist = []
        self.custom_rules = []

    def _get_default_policies(self) -> Dict:
        return {
            'max_risk_score': 8,
            'required_publisher_verification': False,
            'blocked_permissions': [],
            'allowed_publishers': [],
            'blocked_publishers': [],
            'max_days_since_update': 730,
            'min_install_count': 0,
            'allow_obfuscated_code': True,
            'allow_network_calls': True,
            'allow_file_operations': True,
            'allow_code_injection': False,
            'max_dependencies': 200,
            'enforce_source_availability': False,
            'require_documentation': False
        }

    def load_custom_policy(self, policy_path: str):
        try:
            with open(policy_path, 'r') as f:
                custom_policy = json.load(f)

            if 'policies' in custom_policy:
                self.policies.update(custom_policy['policies'])

            if 'allowlist' in custom_policy:
                self.allowlist = custom_policy['allowlist']

            if 'blocklist' in custom_policy:
                self.blocklist = custom_policy['blocklist']

            if 'custom_rules' in custom_policy:
                self.custom_rules = custom_policy['custom_rules']

        except Exception as e:
            print(f"[!] Error loading custom policy: {e}")

    def evaluate(self, extension: Dict, analysis: Dict) -> Dict:
        evaluation = {
            'decision': 'allowed',
            'violations': [],
            'warnings': [],
            'passed_checks': [],
            'policy_score': 0
        }

        ext_id = extension.get('id', 'unknown')

        if self._is_blocklisted(extension):
            evaluation['decision'] = 'blocked'
            evaluation['violations'].append(f'Extension {ext_id} is blocklisted')
            return evaluation

        if self._is_allowlisted(extension):
            evaluation['decision'] = 'allowed'
            evaluation['passed_checks'].append(f'Extension {ext_id} is allowlisted')
            return evaluation

        self._check_risk_score(analysis, evaluation)

        self._check_publisher(extension, evaluation)

        self._check_permissions(extension, analysis, evaluation)

        self._check_code_quality(analysis, evaluation)

        self._check_dependencies(extension, analysis, evaluation)

        self._check_metadata(extension, analysis, evaluation)

        self._apply_custom_rules(extension, analysis, evaluation)

        if evaluation['violations']:
            evaluation['decision'] = 'blocked'
        elif len(evaluation['warnings']) > 3:
            evaluation['decision'] = 'warnings'

        evaluation['policy_score'] = self._calculate_policy_score(evaluation)

        return evaluation

    def _is_allowlisted(self, extension: Dict) -> bool:
        ext_id = extension.get('id', '')
        publisher = extension.get('publisher', '')

        for allowed in self.allowlist:
            if isinstance(allowed, str):
                if allowed == ext_id or allowed == publisher:
                    return True
            elif isinstance(allowed, dict):
                if allowed.get('id') == ext_id:
                    return True
                if allowed.get('publisher') == publisher:
                    return True
                if allowed.get('pattern'):
                    if re.match(allowed['pattern'], ext_id):
                        return True

        if publisher in self.policies.get('allowed_publishers', []):
            return True

        return False

    def _is_blocklisted(self, extension: Dict) -> bool:
        ext_id = extension.get('id', '')
        publisher = extension.get('publisher', '')

        for blocked in self.blocklist:
            if isinstance(blocked, str):
                if blocked == ext_id or blocked == publisher:
                    return True
            elif isinstance(blocked, dict):
                if blocked.get('id') == ext_id:
                    return True
                if blocked.get('publisher') == publisher:
                    return True
                if blocked.get('pattern'):
                    if re.match(blocked['pattern'], ext_id):
                        return True

        if publisher in self.policies.get('blocked_publishers', []):
            return True

        return False

    def _check_risk_score(self, analysis: Dict, evaluation: Dict):
        risk_score = analysis.get('risk_score', 0)
        max_score = self.policies.get('max_risk_score', 10)

        if risk_score > max_score:
            evaluation['violations'].append(
                f'Risk score ({risk_score:.1f}) exceeds maximum allowed ({max_score})'
            )
        elif risk_score > max_score * 0.8:
            evaluation['warnings'].append(
                f'Risk score ({risk_score:.1f}) approaching maximum ({max_score})'
            )
        else:
            evaluation['passed_checks'].append(
                f'Risk score ({risk_score:.1f}) within limits'
            )

    def _check_publisher(self, extension: Dict, evaluation: Dict):
        publisher = extension.get('publisher', 'unknown')

        if publisher == 'unknown':
            evaluation['warnings'].append('Unknown publisher')

        if self.policies.get('required_publisher_verification'):
            metadata = extension.get('metadata', {})
            if not metadata.get('publisher_verified'):
                evaluation['violations'].append('Publisher verification required but not verified')

    def _check_permissions(self, extension: Dict, analysis: Dict, evaluation: Dict):
        perms_analysis = analysis.get('permissions_analysis', {})
        dangerous_perms = perms_analysis.get('dangerous_permissions', [])
        blocked_perms = self.policies.get('blocked_permissions', [])

        for perm in dangerous_perms:
            if perm in blocked_perms:
                evaluation['violations'].append(f'Blocked permission detected: {perm}')
            else:
                evaluation['warnings'].append(f'Dangerous permission: {perm}')

        activation_events = extension.get('manifest', {}).get('activationEvents', [])
        if '*' in activation_events:
            evaluation['warnings'].append('Extension activates on all events')

    def _check_code_quality(self, analysis: Dict, evaluation: Dict):
        code_analysis = analysis.get('code_analysis', {})

        if not self.policies.get('allow_obfuscated_code'):
            obfuscation = code_analysis.get('obfuscation', {})
            if obfuscation.get('obfuscated_files'):
                if len(obfuscation['obfuscated_files']) > 3:
                    evaluation['violations'].append(
                        f"Heavy obfuscation detected in {len(obfuscation['obfuscated_files'])} files"
                    )
                else:
                    evaluation['warnings'].append(
                        f"Some obfuscated code detected"
                    )

        if not self.policies.get('allow_code_injection'):
            injection = code_analysis.get('injection_risks', {})
            dynamic_code = injection.get('dynamic_code', [])
            high_risk = [d for d in dynamic_code if d.get('type') in ['eval', 'exec', 'command_injection']]
            if high_risk:
                evaluation['violations'].append(
                    f"Critical code injection risks found: {len(high_risk)} instances"
                )
            elif dynamic_code:
                evaluation['warnings'].append(
                    f"Potential code injection risks: {len(dynamic_code)} instances"
                )

        if not self.policies.get('allow_network_calls'):
            network = code_analysis.get('network_calls', {})
            suspicious = network.get('suspicious_domains', [])
            if suspicious:
                evaluation['violations'].append(
                    f"Suspicious network calls to {len(set(suspicious))} domains"
                )
            elif network.get('external_urls'):
                evaluation['warnings'].append(
                    f"Network calls detected"
                )

        if not self.policies.get('allow_file_operations'):
            file_ops = code_analysis.get('file_access', {})
            if file_ops.get('file_operations'):
                evaluation['warnings'].append(
                    f"File operations detected"
                )

        file_ops = code_analysis.get('file_access', {})
        if file_ops.get('sensitive_paths'):
            evaluation['violations'].append(
                f"Access to sensitive paths detected: {len(file_ops['sensitive_paths'])} instances"
            )

    def _check_dependencies(self, extension: Dict, analysis: Dict, evaluation: Dict):
        deps_analysis = analysis.get('dependency_analysis', {})

        total_deps = deps_analysis.get('total_dependencies', 0)
        max_deps = self.policies.get('max_dependencies', 100)

        if total_deps > max_deps:
            evaluation['violations'].append(
                f'Too many dependencies ({total_deps}) exceeds maximum ({max_deps})'
            )

        suspicious_deps = deps_analysis.get('suspicious_dependencies', [])
        if suspicious_deps:
            evaluation['warnings'].append(
                f'Suspicious dependencies detected: {len(suspicious_deps)}'
            )

    def _check_metadata(self, extension: Dict, analysis: Dict, evaluation: Dict):
        metadata = analysis.get('metadata_analysis', {})

        if self.policies.get('enforce_source_availability'):
            if not metadata.get('source_available'):
                evaluation['violations'].append('Source code repository not available')

        if self.policies.get('require_documentation'):
            if metadata.get('documentation_quality') == 'poor':
                evaluation['warnings'].append('Poor documentation quality')

        min_installs = self.policies.get('min_install_count', 0)
        if min_installs > 0:
            installs = metadata.get('install_count', 0)
            if installs < min_installs:
                evaluation['warnings'].append(
                    f'Low install count ({installs}) below minimum ({min_installs})'
                )

    def _apply_custom_rules(self, extension: Dict, analysis: Dict, evaluation: Dict):
        for rule in self.custom_rules:
            try:
                if self._evaluate_rule(rule, extension, analysis):
                    action = rule.get('action', 'warning')
                    message = rule.get('message', 'Custom rule triggered')

                    if action == 'block':
                        evaluation['violations'].append(message)
                    elif action == 'warning':
                        evaluation['warnings'].append(message)

            except Exception as e:
                print(f"[!] Error evaluating custom rule: {e}")

    def _evaluate_rule(self, rule: Dict, extension: Dict, analysis: Dict) -> bool:
        rule_type = rule.get('type')

        if rule_type == 'regex':
            pattern = rule.get('pattern')
            field = rule.get('field')
            value = self._get_nested_value(extension, field)
            if value and pattern:
                return bool(re.search(pattern, str(value)))

        elif rule_type == 'threshold':
            field = rule.get('field')
            operator = rule.get('operator', 'gt')
            threshold = rule.get('value', 0)
            value = self._get_nested_value(analysis, field)

            if value is not None:
                if operator == 'gt':
                    return value > threshold
                elif operator == 'gte':
                    return value >= threshold
                elif operator == 'lt':
                    return value < threshold
                elif operator == 'lte':
                    return value <= threshold
                elif operator == 'eq':
                    return value == threshold

        elif rule_type == 'contains':
            field = rule.get('field')
            search_value = rule.get('value')
            value = self._get_nested_value(extension, field)

            if isinstance(value, list):
                return search_value in value
            elif isinstance(value, str):
                return search_value in value

        return False

    def _get_nested_value(self, data: Dict, path: str) -> Any:
        keys = path.split('.')
        value = data

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None

        return value

    def _calculate_policy_score(self, evaluation: Dict) -> float:
        score = 10.0

        score -= len(evaluation['violations']) * 3.0

        score -= len(evaluation['warnings']) * 1.0

        score += len(evaluation['passed_checks']) * 0.5

        return max(0, min(10, score))

    def export_policy(self, output_path: str):
        policy_data = {
            'policies': self.policies,
            'allowlist': self.allowlist,
            'blocklist': self.blocklist,
            'custom_rules': self.custom_rules,
            'exported_at': datetime.now().isoformat()
        }

        with open(output_path, 'w') as f:
            json.dump(policy_data, f, indent=2)

    def add_to_allowlist(self, identifier: str, id_type: str = 'id'):
        entry = {id_type: identifier, 'added_at': datetime.now().isoformat()}
        self.allowlist.append(entry)

    def add_to_blocklist(self, identifier: str, id_type: str = 'id', reason: str = ''):
        entry = {
            id_type: identifier,
            'reason': reason,
            'added_at': datetime.now().isoformat()
        }
        self.blocklist.append(entry)