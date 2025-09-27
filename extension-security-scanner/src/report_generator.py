#!/usr/bin/env python3

import json
import csv
import io
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'json': self._generate_json,
            'html': self._generate_html,
            'csv': self._generate_csv,
            'markdown': self._generate_markdown
        }

    def generate(self, results: Dict, format: str = 'json') -> str:
        generator = self.report_templates.get(format, self._generate_json)
        return generator(results)

    def _generate_json(self, results: Dict) -> str:
        return json.dumps(results, indent=2, default=str)

    def _generate_html(self, results: Dict) -> str:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Extension Security Scan Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
        }}
        .allowed {{ color: #10b981; }}
        .blocked {{ color: #ef4444; }}
        .warning {{ color: #f59e0b; }}
        .extension {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #e5e7eb;
        }}
        .extension.high-risk {{
            border-left-color: #ef4444;
        }}
        .extension.medium-risk {{
            border-left-color: #f59e0b;
        }}
        .extension.low-risk {{
            border-left-color: #10b981;
        }}
        .extension-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .extension-name {{
            font-size: 1.2em;
            font-weight: bold;
            color: #1f2937;
        }}
        .risk-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 500;
        }}
        .risk-critical {{
            background: #fef2f2;
            color: #991b1b;
        }}
        .risk-high {{
            background: #fef2f2;
            color: #991b1b;
        }}
        .risk-medium {{
            background: #fffbeb;
            color: #92400e;
        }}
        .risk-low {{
            background: #f0fdf4;
            color: #166534;
        }}
        .risk-minimal {{
            background: #f0fdf4;
            color: #166534;
        }}
        .findings {{
            margin-top: 15px;
        }}
        .finding {{
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            background: #f9fafb;
        }}
        .violation {{
            background: #fef2f2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }}
        .warning {{
            background: #fffbeb;
            color: #92400e;
            border: 1px solid #fde68a;
        }}
        .info {{
            background: #eff6ff;
            color: #1e40af;
            border: 1px solid #bfdbfe;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background: #f9fafb;
            font-weight: 600;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #6b7280;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Extension Security Scan Report</h1>
        <p>Generated: {results['scan_date']}</p>
        <p>Total Extensions Scanned: {results['total_extensions']}</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Allowed</h3>
            <div class="number allowed">{results['summary']['allowed']}</div>
        </div>
        <div class="summary-card">
            <h3>Blocked</h3>
            <div class="number blocked">{results['summary']['blocked']}</div>
        </div>
        <div class="summary-card">
            <h3>Warnings</h3>
            <div class="number warning">{results['summary']['warnings']}</div>
        </div>
        <div class="summary-card">
            <h3>High Risk</h3>
            <div class="number blocked">{results['summary']['high_risk']}</div>
        </div>
        <div class="summary-card">
            <h3>Medium Risk</h3>
            <div class="number warning">{results['summary']['medium_risk']}</div>
        </div>
        <div class="summary-card">
            <h3>Low Risk</h3>
            <div class="number allowed">{results['summary']['low_risk']}</div>
        </div>
    </div>

    <h2>Extension Details</h2>
"""

        for ext in results['extensions']:
            risk_class = 'low-risk'
            if ext['risk_score'] >= 7:
                risk_class = 'high-risk'
            elif ext['risk_score'] >= 4:
                risk_class = 'medium-risk'

            html += f"""
    <div class="extension {risk_class}">
        <div class="extension-header">
            <div>
                <div class="extension-name">{ext.get('name', 'Unknown')}</div>
                <div style="color: #6b7280; margin-top: 5px;">
                    Publisher: {ext.get('publisher', 'Unknown')} |
                    Version: {ext.get('version', 'Unknown')} |
                    Editor: {ext.get('editor', 'Unknown')}
                </div>
            </div>
            <div>
                <span class="risk-badge risk-{ext['analysis']['risk_level']}">{ext['analysis']['risk_level'].upper()}</span>
                <span style="margin-left: 10px;">Score: {ext['risk_score']:.1f}/10</span>
            </div>
        </div>
"""

            policy = ext.get('policy_evaluation', {})

            if policy.get('violations'):
                html += '<div class="findings"><h4>Violations:</h4>'
                for violation in policy['violations']:
                    html += f'<div class="finding violation">❌ {violation}</div>'
                html += '</div>'

            if policy.get('warnings'):
                html += '<div class="findings"><h4>Warnings:</h4>'
                for warning in policy['warnings']:
                    html += f'<div class="finding warning">⚠️ {warning}</div>'
                html += '</div>'

            if ext['analysis'].get('recommendations'):
                html += '<div class="findings"><h4>Recommendations:</h4>'
                for rec in ext['analysis']['recommendations']:
                    html += f'<div class="finding info">💡 {rec}</div>'
                html += '</div>'

            html += """
    </div>
"""

        html += """
    <div class="footer">
        <p>Extension Security Scanner - Protecting your development environment</p>
    </div>
</body>
</html>"""

        return html

    def _generate_csv(self, results: Dict) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            'Extension ID',
            'Name',
            'Publisher',
            'Version',
            'Editor',
            'Risk Score',
            'Risk Level',
            'Status',
            'Violations',
            'Warnings',
            'Recommendations'
        ])

        for ext in results['extensions']:
            policy = ext.get('policy_evaluation', {})
            writer.writerow([
                ext.get('id', ''),
                ext.get('name', ''),
                ext.get('publisher', ''),
                ext.get('version', ''),
                ext.get('editor', ''),
                f"{ext.get('risk_score', 0):.1f}",
                ext.get('analysis', {}).get('risk_level', ''),
                ext.get('status', ''),
                '; '.join(policy.get('violations', [])),
                '; '.join(policy.get('warnings', [])),
                '; '.join(ext.get('analysis', {}).get('recommendations', []))
            ])

        return output.getvalue()

    def _generate_markdown(self, results: Dict) -> str:
        md = f"""# Extension Security Scan Report

**Generated:** {results['scan_date']}
**Total Extensions Scanned:** {results['total_extensions']}

## Summary

| Metric | Count |
|--------|-------|
| Allowed | {results['summary']['allowed']} |
| Blocked | {results['summary']['blocked']} |
| Warnings | {results['summary']['warnings']} |
| High Risk | {results['summary']['high_risk']} |
| Medium Risk | {results['summary']['medium_risk']} |
| Low Risk | {results['summary']['low_risk']} |

## Extension Details

"""

        critical_extensions = []
        high_risk_extensions = []
        medium_risk_extensions = []
        low_risk_extensions = []

        for ext in results['extensions']:
            risk_level = ext.get('analysis', {}).get('risk_level', 'unknown')
            if risk_level == 'critical':
                critical_extensions.append(ext)
            elif risk_level == 'high':
                high_risk_extensions.append(ext)
            elif risk_level == 'medium':
                medium_risk_extensions.append(ext)
            else:
                low_risk_extensions.append(ext)

        if critical_extensions:
            md += "### 🔴 Critical Risk Extensions\n\n"
            md += self._format_extensions_markdown(critical_extensions)

        if high_risk_extensions:
            md += "### 🔴 High Risk Extensions\n\n"
            md += self._format_extensions_markdown(high_risk_extensions)

        if medium_risk_extensions:
            md += "### 🟡 Medium Risk Extensions\n\n"
            md += self._format_extensions_markdown(medium_risk_extensions)

        if low_risk_extensions:
            md += "### 🟢 Low Risk Extensions\n\n"
            md += self._format_extensions_markdown(low_risk_extensions)

        md += "\n---\n\n*Extension Security Scanner - Protecting your development environment*\n"

        return md

    def _format_extensions_markdown(self, extensions: List[Dict]) -> str:
        md = ""
        for ext in extensions:
            md += f"#### {ext.get('name', 'Unknown')} (v{ext.get('version', 'unknown')})\n\n"
            md += f"- **Publisher:** {ext.get('publisher', 'Unknown')}\n"
            md += f"- **Editor:** {ext.get('editor', 'Unknown')}\n"
            md += f"- **Risk Score:** {ext.get('risk_score', 0):.1f}/10\n"
            md += f"- **Status:** {ext.get('status', 'unknown')}\n"

            policy = ext.get('policy_evaluation', {})

            if policy.get('violations'):
                md += "\n**Violations:**\n"
                for violation in policy['violations']:
                    md += f"- ❌ {violation}\n"

            if policy.get('warnings'):
                md += "\n**Warnings:**\n"
                for warning in policy['warnings']:
                    md += f"- ⚠️ {warning}\n"

            if ext.get('analysis', {}).get('recommendations'):
                md += "\n**Recommendations:**\n"
                for rec in ext['analysis']['recommendations']:
                    md += f"- 💡 {rec}\n"

            md += "\n---\n\n"

        return md

    def generate_summary_report(self, results: Dict) -> str:
        summary = f"""
Extension Security Scan Summary
================================
Scan Date: {results['scan_date']}
Total Extensions: {results['total_extensions']}

Results:
- Allowed: {results['summary']['allowed']}
- Blocked: {results['summary']['blocked']}
- Warnings: {results['summary']['warnings']}

Risk Distribution:
- High Risk: {results['summary']['high_risk']}
- Medium Risk: {results['summary']['medium_risk']}
- Low Risk: {results['summary']['low_risk']}

Top Issues Found:
"""
        violation_counts = {}
        for ext in results['extensions']:
            policy = ext.get('policy_evaluation', {})
            for violation in policy.get('violations', []):
                key = violation.split(':')[0] if ':' in violation else violation
                violation_counts[key] = violation_counts.get(key, 0) + 1

        sorted_violations = sorted(violation_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for violation, count in sorted_violations:
            summary += f"- {violation}: {count} occurrences\n"

        return summary