#!/usr/bin/env python3

import os
import json
import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
import tempfile


class ExtensionScanner:
    def __init__(self):
        self.discovered_extensions = []

    def discover_extensions(self, target: str, scan_locations: Dict) -> List[Dict]:
        extensions = []

        if target in ['vscode', 'all']:
            extensions.extend(self._scan_editor('vscode', scan_locations['vscode']))

        if target in ['cursor', 'all']:
            extensions.extend(self._scan_editor('cursor', scan_locations['cursor']))

        return extensions

    def _scan_editor(self, editor_name: str, paths: List[str]) -> List[Dict]:
        extensions = []

        for path_str in paths:
            path = Path(path_str).expanduser()
            if path.exists():
                print(f"[*] Scanning {editor_name} extensions at: {path}")
                extensions.extend(self._scan_directory(path, editor_name))

        return extensions

    def _scan_directory(self, directory: Path, editor: str) -> List[Dict]:
        extensions = []

        try:
            for item in directory.iterdir():
                if item.is_dir():
                    extension_info = self._parse_extension(item, editor)
                    if extension_info:
                        extensions.append(extension_info)
        except PermissionError:
            print(f"[!] Permission denied accessing: {directory}")

        return extensions

    def _parse_extension(self, ext_dir: Path, editor: str) -> Optional[Dict]:
        package_json = ext_dir / 'package.json'

        if not package_json.exists():
            return None

        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                manifest = json.load(f)

            extension_info = {
                'id': f"{manifest.get('publisher', 'unknown')}.{manifest.get('name', 'unknown')}",
                'name': manifest.get('displayName', manifest.get('name', 'Unknown')),
                'version': manifest.get('version', 'unknown'),
                'publisher': manifest.get('publisher', 'unknown'),
                'description': manifest.get('description', ''),
                'path': str(ext_dir),
                'editor': editor,
                'manifest': manifest,
                'files': self._list_extension_files(ext_dir),
                'size': self._get_directory_size(ext_dir),
                'permissions': self._extract_permissions(manifest),
                'activation_events': manifest.get('activationEvents', []),
                'contributes': manifest.get('contributes', {}),
                'dependencies': manifest.get('dependencies', {}),
                'engines': manifest.get('engines', {}),
                'categories': manifest.get('categories', []),
                'keywords': manifest.get('keywords', []),
                'repository': manifest.get('repository', {}),
                'homepage': manifest.get('homepage', ''),
                'bugs': manifest.get('bugs', {}),
                'license': manifest.get('license', '')
            }

            return extension_info

        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Error parsing extension at {ext_dir}: {e}")
            return None

    def _extract_permissions(self, manifest: Dict) -> List[str]:
        permissions = []

        contributes = manifest.get('contributes', {})

        if 'commands' in contributes:
            permissions.append('commands')

        if 'menus' in contributes:
            permissions.append('menus')

        if 'keybindings' in contributes:
            permissions.append('keybindings')

        if 'configuration' in contributes:
            permissions.append('configuration')

        if 'languages' in contributes:
            permissions.append('languages')

        if 'debuggers' in contributes:
            permissions.append('debuggers')

        if 'terminal' in contributes:
            permissions.append('terminal')

        activation_events = manifest.get('activationEvents', [])
        for event in activation_events:
            if event == '*':
                permissions.append('activation.always')
            elif event.startswith('onCommand:'):
                permissions.append('activation.command')
            elif event.startswith('onLanguage:'):
                permissions.append('activation.language')
            elif event.startswith('onDebug'):
                permissions.append('activation.debug')
            elif event.startswith('workspaceContains:'):
                permissions.append('activation.workspace')
            elif event.startswith('onFileSystem:'):
                permissions.append('activation.filesystem')
            elif event.startswith('onView:'):
                permissions.append('activation.view')
            elif event.startswith('onUri'):
                permissions.append('activation.uri')
            elif event.startswith('onWebviewPanel'):
                permissions.append('activation.webview')
            elif event.startswith('onCustomEditor'):
                permissions.append('activation.editor')

        extension_kind = manifest.get('extensionKind', [])
        if 'ui' in extension_kind:
            permissions.append('ui')
        if 'workspace' in extension_kind:
            permissions.append('workspace')

        return list(set(permissions))

    def _list_extension_files(self, ext_dir: Path) -> List[Dict]:
        files = []
        try:
            for file_path in ext_dir.rglob('*'):
                if file_path.is_file():
                    files.append({
                        'path': str(file_path.relative_to(ext_dir)),
                        'size': file_path.stat().st_size,
                        'extension': file_path.suffix
                    })
        except Exception as e:
            print(f"[!] Error listing files in {ext_dir}: {e}")

        return files

    def _get_directory_size(self, directory: Path) -> int:
        total = 0
        try:
            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    total += file_path.stat().st_size
        except Exception:
            pass
        return total

    def extract_vsix(self, vsix_path: Path, extract_to: Path = None) -> Optional[Path]:
        if not vsix_path.exists() or not vsix_path.suffix == '.vsix':
            return None

        if extract_to is None:
            extract_to = Path(tempfile.mkdtemp(prefix='vsix_'))

        try:
            with zipfile.ZipFile(vsix_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            return extract_to
        except Exception as e:
            print(f"[!] Error extracting VSIX: {e}")
            if extract_to.exists():
                shutil.rmtree(extract_to)
            return None