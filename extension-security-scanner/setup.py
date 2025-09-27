#!/usr/bin/env python3

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="extension-security-scanner",
    version="1.0.0",
    author="Security Team",
    description="A comprehensive security scanner for VS Code and Cursor extensions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/extension-security-scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "pathlib2>=2.3.5",
        "jsonschema>=4.0.0",
        "jinja2>=3.0.0",
        "click>=8.0.0",
        "colorama>=0.4.4",
        "termcolor>=1.1.0",
        "tqdm>=4.62.0",
        "pyyaml>=6.0",
        "python-dateutil>=2.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
        "web": [
            "flask>=2.0.0",
        ],
        "enhanced": [
            "python-magic>=0.4.24",
        ],
    },
    entry_points={
        "console_scripts": [
            "ext-scan=main:main",
            "extension-scanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.yaml", "*.yml", "*.html", "*.css"],
    },
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/yourusername/extension-security-scanner/issues",
        "Source": "https://github.com/yourusername/extension-security-scanner",
        "Documentation": "https://github.com/yourusername/extension-security-scanner/wiki",
    },
)