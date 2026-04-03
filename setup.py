#!/usr/bin/env python3
"""
Unearth Forensic Recovery Tool - Setup Configuration
Enables installation via pip and creates command-line entry points
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file) as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#')
        ]

setup(
    name="Unearth-forensics",
    version="1.0.0",
    description="Professional Forensic Data Recovery Tool for XFS and Btrfs filesystems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Unearth Development Team",
    author_email="dev@Unearth-forensics.org",
    url="https://github.com/yourusername/Unearth",
    license="MIT",
    
    # Package configuration
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    
    # Python version requirement
    python_requires=">=3.11",
    
    # Dependencies
    install_requires=requirements,
    
    # Optional dependencies
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.7.0',
            'flake8>=6.0.0',
            'mypy>=1.4.0',
        ],
        'minimal': [
            'PyQt6>=6.4.0',
            'click>=8.1.0',
            'rich>=13.0.0',
            'psutil>=5.9.0',
        ],
    },
    
    # Entry points - Creates command-line scripts
    entry_points={
        'console_scripts': [
            'Unearth=ui.cli:main',              # Main CLI command
            'Unearth-gui=ui.gui:main',          # GUI launcher
            'Unearth-cli=ui.cli:main',          # Explicit CLI
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Recovery Tools",
        "Topic :: System :: Forensics",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
    ],
    
    # Keywords
    keywords="forensics recovery xfs btrfs data-recovery digital-forensics",   
)