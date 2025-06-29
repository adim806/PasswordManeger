#!/usr/bin/env python3
"""
Setup script for the Secure Password Manager application.
"""

import os
import sys
from setuptools import setup, find_packages

# Read the requirements from requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Read the long description from README.md
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="secure-password-manager",
    version="1.0.0",
    description="A secure, offline password manager desktop application",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Password Manager Team",
    author_email="example@example.com",
    url="https://github.com/example/secure-password-manager",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'password-manager=password_manager.main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
    python_requires='>=3.8',
) 