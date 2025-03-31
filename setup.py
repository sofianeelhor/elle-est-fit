#!/usr/bin/env python3
"""
Setup script for Elle-Est-Fit LFI to RCE Framework.
"""

from setuptools import setup, find_packages
VERSION = "0.1.0"

setup(
    name="elle-est-fit",
    version=VERSION,
    description="LFI to RCE Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="ElleEstFit Contributors",
    author_email="sofiane.el@ynov.com",
    url="https://github.com/sofianeelhor/elle-est-fit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "elle-est-fit=elle_est_fit.cli:main",
        ],
    },
    keywords=["security", "pentest", "lfi", "rce"],
)