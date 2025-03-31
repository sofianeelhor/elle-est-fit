import os
from setuptools import setup, find_packages

about = {}
with open(os.path.join(os.path.dirname(__file__), "elle_est_fit", "__init__.py"), "r") as f:
    exec(f.read(), about)

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="elle-est-fit",
    version=about["__version__"],
    description="LFI to RCE Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=about["__author__"],
    author_email="sofiane.el@ynov.com",
    url="https://github.com/username/elle-est-fit",
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
    keywords=["infosec", "pentest", "lfi", "rce"],
)