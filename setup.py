#!/usr/bin/env python3

import pathlib

from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent

# Handle README.md that might not exist in Docker build
try:
    README = (HERE / "README.md").read_text()
except FileNotFoundError:
    README = "Advanced malware analysis tool using radare2 and r2pipe"

setup(
    name="r2inspect",
    version="1.0.0",
    description="Advanced malware analysis tool using radare2 and r2pipe",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Marc Rivero",
    author_email="mriverolopez@gmail.com",
    url="https://github.com/seifreed/r2inspect",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "r2pipe>=1.8.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "pyfiglet>=0.8.post1",
        "python-magic>=0.4.27",
        "yara-python>=4.3.1",
        "pefile>=2023.2.7",
        'pandas>=1.3.0; python_version < "3.9"',
        'pandas>=1.5.0; python_version >= "3.9" and python_version < "3.11"',
        'pandas>=2.0.0; python_version >= "3.11"',
        "rich>=13.7.0",
        "click>=8.1.7",
        "cryptography>=41.0.7",
        "requests>=2.31.0",
        "colorlog>=6.8.0",
        "pycryptodome>=3.19.0",
        "psutil>=5.9.0",
        "pybloom-live>=4.0.0",
        "simhash>=2.1.0",
    ],
    entry_points={
        "console_scripts": [
            "r2inspect=r2inspect.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
