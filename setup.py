"""
Wheel packager.

"""
from pathlib import Path

from setuptools import setup

root_directory = Path(__file__).parent
readme = (root_directory / "README.md").read_text()

setup(
    name="SecureHardwareExtension",
    version="1.0.1",
    install_requires=[
        "pycryptodome",
    ],
    python_requires=">=3.8",
    author="Michał Juszczyk",
    author_email="michaljuszczyk2@gmail.com",
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    description="A set of tools for AUTOSAR Secure Hardware Extension.",
    url="https://github.com/Deejuha/SecureHardwareExtension",
    long_description=readme,
    long_description_content_type="text/markdown",
)
