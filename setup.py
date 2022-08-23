"""
Wheel packager.

"""
from setuptools import setup

setup(
    name="secure_hardware_extension",
    version="0.2.0",
    install_requires=[
        "pycryptodome",
    ],
    author="Michał Juszczyk",
    author_email="michaljuszczyk2@gmail.com",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    description="A set of tools for AUTOSAR Secure Hardware Extension.",
    url="https://github.com/Deejuha/SecureHardwareExtension",
)
