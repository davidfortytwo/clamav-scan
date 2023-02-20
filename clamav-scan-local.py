#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import os
import re
import subprocess
import argparse

def is_vulnerable_version(version):
    vulnerable_versions = ["1.0.0", "0.105.1", "0.103.7"]
    return version in vulnerable_versions

def check_file_for_vulnerability(clamscan_path, filename):
    with open(filename, 'rb') as f:
        # Read the file contents
        contents = f.read()

        # Check for the vulnerable condition
        if b"HFS+" in contents and b"ClamAV" in contents:
            # CVE-2023-20032: check if the vulnerable version is present
            clamscan_output = subprocess.check_output([clamscan_path, '--version'])
            match = re.search(b'ClamAV ([0-9.]+)', clamscan_output)
            if match:
                version = match.group(1).decode()
                if is_vulnerable_version(version):
                    print(f"File {filename} is vulnerable to CVE-2023-20032!")

        if b"DMG" in contents and b"ClamAV" in contents:
            # CVE-2023-20052: check if the vulnerable version is present
            clamscan_output = subprocess.check_output([clamscan_path, '--version'])
            match = re.search(b'ClamAV ([0-9.]+)', clamscan_output)
            if match:
                version = match.group(1).decode()
                if is_vulnerable_version(version):
                    print(f"File {filename} is vulnerable to CVE-2023-20052!")

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--clamav-dir", help="ClamAV installation directory", default="/usr/local/clamav")
parser.add_argument("directory", help="Directory to scan")
args = parser.parse_args()

# If the clamav-dir argument is not specified, use the default installation directory
if not args.clamav_dir:
    args.clamav_dir = "/usr/local/clamav"

# Set the clamscan binary path based on the specified ClamAV installation directory
clamscan_path = os.path.join(args.clamav_dir, "bin", "clamscan")

# Scan the specified directory for files
for filename in os.listdir(args.directory):
    if os.path.isfile(os.path.join(args.directory, filename)):
        check_file_for_vulnerability(clamscan_path, os.path.join(args.directory, filename))
