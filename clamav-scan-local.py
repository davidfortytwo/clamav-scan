#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import os
import re
import subprocess

def is_vulnerable_version(version):
    vulnerable_versions = ["1.0.0", "0.105.1", "0.103.7"]
    for v in vulnerable_versions:
        if version.startswith(v):
            return True
    return False

# Find the location of the clamscan binary
try:
    clamscan_path = subprocess.check_output(['which', 'clamscan']).strip()
    clamscan_path = clamscan_path.decode()
except subprocess.CalledProcessError:
    print("ClamAV is not installed on this system")
    exit()

# Extract the directory path from the clamscan binary path
clamav_dir = os.path.dirname(os.path.dirname(clamscan_path))

# Check the version of ClamAV installed on the system
clamscan_output = subprocess.check_output([clamscan_path, '--version'])
match = re.search(b'ClamAV ([0-9.]+)', clamscan_output)
if match:
    version = match.group(1).decode()
    if is_vulnerable_version(version):
        print(f"ClamAV version {version} is vulnerable to CVE-2023-20032 and CVE-2023-20052. Please upgrade ClamAV to a non-vulnerable version.")
        print("Upgrade instructions:")
        print("- For Debian/Ubuntu: https://www.clamav.net/documents/installing-clamav-on-debian-and-ubuntu-linux-distributions")
        print("- For Red Hat/CentOS: https://www.clamav.net/documents/installing-clamav-on-redhat-and-centos-linux-distributions")
        print("- For other Linux distributions: https://www.clamav.net/documents/installing-clamav-on-linux")
    else:
        print(f"ClamAV version {version} is not vulnerable to CVE-2023-20032 and CVE-2023-20052.")
else:
    print("ClamAV is not installed on this system")
