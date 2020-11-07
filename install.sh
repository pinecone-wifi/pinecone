#!/usr/bin/env sh

# This installation script currently installs Kali Linux repo packages.
apt update
apt install -y python3-venv dnsmasq hostapd-wpe
rm -rf venv
python3 -m venv venv
. venv/bin/activate
# Using pip 20.2.* with the old resolver until py2neo updates its dependency of prompt_toolkit to version >=3...
pip3 install --upgrade 'pip==20.2.*' setuptools wheel
pip3 install -r requirements.txt
echo
echo "Installation of py2neo package will throw an error until its dependency of prompt_toolkit is updated to version >=3, but it should work fine for Pinecone use case."
