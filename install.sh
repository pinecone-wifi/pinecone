#!/usr/bin/env sh

# This installation script currently installs Kali Linux repo packages.
apt update
apt install -y python3-venv dnsmasq hostapd-wpe
rm -rf venv
python3 -m venv venv
. venv/bin/activate
pip3 install --upgrade pip setuptools wheel
pip3 install -r requirements.txt
