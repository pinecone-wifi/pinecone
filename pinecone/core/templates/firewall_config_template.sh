#!/usr/bin/env bash

sysctl -w net.ipv4.ip_forward=1

iptables -t nat -F
iptables -t nat -A POSTROUTING -s {{ subnet }}/{{ netmask }} -o {{ output_iface }} -j MASQUERADE