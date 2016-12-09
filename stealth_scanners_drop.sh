#!/bin/bash
# These scripts drop common stealth scans by dropping suspicious TCP Flags.

# No flags at all
iptables -A INPUT   -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP

# SYN and FIN are set
iptables -A INPUT   -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# SYN and RST are both set
iptables -A INPUT   -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# FIN and RST are both set
iptables -A INPUT   -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A FORWARD -p tcp --tcp-flags FIN,RST FIN,RST -j DROP

# Only FIN bit set without expected accompanying ACK
iptables -A INPUT   -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A FORWARD -p tcp --tcp-flags ACK,FIN FIN -j DROP

# PSH is the only bit set without expected accompanying ACK
iptables -A INPUT   -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A FORWARD -p tcp --tcp-flags ACK,PSH PSH -j DROP

# PSH is the only bit set without expected accompanying URG
iptables -A INPUT   -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A FORWARD -p tcp --tcp-flags ACK,URG URG -j DROP