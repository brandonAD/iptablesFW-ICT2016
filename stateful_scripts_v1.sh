#!/bin/bash


### ============================= B - 3 =============================== ###
# SSH connections from DMZ - but rate transfer threshbold at 10 MB (per second?)

# https://www.cyberciti.biz/faq/linux-traffic-shaping-using-tc-to-control-http-traffic/
# Limiting Module: http://www.oocities.org/youssef116/writing/ratelim.html

# Approach #1) consider max 1500 bytes, = to 6666 per second
iptables -A -p tcp --dport 22 -s $DMZ -m limit --limit 6666/second 


### ============================= D - 2 =============================== ###
# All outside connections on port 80 are terminated if they exceeed 12 MB
# - we need to use connbytes
iptables -A FORWARD -p tcp --dport 80 -m connbytes --connbytes 12000000:20000000 --conbytes-mode bytes -j DROP

### ============================= D - 3 =============================== ###
# Not more than 10 concurrent connections allowed from outside
iptables -A FORWARD -d $DMZ -p tcp --syn -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP

### ============================= D - 4 =============================== ###
# Only ICMP echo requests from INSIDE & ICMP stateful errors from any.

# Allow ICMP echo requests from INSIDE
iptables -A FORWARD -s $DMZ -d $ANY -p icmp --icmp-type echo-request -j ACCEPT

# Allow stateful resopnses and errors from any
iptables -A FORWARD -p icmp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


### ============================= D - 5 =============================== ###

# "SSH opens" from admin machine in Production or External (never the other
# way around) accepted. Limit SSH attempts to once per 100 ms per source IP (hashlimits)
iptables -A FORWARD -s $ANY -p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/sec --hashlimit-mode srcip --hashlimit-name ssh -j DROP
iptables -A FORWARD -s $ADMIN_MACHINE_PROD  -j ACCEPT
iptables -A FORWARD -s $PROD -j DROP
iptables -A FORWARD -s $CORP -j DROP
iptables -A FORWARD -s $ANY -j ACCEPT

### ============================= D - 6 =============================== ###

# Log all invalid attempts to access DMZ host but limit the log entries to
# 4 per minute with a burst of 6
iptables -N LOG_INVALID_ACCESS_TO_HOST
iptables -A LOG_INVALID_ACCESS_TO_HOST -m limit --limit 4/minute --limit-burst 6 -j LOG --log-prefix "[INVALID DMZ HOST ACCESS]: "
iptables -A LOG_INVALID_ACCESS_TO_HOST -j DROP

# (place rule at the bottom of FORWARD for access to DMZ resources)
iptables -A FORWARD -j LOG_INVALID_ACCESS_TO_HOST

### ============================= G - 1 =============================== ###

# Block any inbound TCP packets with a well known malware signature
# http://blog.nintechnet.com/how-to-block-w00tw00t-at-isc-sans-dfind-and-other-web-vulnerability-scanners/

iptables -N MALWARE_DPI
iptables -A MALWARE_DPI -m string --algo bm --string "cmd.exe" -j DROP

iptables -INPUT -p tcp -j MALWARE_DPI
iptables -FORWARD -p tcp -j MALWARE_DPI

### ============================= G - 2 =============================== ###
# Reduce MSS for GRE packet 
iptables -t mangle -A POSTROUTING -p gre -p tcp -j TCPMSS --set-mss 1000


### ============================= G - 5 =============================== ###
# Drop packet with no TCP timestamp (may be port scanning)
# http://sharadchhetri.com/2013/06/15/how-to-protect-from-port-scanning-and-smurf-attack-in-linux-server-by-iptables/
# --> good use of the 'recent' module here

iptables -A INPUT -p tcp --tpc-option ! 8 -j DROP
iptables -A FORWARD -p tcp --tpc-option ! 8 -j DROP

### ============================= G - 6 =============================== ###
# Create and enforce a black list on the FW that blocks any IP that:
#   - tries to connect to a well known port (on FW1 or inside) that your servers are not supporting
#   - scans the FW or an inside host

# Create a hashtable that will store all hosts to blacklist
ipset -N blockedHosts iphash

# Block all src addresses in the blockedHosts iphash
iptables -A INPUT -m set --match-set blockedHosts src -j DROP

# tries to connect to a well known port (on FW1 or inside) that your servers are not supporting
iptables -A FORWARD -o enp0s8 -p tcp -m multiport ! --dports 80,22,443,20 -j SET --add-set blockedHosts src
iptables -A INPUT   -p tcp           -m multiport ! --dports 80,22,443,20 -j SET --add-set blockedHosts src

# Slow down the user trying to do a portscan.
iptables -A INPUT -p tcp -i enp0s3 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp -i enp0s3 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 -j DROP
iptables -A FORWARD -p tcp -i enp0s3 -m state --state NEW -m recent --set
iptables -A FORWARD -p tcp -i enp0s3 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 -j DROP

# ========================
#     Common Scans (UDC)
#       - adds hosts with common tcp flag patterns for scanning to blacklist
# ========================

# scans the FW or an inside host
iptables -N commonScans 
# These scripts drop common stealth scans by dropping suspicious TCP Flags.

# No flags at all
iptables -A commonScans   -p tcp --tcp-flags ALL NONE -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags ALL NONE -j DROP

# SYN and FIN are set
iptables -A commonScans   -p tcp --tcp-flags SYN,FIN SYN,FIN -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# SYN and RST are both set
iptables -A commonScans   -p tcp --tcp-flags SYN,RST SYN,RST -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# FIN and RST are both set
iptables -A commonScans   -p tcp --tcp-flags FIN,RST FIN,RST -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags FIN,RST FIN,RST -j DROP

# Only FIN bit set without expected accompanying ACK
iptables -A commonScans   -p tcp --tcp-flags ACK,FIN FIN -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags ACK,FIN FIN -j DROP

# PSH is the only bit set without expected accompanying ACK
iptables -A commonScans   -p tcp --tcp-flags ACK,PSH PSH -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags ACK,PSH PSH -j DROP

# PSH is the only bit set without expected accompanying URG
iptables -A commonScans   -p tcp --tcp-flags ACK,URG URG -j SET --add-set blockedHosts src
iptables -A commonScans   -p tcp --tcp-flags ACK,URG URG -j DROP

# Scan INPUT and FORWARD on every packet
iptables -A INPUT -j commonScans 
iptables -A FORWARD -j commonScans


#### OTHER RULES / TRICKS ####
## ** ----------------------------------------------------------------- **
# ** Good rule to match all packets conntrack doesn't understand **

iptables -N INVALID_PKTS
# log
iptables -N INVALID_PKTS -A Inval_pkts -m limit --limit 10/s -j LOG --log-prefix "INVALID: " --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-options
# drop
iptables -N INVALID_PKTS -A Inval_pkts-p tcp -m limit --limit 10/s -j REJECT --reject-with tcp-reset
iptables -A FORWARD -m conntrack --ctstate INVALID -j INVALID_PKTS
# this matches all packets that conntrack doesn't understand (high level safety net)
## ** ----------------------------------------------------------------- **
