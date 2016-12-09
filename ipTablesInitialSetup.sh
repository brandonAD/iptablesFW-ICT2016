#!/bin/sh
# ipTablesInitialSetup.sh
#
# This file is a document of the initial setup used for our IPTables 
# Firewalls 1 and 2 to establish full connectivity everywhere in the
# topology. As we moved into the later parts of the IPTables lab, these
# default configurations changed a lot. This document provides as the
# initial setup from before we started writing more in-depth IPTables
# rules.
#
# - Khalil Stemmler, Alex Kaczmarek, Brandon Dwyer
#
# ===================================================== #
# ================= FIREWALL 1 ======================== #
# ===================================================== #
# 
#
# ========================================
# ======= INTERFACE CONFIGURATION ========
#
#auto lo
#iface lo inet loopback
#
#iface enp0s3 inet dhcp
#
#iface enp0s8 inet static
#       address 192.168.0.1
#       netmask 255.255.0.0
#       network 192.168.0.0
#       broadcast 192.168.0.255
#       dns-nameservers 8.8.8.8         

#iface enp0s9 inet static
#       address 10.0.0.1
#       netmask 255.255.0.0
#       broadcast 10.0.0.255
#       network 10.0.0.0
#       dns-nameservers 8.8.8.8

# =================================
#       Routing Configuration
# =================================

# echo "1" > /proc/sys/net/ipv4/ip_forward
# route add -net 172.16.0.0 netmask 255.255.0.0 gw 192.168.0.2 dev enp0s8
# route add -net 10.0.0.0 netmask 255.255.0.0 dev enp0s9

# =================================
#       Variables
# =================================

PRODUCTION="172.16.0.0/16"
DMZ="192.168.0.0/16"
CORP="10.0.0.0/16"

# =================================
#       IPTABLES (Basic Setup)
# =================================

# Clear all tables and chains (default and user-defined)
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# Set default policy 
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Receive/Send traffic to DMZ
iptables -A INPUT -s $DMZ -j ACCEPT
iptables -A OUTPUT -d $DMZ -j ACCEPT

# Allow NAT from internal sites to the internet
iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

# Permit Internet Access to each site
iptables -A FORWARD -s 0.0.0.0/0 -d $PRODUCTION,$DMZ,$CORP -j ACCEPT
iptables -A FORWARD -d $PRODUCTION,$DMZ,$CORP -d 0.0.0.0/0 -j ACCEPT

# Access Internet from Firewall
iptables -A OUTPUT -d 0.0.0.0/0 -j ACCEPT
iptables -A INPUT -s 0.0.0.0/0 -j ACCEPT


# ===================================================== #
# ================= FIREWALL 2 ======================== #
# ===================================================== #
# 
#
# ========================================
# ======= INTERFACE CONFIGURATION ========
#
#auto lo
#iface lo inet loopback
#
#iface enp0s3 inet static
# address 172.16.0.1
# netmask 255.255.0.0
# network 172.16.0.0
# broadcast 172.16.0.255
# dns-nameservers 8.8.8.8   

#iface enp0s8 inet static
# address 192.168.0.2
# netmask 255.255.0.0
# broadcast 192.168.0.255
# network 192.168.0.0
# dns-nameservers 8.8.8.8

# =================================
#       Routing Configuration
# =================================
# echo "1" > /proc/sys/net/ipv4/ip_forward
# route add -net 0.0.0.0 netmask 0.0.0.0 gw 192.168.0.1 dev enp0s8

# =================================
# ===== IPTABLES CONFIG ===========

# This script contains the basic config of FW2 for reachability in our topology.

# =================================
# Variables
# =================================

PRODUCTION="172.16.0.0/16"
DMZ="192.168.0.0/16"
CORP="10.0.0.0/16"

# =================================
# IPTABLES (Basic Setup)
# =================================

# Clear all tables and chains (default and user-defined)
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# Set default policy 
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow local ICMP Traffic
iptables -A INPUT -p icmp -i enp0s3 -s $PRODUCTION -j ACCEPT
iptables -A INPUT -p icmp -i enp0s8 -s $DMZ -j ACCEPT

# Allow outgoing ICMP traffic
iptables -A OUTPUT -p icmp -o enp0s3 -j ACCEPT
iptables -A OUTPUT -p icmp -o enp0s8 -j ACCEPT

# Allow Internet traffic
iptables -A FORWARD -s $PRODUCTION -d 0.0.0.0/0 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -d $PRODUCTION -j ACCEPT

# Access Internet from Firewall
iptables -A OUTPUT -o enp0s8 -j ACCEPT
iptables -A INPUT -i enp0s8 -j ACCEPT
