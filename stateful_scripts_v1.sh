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
iptables -A FORWARD -d $DMZ -p tcp --syn -m connlimit --connlimit-above 10 --connlimit-mask 32 -j REJECT --reject-with tcp-reset

### ============================= D - 4 =============================== ###
# Only ICMP echo requests from INSIDE & ICMP stateful errors from any.

# Allow ICMP echo requests from INSIDE
iptables -A FORWARD -s $DMZ -p icmp --icmp-type echo-request -j ACCEPT

# Allow stateful resopnses and errors from any
iptables -A FORWARD -p icmp -m conntrack --ctstate ESTABLISHED, RELATED -j ACCEPT


### ============================= D - 5 =============================== ###

# "SSH opens" from admin machine in Production or External (never the other
# way around) accepted. Limit SSH attempts to once per 100 ms per source IP (hashlimits)
iptables -A FORWARD -s $ADMIN_MACHINE_PROD \
    -p tcp --dport 20           \
    -m hashlimit tcp            \         
    --hashlimit-above 100/ms    \
    --hashlimit-mode srcip      \
    --hashlimit-name ssh        \                       
    -m conntrack --ctstate NEW  
    -j DROP

iptables -A FORWARD -s $ADMIN_MACHINE_EXTERNAL \
    -p tcp --dport 20           \
    -m hashlimit tcp            \         
    --hashlimit-above 100/ms    \
    --hashlimit-mode srcip      \
    --hashlimit-name ssh        \                       
    -m conntrack --ctstate NEW  
    -j DROP

### ============================= D - 6 =============================== ###

# Log all invalid attempts to access DMZ host but limit the log entries to
# 4 per minute with a burst of 6
iptables -N LOG_INVALID_ACCESS_TO_HOST
iptables -A LOG_INVALID_ACCESS_TO_HOST -m limit --limit 4/minute --limit-burst 6 -j LOG --log-prefix "[INVALID DMZ HOST ACCESS]: "
iptables -A LOG_INVALID_ACCESS_TO_HOST -j DROP

# (place rule at the bottom of FORWARD for access to DMZ resources)
iptables -A FORWARD -j LOG_INVALID_ACCESS_TO_HOST



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