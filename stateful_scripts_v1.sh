#!/bin/bash

### ============================= D - 3 =============================== ###


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

