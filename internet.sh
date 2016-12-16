#!/bin/bash

iptables -F
iptables -X
iptables -Z

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -A POSTROUTING -o eth0 --jump MASQUERADE
