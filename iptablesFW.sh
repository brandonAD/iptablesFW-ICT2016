#!/bin/bash

##########################################################
#  Written by: 	Brandon A. Dwyer
#		Khalil Stemmler
#		Alexander J. Kaczmarek
#
#  Internet Communications Technology - Class of 2017
#
#  IPTABLES FIREWALL LAB - OCTOBER 2016
#
################ iptablesFW.sh ###########################
#
#This script contains all of the rules that were written
#to successfully fulfill the requirements of William
#Farkas' IPTables Lab (October 2016).
#
#IPTables is an extremely flexible and powerful Firewall.
#It allows manipulation of traffic by using a rule-based
#system to make decisions. The unique benefit of IPTables
#is the degree of granularity that can be used during
#packet matching.
#
#
#In addition, the choice of stateless or stateful rules
#is given to the user. This allows the firewall to
#greatly increase its ability to make decisions when
#deemed necessary.
#
#This script is the result of research done to gain a
#greater appreciation for firewall security.
#
##########################################################


###################################################
###################################################
###################################################
#		    FIREWALL 1		  	  #
###################################################
###################################################
###################################################


###################################################
#		INITIALIZATION
###################################################

#Define variables

PROD="172.16.0.0/16" #Production Subnet
DMZ="192.168.0.0/16" #Demilitarized Zone Subnet
DMZ_SERVER="192.168.0.10" #Demilitarized Zone Server
CORP="10.0.0.0/16" #Corporate Subnet
CORP_ADMIN="10.0.0.11" #Corporate Administrator
MCAST="224.0.0.0/4" #Multicast range
ANY="0.0.0.0/0" #Internet/All

#Reset Iptables' current configuration to default

iptables -F #Flush IPTables rules
iptables -Z #Zero out Chain counters
iptables -X #Deletes all non-default chains

#Create new User Defined Chains

iptables -N prodIN
iptables -N prodOUT
iptables -N dmzIN
iptables -N dmzOUT
iptables -N corpIN
iptables -N corpOUT

iptables -N logAndDrop


#Set IPTables Policy for DEFAULT DENY
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP



###################################################
#                LOGGING RULES
###################################################

iptables -A logAndDrop --source $ANY --jump LOG
iptables -A logAndDrop --source $ANY --jump DROP


###################################################
#               PRODUCTION RULES
###################################################



###################################################
#		  DMZ RULES
###################################################



###################################################
#               CORPORATE RULES
###################################################

####################
# PART E: OUTGOING
####################

# No.1,2: INCOMPLETE
iptables -A corpOUT --protocol tcp --source-port 1025:65535 --destination-port 1025:65535 --jump logAndDrop
iptables -A corpOUT --protocol tcp --destination $DMZ --destination-port 1025:65535 --jump logAndDrop
iptables -A corpOUT --protocol tcp --destination $ANY  --jump ACCEPT

# No.3:
iptables -A corpOUT --protocol icmp --destination $PROD --jump ACCEPT
	#ICMP type 8 is an echo-request
iptables -A corpOUT --protocol icmp --icmp-type 8 --destination $DMZ --jump ACCEPT

# No.4:
iptables -A corpOUT --protocol tcp --source $CORP_ADMIN --destination $DMZ_SERVER,10.0.0.1,192.168.0.2 --destination-port 22 --jump ACCEPT

# No.5:
iptables -A corpOUT --protocol udp --destination $ANY --destination-port 53 --jump ACCEPT

# No.6:
iptables -A corpOUT --destination $MCAST -out-interface enp0s3 --jump logAndDrop
iptables -A corpOUT --destination $MCAST -out-interface enp0s8 --jump ACCEPT

#Default action if there are no matches
iptables -A corpOUT --source $ANY --jump logAndDrop

####################
# PART F: INCOMING
####################

# No.1,2: INCOMPLETE

# No.3:
iptables -A corpIN --protocol icmp --source $PROD --jump ACCEPT
	#ICMP type 0 is an echo-reply
iptables -A corpIN --protocol icmp --icmp-type 0 --source $DMZ --jump ACCEPT

# No.4:
iptables -A corpIN --protocol tcp --destination $CORP_ADMIN --source $DMZ_SERVER,10.0.0.1,192.168.0.2 --source-port 22 --jump ACCEPT

# No.5:
iptables -A corpIN --protocol udp --source $ANY --source-port 53 --jump ACCEPT

# No.6:
iptables -A corpIN --destination $MCAST --in-interface enp0s3 --jump logAndDrop
iptables -A corpIN --destination $MCAST --in-interface enp0s9 --jump ACCEPT

#Default action if there are no matches
iptables -A corpOUT --source $ANY --jump logAndDrop
###################################################
#                 NAT RULES
###################################################

#SNAT so internal hosts can reach the internet

iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE







