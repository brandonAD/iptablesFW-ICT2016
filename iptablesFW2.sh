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
#		    FIREWALL 2		  	  #
###################################################
###################################################
###################################################


###################################################
#		INITIALIZATION
###################################################

#Define variables

PROD="172.16.0.0/16" #Production Subnet
DMZ="192.168.0.0/16" #Demilitarized Zone Subnet
DMZ_ADMIN="192.168.0.11" #DMZ Administrator
DMZ_SERVER="192.168.0.10" #Demilitarized Zone Server
CORP="10.0.0.0/16" #Corporate Subnet
CORP_ADMIN="10.0.0.11" #Corporate Administrator
MCAST="224.0.0.0/4" #Multicast range
ANY="0.0.0.0/0" #Internet/All

#Reset Iptables' current configuration to default

iptables -F #Flush IPTables rules
iptables -Z #Zero out Chain counters
iptables -X #Deletes all non-default chains

#Create a hashtable that will store all hosts to a blacklist
ipset -N blockedHosts iphash

#########################################################
#            Create new User Defined Chains
#########################################################

#These chains identify specific source IP and destination IP pairs
iptables -N CORPtoPROD
iptables -N DMZtoPROD
iptables -N PRODtoDMZ
iptables -N PRODtoCORP
iptables -N PRODtoINET
iptables -N INETtoPROD

#These chains will be used for actual traffic filtration
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
#            Firewall FORWARD Chain
###################################################

iptables -A FORWARD --source $CORP --destination $PROD --jump CORPtoPROD
iptables -A FORWARD --source $DMZ --destination  $PROD --jump DMZtoPROD
iptables -A FORWARD --source $PROD --destination $DMZ --jump PRODtoDMZ
iptables -A FORWARD --source $PROD --destination $CORP --jump PRODtoCORP
iptables -A FORWARD --source $PROD --destination $ANY --jump PRODtoINET
iptables -A FORWARD --source $ANY --destination $PROD --jump INETtoPROD

###################################################
#          SOURCE DESTINATION PAIR UDCs
###################################################

	#corpOUT is handled at Firewall 1
iptables -A CORPtoPROD --jump prodIN
itpables -A CORPtoPROD --jump ACCEPT


	#dmzOUT is handled at Firewall 1
iptables -A DMZtoPROD --jump prodIN
iptables -A DMZtoPROD --jump ACCEPT

iptables -A PRODtoDMZ --jump prodOUT
iptables -A PRODtoDMZ --jump dmzIN
iptables -A PRODtoDMZ --jump ACCEPT

	#corpIN is handled at Firewall 1
iptables -A PRODtoCORP --jump prodOUT
iptables -A PRODtoCORP --jump ACCEPT

iptables -A PRODtoINET --jump prodOUT
iptables -A PRODtoINET --jump ACCEPT

iptables -A INETtoPROD --jump prodIN
iptables -A INETtoPROD --jump ACCEPT


###################################################
#               PRODUCTION RULES
###################################################



###################################################
#		  DMZ RULES
###################################################



###################################################
#               CORPORATE RULES
###################################################










