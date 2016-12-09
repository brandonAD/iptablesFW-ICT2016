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

#########################################################
#	     Create new User Defined Chains
#########################################################

#These chains identify specific source IP and destination IP pairs
iptables -N CORPtoDMZ
iptables -N CORPtoPROD
iptables -N CORPtoINET
iptables -N DMZtoPROD
iptables -N DMZtoCORP
iptables -N DMZtoINET
iptables -N PRODtoCORP
iptables -N PRODtoINET
iptables -N INETtoPROD
iptables -N INETtoDMZ
iptables -N INETtoCORP

#These chains will be for actual traffic filtration
iptables -N prodIN
iptables -N prodOUT
iptables -N dmzIN
iptables -N dmzOUT
iptables -N corpIN
iptables -N corpOUT

#This chain is to eliminate the need for two commands for logging and dropping
iptables -N logAndDrop


#Set IPTables Policy for DEFAULT DENY
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP

###################################################
#	     Firewall FORWARD Chain
###################################################

iptables -A FORWARD --source $CORP --destination $DMZ --jump CORPtoDMZ
iptables -A FORWARD --source $CORP --destination $PROD --jump CORPtoPROD
iptables -A FORWARD --source $CORP --destination $ANY --jump CORPtoINET
iptables -A FORWARD --source $DMZ --destination  $PROD --jump DMZtoPROD
iptables -A FORWARD --source $DMZ --destination $CORP --jump DMZtoCORP
iptables -A FORWARD --source $DMZ --destination $ANY --jump DMZtoINET
iptables -A FORWARD --source $PROD --destination $CORP --jump PRODtoCORP
iptables -A FORWARD --source $PROD --destination $ANY --jump PRODtoINET
	#Internet facing interface is enp0s3
iptables -A FORWARD --in-interface enp0s3 --destination $PROD --jump INETtoPROD
iptables -A FORWARD --in-interface enp0s3 --destination $DMZ --jump INETtoDMZ
iptables -A FORWARD --in-interface enp0s3 --destination $CORP --jump INETtoCORP

###################################################
#	   SOURCE DESTINATION PAIR UDCs
###################################################
iptables -A CORPtoDMZ --jump corpOUT
iptables -A CORPtoDMZ --jump dmzIN
iptables -A CORPtoDMZ --jump ACCEPT

iptables -A CORPtoPROD --jump corpOUT
iptables -A CORPtoPROD --jump prodIN
iptables -A CORPtoPROD --jump ACCEPT

iptables -A CORPtoINET --jump corpOUT
iptables -A CORPtoINET --jump ACCEPT

iptables -A DMZtoPROD --jump dmzOUT
iptables -A DMZtoPROD --jump prodIN
iptables -A DMZtoPROD --jump ACCEPT

iptables -A DMZtoCORP --jump dmzOUT
iptables -A DMZtoCORP --jump corpIN
iptables -A DMZtoCORP --jump ACCEPT

iptables -A DMZtoINET --jump dmzOUT
iptables -A DMZtoINET --jump ACCEPT

iptables -A PRODtoCORP --jump prodOUT
iptables -A PRODtoCORP --jump corpIN
iptables -A PRODtoCORP --jump ACCEPT

iptables -A PRODtoINET --jump prodOUT
iptables -A PRODtoINET --jump ACCEPT

iptables -A INETtoPROD --jump prodIN
iptables -A INETtoPROD --jump ACCEPT

iptables -A INETtoDMZ --jump dmzIN
iptables -A INETtoDMZ --jump ACCEPT

iptables -A INETtoCORP --jump corpIN
iptables -A INETtoCORP --jump ACCEPT

###################################################
#                LOGGING RULES
###################################################

iptables -A logAndDrop --source $ANY --jump LOG
iptables -A logAndDrop --source $ANY --jump DROP


###################################################
#               PRODUCTION RULES
###################################################

####################
# PART A: OUTGOING
####################

# No.1
iptables -A prodOUT --protocol tcp --destination $CORP --destination-port 1:1024 --jump ACCEPT

# No.2
iptables -A prodOUT --protocol tcp --destination $ANY --destination-port 1025:65535 --jump ACCEPT

# No.3
iptables -A prodOUT --protocol udp --destination-port 53 --jump ACCEPT
iptables -A prodIN --protocol udp --source-port 53 --jump ACCEPT

# No.4
iptables -A prodOUT --protocol tcp --destination $DMZ --destination-port 1:65535 --jump ACCEPT

# No.5
iptables -A prodOUT --protocol icmp --icmp-type 8 --destination $ANY --jump ACCEPT

# No.6
iptables -I prodOUT --protocol udp -m conntrack --ctstate INVALID --jump logAndDrop
iptables -I prodOUT --protocol tcp -m conntrack --ctstate INVALID --jump logAndDrop

# No.7
iptables -A prodIN --protocol icmp -m conntrack --ctstate ESTABLISHED,RELATED --jump ACCEPT

####################
# PART B: INCOMING
####################

# No.1:
iptables -A prodIN --protocol tcp --source 10.0.25.0/24 --jump ACCEPT

# No.2:
iptables -A prodIN --protocol tcp --source $CORP --destination-port 443 --jump ACCEPT

# No.4:
iptables -A prodIN --source $DMZ --destination $MCAST --jump ACCEPT

# No.5:
iptables -A prodIN --protocol icmp --icmp-type 8 --source $DMZ,$CORP -j ACCEPT

#Default action if there are no matches
iptables -A prodIN --source $ANY --jump logAndDrop


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

# Rule for allowing SSH access from the internet to 10.0.16.0/20
	#SSH attempts from DMZ and PROD are dropped while incoming so addition drop rules are not necessary here
iptables -A corpOUT --protocol tcp --source 10.0.16.0/20 --source-port 22 --destination $ANY --jump ACCEPT

#Default action if there are no matches
iptables -A corpOUT --source $ANY --jump logAndDrop

####################
# PART F: INCOMING
####################

# No.1:
	# Inverse of Outgoing No.3
iptables -A corpIN --protocol icmp --source $PROD --jump ACCEPT
		#ICMP type 0 is an echo-reply
iptables -A corpIN --protocol icmp --icmp-type 0 --source $DMZ --jump ACCEPT

	# Inverse of Outgoing No.4:
iptables -A corpIN --protocol tcp --destination $CORP_ADMIN --source $DMZ_SERVER,10.0.0.1,192.168.0.2 --source-port 22 --jump ACCEPT

	# Inverse of Outgoing No.5:
iptables -A corpIN --protocol udp --source $ANY --source-port 53 --jump ACCEPT

	# Inverse of Outgoing No.6:
iptables -A corpIN --destination $MCAST --in-interface enp0s3 --jump logAndDrop
iptables -A corpIN --destination $MCAST --in-interface enp0s9 --jump ACCEPT

# No.2:
iptables -A corpIn --protocol tcp --source $DMZ --destination 10.0.16.0/20 --destination-port 22 --jump logAndDrop
iptables -A corpIn --protocol tcp --source $PROD --destination 10.0.16.0/20 --destination-port 22 --jump logAndDrop
iptables -A corpIn --protocol tcp --source $ANY --destination 10.0.16.0/20 --destination-port 22 --jump ACCEPT

#Default action if there are no matches
iptables -A corpOUT --source $ANY --jump logAndDrop

###################################################
#                 NAT RULES
###################################################

#SNAT so internal hosts can reach the internet

iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE







