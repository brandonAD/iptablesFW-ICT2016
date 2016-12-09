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
PROD_ADMIN="172.16.0.11" #Production Administrator
DMZ="192.168.0.0/16" #Demilitarized Zone Subnet
DMZ_ADMIN="192.168.0.11"
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
#	     Create new User Defined Chains
#########################################################

#This chain is a pre-check before any forwarding
iptables -N INIT

#These chains and rules are for Section G, No. 7. Tracking packets in and out of the DMZ
iptables -N dmzPacketsIn
iptables -A dmzPacketsIn --source $ANY --jump RETURN

iptables -N dmzPacketsOut
iptables -A dmzPacketsOut --source $ANY --jump RETURN

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

#This chain is for Section D, No.6
iptables -N logInvalidSSHtoDMZ

#This chain is for adding blocked hosts to a blacklist
iptables -N commonScans

#Logging with a Silent Drop
iptables -N silentLogMalformedPackets
iptables -A silentLogMalformedPackets -j LOG --log-prefix "[Malformed Packet - Silent Drop]: "
iptables -A silentLogMalformedPackets -j DROP

#Logging with an ICMP Response
iptables -N icmpLogMalformedPackets
iptables -A icmpLogMalformedPackets -j LOG --log-prefix "[Malformed Packet - ICMP Error Sent]: "
iptables -A icmpLogMalformedPackets -j REJECT -reject-with icmp-net-prohibited


#Set IPTables Policy for DEFAULT DENY
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP

###################################################
#	     Firewall FORWARD Chain
###################################################

	#These two rules are for Section G, No.7. Tracking DMZ packets in and out.
iptables -A FORWARD --source $DMZ --destination $ANY --jump dmzPacketsOut
iptables -A FORWARD --source $ANY --destination $DMZ --jump dmzPacketsIn

	#All packets are subjected to this check
iptables -A FORWARD --source $ANY --destination $ANY --jump INIT

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

	#prodIN is handled at firewall 2
iptables -A CORPtoPROD --jump corpOUT
iptables -A CORPtoPROD --jump ACCEPT

iptables -A CORPtoINET --jump corpOUT
iptables -A CORPtoINET --jump ACCEPT

	#prodIN is handled at firewall 2
iptables -A DMZtoPROD --jump dmzOUT
iptables -A DMZtoPROD --jump ACCEPT

iptables -A DMZtoCORP --jump dmzOUT
iptables -A DMZtoCORP --jump corpIN
iptables -A DMZtoCORP --jump ACCEPT

iptables -A DMZtoINET --jump dmzOUT
iptables -A DMZtoINET --jump ACCEPT

	#prodIN is handled at firewall 2
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

iptables -A logInvalidSSHtoDMZ -m limit --limit 4/minute --limit-burst 6 --jump LOG --log-prefix "[INVALID DMZ HOST ACCES]"
iptables -A logInvalidSSHtoDMZ --jump DROP

###################################################
#               PRODUCTION RULES
###################################################

####################
# PART A: OUTGOING
####################

# No.1
iptables -A prodOUT --protocol tcp --destination $CORP --destination-port 1:1024 --jump RETURN

# No.2
iptables -A prodOUT --protocol tcp --destination $ANY --destination-port 1025:65535 --jump RETURN

# No.3
iptables -A prodOUT --protocol udp --destination-port 53 --jump RETURN
iptables -A prodIN --protocol udp --source-port 53 --jump RETURN

# No.4
iptables -A prodOUT --protocol tcp --destination $DMZ --destination-port 1:65535 --jump RETURN

# No.5
iptables -A prodOUT --protocol icmp --icmp-type 8 --destination $ANY --jump RETURN

# No.6
iptables -I prodOUT --protocol udp -m conntrack --ctstate INVALID --jump logAndDrop
iptables -I prodOUT --protocol tcp -m conntrack --ctstate INVALID --jump logAndDrop

# No.7
iptables -A prodIN --protocol icmp -m conntrack --ctstate ESTABLISHED,RELATED --jump RETURN

#Default action if there are no matches
iptables -A prodIN --source $ANY --jump logAndDrop

####################
# PART B: INCOMING
####################

# No.1:
iptables -A prodIN --protocol tcp --source 10.0.25.0/24 --jump RETURN

# No.2:
iptables -A prodIN --protocol tcp --source $CORP --destination-port 443 --jump RETURN

# No 3:
iptables -A prodIN --protocol tcp --destination-port 22 --source $DMZ -m limit --limit 6666/second --jump RETURN

# No.4:
iptables -A prodIN --source $DMZ --destination $MCAST --jump RETURN

# No.5:
iptables -A prodIN --protocol icmp --icmp-type 8 --source $DMZ,$CORP -j RETURN

#Default action if there are no matches
iptables -A prodIN --source $ANY --jump logAndDrop

###################################################
#                 DMZ RULES
###################################################

####################
# PART C: OUTGOING
####################

# No.1a:
iptables -A dmzOUT --protocol tcp --destination-port 22 --destination $PROD_ADMIN -j RETURN

# No.1b:
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#Default action; detailed logging is enabled on this chain
iptables -A dmzOUT --source $ANY --jump LOG --log-level 7 --log-prefix "Verbose Logging (DMZ OUTBOUND): "
iptables -A dmzOUT --source $ANY --jump DROP

####################
# PART D: INCOMING
####################

# No.1:
iptables -A dmzIN --protocol tcp --source $ANY -m multiport --destination-port 80,25,443 -j RETURN

# No.2:
iptables -A dmzIN --protocol tcp --source $ANY --destination-port 80 -m connbytes --connbytes 12000000:20000000 -connbytes-mode bytes -j logAndDrop

# No.3:
iptables -A dmzIN --protocol tcp --syn -m connlimit --connlimit-above 10 -connlimit-mask 32 -j logAndDrop

# No.4a:
	#Allow ICMP echo requests from INSIDE. This is an outgoing command in the "incoming" section
iptables -I dmzOUT --protocol icmp --icmp-type echo-request --jump RETURN

# No.4b:
iptables -A dmzIN --protocol icmp -m conntrack --ctstate ESTABLISHED,RELATED --jump RETURN

# No.5:
	#If SSH requests exceed 10 per second, drop the packet (on a per-IP basis)
iptables -A dmzIN --source $ANY --protocol tcp --destination-port 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/s --hashlimit-mode srcip --hashlimit-name SSH --jump logAndDrop
iptables -A dmzIN --source $PROD_ADMIN --protocol tcp --destination-port 22 --jump RETURN
	#The drops below disallow SSH from the PROD and CORP subnets, excluding the admin machine allowed above
iptables -A dmzIN --source $PROD --protocol tcp --destination-port 22 --jump logAndDrop
iptables -A dmzIN --source $CORP --protocol tcp --destination-port 22 --jump logAndDrop
	#The below rule will catch internet SSH traffic
iptables -A dmzIN --source $ANY --protocol tcp --destination-port 22 --jump RETURN

# No.6:
iptables -I dmzIN --protocol tcp --source $DMZ_ADMIN --destination-port 22 -m conntrack --ctstate INVALID --jump logInvalidSSHtoDMZ

#Default action if there are no matches
iptables -A dmzIN --source $ANY --jump logAndDrop

###################################################
#               CORPORATE RULES
###################################################

####################
# PART E: OUTGOING
####################

# No.1:
iptables -A corpOUT --protocol tcp --source-port 1025:65535 --destination-port 1025:65535 --jump logAndDrop

# No.2:
iptables -A corpOUT --protocol tcp --destination $DMZ --destination-port 1:1024 --jump RETURN

# No.3:
iptables -A corpOUT --protocol icmp --destination $PROD --jump RETURN
	#ICMP type 8 is an echo-request
iptables -A corpOUT --protocol icmp --icmp-type 8 --destination $DMZ --jump RETURN

# No.4:
iptables -A corpOUT --protocol tcp --source $CORP_ADMIN --destination $DMZ_SERVER,10.0.0.1,192.168.0.2 --destination-port 22 --jump RETURN

# No.5:
iptables -A corpOUT --protocol udp --destination $ANY --destination-port 53 --jump RETURN

# No.6:
iptables -A corpOUT --destination $MCAST -out-interface enp0s3 --jump logAndDrop
iptables -A corpOUT --destination $MCAST -out-interface enp0s8 --jump RETURN

# Rule for allowing SSH access from the internet to 10.0.16.0/20
	#SSH attempts from DMZ and PROD are dropped while incoming so additional drop rules are not necessary here
iptables -A corpOUT --protocol tcp --source 10.0.16.0/20 --source-port 22 --destination $ANY --jump RETURN

#Default action if there are no matches
iptables -A corpOUT --source $ANY --jump logAndDrop

####################
# PART F: INCOMING
####################

# No.1:
	#Allowing Section A, No.1 into Corporate
iptables -A corpIN --protocol tcp --source $PROD --destination-port 1:1024 --jump RETURN
	#Allowing Section A, No.5 into Corporate
iptables -A corpIN --source $PROD --protocol icmp --icmp-type icmp-request

# No.2:
iptables -A corpIN --protocol tcp --source $DMZ --destination 10.0.16.0/20 --destination-port 22 --jump logAndDrop
iptables -A corpIN --protocol tcp --source $PROD --destination 10.0.16.0/20 --destination-port 22 --jump logAndDrop
iptables -A corpIN --protocol tcp --source $ANY --destination 10.0.16.0/20 --destination-port 22 --jump RETURN

#Default action if there are no matches
iptables -A corpIN --source $ANY --jump logAndDrop

###################################################
#               OTHER  RULES
###################################################

####################
# PART G
####################

# No.1:
iptables -A INIT --in-interface enp0s3 -m string --algo bm --string "cmd.exe" --jump logAndDrop

# No.2:
iptables -t mangle -A INIT --out-interface enp0s3 --protocol gre -jump TCPMSS --set-mss 1000

# No.3:
iptables -A INPUT --in-interface enp0s3 --source 172.16.0.0/16,192.168.0.0/16 -j logAndDrop

# No.4:
	#What is an RFP Check?

# No.5:
iptables -A INIT --source $ANY --protocol tcp ! --tcp-option 8 -logAndDrop

# No.6:
	#Block all source addresses in the blockedHosts iphash (to Firewall or Internal)
iptables -A INPUT -m set --match-set blockedHosts src --jump logAndDrop
iptables -A INIT -m set --match-set blockedHosts sec --jump logAndDrop

	#Tries to connect to a well known port that your servers are not supporting
iptables -A INPUT --protocol tcp -m multiport ! --dports 80,22,443,20 --jump SET --add-set blockedHosts src
iptables -A INIT --out-interface enp0s8 --protocol tcp -m multiport ! --dports 80,22,443,20 --jump SET --add-set blockedHosts src

	#No flags set at all
iptables -A commonScans --protocol tcp --tcp-flags ALL NONE --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags ALL NONE --jump logAndDrop

	#SYN and FIN both set
iptables -A commonScans --protocol tcp --tcp-flags SYN,FIN SYN,FIN --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags SYN,FIN SYN,FIN --jump logAndDrop

	#SYN and RST both set
iptables -A commonScans --protocol tcp --tcp-flags SYN,RST SYN,RST --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags SYN,RST SYN,RST --jump logAndDrop

	#FIN and RST both set
iptables -A commonScans --protocol tcp --tcp-flags FIN,RST FIN,RST --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags FIN,RST FIN,RST --jump logAndDrop

	#Only FIN bit set without expected accompanying ACK
iptables -A commonScans --protocol tcp --tcp-flags ACK,FIN FIN --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags ACK,FIN FIN --jump logAndDrop

	#PSH is the only bit set without expected accompanying ACK
iptables -A commonScans --protocol tcp --tcp-flags ACK,PSH PSH --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags ACK,PSH PSH --jump logAndDrop

	#URG is the only bit set without expexted accompanying ACK
iptables -A commonScans --protocol tcp --tcp-flags ACK,URG URG --jump SET --add-set blockedHosts src
iptables -A commonScans --protocol tcp --tcp-flags ACK,URG URG --jump logAndDrop

	#Scan INPUT and FORWARD on every packet. The "-I" is to insert it at the top of the chain.
iptables -I INIT -j commonScans
iptables -A INPUT -j commonScans

# No.7:
	#The script to track is run separately. "DMZpacketCount.sh"

# No.8:
	#ICMP response to CORP and PROD hosts
iptables -A INIT --source $PROD,$CORP -m conntrack --ctstate INVALID -j icmpLogMalformedPackets
iptables -A INPUT --source $PROD,$CORP -m conntrack --ctstate INVALID -j icmpLogMalformedPackets

	#stealth mode drop method to outside hosts
iptables -A INIT -m conntrack --ctstate INVALID -j silentLogMalformedPackets
iptables -A INPUT -m conntrack --ctstate INVALID -j silentLogMalformedPackets

###################################################
#                 NAT RULES
###################################################

#SNAT so internal hosts can reach the internet

iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE







