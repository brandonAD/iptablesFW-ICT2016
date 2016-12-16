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
echo "[1] CREATING VARIABLES..."
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

echo "[2] FLUSHING IPTABLES + Installing dependencies..."
iptables -F 		#Flush default table (forward) IPTables rules
iptables -Z 		#Zero out default table (forward) Chain counters
iptables -X 		#Deletes all non-default chains (in forward table)
iptables -t mangle -F	#Flushes the mangle table rules
iptables -t mangle -X   #Deletes all non-default chains in mangle table
ipset -X    		#Deletes all ipset hashtables

#Create a hashtable that will store all hosts to a blacklist
apt install ipset -y
ipset -N blockedHosts iphash

#########################################################
#            Create new User Defined Chains
#########################################################

echo "[3] CREATING UDCs..."

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
iptables -A icmpLogMalformedPackets -j REJECT --reject-with icmp-net-prohibited

echo "[4] SETTING DEFAULT POLICY..."

#Set IPTables Policy for DEFAULT DENY
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP

###################################################
#            Firewall FORWARD Chain
###################################################
echo "[5] SETTING UP JUMPS TO UDCs FROM FORWARD CHAIN..."

	#These two rules are for Section G, No.7. Tracking DMZ packets in and out.
iptables -A FORWARD --source $DMZ --destination $ANY --jump dmzPacketsOut
iptables -A FORWARD --source $ANY --destination $DMZ --jump dmzPacketsIn

	#All packets are subjected to this check
iptables -A FORWARD --source $ANY --destination $ANY --jump INIT

iptables -A FORWARD --source $CORP --destination $PROD --jump CORPtoPROD
iptables -A FORWARD --source $DMZ --destination  $PROD --jump DMZtoPROD
iptables -A FORWARD --source $PROD --destination $DMZ --jump PRODtoDMZ
iptables -A FORWARD --source $PROD --destination $CORP --jump PRODtoCORP
iptables -A FORWARD --source $PROD --destination $ANY --jump PRODtoINET
iptables -A FORWARD --source $ANY --destination $PROD --jump INETtoPROD

###################################################
#          SOURCE DESTINATION PAIR UDCs
###################################################

echo "[6] ADDING JUMPS - SRC=CORP"
	#corpOUT is handled at Firewall 1
iptables -A CORPtoPROD --jump prodIN
itpables -A CORPtoPROD --jump ACCEPT

echo "[7] ADDING JUMPS - SRC=DMZ"
	#dmzOUT is handled at Firewall 1
iptables -A DMZtoPROD --jump prodIN
iptables -A DMZtoPROD --jump ACCEPT

echo "[8] ADDING JUMPS - SRC=PROD"
iptables -A PRODtoDMZ --jump prodOUT
iptables -A PRODtoDMZ --jump dmzIN
iptables -A PRODtoDMZ --jump ACCEPT

	#corpIN is handled at Firewall 1
iptables -A PRODtoCORP --jump prodOUT
iptables -A PRODtoCORP --jump ACCEPT

iptables -A PRODtoINET --jump prodOUT
iptables -A PRODtoINET --jump ACCEPT

echo "[9] ADDING JUMPS - SRC=INET"
iptables -A INETtoPROD --jump prodIN
iptables -A INETtoPROD --jump ACCEPT

###################################################
#                LOGGING RULES
###################################################

echo "[10] ADDING LOGGING RULES"
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
echo "[11] ADDING PRODUCTION [OUT] RULES..."

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
iptables -A prodOUT --source $ANY --jump logAndDrop

####################
# PART B: INCOMING
####################

echo "[12] ADDING PRODUCTION [IN] RULES..."


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
#		  DMZ RULES
###################################################

####################
# PART D: INCOMING
####################

echo "[13] ADDING DMZ [IN] RULES..."

# No.1:
iptables -A dmzIN --protocol tcp --source $ANY -m multiport --destination-port 80,25,443 -j RETURN

# No.2:
iptables -A dmzIN --protocol tcp --source $ANY --destination-port 80 -m \
connbytes --connbytes 12000000:20000000 --connbytes-mode bytes --connbytes-dir both -j logAndDrop

# No.3:
iptables -A dmzIN --protocol tcp --syn -m connlimit --connlimit-above 10 --connlimit-mask 32 -j logAndDrop

# No.4a:
        #Allow ICMP echo requests from INSIDE. This is an outgoing command in the "incoming" section
iptables -I dmzOUT --protocol icmp --icmp-type echo-request --jump RETURN

# No.4b:
iptables -A dmzIN --protocol icmp -m conntrack --ctstate ESTABLISHED,RELATED --jump RETURN

# No.5:
        #If SSH requests exceed 10 per second, drop the packet (on a per-IP basis)
iptables -A dmzIN --source $ANY --protocol tcp --destination-port 22 -m conntrack --ctstate NEW  \
-m hashlimit --hashlimit-above 10/s --hashlimit-mode srcip --hashlimit-name SSH --jump logAndDrop

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
#             NO CORPORATE RULES
###################################################



###################################################
#               OTHER  RULES
###################################################

####################
# PART G
####################

echo "[14] ADDING 'OTHER' RULES..."

# No.1:
iptables -A INIT --in-interface enp0s3 -m string --algo bm --string "cmd.exe" --jump logAndDrop

echo "[14.2] Creating GRE Mangle Table..."
# No.2:
# Create a reduce GRE MSS UDC table (mangle instead of forward by default)
iptables -N REDUCE_GRE_MSS -t mangle
iptables -t mangle -A REDUCE_GRE_MSS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000 

iptables -N MANGLE_GRE -t mangle
iptables -t mangle -A MANGLE_GRE -p gre ! --destination $CORP,$PROD,$DMZ --jump REDUCE_GRE_MSS

echo "[14.2] Creating GRE Mangle Table... Done"

# On GRE packets, send to GRE_REDUCE_MSS to reduce MSS if SYN packet
#iptables -t mangle -A INIT -p gre --out-interface enp0s3 --jump REDUCE_GRE_MSS

# No.3:
iptables -A INPUT --in-interface enp0s3 --source 172.16.0.0/16,192.168.0.0/16 -j logAndDrop

# No.4:
        #What is an RFP Check?

# No.5:
iptables -A INIT --source $ANY --protocol tcp ! --tcp-option 8 -j logAndDrop

# No.6:
        #Block all source addresses in the blockedHosts iphash (to Firewall or Internal)
iptables -A INPUT -m set --match-set blockedHosts src --jump logAndDrop
iptables -A INIT -m set --match-set blockedHosts src --jump logAndDrop

        #Tries to connect to a well known port that your servers are not supporting
iptables -A INPUT --protocol tcp -m multiport ! --dports 80,22,443,20  \
--jump SET --add-set blockedHosts src

iptables -A INIT --out-interface enp0s8 --protocol tcp \
-m multiport ! --dports 80,22,443,20 --jump SET --add-set blockedHosts src

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

# No.9:
        #The script showing routing tables and configuration is separate. "IPTablesInitialSetup.sh"








