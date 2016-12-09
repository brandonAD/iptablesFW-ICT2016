#!/bin/bash

####################################################################################
				#DMZ Count Script
####################################################################################

#The UDCs and rules are already executed in the Firewall scripts. These are here for
#reference.



#iptables -N dmzPacketsIn
#iptables -A dmzPacketsIn --source $ANY --jump RETURN

#iptables -N dmzPacketsOut
#iptables -A dmzPacketsOut --source $ANY --jump RETURN

#iptables -A FORWARD --source $DMZ --destination $ANY --jump dmzPacketsOut
#iptables -A FORWARD --source $ANY --destination $DMZ --jump dmzPacketsIn

####################################################################################

DMZinboundPackets=`iptables -nvx -L dmzPacketsIn --line-numbers | grep "\-\-" | tr ' ' ',' | tr -s ',' | cut -f 2 -d ','`

DMZoutboundPackets=`iptables -nvx -L dmzPacketsOut --line-numbers | grep "\-\-" | tr ' ' ',' | tr -s ',' | cut -f 2 -d ','`


echo $(date) " [INBOUND DMZ] Inbound DMZ Packets: " ${DMZinboundPackets} >> /var/log/DMZcount
echo $(date) " [OUTBOUND DMZ] Outbound DMZ Packets: " ${DMZoutbundPackets} >> /var/log/DMZcount
