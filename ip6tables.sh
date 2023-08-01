#!/bin/bash
# A bash shell script for ip6tables to protect single hosting / dedicated / vps / colo server running CentOS / Debian / RHEL / or any other Linux distribution.
# -------------------------------------------------------------------------
# Copyright (c) 2023
# This script is licensed under GNU GPL version 2.0 or above

IPT6="/sbin/ip6tables"
 
# Interfaces 
PUB_IF="eth1"
PUB_LO="lo0"
PUB_VPN="eth0"
 
# Custom chain names
CHAINS="chk_tcp6_packets_chain chk_tcp_inbound chk_udp_inbound chk_icmp_packets"
HTTP_SERVER_6="2001:470:1f04:55a::2 2001:470:1f04:55a::3 2001:470:1f04:55a::4 2001:470:1f04:55a::5"
 
echo "Starting IPv6 firewall..."
# first clean old mess
$IPT6 -F
$IPT6 -X
$IPT6 -Z
for table in $(</proc/net/ip6_tables_names)
do
	$IPT6 -t $table -F
	$IPT6 -t $table -X
	$IPT6 -t $table -Z
done
$IPT6 -P INPUT ACCEPT
$IPT6 -P OUTPUT ACCEPT
$IPT6 -P FORWARD ACCEPT
 
# Set default DROP all
$IPT6 -P INPUT DROP
$IPT6 -P OUTPUT DROP
$IPT6 -P FORWARD DROP
 
# Create the chain 
for c in $CHAINS
  do $IPT6 --new-chain $c
done
 
# Input policy
$IPT6 -A INPUT -i $PUB_LO -j ACCEPT
$IPT6 -A INPUT -i $PUB_VPN -j ACCEPT
$IPT6 -A INPUT -i $PUB_IF -j  chk_tcp6_packets_chain
$IPT6 -A INPUT -i $PUB_IF -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT6 -A INPUT -i $PUB_IF -p tcp -j chk_tcp_inbound 
$IPT6 -A INPUT -i $PUB_IF -p udp -j chk_udp_inbound 
$IPT6 -A INPUT -i $PUB_IF -p icmp -j chk_icmp_packets 
$IPT6 -A INPUT -i $PUB_IF -p ipv6-icmp -j chk_icmp_packets   
$IPT6 -A INPUT -i $PUB_IF -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "INPUT OUTPUT "
$IPT6 -A INPUT -i $PUB_IF -j DROP
 
# Output policy
$IPT6 -A OUTPUT -o $PUB_LO -j ACCEPT
$IPT6 -A OUTPUT -o $PUB_VPN -j ACCEPT
$IPT6 -A OUTPUT -o $PUB_IF -j ACCEPT 
$IPT6 -A OUTPUT -o $PUB_IF -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "DROP OUTPUT "
 
### Custom chains ###
# Bad packets chk 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "Bad tcp packets" 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "Bad tcp packets" 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "BAD tcp" 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "Bad tcp" 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "Bad tcp " 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "Bad tcp " 
$IPT6 -A chk_tcp6_packets_chain -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
$IPT6 -A chk_tcp6_packets_chain -p tcp -j RETURN 
 
# Open TCP Ports 
# Open http port
for h in $HTTP_SERVER_6
do 
   $IPT6 -A chk_tcp_inbound -p tcp -m tcp --dport 80 -d $h -j ACCEPT
done
 
# Open 53 port
$IPT6 -A chk_tcp_inbound -p tcp -m tcp --dport 53 -j ACCEPT 
############################### 
# Add your rules below to open other TCP ports
# Open smtp 
# $IPT6 -A chk_tcp_inbound -p tcp -m tcp --dport 25 -j ACCEPT 
# Open pop3 
# $IPT6 -A chk_tcp_inbound -p tcp -m tcp --dport 113 -j ACCEPT 
# Open ssh 
# $IPT6 -A chk_tcp_inbound -p tcp -m tcp --dport 22 -j ACCEPT 
############################### 
# do not modify following rule
$IPT6 -A chk_tcp_inbound -p tcp -j RETURN 
 
# Open UDP Ports 
# Open dns 53 udp
$IPT6 -A chk_udp_inbound -p udp -m udp --dport 53 -j ACCEPT 
############################### 
# Add your rules below to open other UDP ports
# 
############################### 
# do not modify following rule
$IPT6 -A chk_udp_inbound -p udp -j RETURN 
 
# ICMP - allow ping pong
$IPT6 -A chk_icmp_packets -p ipv6-icmp -j ACCEPT 
$IPT6 -A chk_icmp_packets -p icmp -j RETURN
