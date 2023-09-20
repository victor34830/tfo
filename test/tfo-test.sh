#!/usr/bin/bash

#
# this script should be executed after starting tcpoptim, with these parameters:
#
# /apps/tcpoptim --vdev=net_tap0,iface=tfo-priv --vdev=net_tap1,iface=tfo-pub -l 0,1 -- -d 0,1
#
# means: starts with 2 ports, which are backed by tap device on linux system, with one worker thread.
#

# configure private side in a network namespace
# mac addr set for arp is a dummy, it will prevent linux to search for it with arp protocol.
ip netns add far 2> /dev/null
ip link set tfo-priv netns far
ip -n far link set tfo-priv up
ip -n far link set lo up 
ip -n far addr add 192.168.41.1/24 dev tfo-priv
ip -n far route add default via 192.168.41.2 dev tfo-priv
ip netns exec far arp -s 192.168.41.2 00:64:74:61:70:31

# configure public side, on global network namespace
ip link set tfo-pub up
ip addr add 192.168.41.2/24 dev tfo-pub
arp -s 192.168.41.1 00:64:74:61:70:30 

# send a packet from each side, so tcpoptim can learn macs from each sides.
ip netns exec far ping -W 0.1 -c 1 192.168.41.2
ping -W 0.1 -c 1 192.168.41.1

# may add some latency / packet drop on links
#ip netns exec far tc qdisc add dev tfo-priv root netem delay 250ms 25ms loss 1%
#ip netns exec far tc qdisc add dev tfo-priv root netem delay 100ms
#ip netns exec far tc qdisc add dev tfo-priv root netem delay 300ms loss 3%

# run wget test. required: http server installed on localhost.
# ip netns exec far wget http://192.168.41.2/image.iso -O/dev/null

# nat on tfo-pub
#ip r add 192.168.42.0/24 via 192.168.41.2 dev tfo-pub
#arp -i tfo-pub -s 192.168.42.0 00:64:74:61:70:30 

