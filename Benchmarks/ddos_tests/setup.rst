============
Client1
============

- CPU model name: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
- CPUs: 4
- Kernel: 4.15.0-52-generic
- NIC: RTL 8111/8168/8411
- NIC Capacity: 1Gb/s

============
Client2
============

- CPU model name: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
- CPUs: 4
- Kernel: 5.1.12
- NIC: RTL 8111/8168/8411
- NIC Capacity: 1Gb/s

============
Router
============

- CPU model name: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
- CPUs: 4
- Kernel: 5.2.0-rc2(modified)
- NIC: RTL 8111/8168/8411
- NIC Capacity: 1Gb/s

============
Server
============

- CPU model name: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
- CPUs: 4
- Kernel: 5.2.0
- NIC: RTL 8111/8168/8411
- NIC Capacity: 1Gb/s

==============
XDPLua Version
==============

In this test we are using the XDPLua helper version with Luaunpack

This version is available in this `branch
<https://github.com/VictorNogueiraRio/linux/tree/xdp_lua_helper_with_unpack>`_.

==================================
Test Procedure
==================================

We have 4 laptops, with the same hardware and connected to the same network
Two running as clients, another as a router and the last one as a server

The clients are both connected to the router through a 1gbit switch
The router is connected directly to the server

The first measurement we do is the baseline, which is done without any kind of DoS protection
The second one is done using XDPLua, with a filter that drops all incoming tcp packets destined to port 80
The third one is done using eBPF, with a filter that drops all incoming tcp packets destined to port 80
The last one is done using iptables, with a rule that drops all incoming tcp packets destined to port 80

==================================
Server
==================================

On the server, we run iperf listening at port 5010

==================================
Client 1
==================================

On client 1 we run the following iperf command: iperf3 -c 10.0.0.1 -t 20 -p 5010
This command sends packets to the ip '10.0.0.1' at port 5010 and does this for 20 seconds

==================================
Client 2
==================================

On client 2 we run the following hping command: hping3 -d 100 -S -p 80 --flood 10.0.0.1
This command sends tcp syn packets with payloads of 100 Bytes to the ip '10.0.0.1' at port 80
The --flood option makes hping send packets as fast as possible.

==================================
Router
==================================

On the router we insert a filter logic inside it's XDP environment.
The logic simply drops all TCP packets that come from a specific destination port.
We created one version of this filter in Lua and the other in eBPF

==================================
Results
==================================

You can find the raw results in the results file inside this directory.
