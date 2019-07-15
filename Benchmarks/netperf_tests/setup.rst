============
Laptops
============

- Linux Distribution: Arch Linux
- Kernel Version: 5.2.0-rc2+
- CPU model name: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
- CPUs: 4

==============
XDPLua Version
==============

In this test we are using the helper version of XDPLua

This version is available in this `branch
<https://github.com/VictorNogueiraRio/linux/tree/xdp_lua_helper_version>`_.

==================================
Test Procedure
==================================

We have 3 laptops, running the same operating system, with the same hardware and connected to the same network
One running as a client, another as a router and the last one as a server

The router is connected directly to the server

==================================
Server
==================================

On the server, we run netserver listening at port 5000

==================================
Client
==================================

On the client we run the following netperf command: netperf -T TCP_RR -l 20 -D 1 -T 2,2 -H 192.168.1.1 -p 5000

==================================
Router
==================================

On the router we insert a filter logic inside it's XDP environment.
The logic simply drops all TCP packets that come from a specific source source port.
We created one version of this filter in Lua and the other in eBPF

==================================
Results
==================================

You can find the raw results in the results file inside this very directory.
It basically showed that eBPF, running in the XDP environment was 14% faster than Lua.
