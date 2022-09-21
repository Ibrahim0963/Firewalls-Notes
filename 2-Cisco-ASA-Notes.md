Unit 1: Basics of the ASA Firewall
### Introduction to Firewalls ###

Firewalls, like routers can use access-lists to check for the source and/or destination address or port numbers, that’s layer 3 and 4 of the OSI model. when they receive a packet, they check if it matches an entry in the access-list and if so, they permit or drop the packet. That’s it.

Stateful vs. Stateless:
-> Stateful treat the data as a whole and keep track of all incoming and outgoing connections. If connection if created from inside to outside firewall will track this connection and if any packets goes in, firewall will permits it.
-> Stateless treat the data as an individual packets and does not keep track of any incoming and outgoing connections

Packet Inspection:
Packet inspection means we can inspect up to layer 7 of the OSI model (3-7). This means we can look at application data and even the payload, so Instead of blocking all IP addresses that belong to anydomain.com, you can create a filter that looks for the URI in HTTP requests and block those instead

Security Zones:
Cisco routers, by default, will permit and forward all packets they receive, if they have a matching route in their routing table. for restriction configure some access-lists (bad idea!), so we work with security zones.
Inside Zone for our LAN and Outside zone for our WAN
Zone's Rules:
-> Traffic from a “high” security level(LAN/trusted) to a “lower” security level(WAN/untrusted) is permitted.
LAN > WAN permit
-> Traffic from a “low” security level to a “higher” security level is denied.
WAN -> LAN denied
(Since the firewall is stateful, it keeps track of outgoing connections and will permit the return traffic from our LAN)

Exceptions can be made with access-list.

DMZ Traffic denied (standard):
DMZ -> Inside
Outside -> DMZ

To ensure connection from Outside to DMZ, we use access-list, that only permits traffic to the ip and port that the server in the DMZ use.


### Cisco ASA Erase Configuration ###
2 ways to erase the configuraiton:
-> command >write erase 
-> use the default factory method: >configure factory-default $ip $subnetmask


### Cisco ASA ASDM Configuration ###
Cisco’s ASDM (Adaptive Security Device Manager) is the GUI that Cisco offers to configure and monitor your Cisco ASA firewall.

How to Enable:
1. ASDM image should be on the flash memory of the ASA: 
>show disk0:

2. tell the ASA what ASDM image to use: 
>asdm image disk0:asdm-123.bin

3. ASDM requires HTTP(disabled by default). To enable it: 
>http server enable

4. specify which network and interface are permitted to use the HTTP server (Instead of giving everyone access): 
>http 192.168.1.0 255.255.255.0 INSIDE -> whole network 
>http 192.168.1.15 255.255.255.255 INSIDE -> only 1 IP
same goes for ssh > ssh $IP $SUSBNETMASK INSIDE

5. make user account: 
> username ADMIN password PASSWORD privilege 15 (admin account should be privilege level 15)

6. then access it from https://192.168.x.254 enter username and password, then either run it direct from the ASA’s flash memory or install it on your machine first.


### Cisco ASA Security Levels ###
security levels indicate how trusted an interface is compared to another interface (the higher the most trusted 0-100). Each interface on the ASA is a security zone.

An interface with a high security level can access an interface with a low security level but the other way around is not possible unless we configure an access-list that permits this traffic.

Security level 0: the lowest and enabled by default to the "OUTSIDE" interface, which means traffic from outside are denied unless we permit it within an access-list.

Security level 100: the highest and enabled by default to the "INSIDE" interface. We use it for our LAN. Since this is the highest security level, by default it can reach all the other interfaces.

Security level 1-99: here we can create any other security levels that we want. Example: for our DMZ with security level 50.
IMPORTANT TO NOTICE!!!!!
LAN/inside -> DMZ allowed because 100(LAN) > 50(DMZ)
DMZ -> LAN/inside denied because 50(DMZ) < 100(LAN)
DMZ -> WAN/outside allowed because 50(DMZ) > 0(WAN)

LAB: 3 routers (R1,R2,R3) and in the middle one ASA
ASA Interface E0/0 as the INSIDE.
ASA Interface E0/1 as the OUTSIDE.
ASA Interface E0/2 as our DMZ.

configuring the ASA with these interfaces:
ASA_FW(config)# interface E0/0
ASA_FW(config-if)# nameif INSIDE
INFO: Security level for "INSIDE" set to 100 by default.
ASA_FW(config-if)# ip address 192.168.1.254 255.255.255.0
ASA_FW(config-if)# no shutdown

ASA_FW(config)# interface E0/1
ASA_FW(config-if)# nameif OUTSIDE
INFO: Security level for "OUTSIDE" set to 0 by default.
ASA_FW(config-if)# ip address 192.168.2.254 255.255.255.0
ASA_FW(config-if)# no shutdown

ASA_FW(config)# interface E0/2
ASA_FW(config-if)# nameif DMZ
INFO: Security level for "DMZ" set to 0 by default.
ASA_FW(config-if)# security-level 50
ASA_FW(config-if)# ip address 192.168.3.254 255.255.255.0
ASA_FW(config-if)# no shutdown

The nameif command is used to specify a name for the interface

1. Traffic from the ASA
>ping 192.168.1/2/3.1 -> allowed because routers are using ASA as their default gateway

NOTICE: By default the ASA has a global inspection policy, that doesn’t permit ICMP traffic. If you want to ping between devices through your ASA firewall then we have to inspect ICMP traffic:

ASA_FW(config)# policy-map global_policy
ASA_FW(config-pmap)# class inspection_default
ASA_FW(config-pmap-c)# inspect icmp

Now ICMP traffic will be allowed between different interfaces.

2. Traffic from INSIDE to OUTSIDE and DMZ are allowed because 100(INSIDE) > 0(OUTSIDE)

3. Traffic from OUTSIDE to INSIDE and DMZ are denied because 0(OUTSIDE) > 100(INSIDE)

4. Traffic from DMZ 
to INSIDE denied because 50(DMZ) < 100(INSIDE)
to OUTSIDE allowed because 50(DMZ) > 0(OUTSIDE)

LAN/inside -> DMZ allowed because 100(LAN) > 50(DMZ)
DMZ -> LAN/inside denied because 50(DMZ) < 100(LAN)
DMZ -> WAN/outside allowed because 50(DMZ) > 0(WAN)

Exceptions can be made with access-lists

5. Rules
-> Traffic from a higher security level to lower security level is allowed.
-> Traffic from a lower security level to a higher security level is not allowed
-> Traffic between interfaces with the same security level is not allowed. To change this use this command (same-security-traffic permit inter-interface)

Unit2: NAT/PAT ###################################################
### Cisco ASA Dynamic NAT Configuration IN to OUT ###

configuring dynamic NAT
LAB: 2 routers (R1,R2) and in the middle ASA firewall

configuration of the 2 routers:
ASA1(config)# interface e0/0
ASA1(config-if)# nameif INSIDE
ASA1(config-if)# ip address 192.168.1.254 255.255.255.0
ASA1(config-if)# no shutdown

ASA1(config)# interface e0/1
ASA1(config-if)# nameif OUTSIDE
ASA1(config-if)# ip address 192.168.2.254 255.255.255.0
ASA1(config-if)# no shutdown

configuration of the dynamic NAT (for ASA 8.3 and later):

1. configure a network object that defines the pool with public IP addresses that we want to use for translation

ASA1(config)# object network PUBLIC_POOL 
ASA1(config-network-object)# range 192.168.2.100 192.168.2.200

-> Define the 192.168.2.100 – 200 range from the 192.168.2.0/24 subnet that we use on the outside interface

2. configure a network object for the hosts that we want to translate

ASA1(config)# object network INTERNAL
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (INSIDE,OUTSIDE) dynamic PUBLIC_POOL

The network object called “INTERNAL” specifies the subnet that we want to translate (the entire 192.168.1.0 /24) subnet (will be translated to the range 192.168.2.100-200) and also has the NAT rule. When traffic from the inside goes to the outside, we will translate it to the public pool (the range 192.168.2.100-200) that we created earlier.

TO_SUM_UP: NAT will translate 192.168.1.0/24(INSIDE) to 192.168.2.100-200(OUTSIDE), when traffic from the inside goes to the outside.



if you run out of IP addresses in the public pool, you enable "NAT fallback", which mean to use the IP address on the outside interface (192.168.2.254) for translation.

ASA1(config)# object network INTERNAL
ASA1(config-network-object)# nat (INSIDE,OUTSIDE) dynamic PUBLIC_POOL interface

to check if dynamic NAT configuration is working or not, use telnet to connect to R2:
R1#telnet 192.168.2.2

to see if any traffic is translated
ASA1# show nat
ASA1# show nat detail

keyword "detail" show that traffic from the 192.168.1.0/24 subnet has been translated but it still doesn’t tell us exactly what source IP has been translated to which IP in the public pool, to see that 
ASA1# show xlate


### Cisco ASA Dynamic NAT with DMZ ###
LAB: 3 routers (R1,R2,R3) and in the middle one ASA
Security levels: INSIDE: 100, OUTSIDE: 0, DMZ: 50

We will configure NAT for the following traffic patterns:
-> Traffic from hosts on the INSIDE to the OUTSIDE, we’ll use a “public” pool for this.
-> Traffic from hosts on the INSIDE to the DMZ, we’ll use a “DMZ” pool for this.
-> Traffic from hosts on the DMZ to the OUTSIDE, we’ll use the same public pool for this

1. configuration the interfaces(we done this before!)

ASA1(config)# interface e0/0
ASA1(config-if)# nameif INSIDE
ASA1(config-if)# ip address 192.168.1.254 255.255.255.0
ASA1(config-if)# no shutdown

ASA1(config)# interface e0/1
ASA1(config-if)# nameif OUTSIDE
ASA1(config-if)# ip address 192.168.2.254 255.255.255.0
ASA1(config-if)# no shutdown

ASA1(config)# int e0/2
ASA1(config-if)# nameif DMZ
ASA1(config-if)# security-level 50
ASA1(config-if)# ip address 192.168.3.254 255.255.255.0
ASA1(config-if)# no shutdown

2. Dynamic NAT with three Interfaces
-> First we create the pools:

ASA1(config)# object network PUBLIC_POOL
ASA1(config-network-object)# range 192.168.2.100 192.168.2.200

ASA1(config)# object network DMZ_POOL
ASA1(config-network-object)# range 192.168.3.100 192.168.3.200

-> Second we create network objects for the NAT translations:

ASA1(config)# object network INSIDE_TO_DMZ
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (INSIDE,DMZ) dynamic DMZ_POOL

The first network object is called INSIDE_TO_DMZ and specifies the subnet of the INSIDE hosts. The NAT entry translates the 192.168.1.0/24 subnet to IP addresses in the pool called DMZ_POOL. The other network objects are similar:

ASA1(config)# object network INSIDE_TO_OUTSIDE
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (INSIDE,OUTSIDE) dynamic PUBLIC_POOL

ASA1(config)# object network DMZ_TO_OUTSIDE
ASA1(config-network-object)# subnet 192.168.3.0 255.255.255.0
ASA1(config-network-object)# nat (DMZ,OUTSIDE) dynamic PUBLIC_POOL

to verify we generate some traffic between the routers and see if their IP packets are translated correctly:

R1#telnet 192.168.2.2
ASA1# show xlate

R1#telnet 192.168.3.3
ASA1# show xlate

R3#telnet 192.168.2.2
ASA1# show xlate


### Cisco ASA PAT Configuration ###
Configuring PAT:
LAB: 2 routers (R1,R2) and in the middle ASA firewall
we will use PAT to translate traffic from our hosts on the INSIDE that want to reach the OUTSIDE.

Basic Configuration:

ASA1(config)# interface e0/0
ASA1(config-if)# nameif INSIDE
ASA1(config-if)# ip address 192.168.1.254 255.255.255.0
ASA1(config-if)# no shutdown

ASA1(config)# interface e0/1
ASA1(config-if)# nameif OUTSIDE
ASA1(config-if)# ip address 192.168.2.254 255.255.255.0
ASA1(config-if)# no shutdown

PAT Configuration(for ASA 8.3 or higher):

1. configure a network object:

ASA1(config)# object network INSIDE
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (INSIDE,OUTSIDE) dynamic 192.168.2.253

This tells our firewall to translate traffic from the 192.168.1.0/24 subnet to the OUTSIDE to IP address 192.168.2.253
192.168.2.253 should not in use on the interface, if it used, you will get an error, so use the keyword "interface" instead like below

2. generate some traffic from R1

R1#telnet 192.168.2.2
ASA1# show xlate

-> It has been translated from 192.168.1.1 to 192.168.2.253, just as we configured

2. how to use the IP address on your OUTSIDE interface for PAT:

ASA1(config)# object network INSIDE_TO_OUTSIDE
ASA1(config-network-object)#  nat (INSIDE,OUTSIDE) dynamic interface

Instead of specifying the IP address you need to use the keyword “interface”. It’s a good idea to do this when you get a dynamic IP address from your ISP. 

R1#telnet 192.168.2.2
ASA1# show xlate

-> traffic from R1 has been translated to 192.168.2.254

## Cisco ASA NAT Exemption ##
**NAT exemption allows you to exclude traffic from being translated with NAT (senario: site-to-site VPN tunnel)**

LAB: 3 Servers (S1,S2,S3), 2 ASA:
- S1 and S2 are servers on internal networks.
- S3 is a server on the Internet.
- ASA1 and ASA2 use NAT to translate traffic from S1 and S2 to the IP address on their GigabitEthernet 0/0 interfaces.
- We use an IPSec IKEv2 VPN tunnel between ASA1 and ASA2 for traffic between S1 and S2.
- HTTP server runs on S1, S2, and S3, so that we have something to connect to.

0. LAB Configurations:>
-> On ASA1:
hostname ASA1
!
interface GigabitEthernet0/0
 nameif OUTSIDE
 security-level 0
 ip address 10.10.10.1 255.255.255.0 
!
interface GigabitEthernet0/1
 nameif INSIDE
 security-level 100
 ip address 192.168.1.254 255.255.255.0                 
 
-> On ASA2
hostname ASA2
!
interface GigabitEthernet0/0
 nameif OUTSIDE
 security-level 0
 ip address 10.10.10.2 255.255.255.0 
!
interface GigabitEthernet0/1
 nameif INSIDE
 security-level 100
 ip address 192.168.2.254 255.255.255.0

-> On S1
hostname S1
!
no ip routing
!
no ip cef
!
interface GigabitEthernet0/1
 ip address 192.168.1.101 255.255.255.0
!
ip default-gateway 192.168.1.254
!
ip http server
!
end

-> On S2
hostname S2
!
no ip routing
!
no ip cef
!
interface GigabitEthernet0/1
 ip address 192.168.2.102 255.255.255.0
!
ip default-gateway 192.168.2.254
!
ip http server
!
end

-> On S3
hostname S3
!
ip cef
!
interface GigabitEthernet0/1
 ip address 10.10.10.3 255.255.255.0
!
ip http server
!
end

1. PAT configuration:
We translate all traffic from the subnets where the hosts reside to the outside interface of the ASAs

ASA1(config)# object network INSIDE
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (INSIDE,OUTSIDE) dynamic interface 

ASA2(config)# object network INSIDE
ASA2(config-network-object)# subnet 192.168.2.0 255.255.255.0
ASA2(config-network-object)# nat (INSIDE,OUTSIDE) dynamic interface

2. configuring a VPN tunnel between ASA1 and ASA2 - IPSec Site-to-Site VPN

-> We configure an IKEv2 policy on both ASAs

ASA1 & ASA2#
(config)# crypto ikev2 policy 10
(config-ikev2-policy)# encryption aes
(config-ikev2-policy)# group 2 // 1-15 group
(config-ikev2-policy)# prf sha
(config-ikev2-policy)# lifetime seconds 86400

-> IPSec proposal

ASA1 & ASA2#
(config)# crypto ipsec ikev2 ipsec-proposal MY_PROPOSAL
(config-ipsec-proposal)# protocol esp encryption aes
(config-ipsec-proposal)# protocol esp integrity sha-1

-> We need an access-list to define the traffic we want to encrypt. In this example, we’ll encrypt all traffic between the 192.168.1.0/24 and 192.168.2.0/24 subnets

ASA1(config)# access-list LAN1_LAN2 extended permit ip  192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0

ASA2(config)# access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0

-> We need a crypto map to set the remote peer IP address, to combine the access-list with the proposal, and activate it on the outside interface:

ASA1(config)# crypto map MY_CRYPTO_MAP 1 match address LAN1_LAN2
ASA1(config)# crypto map MY_CRYPTO_MAP 1 set peer 10.10.10.2
ASA1(config)# crypto map MY_CRYPTO_MAP 1 set ikev2 ipsec-proposal MY_PROPOSAL
ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

ASA2(config)# crypto map MY_CRYPTO_MAP 1 match address LAN2_LAN1
ASA2(config)# crypto map MY_CRYPTO_MAP 1 set peer 10.10.10.1
ASA2(config)# crypto map MY_CRYPTO_MAP 1 set ikev2 ipsec-proposal MY_PROPOSAL
ASA2(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

-> We configure the tunnel-group to configure pre-shared keys

ASA1(config)# tunnel-group 10.10.10.2 type ipsec-l2l
ASA1(config)# tunnel-group 10.10.10.2 ipsec-attributes 
ASA1(config-tunnel-ipsec)# ikev2 local-authentication pre-shared-key CISCO123 
ASA1(config-tunnel-ipsec)# ikev2 remote-authentication pre-shared-key CISCO456

ASA2(config)# tunnel-group 10.10.10.1 type ipsec-l2l 
ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes 
ASA2(config-tunnel-ipsec)# ikev2 local-authentication pre-shared-key CISCO456
ASA2(config-tunnel-ipsec)# ikev2 remote-authentication pre-shared-key CISCO123

-> Enable IKEv2 on the outside interface:

ASA1 & ASA2
(config)# crypto ikev2 enable OUTSIDE

-> make sure each ASA has a route to the subnet on the other side

ASA1(config)# route OUTSIDE 192.168.2.0 255.255.255.0 10.10.10.2

ASA2(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

3. NAT Exception:
We now have a working configuration where we use PAT to translate traffic from our hosts and a site-to-site IPSec IKEv2 VPN tunnel

3.1: Without NAT Exemption
what happens when we connect from S1 to S3?, let's see:

S1#telnet 10.10.10.3 80
ASA1# show xlate
-> traffic from 192.168.1.101 is translated to 10.10.10.1

Let’s try something else. I’ll clear the NAT table first:

ASA1# clear xlate
S1#telnet 192.168.2.102 80

let's try to connect from S1 to S2:
S1#telnet 192.168.2.102 80

This isn’t working. There are no IKEv2 security associations:
ASA1# show crypto isakmp sa 
why ???

Let’s take a look at the NAT table
ASA1# show xlate

The ASA’s order of operation is that it first translates a packet with NAT, then checks if the packet should be encrypted or not. This packet doesn’t match our LAN1_LAN2 access-list, so it won’t be encrypted. -> so won't be translated :)
ASA2 drops the packet because no access-list permits traffic from the outside to the inside.

To fix this, we need to make an exception so that traffic between 192.168.1.101 and 192.168.2.102 won’t be translated with NAT. We can do this with NAT exemption

3.2 With NAT Exemption:

-> First, I’ll create a network object for subnet 192.168.2.0/24

ASA1(config)# object network LAN2
ASA1(config-network-object)# subnet 192.168.2.0 255.255.255.0

-> Second, we create an additional NAT rule:

ASA1(config)# nat (INSIDE,OUTSIDE) source static INSIDE INSIDE destination static LAN2 LAN2

The rule says to the ASA to translate traffic
* From INSIDE 192.168.1.0/24 destined to OUTSIDE 192.168.2.0/24 to 192.168.1.0/24.
* From OUTSIDE 192.168.2.0/24 destined to INSIDE 192.168.1.0/24 to 192.168.2.0/24.
** In other words, don’t translate the traffic between 192.168.1.0/24 and 192.168.2.0/24.

-> third, We configure the same thing on ASA2:

ASA2(config)# object network LAN1
ASA2(config-network-object)# subnet 192.168.1.0 255.255.255.0

ASA2(config-network-object)# nat (INSIDE,OUTSIDE) source static INSIDE INSIDE destination static LAN1 LAN1

let’s try to connect from S1 to S2 one more time:
S1#telnet 192.168.2.102 80

It works now :)

Let’s check the NAT table 
ASA1# show xlate

we see the two NAT exemption rules. Let’s check if we have an IKEv2 security association:
ASA1# show crypto isakmp sa

We can also verify that packets are encrypted and decrypted:
ASA1# show crypto ipsec sa

Conclusion:
* You have now learned how to use NAT exemption to exclude traffic from being translated with NAT


### Cisco ASA Per-Session vs Multi-Session PAT ###

Since ASA version 9.x there are some changes to PAT (Port Address Translation). We now have two types of PAT:
-> Per-Session PAT
-> Multi-Session PAT

When a PAT session ends we have two options (IMPORTANT):
-> Per-Session PAT removes the translation entry immediately.
-> Multi-Session PAT will wait for 30 seconds (default timeout) before removing the translation entry.

Cisco recommends to use Per-Session PAT for hit-and-run traffic like HTTP or HTTPS so you can avoid having a lot of translations entries that are waiting for the 30 second timeout to expire. You shouldn’t use it for realtime traffic like VoIP.

without Per-Session PAT the connection rate is about 2000 per second. If you enable it, the connection rate is about 65535 / average lifetime. (Connection Rate is 2000 means 2000 connections can be made per second)

The ASA firewall will use per-session PAT by default. To find the rules in the configuration:

ASA1# show run | include xlate per-session

NOTE: since ASA version 9.x, the keyword “any” means IPv4 + IPv6 traffic. If you want to match IPv4 traffic you should use “any4” and for IPv6 you need to use “any6”.

LAB: 2 routers(R1,R2) and one ASA firewall

1. Basic Configuration:

ASA1(config)# interface e0/0
ASA1(config-if)# nameif INSIDE
ASA1(config-if)# ip address 192.168.1.254 255.255.255.0

ASA1(config)# interface e0/1
ASA1(config-if)# nameif OUTSIDE
ASA1(config-if)# ip address 192.168.2.254 255.255.255.0

ASA1(config)# object network INSIDE_TO_OUTSIDE
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (INSIDE,OUTSIDE) dynamic interface

2. To see how the ASA firewall deals with our PAT translations we can enable a debug

ASA1# debug nat 255

3. Generate some traffic with telent

R1#telnet 192.168.2.2

Now you will see a debug message on the ASA, which show you how it translated our traffic between R1 and R2, to verify:

ASA1# show xlate

Wenn you kill the telnet session on R1 >exit , the debug on ASA shows a message that the firewall removes the translation entry right away, to verify:

ASA1# show xlate

TO_SUM_UP: Per-Session PAT will remove the translation immediately as soon as I closed the TCP session

Multi-Session PAT:

firstly, remove the entry that enables Per-Session PAT for all TCP traffic and then enable Multi-Session PAT, with keeping the debug enabled:

ASA1(config)# no xlate per-session permit tcp any4 any4
ASA1(config)# xlate per-session deny tcp any4 any4

Now let’s telnet from R1 to R2:

R1#telnet 192.168.2.2

The debug on ASA show a message that the translation entry that is created, to verify:

ASA1# show xlate

Now kill the telent session, it will take 30 seconds before the translation entry will be removed. The debug shows a message after 30s.

### Cisco ASA Static NAT Configuration ###
We learned so far, how outbound traffic configuration works in "ASA terminology", what about inbound traffic? outside want to access inside?

we achieve this with 2 things:
* Configure static NAT so that the internal server is reachable through an outside public IP address.
* Configure an access-list so that the traffic is allowed.

LAB: 2 routers(R1/DMZ,R2/OUTSIDE) and one ASA firewall
Senario: R1/DMZ is a webserver and R2/OUTSIDE want to reach R1

1. Static NAT Configuration (ASA version 8.3 and later)

-> First we will create a network object that defines our “webserver” in the DMZ and also configure to what IP address it should be translated

ASA1(config)# object network WEB_SERVER
ASA1(config-network-object)# host 192.168.1.1
ASA1(config-network-object)# nat (DMZ,OUTSIDE) static 192.168.2.200

The configuration above tells the ASA, if an outside device connects to IP address 192.168.2.200 that it should be translated to IP address 192.168.1.1. This takes care of NAT but we still have to create an access-list or traffic will be dropped:

-> Creating access-list:

ASA1(config)# access-list OUTSIDE_TO_DMZ extended permit tcp any host 192.168.1.1

The access-list above allows any source IP address to connect to IP address 192.168.1.1 (for ASA version 8.3 or later you need to specify the “real” IP address, not the “NAT translated” address)

-> Activate this access-list

ASA1(config)# access-group OUTSIDE_TO_DMZ in interface OUTSIDE

This enables the access-list on the outside interface

-> telnet from R2 to R1 on TCP port 80 to see if it works

R2#telnet 192.168.2.200

It worked :), to verify

ASA1# show xlate
ASA1# show access-list


2. Static NAT for entire subnet
The previous example for only a few server by creating a couple of static NAT translations
Now we will translate an entire subnet to an entire pool of IP'sa

LAB: 3 routers(R1,R2,R3) and one ASA firewall
R1,R3: DMZ zone 
Senario: our ISP gave us a pool of IP addresses, let’s say 10.10.10.0/24. We can use this pool to translate all the servers in the DMZ, let's see how:

-> we create an object network for 10.10.10.0/24 from ISP:

ASA1(config)# object network PUBLIC_POOL
ASA1(config-network-object)# subnet 10.10.10.0 255.255.255.0

-> we create an object network for the DMZ-Zone and to enable NAT:

ASA1(config)# object network DMZ
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0
ASA1(config-network-object)# nat (DMZ,OUTSIDE) static PUBLIC_POOL

The configuration above tells the ASA to translate any IP address from the subnet DMZ (192.168.1.0 /24) to an IP address in the PUBLIC_POOL (10.10.10.0 /24)

-> Create access-list:

ASA1(config)# access-list OUTSIDE_TO_DMZ permit tcp any 192.168.1.0 255.255.255.0

-> Active the access-list on the outside:

ASA1(config)# access-group OUTSIDE_TO_DMZ in interface OUTSIDE

That's all :), verify

ASA1# show xlate 

-> Let’s enable a debug so we can see what addresses are used when we translate

ASA1# debug nat 255

-> telnet from R2 and R3 to the first IP address in the pool:

R2#telnet 10.10.10.1
R2#telnet 10.10.10.3

### Cisco ASA NAT Port Forwarding ###
NAT Port Forwarding is useful when you have a single public IP address and multiple devices behind it that you want to reach from the outside world

LAB: 2 Server (SSH,HTTP), one ASA and one router(R2)
Senario: ASA in the middle, above we have 2 servers, and beside is OUTSIDE. Our goal is to make outside reach the 2 servers inside

Now we forward anyone connect to our public IP with SSH/22 or HTTP/80 to the servers inside. 

-> Basic and final configuration for ASA1,HTTP,SSH,R2
*** ASA1 ***
hostname ASA1
!
interface GigabitEthernet0/0
 nameif OUTSIDE
 security-level 0
 ip address 192.168.2.254 255.255.255.0 
!             
interface GigabitEthernet0/1
 nameif DMZ
 security-level 50
 ip address 192.168.3.254 255.255.255.0 
!
object network WEB_SERVER
 host 192.168.3.1
object network SSH_SERVER
 host 192.168.3.3
!
access-list DMZ_SERVERS extended permit tcp any host 192.168.3.1 eq www 
access-list DMZ_SERVERS extended permit tcp any host 192.168.3.3 eq ssh 
!
object network WEB_SERVER
 nat (DMZ,OUTSIDE) static interface service tcp www www 
object network SSH_SERVER
 nat (DMZ,OUTSIDE) static interface service tcp ssh 10022 
access-group DMZ_SERVERS in interface OUTSIDE
!
: end

*** HTTP Server ***
hostname HTTP
!
no ip routing
!
interface GigabitEthernet0/1
 ip address 192.168.3.1 255.255.255.0
 no ip route-cache
 duplex auto
 speed auto
 media-type rj45
!
ip default-gateway 192.168.3.254
!
ip http server
!
end

*** SSH Server ***
hostname SSH
!
no ip routing
!
interface GigabitEthernet0/1
 ip address 192.168.3.3 255.255.255.0
 no ip route-cache
 duplex auto
 speed auto
 media-type rj45
!
ip default-gateway 192.168.3.254
ip forward-protocol nd
!
line vty 0 4
 login
 transport input ssh
line vty 5 924
 login
 transport input ssh
!
end

*** R2 ***
hostname R2
!
no ip routing
!
interface GigabitEthernet0/1
 ip address 192.168.2.2 255.255.255.0
 no ip route-cache
 duplex auto
 speed auto
 media-type rj45
!
ip default-gateway 192.168.2.254
!
end


-> Configuring HTTP server

ASA1(config)# object network WEB_SERVER
ASA1(config-network-object)# host 192.168.3.1
ASA1(config-network-object)# nat (DMZ,OUTSIDE) static interface service tcp 80 80

We create a network object that specifies the real IP address of the web server and then we create our NAT rule. By using the keyword interface we tell the ASA to use the IP address on the (outside) interface. The first port number is the port that the server is listening on, the second port number is the outside port number.  

-> configuring another PAT entry for the SSH server:

ASA1(config)# object network SSH_SERVER
ASA1(config-network-object)# host 192.168.3.3
ASA1(config-network-object)# nat (DMZ,OUTSIDE) static interface service tcp 22 10022

above commands are similar to the first one. Whenever someone connects on TCP port 10022, it will be forwarded to TCP port 22.

-> creating and activating the access-list:

ASA1(config)# access-list DMZ_SERVERS extended permit tcp any host 192.168.3.1 eq 80
ASA1(config)# access-list DMZ_SERVERS extended permit tcp any host 192.168.3.3 eq 22

ASA1(config)# access-group DMZ_SERVERS in interface OUTSIDE

This access-list will allow traffic from the outside to our servers

-> to a nice overview of all the forwarded ports that we configured:

ASA1# show  xlate 

-> to verify:

R2#telnet 192.168.2.254 80
R2#ssh -l cisco -p 10022 192.168.2.254


### Cisco ASA Hairpin Internal Server ###
The Cisco ASA firewall doesn’t like traffic that enters and exits the same interface. This kind of traffic pattern is called hairpinning or u-turn traffic

LAB: 2.8 cisco-asa-hairpin-internal-server.png
Senario: we have web server using IP address 192.168.1.2 on our internal LAN. The ASA is configured so that IP address 192.168.2.220 on the outside is translated to IP address 192.168.1.2. This allows users on the Internet to access our webserver. 

What if we want our internal hosts to access the webserver using the same outside IP address (192.168.2.220) instead of its internal IP address (192.168.1.2)? We can do this by configuring hairpinning on our ASA

Recommended: Instead of configuring hairpinning it might be a better idea to setup a local DNS server that resolves the hostname of the webserver to the local IP address

-> Basic Configuration:

*** on H1 (clients) ***
hostname H1
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
!
ip default-gateway 192.168.1.254
!
end

*** on Web Server ***
hostname Web
!
interface GigabitEthernet0/1
 ip address 192.168.1.2 255.255.255.0
!
ip default-gateway 192.168.1.254
!
end

*** on H2 ***
hostname H2
!
interface GigabitEthernet0/1
 ip address 192.168.2.3 255.255.255.0
!
ip default-gateway 192.168.2.254
!
end

*** on ASA1 ***
hostname ASA1
!
interface GigabitEthernet0/0
 nameif OUTSIDE
 security-level 0
 ip address 192.168.2.254 255.255.255.0 
!             
interface GigabitEthernet0/1
 nameif INSIDE
 security-level 100
 ip address 192.168.1.254 255.255.255.0 
!
object network WEB_SERVER
 host 192.168.1.2
access-list OUTSIDE_TO_INSIDE extended permit tcp any host 192.168.1.2 
!
object network WEB_SERVER
 nat (INSIDE,OUTSIDE) static 192.168.2.220
access-group OUTSIDE_TO_INSIDE in interface OUTSIDE
!
: end

-> See now ASA Configuration:

ASA1# show xlate

Configuration shows that host on outside can reach the webserver, to verify:

H2#telnet 192.168.2.220 80
It works

but H1 is inside but he can't reach the webserver using outside IP

H1#telnet 192.168.2.220 80
Error timeout

to fix this:
1. tell our ASA to permit traffic that enters and exits the same interface

ASA1(config)# same-security-traffic permit intra-interface

2. Now we can focus on the NAT configuration. First I will create some objects that match:
-> the subnet of the internal hosts (192.168.1.0 /24).
-> the translated outside IP address of the webserver.
-> the inside IP address of the webserver.
-> the TCP port that we use for HTTP traffic.

ASA1(config)# object-group network INTERNAL_HOSTS
ASA1(config-network-object-group)# network-object 192.168.1.0 255.255.255.0

ASA1(config)# object network WEB_PUBLIC
ASA1(config-network-object)# host 192.168.2.220

ASA1(config)# object network WEB_LOCAL
ASA1(config-network-object)# host 192.168.1.2

ASA1(config# object service HTTP
ASA1(config-service-object)# service tcp destination eq 80

3. Now configure the NAT translation:

ASA1(config-service-object)# nat (INSIDE,INSIDE) source dynamic INTERNAL_HOSTS interface destination static WEB_PUBLIC WEB_LOCAL service HTTP HTTP

Explaining the command above:
-> (INSIDE,INSIDE): we are translating traffic from the inside that is going to the inside, this is the hairpinning part.

-> source dynamic INTERNAL_HOSTS interface:  the source of the traffic has to be the 192.168.1.0 /24 subnet and it has to be translated to the IP address of the interface, this will be 192.168.1.254 (the IP address on the inside interface of the ASA).

-> destination static WEB_PUBLIC WEB_LOCAL: we only want to translate traffic that is destined to 192.168.2.220.

-> service HTTP HTTP: we only want to translate traffic that is destined for TCP port 80.

IMPORTANT: we did "hairpinning" to make the server response go through the ASA then to the client inside. without "hairpinning" the webserver response will be sent directly to the client inside

4. Verify:

H1#telnet 192.168.2.220 80
ASA1# show xlate 

ASA final Configuration:
hostname ASA1
!
interface GigabitEthernet0/0
 nameif OUTSIDE
 security-level 0
 ip address 192.168.2.254 255.255.255.0 
!             
interface GigabitEthernet0/1
 nameif INSIDE
 security-level 100
 ip address 192.168.1.254 255.255.255.0 
!
same-security-traffic permit intra-interface
!
object network WEB_LOCAL
 host 192.168.1.2
!
object network WEB_PUBLIC
 host 192.168.2.220
!
object network INTERNAL_HOSTS
subnet 92.168.1.0 255.255.255.0
!
object service HTTP
 service tcp destination eq www 
!
object network LAN_TO_PUBLIC
 subnet 192.168.1.0 255.255.255.0
!
access-list OUTSIDE_TO_INSIDE extended permit tcp any host 192.168.1.2 
!
nat (INSIDE,INSIDE) source dynamic INTERNAL_HOSTS interface destination static WEB_PUBLIC WEB_LOCAL service HTTP HTTP
!
object network WEB_SERVER
 nat (INSIDE,OUTSIDE) static 192.168.2.220
access-group OUTSIDE_TO_INSIDE in interface OUTSIDE
!
: end


Unit 3: Access-Lists
### Introduction to access-list ! ###

-> Access-lists work on the network (layer 3) and the transport (layer 4) layer and used for "filtering" and "classification"

*** "Filtering" is used to permit or deny traffic reaching certain parts of our network. Example: host from network x denied from accessing webserver in network y.

*** "Classification" does not drop IP packets like filtering does but we use it to “select” traffic. Example: in a VPN connection we want to "select" what traffic we want to encrypt, like traffic from network x to network y should be encrypted and this called classification

After creating an access-list, there is 3 spots where we can place them:

1. Inbound: all packets that reach your router will hit the access-list and will have to be checked against the access-list

2. Outbound: IP packets will go through the router and once they are leaving the interface they will be checked against the access-list

3. VTY line: We can use this to secure telnet and/or SSH traffic.

to show access-list statments: 

Router#show access-lists 

packet checking in access-list from the top to down. It not matches any of the statments in ACL, packet will dropped.

If a packet does match a certain statement then there is immediate action. The packet will either be permitted (forward) or denied (discarded). For example, if we have a packet that matches statement 10 then the router will not check if it “also” matches statement 20.

At the bottom of every access-list there is a deny any which means if you didn’t explicitly permit something it will be dropped anyway.

-> access-list has 2 type:
1. standard access-list
2. extended access-list

1. Standard access-list:
Packet form: L2 Header(IP Packet(Source IP))
The standard access-list checks only for source IP's

2. Extended access-list:
Packet form: L2 Header(IP Packet(Source IP, Destination IP, Transport Layer Header TCP/UDP ))
Extended access-list checks for src/dest ip and match on transport layer (layer 4) information like TCP or UDP port numbers

-> To recognize the standard and extended access-list:

IPv4 ACL Type   Number / Identification

Standard		1-99 or 1300-1999

Extended		100-199 or 2000-2699

Named			Pick any name you like

If you don’t like numbers you can also use named access-lists by choosing a name, this works for both standard and extended access-lists.

-> Setting up access-lists:
1. Create an access-list and assign it to an interface
2. You can only have a single ACL per direction, so it’s impossible to have 2 inbound access-lists.
3. If packet matches a statement, the router doesn’t check if it matches any other statements.
4. The last statement is deny any

### Cisco ASA Access-List ###
The Cisco ASA firewall uses access-lists that are similar to the ones on IOS routers and switches.

Access-lists will allow only traffic from high security level to low security level. all other traffic will be dropped.

Access-lists are created globally and applied with the "access-group" command. They can be applied in-, outbound or on VTY line

-> Things to know about access-lists on ASA firewall:
** The source ip for outbound traffic (high -> low security level) on access-list statement should be real (not the NAT translated one).
** The destination ip for inbound traffic (low -> high security) on access-list statements should be
- The translated address for any ASA version before 8.3.
- The real address for ASA 8.3 and newer.
** The access-list is always checked before NAT translation.

LAB: 3 routers (R1/inside, R2/outside, R3/DMZ) and one ASA firewall in the middle

This means the following traffics are allowed:
- R1 can reach R2 or R3 (from security level 100 to 0 or 50)
- R2 can’t reach any devices (from security level 0  to 50 or 100)
- R3 can reach R2 but not R1 (from security level 50 to 0 or 100)

-> Task-1: Restrict traffic from R1/inside to our http server on R2/outside:

1. enable http server on R2:
R2(config)#ip http server 

2. connect from R1 to R2:
R1#telnet 192.168.2.2 80

It works!, by default

3. create an access-list that restricts HTTP traffic from inside to outside/http server, all other traffic will be permitted:
ASA1(config)# access-list INSIDE_INBOUND deny tcp any host 192.168.2.2 eq 80
ASA1(config)# access-list INSIDE_INBOUND permit ip any any

(any, any4, any6 already explained)

4. to enable the ACL:
ASA1(config)# access-group INSIDE_INBOUND in interface INSIDE

access-group command to enable ACL named "INSIDE_INBOUND" on the interface named INSIDE, in for inbound traffic.

5. verify:
R1#telnet 192.168.2.2 80

not working!, exactly like we want, to see why:

ASA1# show access-list INSIDE_INBOUND

-> Task-2: Permit Traffic to DMZ from outside
senario: we have telnet server on DMZ and we want to access it from the internet

1. Create an access-list (named OUTSIDE_INBOUND permit connection to our telnet server):
ASA1(config)# access-list OUTSIDE_INBOUND permit tcp any host 192.168.3.3 eq 23

2. Apply that access-list (named OUTSIDE_INBOUND on outside interface):
ASA1(config)# access-group OUTSIDE_INBOUND in interface OUTSIDE

3. verify:
R2#telnet 192.168.3.3

It works!

ASA1# show access-list OUTSIDE_INBOUND

-> Task-3: Restrict Outbound Traffic
Senario: our hosts and servers that are located in the inside or DMZ can only use one particular DNS server on the outside

1. Create access-list:

ASA1(config)# access-list ALL_OUTBOUND permit udp any host 192.168.2.2 eq 53
ASA1(config)# access-list ALL_OUTBOUND deny udp any any eq 53               
ASA1(config)# access-list ALL_OUTBOUND permit ip any any

2. Apply that access-list:

ASA1(config)# access-group ALL_OUTBOUND out interface OUTSIDE

3. Enable DNS server on R1 and configure R1 and R2 to use that DNS:

R2(config)#ip dns server 
R2(config)#ip host R2 192.168.2.2
R1, R3
(config)#ip name-server 192.168.2.2

4. testing by doing DNS lookup:

R1#ping R2
R3#ping R2

It works, this traffic are permitted by default since we go from a higher security level to a lower security level

5. let's have a look at ASA firewall access-list:

ASA1# show access-list ALL_OUTBOUND

6. let's see if we configure another DNS on R1:

R1(config)#no ip name-server 192.168.2.2
R1(config)#ip name-server 192.168.2.200
R1#ping R2

There is no response, to show the access-list on ASA firewall:

ASA1# show access-list ALL_OUTBOUND

-> Task-4: Editing Access-Lists:
Senario: add a new entry to an existing access-list in between some other entries

1. Create an access-list:

ASA1(config)# access-list ALL_OUTBOUND line 3 extended deny tcp any any

By specifying the line, you tell the ASA where to put this entry. Here’s what the access-list looks like now:

ASA1# show access-list ALL_OUTBOUND

2. if you want to remove an ACL, just put no in front of that ACL:

ASA1(config)# no access-list ALL_OUTBOUND line 3 extended deny tcp any any
ASA1# show access-list ALL_OUTBOUND                               

-> Task-5: Global Access-List:
The global access-list is useful when you have many interfaces and you don’t want to enable an access-list on each one of them. When you use this, you create an access-list like you normally do but instead of enabling on an interface, we enable it globally.

It is only applied to all inbound traffic on all interfaces. It doesn’t work for outbound traffic.

Senario: all devices on any interface that is connected to the ASA are only allowed to use a SMTP server on 192.168.3.3. All other SMTP traffic is not allowed:

1. Creating the ACL's:
ASA1(config)# access-list SMTP extended permit tcp any host 192.168.3.3 eq 25  
ASA1(config)# access-list SMTP extended permit tcp host 192.168.3.3 eq 25 any
ASA1(config)# access-list SMTP extended deny tcp any any eq 25
ASA1(config)# access-list SMTP extended permit ip any any

2. enable/apply it globally:

ASA1(config)# access-group SMTP global

instead of specifying the interface and direction we use the global keyword, to verify: 

R2#telnet 192.168.3.3 25
ASA1# show access-list SMTP

### Cisco ASA Remove Access-List ###

1. put "no" in front of the entry access-list:

ASA1(config)# no access-list MY_ACL permit ip any host 192.168.1.1

2. use "clear configure" to remove the entire ACL 

ASA1(config)# clear configure access-list MY_ACL

The clear configure command is not only to remove access-lists but you can use it to remove entire sections from your configuration. Try a “clear configure ?” on your ASA firewall and you will see a huge list with sections that you can remove from your configuration with this command.

### Cisco ASA Object Group for Access-List ###
Imagine you have to manage a Cisco ASA firewall that has hundreds of hosts and dozens of servers behind it, and for each of these devices we require access-list rules that permit or deny traffic.

With so many devices you will have a LOT of access-list statements and it might become an administrative nightmare to read, understand and update the access-list.

To make our lives a bit easier, Cisco introduced the object-group on Cisco ASA Firewalls

An object-group lets you “group” objects, this could be a collection of IP addresses, networks, port numbers, etc. Instead of creating an access-list with many different statements we can refer to an object-group. This makes the access-list smaller and easier to read. Whenever you make changes in the object-group, these are also reflected in the access-list

There are different types of object groups, let’s take a look what options we have on the ASA:

ASA1(config)# object-group ?
icmp-type, network, protocol, security, service, user

we will focus on network (used for IP addresses / network addresses) and service (used for TCP/UDP port numbers)

Example: 
Senario: we have five web servers in the DMZ. This means we require access to TCP port 80 for their IP addresses and our ACL command will be:

ASA1(config)# access-list HTTP_TO_DMZ permit tcp any host 192.168.3.1 eq 80
ASA1(config)# access-list HTTP_TO_DMZ permit tcp any host 192.168.3.2 eq 80
ASA1(config)# access-list HTTP_TO_DMZ permit tcp any host 192.168.3.3 eq 80
ASA1(config)# access-list HTTP_TO_DMZ permit tcp any host 192.168.3.4 eq 80
ASA1(config)# access-list HTTP_TO_DMZ permit tcp any host 192.168.3.5 eq 80

but here we wrote 5 statements :|

- let's do it easier with object-group, first we delete all the above ACL's:

ASA1(config)# clear configure access-list HTTP_TO_DMZ

1. we will create a network "object-group" where we configure the IP addresses of all my servers in the DMZ

ASA1(config)# object-group network WEB_SERVERS
ASA1(config-network-object-group)# network-object host 192.168.3.1
ASA1(config-network-object-group)# network-object host 192.168.3.2
ASA1(config-network-object-group)# network-object host 192.168.3.3
ASA1(config-network-object-group)# network-object host 192.168.3.4
ASA1(config-network-object-group)# network-object host 192.168.3.5

2. we will create the access-list again and we’ll use the object-group in it

ASA1(config)# access-list HTTP_TO_DMZ permit tcp any object-group WEB_SERVERS eq 80

The ACL has been reduce from five statements to just one statement. Instead of specifying each IP address separately, I refer to the object-group, to see the configurations and the access-list:

ASA1(config)# show run | include HTTP_TO_DMZ

ASA1(config)# show access-list HTTP_TO_DMZ 

access-list will show you both the object-group and the specific entries

Senario: our web servers require access to some extra TCP ports…besides TCP port 80 we also need access to 22, 23 and 443.

We could update our access-list to add these ports:

ASA1(config)# access-list HTTP_TO_DMZ permit tcp any object-group WEB_SERVERS eq 22
ASA1(config)# access-list HTTP_TO_DMZ permit tcp any object-group WEB_SERVERS eq 23
ASA1(config)# access-list HTTP_TO_DMZ permit tcp any object-group WEB_SERVERS eq 443

but here we have also 4 statements, to make it easier we use "object-group" that combines all our TCP ports :

ASA1(config)# object-group service DMZ_SERVICES tcp
ASA1(config-service-object-group)# port-object eq 22
ASA1(config-service-object-group)# port-object eq 23
ASA1(config-service-object-group)# port-object eq 80
ASA1(config-service-object-group)# port-object eq 443

we use a service object-group and it’s called DMZ_SERVICES. We add all the TCP ports that we want to use. We will re-create the access-list to look like this:

ASA1(config)# access-list HTTP_TO_DMZ permit tcp any object-group WEB_SERVERS object-group DMZ_SERVICES

We only require a single statement. The first object-group refers to the IP addresses and the second one refers to our TCP ports, to see the configuration: 

ASA1(config)# show run | include HTTP_TO_DMZ

to see everything, we use access-list command:

ASA1(config)# show access-list HTTP_TO_DMZ

That’s 20 statements that we reduced to 1 statement in our access-list because of our object-groups

### Cisco ASA Time Based Access-List ###
For each entry that you configure you can specify it to be valid only during a certain time or day.

Lab: 2 routers (R1, R3/http) and one ASA in the middle
we want our hosts inside R1 should not access the web server R3 only during the working hours:

1. Configure the clock:

ASA1(config)# clock set 13:55:00 3 December 2014

2. Create a time-range:

ASA1(config)# time-range WORK_HOURS   
ASA1(config-time-range)# periodic weekdays 09:00 to 17:00

This time-range called “WORK_HOURS” matches on weekdays and between 09:00 to 17:00.

3. Create an access-list:

ASA1(config)# access-list INSIDE_INBOUND extended deny tcp any any eq 80 time-range WORK_HOURS
ASA1(config)# access-list INSIDE_INBOUND extended permit ip any any
ASA1(config)# access-group INSIDE_INBOUND in interface inside

The access-list above denies traffic with destination TCP port 80 but only if it’s within our time-range. All other traffic is permitted. 

4. verify:

R1#telnet 192.168.3.3 80

I’ll telnet to TCP port 80 from R1 to R3 in the DMZ and it doesn’t work

ASA1# show access-list INSIDE_INBOUND


### Cisco ASA VLANs and Sub-Interfaces ###

- Each interface on a Cisco ASA firewall is a security zone, so security zones are limited to the number of interfaces. ASA has only 4 interfaces. 
- Sometimes we need additional security zones. like one zone for all DNS servers, one zones for all mail servers, one zones for all web servers and so on, so for that we have trunking and logical interfaces which means we can create multiple logical sub-interfaces on a single physical interface
- Each sub-interface can be assigned to a different security zone and they are separated by VLANs (we can create up to 1024 VLAN's)

The physical interface on the ASA will become a trunk interface which is not assigned to any security zone. Each sub-interface will be configured for a VLAN, security zone and security level

LAB: ASA firewall with one physical interface has 2 logical sub-interface. One ASA, one switch and 2 routers (R1/inside-1, R2/inside-2)

INSIDE-1 which uses VLAN 10 and has a security level of 70.
INSIDE-2 which uses VLAN 20 and has a security level of 80.

- Ethernet 0/0.10 will be used for security zone “INSIDE1” and uses VLAN 10.
- Ethernet 0/0.20 will be used for security zone “INSIDE2” and uses VLAN 20.
- The physical interface is not configured for any security zone.



-> Configurations:
- ASA Firewall Configuration:

ASA1(config)# interface Ethernet 0/0
ASA1(config-if)# no nameif
ASA1(config-if)# no security-level 
ASA1(config-if)# no ip address 
ASA1(config-if)# no shutdown

The configuration above is the default configuration for an interface on the ASA

declare the VLAN's:

ASA1(config)# interface Ethernet 0/0.10
ASA1(config-subif)# vlan 10
ASA1(config-subif)# nameif INSIDE1
ASA1(config-subif)# security-level 70
ASA1(config-subif)# ip address 192.168.10.254 255.255.255.0

ASA1(config)# interface Ethernet 0/0.20
ASA1(config-subif)# vlan 20
ASA1(config-subif)# nameif INSIDE2
ASA1(config-subif)# security-level 80
ASA1(config-subif)# ip address 192.168.20.254 255.255.255.0

- switch Configuration:

SW1(config)#interface FastEthernet 0/14
SW1(config-if)#switchport trunk encapsulation dot1q 
SW1(config-if)#switchport mode trunk 
SW1(config-if)#switchport trunk allowed vlan 10,20
SW1(config-if)#no shutdown

The interface connected to the ASA should be in trunk mode. It’s a good security practice to only allow the VLANs that we really want to use. The interfaces that connect the routers should be in access mode:

SW1(config)#interface FastEthernet 0/1
SW1(config-if)#switchport mode access
SW1(config-if)#switchport access vlan 10
SW1(config-if)#no shutdown

SW1(config)#interface FastEthernet 0/2
SW1(config-if)#switchport mode access 
SW1(config-if)#switchport access vlan 20
SW1(config-if)#no shutdown

The interface connected to R1 should be in VLAN 10 and R2 should be in VLAN 20

- Router Configuration:

R1(config)#interface FastEthernet 0/0
R1(config-if)#ip address 192.168.10.1 255.255.255.0
R1(config-if)#no shutdown
R1(config)#ip route 0.0.0.0 0.0.0.0 192.168.10.254

R2(config)#interface FastEthernet 0/0
R2(config-if)#ip address 192.168.20.2 255.255.255.0
R2(config-if)#no shutdown
R2(config)#ip route 0.0.0.0 0.0.0.0 192.168.20.254

Each router has an IP address and a default route that points to our ASA.

-> To verify:
let's ping from routers to the default gateways

R1#ping 192.168.10.254

R2#ping 192.168.20.254

It works, let's see if internal-VLAN communication works:

R2#telnet 192.168.10.1

It works :) 


Unit 5: IPSEC VPN

### Cisco ASA Site-to-Site IKEv1 IPsec VPN ###
Site-to-site IPsec VPNs are used to “bridge” two distant LANs together over the Internet to communicate.

-> How to configure IKEv1 IPsec between two Cisco ASA firewalls to bridge two LANs together:

LAB: 2 routers (R1, R2) and 2 ASA firewalls (ASA1, ASA2)
R1 -> ASA1 -> ASA2 -> R2

# 1. Phase 1 Configuration:

firstly establish a secure channel between the two peers. The ASAs will 1.exchange secret keys, 2.they authenticate each other and 3.will negotiate about the IKE security policies. This is what happens in phase 1:

- Authenticate and protect the identities of the IPsec peers.
- Negotiate a matching IKE policy between IPsec peers to protect the IKE exchange.
- Perform an authenticated Diffie-Hellman exchange to have matching shared secret keys.
- Setup a secure tunnel for IKE phase 2.

steps to configure IPSec VPN:
1. configure Phase-1 paramets
2. Enable iKEv1 on outside interface
3. Create tunnel group and pre-shared key
4. Create IPSec transform set
5. Create Crypto Map
6. Apply Crypto Map to exit interface

*** configuration on ASA1:

1. Setting up the IKEv1 policy

ASA1(config)# crypto ikev1 policy 10 
ASA1(config-ikev1-policy)# authentication pre-share 
ASA1(config-ikev1-policy)# encryption aes
ASA1(config-ikev1-policy)# hash sha
ASA1(config-ikev1-policy)# group 2
ASA1(config-ikev1-policy)# lifetime 3600

- The IKEv1 policy starts with a priority number, I picked number 10. The lower the number, the higher the priority. You can use this if you have multiple peers.
- We use a pre-shared key for authentication.
- Encryption is done with AES.
- SHA is used for hashing.
- We use Diffie-Hellman group 2 for secret key exchange.
- The security association is 3600 seconds, once this expires we will do a renegotiation

IMPORTANT: If you use any ASA version before ASA 8.4 then the keyword “ikev1” has to be replaced with “isakmp”.

2. The IKEv1 policy is configured, to enable it:

ASA1(config)# crypto ikev1 enable OUTSIDE
ASA1(config)# crypto isakmp identity address 

The first command enables our IKEv1 policy on the OUTSIDE interface and the second command is used so the ASA identifies itself with its IP address, not its FQDN

3. Now we need to specify the remote peer and a pre-shared key. This is done with a tunnel-group:

ASA1(config)# tunnel-group 10.10.10.2 type ipsec-l2l

The IP address above is the IP address of the OUTSIDE interface on ASA2. The type “ipsec-l2l” means lan-to-lan

4. Configure the pre-shared key

ASA1(config)# tunnel-group 10.10.10.2 ipsec-attributes 
ASA1(config-tunnel-ipsec)# ikev1 pre-shared-key MY_SHARED_KEY

The pre-shared key is configured as an attribute for the remote peer. I’ll use “MY_SHARED_KEY” as the pre-shared key between the two ASA firewalls. 

Now we configure the same thing on ASA2: 

ASA2(config)# crypto ikev1 policy 10
ASA2(config-ikev1-policy)# authentication pre-share 
ASA2(config-ikev1-policy)# encryption aes
ASA2(config-ikev1-policy)# hash sha
ASA2(config-ikev1-policy)# group 2
ASA2(config-ikev1-policy)# lifetime 3600

ASA2(config)# crypto ikev1 enable outside
ASA2(config)# crypto isakmp identity address 

ASA2(config)# tunnel-group 10.10.10.1 type ipsec-l2l

ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes 
ASA2(config-tunnel-ipsec)# ikev1 pre-shared-key MY_SHARED_KEY

# 2. Phase 2 configuration:
Once the secure tunnel from phase 1 has been established, we start with phase 2. Here the two firewalls will negotiate about the IPsec security parameters that will be used to protect the traffic within the tunnel, in other words:

- Negotiate IPsec security parameters through the secure tunnel from phase 1.
- Establish IPsec security associations.
- Periodically renegotiates IPsec security associations for security.

1. Configure an access-list that defines what traffic to encrypt. This will be the traffic between 192.168.1.0 /24 and 192.168.2.0 /24.

ASA1(config)# access-list LAN1_LAN2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0

2. The IPsec peers will negotiate about the encryption and authentication algorithms and this is done using a transform-set. Here’s what it looks like:

ASA1(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac

The transform set is called “MY_TRANSFORM_SET” and it specifies that we want to use ESP with 256-bit AES encryption and SHA for authentication

3. configure a crypto map which has all the phase 2 parameters

ASA1(config)# crypto map MY_CRYPTO_MAP 10 match address LAN1_LAN2
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.2
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds 3600
ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

- The crypto map is called “MY_CRYPTO_MAP” and number 10 is the sequence number. The sequence number is used because you can have a single crypto map for multiple different remote peers.
- The set peer command configures the IP address of the remote peer, ASA2 in this example.
- The set ikev1 transform-set command is used to refer to the transform set that we configured before.
- The set security-association command specifies when the security association will expire and when we do a renegotiation.
- The interface command activates the crypto map on the interface.

Now the same configuration on ASA2:

ASA2(config)# access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0

ASA2(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac
ASA2(config)# crypto map MY_CRYPTO_MAP 10 match address LAN2_LAN1
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.1   
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds 3600                             
ASA2(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

4. make sure the the firewalls reach each other, so use routing:

ASA1(config)# route OUTSIDE 192.168.2.0 255.255.255.0 10.10.10.2

ASA2(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

don't forget ASA1,2(config)# write memory to save configuration

# 3. To verify:

ping from R1 to R2
R1#ping 192.168.2.2             

ASA1# show crypto isakmp sa

State: MM_ACTIVE means that the IPsec tunnel has been established

ASA1# show crypto ipsec sa

Final Configuration:

*** ASA1 ***
hostname ASA1
!
interface FastEthernet0/0
 nameif INSIDE
 security-level 100
 ip address 192.168.1.254 255.255.255.0 
!             
interface FastEthernet0/1
 nameif OUTSIDE
 security-level 0
 ip address 10.10.10.1 255.255.255.0 
!
access-list LAN1_LAN2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0 
!
route OUTSIDE 192.168.2.0 255.255.255.0 10.10.10.2 1
!
crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac 
!
crypto map MY_CRYPTO_MAP 10 match address LAN1_LAN2
crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.2 
crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds 3600
crypto map MY_CRYPTO_MAP interface OUTSIDE
!
crypto isakmp identity address 
crypto ikev1 enable OUTSIDE
crypto ikev1 policy 10
 authentication pre-share
 encryption aes
 hash sha
 group 2
 lifetime 3600
!
tunnel-group 10.10.10.2 type ipsec-l2l
tunnel-group 10.10.10.2 ipsec-attributes
 ikev1 pre-shared-key *****
!
end

*** ASA2 ***
hostname ASA2
!
interface FastEthernet0/0
 nameif INSIDE
 security-level 100
 ip address 192.168.2.254 255.255.255.0 
!             
interface FastEthernet0/1
 nameif OUTSIDE
 security-level 0
 ip address 10.10.10.2 255.255.255.0 
!
access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0 
!
route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1 1
!
crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac 
!
crypto map MY_CRYPTO_MAP 10 match address LAN2_LAN1
crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.1 
crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds 3600
crypto map MY_CRYPTO_MAP interface OUTSIDE
!
crypto isakmp identity address 
crypto ikev1 enable OUTSIDE
crypto ikev1 policy 10
 authentication pre-share
 encryption aes
 hash sha
 group 2
 lifetime 3600
!
tunnel-group 10.10.10.1 type ipsec-l2l
tunnel-group 10.10.10.1 ipsec-attributes
 ikev1 pre-shared-key *****
!
end 

*** ASA2 ***
hostname R1
!
no ip routing
!
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 duplex auto
 speed auto
!
ip default-gateway 192.168.1.254
!
end

*** ASA2 ***
hostname R2
!
no ip routing
!
interface FastEthernet0/0
 ip address 192.168.2.2 255.255.255.0
 duplex auto
 speed auto
!
ip default-gateway 192.168.2.254
!
end

Youtube Vidoe: https://www.youtube.com/watch?v=s7bQ9p8eZ00


### Cisco ASA Site-to-Site IKEv1 IPsec VPN Dynamic Peer ###
To configure a site-to-site IPsec VPN but with dynamic IP address on one of the ASAs.

LAB: like before
R1 -> ASA1 -> ASA2 -> R2
ASA1 will use a static IP, ASA2 will use a dynamic IP address.

-> Phase 1 Configuration:
1. Create IKEv1 policy:

ASA1 & ASA2
(config)# crypto ikev1 policy 10
(config-ikev1-policy)# authentication pre-share
(config-ikev1-policy)# encryption aes
(config-ikev1-policy)# hash sha
(config-ikev1-policy)# group 2
(config-ikev1-policy)# lifetime 3600

2. Enable IKEv1 policy on outside interface on ASA:

ASA1 & ASA2
(config)# crypto isakmp identity address 
(config)# crypto ikev1 enable OUTSIDE

3. Configure a tunnel group:

- Tunnel-Group Static Peer ASA1

ASA1(config)# tunnel-group DefaultL2LGroup ipsec-attributes 
ASA1(config-tunnel-ipsec)# ikev1 pre-shared-key MY_SHARED_KEY

Normally we configure an IP address of the remote peer in our tunnel-group. Since the remote peer is using a dynamic IP address, we need to use the “DefaultL2LGroup” tunnel-group. This is a built-in tunnel-group and all connections that don’t match another tunnel-group will belong to this group:

- Tunnel-Group ASA2 Dynamic Peer
On ASA2 we can use a “normal” tunnel-group where we specify our IP address:

ASA2(config)# tunnel-group 10.10.10.1 type ipsec-l2l
ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes
ASA2(config-tunnel-ipsec)# ikev1 pre-shared-key MY_SHARED_KEY

-> Phase 2 configuration:

1. Configure the transform-set:

ASA1 & ASA2
(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac

2. Create some access-lists that define what traffic should be encrypted:

ASA1(config)# access-list LAN1_LAN2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0

ASA2(config)# access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0

3. Configure the Crypto map 

- Crypto Map Static Peer ASA1
Here we use a dynamic map:

ASA1(config)# crypto dynamic-map MY_DYNA_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA1(config)# crypto dynamic-map MY_DYNA_MAP 10 match address LAN1_LAN2
ASA1(config)# crypto dynamic-map MY_DYNA_MAP 10 set reverse-route

In the dynamic map we refer to the "transform set" and the "access-list" that we just created. We also add the "reverse-route" parameter. This allows the ASA to automatically insert a static route in the routing table for networks behind the remote peer

Now we can create a crypto map where we refer to the dynamic map we just created:

ASA1(config)# crypto map MY_CRYPTO_MAP 10 ipsec-isakmp dynamic MY_DYNA_MAP
ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

ASA1 is now ready to accept VPN connections from any IP address. Let’s continue with ASA2.

- Crypto Map ASA2 Dynamic Peer
Here we create the normal crypto map:

ASA2(config)# crypto map MY_CRYPTO_MAP 10 match address LAN2_LAN1
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.1 
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA2(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

and don't forget to add a static route:

ASA2(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

-> Verify:

Since ASA1 doesn’t know the IP address of ASA2, we’ll have to initiate the connection from ASA2

R2#ping 192.168.1.1 

ASA1# show crypto isakmp sa
ASA2# show crypto isakmp sa

ASA1# show route static 

ASA1# show crypto ipsec sa -> verify that packets have been encrypted/decrypted
ASA2# show crypto ipsec sa

Everything is working fine, let's check if it's dynamic by changing the outside IP address on ASA2 to find out

ASA2(config)# interface GigabitEthernet0/1
ASA2(config-if)# ip address 10.10.10.200 255.255.255.0

R2#ping 192.168.1.1 

ASA1# show crypto isakmp sa | include Peer

Final Configuration:
in the file named "4.2 final configuration"

### Cisco ASA Site-to-Site IKEv1 IPsec VPN Dynamic Peers ###
Here we will configure the both ASA firewall with dynamic IP

LAB: See 4.3 picture
We will configure two VPN tunnels:
- Between ASA1 and ASA2.
- Between ASA1 and ASA3.
ASA1 will use a static IP address, and ASA2/ASA3 have dynamic IP addresses

-> ASA1 - Static IP: 

ASA1(config)# crypto ikev1 policy 10
ASA1(config-ikev1-policy)# authentication pre-share 
ASA1(config-ikev1-policy)# encryption aes-256
ASA1(config-ikev1-policy)# hash sha
ASA1(config-ikev1-policy)# group 2

ASA1(config)# crypto isakmp identity address 
ASA1(config)# crypto ikev1 enable OUTSIDE

ASA1(config)# tunnel-group ASA1_ASA2 type ipsec-l2l
ASA1(config)# tunnel-group ASA1_ASA2 ipsec-attributes
ASA1(config-tunnel-ipsec)# ikev1 pre-shared-key ASA1_ASA2_KEY

ASA1(config)# tunnel-group ASA1_ASA3 type ipsec-l2l
ASA1(config)# tunnel-group ASA1_ASA3 ipsec-attributes
ASA1(config-tunnel-ipsec)#  ikev1 pre-shared-key ASA1_ASA3_KEY

ASA1(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac

ASA1(config)# access-list LAN1_LAN2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0
ASA1(config)# access-list LAN1_LAN3 extended permit ip 192.168.1.0 255.255.255.0 192.168.3.0 255.255.255.0

ASA1(config)# crypto dynamic-map ASA1_ASA2 10 match address LAN1_LAN2
ASA1(config)# crypto dynamic-map ASA1_ASA2 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA1(config)# crypto dynamic-map ASA1_ASA2 10 set reverse-route

ASA1(config)# crypto dynamic-map ASA1_ASA3 10 match address LAN1_LAN3
ASA1(config)# crypto dynamic-map ASA1_ASA3 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA1(config)# crypto dynamic-map ASA1_ASA3 10 set reverse-route

ASA1(config)# crypto map MY_CRYPTO_MAP 10 ipsec-isakmp dynamic ASA1_ASA2
ASA1(config)# crypto map MY_CRYPTO_MAP 20 ipsec-isakmp dynamic ASA1_ASA3

ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

-> ASA2 – Dynamic IP:

1. Create IKEv1 policy
ASA2(config)# crypto ikev1 policy 10
ASA2(config-ikev1-policy)# authentication pre-share
ASA2(config-ikev1-policy)# encryption aes-256
ASA2(config-ikev1-policy)# hash sha
ASA2(config-ikev1-policy)# group 2

2. Enable IKEv1 policy on outside interface
ASA2(config)# crypto isakmp identity key-id ASA1_ASA2
ASA2(config)# crypto ikev1 enable OUTSIDE

ASA1 has to figure out which tunnel-group to use when ASA2 initiates a VPN connection. This is done with the key-id above. This name has to match with the tunnel-group that we configured on ASA1

3. Configure the tunnel group
ASA2(config)# tunnel-group 10.10.10.1 type ipsec-l2l
ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes
ASA2(config-tunnel-ipsec)# ikev1 pre-shared-key ASA1_ASA2_KEY

The tunnel-group configuration is pretty straight-forward. We define the IP address of ASA1 and the correct pre-shared key

4. Configure a transform-set

ASA2(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac

5. Create an access-list:

ASA2(config)# access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0

6. Configure the crypto map:

ASA2(config)# crypto map MY_CRYPTO_MAP 10 match address LAN2_LAN1
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.1 
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 phase1-mode aggressive 
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA2(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

7. Static route:

ASA2(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1


-> ASA3 – Dynamic IP: 

ASA3(config)# crypto ikev1 policy 10
ASA3(config-ikev1-policy)# authentication pre-share 
ASA3(config-ikev1-policy)# encryption aes-256
ASA3(config-ikev1-policy)# hash sha
ASA3(config-ikev1-policy)# group 2

ASA3(config)# crypto isakmp identity key-id ASA1_ASA3
ASA3(config)# crypto ikev1 enable OUTSIDE

ASA3(config)# tunnel-group 10.10.10.1 type ipsec-l2l
ASA3(config)# tunnel-group 10.10.10.1 ipsec-attributes 
ASA3(config-tunnel-ipsec)# ikev1 pre-shared-key ASA1_ASA3_KEY

ASA3(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac

ASA3(config)# access-list LAN3_LAN1 extended permit ip 192.168.3.0 255.255.255 192.168.1.0 255.255.255.0

ASA3(config)# crypto map MY_CRYPTO_MAP 10 match address LAN3_LAN1
ASA3(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.1 
ASA3(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 phase1-mode aggressive 
ASA3(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA3(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

ASA3(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

-> Verify:

pings from R2 and R3 to R1 to trigger the ASA firewalls to initiate a VPN connection
R2#ping 192.168.1.1 
R3#ping 192.168.1.1 
It works! 

to look at the VPN connection closer: 
ASA1# show crypto isakmp sa

to make sure the traffic is encrypted:
ASA1# show crypto ipsec sa peer 10.10.10.2
ASA1# show crypto ipsec sa peer 10.10.10.3

to prove it works, we will change the IP on ASA2 and ASA3
ASA2(config)# interface GigabitEthernet 0/1
ASA2(config-if)# ip address 10.10.10.20 255.255.255.0
ASA3(config)# interface GigabitEthernet 0/1
ASA3(config-if)# ip address 10.10.10.30 255.255.255.0

Let’s do another ping:
R2#ping 192.168.1.1 
R3#ping 192.168.1.1 

ASA1# show crypto isakmp sa | include Peer


### OpenSSL Certification Authority (CA) on Ubuntu Server ###
OpenSSL is a free, open-source library that you can use for digital certificates, like building your own CA.

Use case:
HTTPS, VPN instead of using a pre-shared key for authentication, Wireless

so instead of paying companies for CA, we can create our own for our applications

How to build:

1. make sure of your time:
$ sudo apt-get install ntp
$ cat /etc/ntp.conf | grep server
$ ntpq -p

2. OpenSSL configuration:
# vim /usr/lib/ssl/openssl.cnf and edit

[ CA_default ]
dir = ./demoCA -> dir = /root/ca  -> directory where I save my keys and certificates

[ policy_match ]
change them all to optional (only for lab)

3. Create a root CA:
This consists of a private key and root certificate. These two items are the “identity” of our CA.

# touch index.txt -> OpenSSL keeps track of all signed certificates

# echo '1234' > serial -> Each signed certificate will have a serial number, we start with number 1234

# openssl genrsa -aes256 -out cakey.pem 4096 -> generate the root private key

# openssl req -new -x509 -key /root/ca/cakey.pem -out cacert.pem -days 365 -set_serial 0 -> we used  the root private key to create the root certificate

https://www.ipswitch.com/blog/how-to-use-openssl-to-generate-certificates?adlt=strict


### Cisco ASA Site-to-Site IPsec VPN Digital Certificates ###
When you use pre-shared keys, you have to manually configure a pre-shared key for each peer that you want to use IPsec with.

With digital certificates, each peer gets a certificate from a CA (Certificate Authority). When two peers want to use IPsec, they exchange their certificates to authenticate each other.

LAB: R1, R2, ASA1, ASA2, OpenSSL
ASA's firewall to build the VPN IPSec to encrypt traffic, and ther routers to test the VPN IPSec.

1. Set the time to your local time.
https://networklessons.com/cisco/asa-firewall/cisco-asa-clock-configuration

2. After creating the root certificate, we import the root certificate on our ASA, for that we need to configure a trustpoint:

ASA1(config)# crypto ca trustpoint MY_CA
ASA1(config-ca-trustpoint)# enrollment terminal 

we created a trustpoint called MY_CA and we enable the "enrollment terminal" for copy and paste on the terminal

to enroll the our CA on the terminal:

ASA1(config)# crypto ca authenticate MY_CA
paste the contents of the cacert.pem file then write quit

Now the ASA will trust certificates that are signed by our CA.


3. Generate CSR(Certificate Signing Request) on ASA:

The next step is to create a certificate for ASA1. We will do this by creating a CSR (Certificate Signing Request) which the CA will sign.

-> 1. configure a hostname and domainname for our ASA:
ASA1(config)# hostname ASA1 
ASA1(config)# domain-name networklessons.local

-> 2. The CSR has to be signed with a private key, to generate one:
ASA1(config)# crypto key generate rsa label ASA1_KEY modulus 2048

This will generate a key-pair called ASA1_KEY

-> 3. configure the attributes for our CSR in the trustpoint:
ASA1(config)# crypto ca trustpoint MY_CA

-> 4. configure the FQDN for our ASA:
ASA1(config-ca-trustpoint)# fqdn ASA1.networklessons.local

-> 5. configure the attributes that identify our device:
ASA1(config-ca-trustpoint)# subject-name O=Networklessons, C=NL, EA=admin@networklessons.local, ST=North-Brabant, CN=ASA1.networklessons.local

-> 6. specify the key that we want to use so sign the CSR. We will use the key-pair that we just created:
ASA1(config-ca-trustpoint)# keypair ASA1_KEY

-> 7. Now we are ready to create the CSR:
ASA1(config)# crypto ca enroll MY_CA

-> 8. Copy the content of the certificate into a new file, then use OpenSSL to sign the CSR:
# openssl ca -in ASA1_CSR.txt -out ASA1_SIGNED.pem

-> 9. Now we import this ASA1_SIGNED.pem file to our ASA:
ASA1(config)# crypto ca import MY_CA certificate 

paste the content of the ASA1_SIGNED.pem to the terminal then write quit

4. We repeat this on ASA2

-> 1. 
ASA2(config)# crypto ca trustpoint MY_CA                         
ASA2(config-ca-trustpoint)# enrollment terminal

-> 2.
ASA2(config)# crypto ca authenticate MY_CA
paste the .pem content and write quit

-> 3. generate a key-pair and configure the attributes for the CSR:

ASA2(config)# crypto key generate rsa label ASA2_KEY modulus 2048

ASA2(config)# crypto ca trustpoint MY_CA
ASA2(config-ca-trustpoint)# fqdn ASA2.networklessons.local
ASA2(config-ca-trustpoint)# subject-name O=Networklessons, C=NL, EA=admin@networklessons.local, ST=North-Brabant, CN=ASA2.networklessons.local
ASA2(config-ca-trustpoint)# keypair ASA2_KEY
ASA2(config-ca-trustpoint)# exit

-> 4. Create the CSR:
ASA2(config)# crypto ca enroll MY_CA

-> 5. Sign the CSR with OpenSSL to create a certificate, saved as ASA2_SIGNED.pem
# openssl ca -in ASA2_CSR.txt -out ASA2_SIGNED.pem

-> 6. Import this certificate on ASA2
ASA2(config)# crypto ca import MY_CA certificate 
paste the .pem file into the terminal

Now both firewalls has signed certificate by us

The VPN configuration for digital certificates is 99% the same as for pre-shared keys. 

4. Phase 1 Configuration:

-> 1. Configure the ikev1 policy
ASA1(config)# crypto ikev1 policy 10
ASA1(config-ikev1-policy)# authentication rsa-sig
ASA1(config-ikev1-policy)# encryption 3des
ASA1(config-ikev1-policy)# hash sha
ASA1(config-ikev1-policy)# group 1
ASA1(config-ikev1-policy)# lifetime 86400

we used the authentication rsa-sig command to tell the ASA to use its certificate instead of a pre-shared key, 

-> 2. Enable the policy on outside interface:
ASA1(config)# crypto ikev1 enable OUTSIDE

-> 3. Configure the tunnel group
ASA1(config)# tunnel-group 10.10.10.2 type ipsec-l2l
ASA1(config)# tunnel-group 10.10.10.2 ipsec-attributes
ASA1(config-tunnel-ipsec)# ikev1 trust-point MY_CA

we used the MY_CA trustpoint for the connection to ASA2

-> 4. configure the same on ASA2

ASA2(config)# crypto ikev1 policy 10
ASA2(config-ikev1-policy)# authentication rsa-sig
ASA2(config-ikev1-policy)# encryption 3des
ASA2(config-ikev1-policy)# hash sha
ASA2(config-ikev1-policy)# group 1
ASA2(config-ikev1-policy)# lifetime 86400

ASA2(config)# crypto ikev1 enable OUTSIDE

ASA2(config)# tunnel-group 10.10.10.1 type ipsec-l2l 
ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes 
ASA2(config-tunnel-ipsec)# ikev1 trust-point MY_CA

4. Phase 2 Configuration:

-> 1. Create an access-list:
ASA1(config)# access-list LAN1_LAN2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0

-> 2. Create an transform-set
ASA1(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-3des esp-sha-hmac

-> 3. Configure the Crypto-map:
ASA1(config)# crypto map MY_CRYPTO_MAP 10 match address LAN1_LAN2
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.2 
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds
ASA1(config)# crypto map MY_CRYPTO_MAP 10 set trustpoint MY_CA
ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

Above you can see we specify the trustpoint under the crypto map

-> 4. we do the same on ASA2:

ASA2(config)# access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0

ASA2(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-3des esp-sha-hmac

ASA2(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-3des esp-sha-hmac
ASA2(config)# crypto map MY_CRYPTO_MAP 10 match address LAN2_LAN1
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.1 
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds
ASA2(config)# crypto map MY_CRYPTO_MAP 10 set trustpoint MY_CA
ASA2(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

-> 5. Configure the static route

ASA1(config)# route OUTSIDE 192.168.2.0 255.255.255.0 10.10.10.2
ASA2(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

5. Verification:
check the trustpoint and certificates

ASA1# show crypto ca trustpoints MY_CA -> to see our trustpoint

ASA1# show crypto ca certificates -> to check for certificates

R1#ping 192.168.2.2 -> to test our VPN, ping from R1 to R2

ASA1# show crypto isakmp sa -> to see the security association

ASA1# show crypto ipsec sa -> to see what traffic is encrypted


### Cisco ASA Site-to-Site IKEv2 IPSEC VPN ###
How to configure site-to-site IKEv2 IPsec VPN (VPN between ASA1 and ASA2)

LAB: 2 routers (R1, R2) and 2 ASA firewalls (ASA1, ASA2)

1. Configure the IKEv2 policy:

ASA1 & ASA2#
(config)# crypto ikev2 policy 10
ASA1(config-ikev2-policy)# encryption aes
ASA1(config-ikev2-policy)# group 2
ASA1(config-ikev2-policy)# prf sha
ASA1(config-ikev2-policy)# lifetime seconds 86400

The configuration is similar to the IKEv1 policy, the only new command is "prf sha". PRF is the Pseudo Random Function algorithm which is the same as the integrity algorithm.

2. IKEv2 IPSEC Proposal:
similar to phase 2 of IKEv1 where we have to configure a transform set. For IKEv2 we call this the IPSEC proposal and to configure: 

ASA1 & ASA2#
(config)# crypto ipsec ikev2 ipsec-proposal MY_PROPOSAL 
(config-ipsec-proposal)# protocol esp encryption aes
(config-ipsec-proposal)# protocol esp integrity sha-1

We will use ESP, AES as the encryption algorithm and SHA for integrity

3. Create the access-list to define what traffic to encrypt:

ASA1(config)# access-list LAN1_LAN2 extended permit ip host 192.168.1.1 host 192.168.2.2

ASA2(config)# access-list LAN2_LAN1 extended permit ip host 192.168.2.2 host 192.168.1.1

4. Configure the crypto map that combines the access-list, remote peer and IKEv2 proposal together: 

ASA1(config)# crypto map MY_CRYPTO_MAP 1 match address LAN1_LAN2
ASA1(config)# crypto map MY_CRYPTO_MAP 1 set peer 10.10.10.2   
ASA1(config)# crypto map MY_CRYPTO_MAP 1 set ikev2 ipsec-proposal MY_PROPOSAL
ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

ASA2(config)# crypto map MY_CRYPTO_MAP 1 match address LAN2_LAN1
ASA2(config)# crypto map MY_CRYPTO_MAP 1 set peer 10.10.10.1         
ASA2(config)# crypto map MY_CRYPTO_MAP 1 set ikev2 ipsec-proposal MY_PROPOSAL                                
ASA2(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

The crypto map is called “MY_CRYPTO_MAP” and it specifies the access-list, remote peer and the IKEv2 proposal. It has been attached to the OUTSIDE interface.

5. configure the tunnel group. This is where we define authentication and the pre-shared-key:

ASA1(config)# tunnel-group 10.10.10.2 type ipsec-l2l
ASA1(config)# tunnel-group 10.10.10.2 ipsec-attributes 
ASA1(config-tunnel-ipsec)# ikev2 local-authentication pre-shared-key CISCO123 
ASA1(config-tunnel-ipsec)# ikev2 remote-authentication pre-shared-key CISCO456

ASA2(config)# tunnel-group 10.10.10.1 type ipsec-l2l 
ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes 
ASA2(config-tunnel-ipsec)# ikev2 local-authentication pre-shared-key CISCO456
ASA2(config-tunnel-ipsec)# ikev2 remote-authentication pre-shared-key CISCO123

Above we configured the remote peer and the IPSEC type (lan to lan). IKEv2 allows us to use different authentication methods for each peer. In this example I used a different pre-shared key for each peer.

6. Enable the IKEv2 on the interface:

ASA1(config)# crypto ikev2 enable OUTSIDE
ASA2(config)# crypto ikev2 enable OUTSIDE

7. Configure the static route to make routers reachable:

ASA1(config)# route OUTSIDE 192.168.2.0 255.255.255.0 10.10.10.2
ASA2(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

8. Verify: 

to check, if we have a IKEv2 security association:
ASA1# show crypto isakmp sa

to check if the traffic is encrypted:
ASA1# show crypto ipsec sa


Nowadays you should always use IKEv2 (if possible). It supports a couple of things that IKEv1 doesn’t.

- IKEv2 uses fewer messages than IKEv1 to establish the tunnel and uses less bandwidth.
- IKEv2 has built-in support for NAT traversal.
- IKEv2 has a built-in keepalive mechanism (Dead Peer Detection).
- IKEv2 supports EAP authentication.
- IKEv2 has some built-in mechanisms against DoS attacks.

In short, there’s no reason to use IKEv1 anymore unless you have older equipment that doesn’t support IKEv2 for some reason.


### Cisco ASA Remote Access VPN ###
How to configure remote access IPsec VPN using the Cisco VPN client. This allows remote users to connect to the ASA and access the remote network through an IPsec encrypted tunnel.

The remote user requires the Cisco VPN client software on his/her computer, once the connection is established the user will receive a private IP address from the ASA and has access to the network.

The Cisco VPN client is end-of-life and has been replaced by the Cisco Anyconnect Secure Mobility Client, but still used widely

LAB: one router (R1/inside), one ASA (ASA1) and one user (outside)

1. Configure a VPN pool with IP addresses that we will assign to remote VPN users:

ASA1(config)# ip local pool VPN_POOL 192.168.10.100-192.168.10.200

2. Tell the ASA that we will use this local pool for remote VPN users

ASA1(config)# vpn-addr-assign local


3. NAT Exception: 
If NAT is enabled on ASA then we need to ensure that traffic between 192.168.1.0/24 (the local network) and 192.168.10.0/24 (our remote VPN users) doesn’t get translated, so we use NAT excemption (for ASA version 8.3 or higher):

ASA1(config)# object network LAN  
ASA1(config-network-object)# subnet 192.168.1.0 255.255.255.0

ASA1(config)# object network VPN_POOL
ASA1(config-network-object)# subnet 192.168.10.0 255.255.255.0

ASA1(config)# nat (INSIDE,OUTSIDE) source static LAN LAN destination static VPN_POOL VPN_POOL

we create 2 network objects, one for our local network and another one for the remote VPN users. The NAT rule tells the ASA not to translate traffic between the two networks

4. Group Policy:
wenn remote user establish the VPN, he can't access the Internet. Only the remote network is reachable. For security reasons this is a good practice as it forces you to send all traffic through the ASA. If you don’t want this then you can enable "split tunneling" to use the VPN only for access to the remote network. Here’s how to enable it:

ASA1(config)# access-list SPLIT_TUNNEL standard permit 192.168.1.0 255.255.255.0

To create a group policy. allows you to assign different remote users to different groups with different attributes. You might want to have a group policy for “network engineers” and another one for “regular users” each with different DNS servers, timeout settings, etc.

ASA1(config)# group-policy VPN_POLICY internal
ASA1(config)# group-policy VPN_POLICY attributes
ASA1(config-group-policy)# dns-server value 8.8.8.8
ASA1(config-group-policy)# vpn-idle-timeout 15
ASA1(config-group-policy)# split-tunnel-policy tunnelspecified
ASA1(config-group-policy)# split-tunnel-network-list value SPLIT_TUNNEL

The group policy is called VPN_POLICY and it’s an internal group policy which means it is created locally on the ASA. You can also specify an external group policy on a RADIUS server. I added some attributes, for example a DNS server and an idle timeout (15 minutes). Split tunneling is optional but I added it to show you how to use it, it refers to the access-list we created earlier.

If you want to configure an access-list so the remote VPN users can only reach certain networks, IP addresses or ports then you can apply this under the group policy.

5. create a user for remote access

ASA1(config)# username VPN_USER password MY_PASSWORD

6. Configure an IPSec Phase 1:

ASA1(config)# crypto ikev1 policy 10
ASA1(config-ikev1-policy)# encryption aes
ASA1(config-ikev1-policy)# hash sha
ASA1(config-ikev1-policy)# authentication pre-share 
ASA1(config-ikev1-policy)# group 2
ASA1(config-ikev1-policy)# lifetime 86400

AES for encryption, SHA for integrity, a pre-shared key and Diffie-Hellman group 2 for key exchange and The lifetime is 86400 seconds

Enable the IKEv1 policy on the outside interface:

ASA1(config)# crypto ikev1 enable OUTSIDE
ASA1(config)# crypto isakmp identity address

7. Configure an IPSec Phase 2:

-> 
ASA1(config)# crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes esp-sha-hmac

we configure a transform set called “MY_TRANSFORM_SET” and we use ESP with AES/SHA.

-> 
configure a dynamic crypto map, since the remote VPN users probably are behind dynamic IP addresses and we don’t know which ones:

ASA1(config)# crypto dynamic-map MY_DYNA_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET

The dynamic crypto map is called “MY_DYNA_MAP” and it refers to the transform set. Even though we have a dynamic crypto map, we still have to attach this to a static crypto map: 

ASA1(config)# crypto map MY_CRYPTO_MAP 10 ipsec-isakmp dynamic MY_DYNA_MAP

-> 
attach it to the outside interface:

ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

8. Create the tunnel group:
It binds the group policy and pool together and it’s where we configure a pre-shared key for the group policy:

ASA1(config)# tunnel-group MY_TUNNEL type remote-access 
ASA1(config)# tunnel-group MY_TUNNEL general-attributes 
ASA1(config-tunnel-general)# address-pool VPN_POOL
ASA1(config-tunnel-general)# default-group-policy VPN_POLICY

The tunnel group is called “MY_TUNNEL” and we add the pool and group policy

-> 
we configure its attributes

ASA1(config)# tunnel-group MY_TUNNEL ipsec-attributes 
ASA1(config-tunnel-ipsec)# ikev1 pre-shared-key MY_SHARED_KEY

we set the pre-shared key to “MY_SHARED_KEY

9. Verification:

install the VPN client:
-> click on new
-> Host is the outside IP address
-> Name is the tunnel group name, (e.g. MY_TUNNEL)
-> Password is the pre-shared key under the tunnel group (e.g. MY_SHARED_KEY), not the user password.
-> Save the setting, then connect
-> enter the usernaem and password we created

on client pc you can see the ip >ipconfig /all
and ping to R1 >ping 192.168.1.1

on ASA firewall:
ASA1# show crypto ipsec sa


### Cisco ASA VPN Filter ###
The Cisco ASA supports VPN filters that let you filter decrypted traffic that exits a tunnel or pre-encrypted traffic before it enters a tunnel.

VPN filters use access-lists and you can apply them to:
Group policy, Username attributes, Dynamic access policy (DAP)
Priority (overrules): Dynamic access policy -> Unsername attributes -> group policy.

we will Configure VPN filter on remote access VPN using group policy and username attributes

LAB: 2 routers (R1/inside, R2/inside), one ASA and one remote user(outside) 5.7 
Senario: we want a remote user to access the inside network (2 routers) through the ASA firewall.

1. we set the basic configuration on ASA1, R1, R2

2. we try from client pc to connect with the network through VPN Client APP, then we ping the routers to check if client can reach them.

As shown we have full access to the 192.168.1.0/24 network, to restrict we use one of (Group policy, Username attributes, Dynamic access policy (DAP))

-> Group Policy:

1. Create access-list that only permits ICMP traffic to R1:
ASA1(config)# access-list RESTRICT_VPN permit icmp any host 192.168.1.1

2. We apply the access-list to the group policy:
ASA1(config)# group-policy VPN_POLICY attributes
ASA1(config-group-policy)# vpn-filter value RESTRICT_VPN

3. We need to reconnect our VPN client either from VPN client or to disconnect from the ASA and reconnect from the VPN client:
ASA1# clear crypto ipsec sa
ASA1# debug acl filter -> to enable a debug

4. to verify:
ASA1# show asp table filter

then try to ping from R1 and R2
the R1 will work but the R2 will not :) 

-> Username Attributes

1. Create access-list that only permits ICMP traffic 
ASA1(config)# access-list RESTRICT_VPN_USER extended permit icmp any any

2. enable this access-list under the username attributes:
ASA1(config)# username VPN_USER attributes
ASA1(config-username)# vpn-filter value RESTRICT_VPN_USER

3. reconnect from the VPN client

4. the "Username Attributes" overrule the group policy, to check:
C:\Users\h1>ping 192.168.1.1 -n 1
C:\Users\h1>ping 192.168.1.2 -n 1

The traffic is permitted, to see the ASP table:

ASA1# show asp table filter hits


### Cisco ASA Hairpin Remote VPN Users ###
firewall doesn’t like traffic that enters and exits the same interface. This behavior is typically known as “hairpin” or “u-turn”.

LAB: ASA, R1, remote user 5.8
Senario: remote user traffic will og through the ASA to the R2 to outside

Remote user access the ASA through a VPN, the traffic will use the same interface to go to  R1/outside. By default the ASA will drop these traffic, because it comes in and goes out from the same interface.
The second issue is that you need to enable NAT, because private IP's are not routed on the internet


1. Basic Configuration:
In the file 5.8 basic configuration

2. ASA to permit traffic that enter and exist from the same interface:
ASA1(config)# same-security-traffic permit intra-interface

3. configure NAT:
ASA1(config)# nat (OUTSIDE,OUTSIDE) source dynamic VPN_POOL interface

It will translate traffic from our network object called VPN_POOL (which matches the 192.168.10.1/24) to the outside interface on our ASA firewall

4. Verify:
C:\Users\H1>ping 2.2.2.2
ASA1# show xlate 


### IKEv2 Cisco ASA and strongSwan ###
configure an IPsec IKEv2 tunnel between a Cisco ASA Firewall and a Linux strongSwan server. StrongSwan is an IPsec VPN implementation on Linux which supports IKEv1 and IKEv2 and some EAP/mobility extensions.

LAB: Swan server, one ASA1 and 2 routers (R1, R2)

-> 1. strongSwan Configuration
strongSwan is in the default Ubuntu repositories so installing it is very simple
# apt-get install strongswan

1. Edit the ipsec.conf file /etc/ipsec.config to: 

config setup
        # strictcrlpolicy=yes
        # uniqueids = no

conn %default
        ikelifetime=1440m
        keylife=60m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev1
        authby=secret

conn ciscoasa
        left=10.10.10.1
        leftsubnet=192.168.1.0/24
        leftid=10.10.10.1
        right=10.10.10.2
        rightsubnet=192.168.2.0/24
        rightid=10.10.10.2
        auto=add
        ike=aes128-sha1-modp1536
        esp=aes128-sha1
        keyexchange=ikev2

The first parameters are under the %default connection which means they apply to all connections unless overruled by a specific connection profile:

- ikelifetime=1440m: This is the IKE Phase 1 (ISAKMP) lifetime. In strongSwan this is configured in minutes. The default value equals 86400 seconds (1 day). This is a common value and also the default on our Cisco ASA Firewall.
- keylife=60m: This is the IKE Phase2 (IPsec) lifetime. Default strongSwan value is 60 minutes which is the same as our Cisco ASA Firewall’s 3600 seconds (1 hour).
- rekeymargin=3m: How long before the SA expiry should strongSwan attempt to negiotate the replacements. This is used so when a SA is about to expire, there is already a new SA so that we don’t have any downtime when the current SA expires. This is a local value, it doesn’t have to match with the other side.
- keyingtries=1: How many attempts should strongSwan make to negotiate a connection (or replacement) before giving up. This is a local value, doesn’t have to match with the other side.
- keyexchange=ikev1: The default is to use IKEv1, we will overule this with another connection profile.
- authby=secret: The default authentication method is to use pre-shared keys.

edit also in the ciscoasa profile in the ipsec.config file to:

- left=10.10.10.1: strongSwan sees itself as “left” so this is where we configure the IP address of strongSwan that we want to use for the IPsec VPN.
- leftsubnet=192.168.1.0/24: The subnet behind strongSwan that we want to reach through the VPN.
- leftid=10.10.10.1: how strongSwan should identify itself, this can be an IP address or a FQDN. We’ll use the IP address.
- right=10.10.10.2: the IP address of the Cisco ASA Firewall.
- rightsubnet=192.168.2.0/24: The subnet behind the Cisco ASA Firewall.
- rightid=10.10.10.2: the ID of the Cisco ASA Firewall.
- auto=add: This means that this connection is loaded when the IPSEC daemon starts but the tunnel isn’t built right away. The tunnel will be built as soon as there is traffic that should go through the tunnel. if you set this value to “start” then the tunnel will be built as soon as the daemon is started.
- ike=aes128-sha1-modp1536: The security parameters for IKE Phase 1, in this example we use AES 128-bit, SHA-1 and DH Group 5.
- esp=aes128-sha1: We use ESP, AES 128-bit and SHA-1 for Phase 2.
- keyexchange=ikev2: We want to use IKEv2 for this connection profile.

2. Configure the pre-shared keys in the ipsec.secrets file /etc/ipsec.secrets:

NOTE: IKEv2 allows us to use a different pre-shared key for each peer, but we will use the same key for both sites.

add below to ipsec.secrets file: 

10.10.10.1 : PSK "networklessons"
10.10.10.2 : PSK "networklessons"

Now we are done with the IPSec configuration.

3. Enable forwad IP packets on linux:
# sysctl -w net.ipv4.ip_forward=1

or for permanent:
# echo "net.ipv4.ip_forward = 1" |  tee -a /etc/sysctl.conf

Now everything is configured for strongSwan

4. start the IPSec daemon:
# ipsec start

-> 2. Cisco ASA configuration:
The following commands are already explained

1. Configure the interfaces:

ASA1(config)# interface e0/0
ASA1(config-if)# no shutdown
ASA1(config-if)# nameif INSIDE
ASA1(config-if)# ip address 192.168.2.254 255.255.255.0

ASA1(config)# interface e0/1
ASA1(config-if)# no shutdown
ASA1(config-if)# nameif OUTSIDE
ASA1(config-if)# ip address 10.10.10.2 255.255.255.0

2. Start configuring the VPN setting, let's create the IKEv2 policy:

ASA1(config)# crypto ikev2 policy 10
ASA1(config-ikev2-policy)# encryption aes
ASA1(config-ikev2-policy)# group 5
ASA1(config-ikev2-policy)# prf sha
ASA1(config-ikev2-policy)# lifetime seconds 86400

This matches the settings of strongSwan (AES 128-bit, DH group 5 and SHA-1)

3. Configure the IPsec settings

ASA1(config)# crypto ipsec ikev2 ipsec-proposal MY_PROPOSAL
ASA1(config-ipsec-proposal)# protocol esp encryption aes
ASA1(config-ipsec-proposal)# protocol esp integrity sha-1

This also matches the IPsec settings of strongSwan, AES 128-bit and SHA-1.

4. Configure the access-list

ASA1(config)# access-list LAN2_LAN1 extended permit ip 192.168.2.0 255.255.255.0 192.168.1.0 255.255.255.0

5. Configure the crypto map:

ASA1(config)# crypto map MY_CRYPTO_MAP 1 match address LAN2_LAN1
ASA1(config)# crypto map MY_CRYPTO_MAP 1 set peer 10.10.10.1
ASA1(config)# crypto map MY_CRYPTO_MAP 1 set ikev2 ipsec-proposal MY_PROPOSAL
ASA1(config)# crypto map MY_CRYPTO_MAP interface OUTSIDE

We attach the access-list and IPsec settings to the crypto map, configure the remote peer (strongSwan) and enable it on the outside interface

6. Configure the pre-shared keys:

ASA1(config)# tunnel-group 10.10.10.1 type ipsec-l2l
ASA1(config)# tunnel-group 10.10.10.1 ipsec-attributes
ASA1(config-tunnel-ipsec)# ikev2 local-authentication pre-shared-key networklessons
ASA1(config-tunnel-ipsec)# ikev2 remote-authentication pre-shared-key networklessons

We use the same pre-shared keys as what we configured on strongSwan

7. Enable the IKEv2 on the outside interface:

ASA1(config)# crypto ikev2 enable OUTSIDE

8. create the static route:

ASA1(config)# route OUTSIDE 192.168.1.0 255.255.255.0 10.10.10.1

-> 3. Verification:
ping from R1 to R2, this should trigger the ASA to build the IPsec tunnel:

R1#ping 192.168.2.2

It works!

-> 4. Cisco ASA verification: 
ASA1# show crypto isakmp sa
ASA1# show crypto ipsec sa

-> 5. strongSwan verification:
# ipsec statusall -> tells us that we have a security association with the ASA
# ip -s xfrm policy -> show the IPsec policy settings

-> 6. for any errors: 

check the log files:
# cat /var/log/auth.log -> Any authentication errors will show up in this log file

or 

start the tunnel on strongSwan manually as it will give you debug information on the terminal:
# ipsec up ciscoasa

That’s all, The only thing left to do on the Ubuntu server is configuring IPtables. Right now the server will forward anything, it would be wise to restrict incoming and forwarding traffic


Unit 6: SSL VPN

###  Cisco ASA Anyconnect Remote Access VPN ###
Anyconnect is the replacement for the old Cisco VPN client and supports SSL and IKEv2 IPsec. 
The ASA offers two SSL VPN modes:
- Clientless WebVPN
- AnyConnect VPN

-> Clientless WebVPN:
No VPN client require, just with the web browser of the client and the ASA firewall IP. 
Problem: access ist limited (no full access)

-> Anyconnect VPN:
anyclient client VPN is require on the client to connect to the ASA and will receive an IP address from a VPN pool, allowing full access to the network.

LAB: R1/inside, ASA1 and remote user/outside
Senario: remote user on outside want to access the inside network 

-> 1. ASA configuration:

1. transfer the anyconnect VPN to the ASA firewall flash momery, to show the flash momery:

ASA1# show flash: 

2. Enable clientless WebVPN

ASA1(config)# webvpn

3. specify the anyconnect PKG file to use:

ASA1(config-webvpn)# anyconnect image flash:/anyconnect-win-3.1.03103-k9.pkg

There is for windows, linux and MAC OS. depend on what users we need to support.

4. Enable client WebVPN on the outside interface:
ASA1(config-webvpn)# enable outside

5. Enable anyconnect:

ASA1(config-webvpn)# anyconnect enable

6. When you have an inbound access-list on the outside interface then all your decrypted traffic from the SSL WebVPN has to match the inbound access-list. You can either create some permit statements for the decrypted traffic or you can just tell the ASA to let this traffic bypass the access-list:

ASA1(config)# sysopt connection permit-vpn

7. Make user connect to our WebVPN using https only, so if they use http, ASA will redirect them to https:

ASA1(config)# http redirect OUTSIDE 80

8. configure a pool with IP addresses for remote users to assign by th ASA:

ASA1(config)# ip local pool VPN_POOL 192.168.10.100-192.168.10.200 mask 255.255.255.0

9. configure split tunneling to allow users to access the internet also, so we configure an ACL that specifies what networks we want to reach through the tunnel:

ASA1(config)# access-list SPLIT_TUNNEL standard permit 192.168.1.0 255.255.255.0

SSL VPN tunnel will only be used to reach the 192.168.1.0/24 network.

10. Configure the anyconnect group policy:

ASA1(config)# group-policy ANYCONNECT_POLICY internal
ASA1(config)# group-policy ANYCONNECT_POLICY attributes
ASA1(config-group-policy)# vpn-tunnel-protocol ssl-client ssl-clientless 
ASA1(config-group-policy)# split-tunnel-policy tunnelspecified
ASA1(config-group-policy)# split-tunnel-network-list value SPLIT_TUNNEL
ASA1(config-group-policy)# dns-server value 8.8.8.8
ASA1(config-group-policy)# webvpn
ASA1(config-group-webvpn)# anyconnect keep-installer installed
ASA1(config-group-webvpn)# anyconnect ask none default anyconnect
ASA1(config-group-webvpn)# anyconnect dpd-interval client 30
ASA1(config-group-webvpn)# exit

- The group policy is called “ANYCONNECT_POLICY” and it’s an internal group policy which means that we configure it locally on the ASA. An external group policy could be on a RADIUS server.
- The VPN tunnel protocol is ssl-client (for anyconnect) and also ssl-clientless (clientless SSL VPN).
- Split tunneling has been enabled and we refer to the access-list “SPLIT_TUNNEL” that we just created.
- The DNS server 8.8.8.8 will be assigned to remote VPN users.
- Normally when the remote VPN user terminates the session, the anyconnect installer will be uninstalled. The anyconnect keep-installer installed command leaves it installed on the user’s computer.
- The anyconnect ask command specifies how the anyconnect client will be installed on the user’s computer. The none default anyconnect part tells the ASA not to ask the user if he/she wants to use WebVPN or anyconnect but just starts the download of the anyconnect client automatically.
- The anyconnect dpd-interval command is used for Dead Peer Detection. The remote user’s anyconnect client will check every 30 seconds if the ASA is still responding or not. You can also use dpd-interval gateway so that the ASA checks if the remote user is still responding.

Group policy configuration is done

11. Create a tunnel group which binds the group policy and VPN pool together:

ASA1(config)# tunnel-group MY_TUNNEL type remote-access 
ASA1(config)# tunnel-group MY_TUNNEL general-attributes 
ASA1(config-tunnel-general)# default-group-policy ANYCONNECT_POLICY
ASA1(config-tunnel-general)# address-pool VPN_POOL
ASA1(config-tunnel-general)# exit

12. When the remote user connects, the ASA will show a group name to the remote user, we can specify the group name like this: 

ASA1(config)# tunnel-group MY_TUNNEL webvpn-attributes 
ASA1(config-tunnel-webvpn)# group-alias SSL_USERS enable

The ASA will show the group name “SSL_USERS” for the remote user, when he connects.

13. If you have multiple tunnel groups then your remote users should be able to select a certain tunnel group:

ASA1(config)# webvpn
ASA1(config-webvpn)# tunnel-group-list enable 

14. Create a user account:

ASA1(config)# username SSL_USER password MY_PASSWORD

15. tell the ASA that this user account is allowed to access the network:

ASA1(config)# username SSL_USER attributes
ASA1(config-username)# service-type remote-access 

Now we configure everything on the ASA, let's move to the client

-> 2. Client Configuration:

1. Open the browser and enter the ASA ip:
ASA has a self-signed certificate, which is not recognized by the browser

2. Enter the Username and password, we created before and choose the group name:
The client tries to download the anyconnect automatically (because of the anyconnect ask none default anyconnect command). 

3. Because of the self-signed certificate, you will get an error, so click on 
change setting -> apply change -> retry the connection -> connect anyway -> It will download the anyconnect VPN on the client device

-> 3. Verification on client and ASA:

C:UsersVPN>ping 192.168.1.1 -> ping from client to R1
C:UsersVPN>ipconfig /all

ASA1# show vpn-sessiondb anyconnect 

we are done :) 


### Cisco ASA Anyconnect Self Signed Certificate ###
By default the Cisco ASA firewall has a self signed certificate that is regenerated every time you reboot it. This can be an issue when you are using SSL VPN as the web browser of your user will give a warning every time it sees an untrusted certificate.

To fix, there are 2 options:
- Purchase and install an SSL certificate on the ASA from a trusted CA.
- Generate a self signed SSL certificate on the ASA and export it to your user’s computer.

The first option is the best one, you buy an SSL certificate from a provider like Verisign, Entrust, Godaddy, etc. and install it on the ASA.
With this, there is nothing more to do :)

The second options, We will generate a SSL certificate on the ASA and self-sign it. This certificate is permanent so it doesn’t dissapear when you reboot the ASA, the problem however is that you have to export and import this certificate on each of your remote users’ computers, let's do that :)

LAB: ASA1, one remote user on the outside

-> 1. ASA configuration:

1. Set the current time, date, assign a hostname and domain name:

ciscoasa(config)# clock set 13:48:00 10 Dec 2014
ciscoasa(config)# hostname ASA1
ASA1(config)# domain-name NETWORKLESSONS.LOCAL

When a remote user opens the web browser they need to use the FQDN (ASA1.NETWORKLESSONS.LOCAL) to reach the ASA. If you use the IP address you will still get a certificate error!

2. Generate RSA key (it will automatically generate two keys public and private)

ASA1(config)# crypto key generate rsa label MY_RSA_KEY modulus 1024

The key pair is called “MY_RSA_KEY”. You can see them here:

ASA1(config)# show crypto key mypubkey rsa | begin MY_RSA_KEY

3. Create a trustpoint. The trustpoint is a container where certificates are stored. This is where we configure parameters like the FQDN, subject name, keypair, etc:

ASA1(config)# crypto ca trustpoint SELF_TRUSTPOINT
ASA1(config-ca-trustpoint)# enrollment self
ASA1(config-ca-trustpoint)# fqdn ASA1.NETWORKLESSONS.LOCAL
ASA1(config-ca-trustpoint)# subject-name CN=ASA1.NETWORKLESSONS.LOCAL
ASA1(config-ca-trustpoint)# keypair MY_RSA_KEY

The trustpoint is called “SELF_TRUSTPOINT” and the enrollment self command means that the ASA will sign its own certificates. The certificate will be assigned to ASA1.NETWORKLESSONS.LOCAL. We will use the RSA keypair that we just generated

4. Enroll the actual certificate and to verify:

ASA1(config)# crypto ca enroll SELF_TRUSTPOINT
ASA1(config)# show crypto ca certificates 

5. Enable the trustpoint on the outside interface

ASA1(config)# ssl trust-point SELF_TRUSTPOINT outside

6. Export the certificate so that we can import it on the user’s computer:

ASA1(config)# crypto ca export SELF_TRUSTPOINT identity-certificate 

Copy the certificate and paste it to a file. Save the file with a .pem extension.

-> 2. Client Configuration:

1. click on Run and enter “certmgr.msc”. It open the certificate manager
Here’s where you can manage all certificate on your Windows 7 computer. The certificate from the ASA should be imported in the Trusted Root Certification Authorities -> all tasks -> import

After install the Certificate, make sure to access the ASA using the FQDN "ASA1.NETWORKLESSONS.LOCAL" and not by the IP.

Add the host with the ip in the hosts file, on windows:
notepad c:windowssystem32driversetchosts
10.10.10.1		ASA1.NETWORKLESSONS.LOCAL

2. Now open the browser and enter "HTTPS://ASA1.NETWORKLESSONS.LOCAL"


That's all, this option is good, if we do not have many remote users


### Cisco ASA Anyconnect Local CA ###

When we configured the ASA to self-sign its certificate, we used the ASA as a local CA. The cool thing is that we can also use this feature to create certificates for our users. This allows us to have two-factor authentication for the remote users: username/password + user certificate.

LAB: ASA1, remote user/outside and one local CA server.

The ASA will be configured as a local CA and we will generate two certificates:
- User certificate that the user will use for authentication.
- ASA certificate so that the user can validate the ASA firewall.

-> 1. ASA local CA configuration:

1. Configure the ASA as a local CA:

ASA1(config)# crypto ca server
ASA1(config-ca-server)# smtp from-address LOCAL-CA@NETWORKLESSONS.LOCAL
ASA1(config-ca-server)# subject-name-default CN=ASA1 O=NETWORKLESSONS.LOCAL C=NL
ASA1(config-ca-server)# lifetime ca-certificate 1825
ASA1(config-ca-server)# lifetime certificate 365
ASA1(config-ca-server)# issuer-name CN=ASA1-LOCAL-CA C=NL O=NETWORKLESSONS.LOCAL
ASA1(config-ca-server)# keysize server 2048
ASA1(config-ca-server)# no shutdown

The ASA will ask you to choose a passphrase for the private key. Now the certificate server will be up and running. You can see our certificate here:

ASA1# show crypto ca certificates 

The trustpoint (that’s where the certificates are stored) is created automatically.

2. Enroll User Certificate
We can now add a user to the CA database, when you do this the username has to be the same as the common name (CN):

ASA1(config)# crypto ca server user-db add cert_user dn CN=cert_user

The user account “cert_user” has been added. We will allow this user to enroll a certificate by using an OTP (One Time Password).

3. Enable OTP:

ASA1(config)# crypto ca server user-db allow cert_user display-otp 
Username: cert_user
OTP: 805AF0FE3FD89EFE

When the user requests to enroll the certificate, we’ll need to enter the OTP. Instead of OTP you can also use e-mail delivery.

4. Enroll the user certificate on a computer
- open the link: https://asa1.networklessons.local/+CSCOCA+/enroll.html
- Enter the username and the OTP

Now you can download the certificate

NOTE: The wizard prompts for the password of the private key. You need to enter the OTP here.

5. Install the certificate on the client and to verify:
click on Run and enter “certmgr.msc” to open the certificate manager
under /personal/certificate you will the the ASA certificate

You can also see it on ASA:
ASA1# show crypto ca server user-db 

-> 2. Enroll ASA Certificate:

Authentication happen, when user show the certificate to the ASA and ASA shows the certificate to the user, so that they can validate each other.

1. Create a username for the ASA, just like we did for the user:
We will use a Windows 7 computer from an administrator to enroll the ASA certificate, save it and then import it on the ASA using the CLI or ASDM.

ASA1(config)# crypto ca server user-db add asa1 dn CN=ASA1.NETWORKLESSONS.LOCAL,C=NL,O=NETWORKLESSONS.LOCAL

IMPORTANT: username has to match the hostname of your ASA

2. Enable OTP for the enrollment:

ASA1(config)# crypto ca server user-db allow asa1 display-otp 
you will get a username and OTP

3. use an admin computer to create the certificate so that we can install it afterwards on the ASA. 
- Open browser on client and go to https://asa1.networklessons.local/+CSCOCA+/enroll.html
- Enter username and OTP we just get from enabling the OTP
- Download the certificate

-> 3. Import certificate on ASA:

1. With CLI

- The ASA only accepts a base 64 format certificate (PEM file) but we have a PKCS12 certificate (p12 file). so we convert it with linux:
$ openssl base64 -in asa1.p12 -out asa1.pem

- now import the certificate on the ASA, and we’ll do this in its own trustpoint:
ASA1(config)# crypto ca import MY_TRUSTPOINT pkcs12 2673CDA6D45D4D1A
The trustpoint is called “MY_TRUSTPOINT” and the number at the end is the OTP

- Now copy the certificate and paste it on the console, then end with quit

Done

2. With ASDM

- login and go to Configuration > Remote access VPN -> Certificate Management > Identity Certificates

- click on add button. Enter a name for the trustpoint and select the certificate. The advantage of ASDM is that you don’t have to convert the certificate yourself to the base64 format. Click on Add Certificate and you are done.

-> 4. Enable Trustpoint

- We need to enable the trustpoint that we just created on the outside interface of the ASA so that it is used for certificate validation:

ASA1(config)# crypto ca trustpoint LOCAL-CA-SERVER
ASA1(config-ca-trustpoint)# no client-types

The trustpoint “LOCAL-CA-SERVER” was automatically created when we configured the local CA

- We tell the ASA not to use this trustpoint for certificate validation. Now we enable the correct trustpoint:

ASA1(config)# crypto ca trustpoint MY_TRUSTPOINT
ASA1(config-ca-trustpoint)# client-types ssl

The trustpoint we just created called "MY_TRUSTPOINT" and it used for certificate validation.

- Enable it on the outside interface:

ASA1(config-ca-trustpoint)# ssl trust-point MY_TRUSTPOINT outside

-> 5. User Authentication Settings

- Create a password for the user "cert_user" we just created before:
ASA1(config)# username cert_user password MY_PASSWORD

- configure the tunnel group so that it enables certificate authentication:
ASA1(config)# tunnel-group MY_TUNNEL webvpn-attributes 
ASA1(config-tunnel-webvpn)# authentication aaa certificate

Done

-> 6. Verify, if our remote user is able to authenticate using username/password + certificate!

- from client go to https://asa1.networklessons.local/
Enter Croup name, username and password.

- On ASA firewall:
ASA1# show vpn-sessiondb detail anyconnect 


Unit 7: Network Management

### Cisco ASA Clock Configuration ###
The Cisco ASA firewall has a battery on the motherboard that saves the clock settings. Even when it’s is powered off, the clock will be stored.

why ASA time is important ?
To track logs for events and the PKI authentication 

- Configure manually:
ASA1(config)# clock set 13:15:00 Dec 19 2014
ASA1# show clock

- The default timezone is UTC, to change this:
ASA1(config)# clock timezone CET +1

- Tell the ASA about the start and the end of the summer time (CEST -> Central Europe Summer Time)
ASA1(config)# clock summer-time CEST recurring last Sun Mar 02:00 last Sun Oct 03:00

- Configure it using a NTP server:
ASA1(config)# ntp server 192.168.1.1 source INSIDE -> specifying the source IP address is optional
ASA1# show ntp status 

- To enable authentication for NTP.
ASA1(config)# ntp authenticate
ASA1(config)# ntp authentication-key 1 md5 MY_PASSWORD
ASA1(config)# ntp trusted-key 1
ASA1(config)# ntp server 192.168.1.1 key 1 source INSIDE

We enabled NTP authentication and configured a key with a password. We tell the ASA that key 1 is trusted and to use this key to authenticate the NTP server.

### Cisco ASA Syslog Configuration ###
The Cisco ASA firewall generates syslog messages for many different events. For example, interfaces going up or down, security alerts, debug information and more. We can configure the ASA to tell it how much and where to store logging information

Firstly we enable logging:
ASA1(config)# logging enable


-> 1. Logging to SSH or Telnet

To see logging options:
ASA1(config)# logging monitor ?

The logging monitor command configures the level of logging that we want to use. For example, when you select debugging (level 7) then it will log all lower levels as well. If you select “errors” then it will only log level 3,2,1 and 0. We will select debugging so that we can see debug messages on our telnet or SSH session and enable it:

ASA1(config)# logging monitor debugging
ASA1(config)# terminal monitor

-> 2. Logging to Internal Buffer

Could be usee for syslog messages.
ASA1(config)# logging buffered warnings

This will log all syslog messages with level “warnings” or lower to the internal buffer. We can also configure the size of the internal buffer:

ASA1(config)# logging buffer-size 8192
By default it’s only 4KB, I changed it to 8KB with the logging buffer-size command. Let’s see if we can find some syslog information in our internal buffer:

ASA1(config)# interface E0/0
ASA1(config-if)# shutdown
ASA1(config-if)# no shutdown

Shutting an interface is something that will be logged. Now use the show logging command to view the log:

ASA1# show logging 

we can see the logs 

-> 3. Logging to console
We can log syslog messages to the console like this:

ASA1(config)# logging console warnings

If there are too many logging messages then it will be rate-limited and even dropped if the console can’t handle it.

-> 4. Logging to e-mail
We can also send syslog messages directly to e-mail:

ASA1(config)# logging mail alerts
ASA1(config)# logging from-address asa@networklessons.com
ASA1(config)# logging recipient-address info@networklessons.com
ASA1(config)# smtp-server 192.168.1.1

This will send all syslog messages with level “alerts” or lower to an e-mail address. Don’t forget to configure a SMTP server.

-> 5. Logging to ASDM

To enable:
ASA1(config)# logging asdm debugging

Then login to your ASDM and click on home tab, you will see logs at the bottom

-> 6. Logging to Syslog Server

To enabele:
ASA1(config)# logging host INSIDE 192.168.1.3
ASA1(config)# logging trap alerts

You need to configure the host and the level of syslog messages

-> 7. Logging to SNMP server
we can send syslog messages as SNMP traps to a SNMP server:

ASA1(config)# snmp-server host INSIDE 192.168.1.1 trap community MY_COMMUNITY
ASA1(config)# snmp-server enable traps syslog
ASA1(config)# logging history notifications

First we configure the SNMP server and the community and then we tell the ASA to send syslog messages using SNMP traps. The logging history commands sets the syslog level.


### Cisco ASA Firewall Active / Standby Failover ###

The Cisco ASA firewall is often an important device in the network. We use it for (remote access) VPNs, NAT/PAT, filtering and more. Since it’s such an important device it’s a good idea to have a second ASA in case the first one fails.

The ASA supports active/standby failover which means one ASA becomes the active device, it handles everything while the backup ASA is the standby device. It doesn’t do anything unless the active ASA fails.

The failover mechanism is stateful which means that the active ASA sends all stateful connection information state to the standby ASA. This includes TCP/UDP states, NAT translation tables, ARP table, VPN information and more.

When the active ASA fails, the standby ASA will take over and since it has all connection information, your users won’t notice anything.

requirements:
- Platform has to be the same: for example 2x ASA 5510 or 2x ASA 5520.
- Hardware must be the same: same number and type of interfaces. Flash memory and RAM has to be the same.
- Same operating mode: routed or transparent mode and single or multiple context mode.
- License has to be the same..number of VPN peers, encryption supported, etc.
- Correct license. Some of the “lower” models require the Security Plus license for failover (the ASA 5510 is an example).

LAB: 2 routers(R1,R2), 2 switches and 2 ASA firewalls
R1 <-> Switch1/inside <-> ASA1 &ASA2 <-> ASA1 &ASA2 <-> outside/switch2 <-> R2

- routers: to generate some traffic
- ASA1: active mode
- ASA2: standby mode
- ASA1 and ASA2 are connected directly to synchronize connection information for failover

Configuration:

1. Configure the failover interface on ASA1:

-> enable the interface:
ASA1(config)# interface Ethernet 0/3
ASA1(config-if)# no shutdown

-> make ASA1 active primary:
ASA1(config)# failover lan unit primary 

-> conifigure the interface to be failover:
ASA1(config)# failover lan interface FAILOVER Ethernet 0/3 

-> tell the ASA to use this interface for stateful failover:
ASA1(config)# failover link FAILOVER Ethernet 0/3 

-> configure the IP addresses on the failover interface:
ASA1(config)# failover interface ip FAILOVER 192.168.12.1 255.255.255.0 standby 192.168.12.2 

ASA1 (active) will use IP address 192.168.12.1 and ASA2 (standby) will use 192.168.12.2

-> enable failover:
ASA1(config)# failover

Now Failover is now configured on ASA1

-> configure some security zones and IP addresses on the “normal” Interfaces:
ASA1(config)# interface Ethernet 0/0
ASA1(config-if)# no shutdown
ASA1(config-if)# nameif INSIDE
ASA1(config-if)# ip address 192.168.1.254 255.255.255.0 standby 192.168.1.253

ASA1(config)# interface Ethernet 0/1
ASA1(config-if)# nameif OUTSIDE
ASA1(config-if)# ip address 192.168.2.254 255.255.255.0 standby 192.168.2.253

-> to monitor physical interfaces:
ASA1(config)# monitor-interface INSIDE
ASA1(config)# monitor-interface OUTSIDE

-> configure the same on ASA2:
ASA2(config)# failover lan unit secondary
ASA2(config)# failover lan interface FAILOVER Ethernet 0/3
ASA2(config)# failover link FAILOVER Ethernet 0/3
ASA2(config)# failover interface ip FAILOVER 192.168.12.1 255.255.255.0 standby 192.168.12.2
ASA2(config)# failover
ASA2(config)# interface Ethernet 0/3
ASA2(config-if)# no shutdown

We configure ASA2 to be the standby device, its Ethernet 0/3 interface will be used for failover and we configure the active and standby IP addresses. lastly we enabled the interface.

-> last thing, to save the configuration:
ASA1# write memory 
the ASA2 will save the configuration automatically, because the ASA1 will send all the informations.

-> to verify:
ASA1# show failover -> to get an overview about the active/standby devices 
R1#telnet 192.168.2.2 -> to generate traffic, telnet from R1 to R2
ASA1# show failover | include TCP

-> everything works, so let's test the failover:
go to Switch1 and shutdown there the interface to the switch
SW1(config)#interface FastEthernet 0/14
SW1(config-if)#shutdown

ASA1# show failover | include This host


Unit 8: Troubleshooting

### Cisco ASA Packet Drop Troubleshooting ###
As a firewall, the Cisco ASA drops packets. That’s great until it drops packets that you want to permit, and you have no idea what is going on. Fortunately, the ASA supports different tools to show you why and what packets it drops. Tools:
- Connection State
- Interface Drops
- Syslog
- ASP Drops
- Packet Capture
- Packet Tracer
- Service Policy
- Conclusion

LAB: 2 Hosts (H1/inside,H2/outside) and one ASA firewall in the middle
Two “host” devices:
These are routers with ip routing disabled, and they use ASA1 as their default gateway.
An HTTP server is enabled on both devices.

-> We start with basic configuration (see file 8.1)
H1 will reach H2, but H2 will not reach H2, because of the security levels

H2#telnet 192.168.1.1 80 -> not reachable
let say, we do not know why not reachable and we start to investigate

1. Interface drops
The ASA keeps track of drops on the interface.

ASA1# show interface GigabitEthernet 0/1 | include packets dropped

Show us how many packets are dropped, but we have no idea what. You can use "ASA# clear interface" to reset this counter.

2. Syslog
The ASA has over 2000 unique syslog messages.

-> Enable logging up to the debug level:
ASA1(config)# logging enable
ASA1(config)# logging buffered debugging

-> Optionally, Increase the buffer size so you can store more syslog messages:
ASA1(config)# logging buffer-size 1000000

-> to verify:
H2#telnet 192.168.1.1 80
ASA1(config)# show logging

We get the syslog messages and the code. You search the code on cisco to see what it means.
https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html

to filter the messages :
ASA1(config)# show logging | include 106001
ASA1(config)# show logging | exclude 111008|111009|111010|302010

3. ASP drops:
check the Accelerated Security Path (ASP) drops with the "show asp drop" command. This command gives an overview of packets that the ASA drops with a reason.
ASA1# show asp drop
ASA1# clear asp drop 

4. Packet Capture
We can also capture packets to take a closer look. There are two options:
- Capture ASP dropped packets
- Capture any packets you want.

-> ASP Drops Capture:

To capture traffic
ASA1(config)# capture ASP_DROPS type asp-drop acl-drop

To generate some traffic:
H2#telnet 192.168.1.1 80

To show the captured packets:
ASA1(config)# show capture ASP_DROPS


https://www.youtube.com/watch?v=8T-Vdz5fMIw
https://www.youtube.com/watch?v=G6NocPrQ1hI
https://www.youtube.com/watch?v=lJ8y5FnT7m4
