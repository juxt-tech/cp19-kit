# NetAcad "CyberPatriot Content" course map (CP19)

Scanned 2026-11-14 from course instance '26-'27 CyberPatriot 19-3455 (same instructor as the team's
19-3462; the content is the standard CyberPatriot course). Due date for everything: 1 Apr 2027.

## What's NOT there
- **No answer keys, checklists or instructor files.** "Course Resources" and "Instructor Added
  Resources" are both empty for students.
- What *is* there: reading modules, **Packet Tracer activities (.pka, auto-graded, same engine as the
  competition)**, "Lab -" write-ups (meant for real equipment; you can rebuild them in PT, but nothing
  grades them), and a **Module Quiz** at the end of each module (quiz practice).

## How to practice with it
1. Open the module -> expand the section -> click the **Packet Tracer -** item -> download the .pka.
2. Do it **without** looking at hints. Then Check Results -> Assessment Items: every red X goes into
   `checklists/cisco.md` section G.
3. Paste each device's `show run` into a folder and run `python cisco/lint/lint_showrun.py <folder>`.
4. Do the Module Quiz for the quiz half of the competition.

## Round 2 topics: do these first (closest to the R2 practice lab)
| Priority | Activity | Module | Why |
|---|---|---|---|
| 1 | **13.5.5 Packet Tracer - Configure DTP** | 13 VLANs | the exact topic the R2 practice lost points on |
| 2 | 13.6.1 Packet Tracer - Implement VLANs and Trunking | 13 VLANs | VLANs + trunks + allowed lists end to end |
| 3 | 17.5.1 Packet Tracer - Inter-VLAN Routing Challenge | 17 Inter-VLAN | router-on-a-stick under pressure |
| 4 | 17.3.8 Packet Tracer - Configure Layer 3 Switching and Inter-VLAN Routing | 17 Inter-VLAN | 3650 SVIs, `ip routing`, routed ports (the R2 distribution switches) |
| 5 | 21.5.3 Packet Tracer - Propagate a Default Route in OSPFv2 | 21 OSPF config | `default-information originate` |
| 6 | 21.7.1 Packet Tracer - Single-Area OSPFv2 Configuration | 21 OSPF config | full OSPF build |
| 7 | 25.5.1 Packet Tracer - IPv4 ACL Implementation Challenge | 25 ACL config | named extended ACLs, ordering, placement |
| 8 | 10.6.1 Packet Tracer - Configure IPv4 and IPv6 Static and Default Routes | 10 Static routing | floating statics / default routes |

STP has **no .pka** in this course (modules 15-16 are "Lab -" only). Practice STP root priorities,
RSTP, PortFast and BPDU Guard in `cisco/labs/r2-practice/` instead.
DHCP: module 19 (CCNP ENARSI) covers DHCP relay in 19.3 and has hands-on labs in 19.11 and 19.14.
Module 26's only PT activity is a home wireless router, so skip it.

## Every Packet Tracer activity found, by module
| Module | Packet Tracer activities |
|---|---|
| 2 Basic Switch and End Device Config | 2.3.7 Navigate the IOS; 2.5.5 Configure Initial Switch Settings; 2.7.6 Implement Basic Connectivity; 2.9.1 Basic Switch and End Device Configuration |
| 10 IP Static Routing | 10.6.1 Configure IPv4 and IPv6 Static and Default Routes |
| 11 Basic Device Configuration | 11.0.5 Logical and Physical Mode Exploration; 11.3.6 Configure SSH; 11.4.7 Configure Router Interfaces; 11.5.10 Verify Directly Connected Networks; 11.6.1 Implement a Small Network |
| 12 Switching Concepts | none |
| 13 VLANs | 13.1.4 Who Hears the Broadcast?; 13.2.8 Investigate a VLAN Implementation; 13.4.5 Configure Trunks; 13.5.5 Configure DTP; 13.6.1 Implement VLANs and Trunking |
| 14 Basic Router Configuration | 14.1.4 Configure Initial Router Settings; 14.3.4 Connect a Router to a LAN; 14.3.5 Troubleshoot Default Gateway Issues |
| 15-16 STP / Advanced STP | none (Lab only: 15.1.2 Observe STP Topology Changes and Implement RSTP; 16.1.2 Implement Advanced STP Modifications) |
| 17 Inter-VLAN Routing | 17.2.7 Configure Router-on-a-Stick; 17.3.8 Layer 3 Switching and Inter-VLAN Routing; 17.4.8 Troubleshoot Inter-VLAN Routing; 17.5.1 Inter-VLAN Routing Challenge |
| 19 Implementing DHCP (ENARSI) | labs in 19.11 (IPv6 addresses dynamically) and 19.14 (troubleshoot DHCPv4/v6) |
| 21 Single-Area OSPFv2 Config | 21.2.13 Point-to-Point OSPFv2; 21.3.11 Determine the DR and BDR; 21.4.11 Modify Single-Area OSPFv2; 21.5.3 Propagate a Default Route; 21.6.6 Verify Single-Area OSPFv2; 21.7.1 Single-Area OSPFv2 Configuration; 21.7.3 Multiarea OSPF Exploration |
| 23 Access Control Lists (Network Defense) | 23.5.5 Named Standard ACLs; 23.5.6 Numbered Standard ACLs; 23.5.12 / 23.5.13 Extended ACLs Scenarios 1-2; 23.6.5 IP ACLs to Mitigate Attacks; 23.7.4 IPv6 ACLs |
| 25 ACLs for IPv4 Configuration | 25.1.8 Numbered Standard; 25.1.9 Named Standard; 25.2.7 Configure and Modify Standard; 25.4.12 / 25.4.13 Extended Scenarios 1-2; 25.5.1 IPv4 ACL Implementation Challenge |
| 26 Dynamic Addressing with DHCP | 26.2.3 Configure DHCP on a Wireless Router |
| 28 NAT for IPv4 | 28.4.5 Configure Static NAT; 28.6.7 Configure PAT; 28.8.1 Configure NAT for IPv4 |
| 29 Secure Device Access | 29.4.8 Configure Secure Passwords and SSH |
| 32 AAA | 32.2.6 Local AAA for Console and VTY; 32.4.9 Server-Based Authentication with TACACS+ and RADIUS |
| 35 Site-to-Site IPsec VPNs | 35.5.5 Configure and Verify a Site-to-Site IPsec VPN |
| 37 ASA Firewall Configuration | 37.7.5 ASA Basic Settings and Firewall Using the CLI |
| 38 Zone-Based Policy Firewalls | 38.3.11 Configure a ZPF |

Not scanned: ITN theory modules (Networking Today, Protocols, Data Link, Ethernet Switching, ICMP,
Address Resolution, Network Layer, IPv4 Addressing), OSPF Concepts, ACL Concepts, Network Security
Concepts, Admin Roles, VPNs, ASA intro, Security Testing, CyberOps / Ethical Hacker / Intro to
Cybersecurity, Advanced OSPF, OSPFv3, HSRP (different page layout).

## Course order (16 modules), mapped to rounds
| Course module | Units | Round (per `checklists/cisco.md` section F) |
|---|---|---|
| 1-3 | ITN basics, switch/end-device config, protocols, data link, Ethernet, ICMP, ARP, network layer, IPv4, static routing, basic device config, switching concepts | Round 1 |
| 4-6 | VLANs, basic router config, STP, advanced STP, inter-VLAN routing, routing between networks, DHCP (ENARSI), OSPFv2 concepts + config | Round 2 |
| 7-9 | attacks/concepts, ACLs (Network Defense + ENSA), DHCP (Networking Essentials), network security concepts, NAT, securing device access | State+ |
| 10-16 | ethical hacking, AAA, admin roles, VPNs + IPsec, ASA, zone-based firewalls, security testing, CyberOps, advanced OSPF, OSPFv3, HSRP | Semifinals / Nationals |
