# Cisco Networking Challenge Playbook (CyberPatriot 19)

No AI during scored rounds. This is your solo playbook. Templates to copy are in `cisco/templates/`.
Two parts: **(A) Packet Tracer** inside the CP testing VM and **(B) the NetAcad quiz**. **Click a section to open it.**

<details>
<summary><b>A. Packet Tracer: test-day flow</b> (before the day, on the day, habits)</summary>

### Before the day
- [ ] VMware **25H2 / 26H1 or newer** (17.x can't open the VM).
- [ ] `cyberpatriot-testing-vm.ova` downloaded, SHA-256 checked, imported. Encryption password written down. You can reach the "Enter your Unique ID" screen.
- [ ] School network allows `*.cpevent.net` and `*.netacad.com`.

### On the day
1. Start the VM → Windows password `cisco` → enter the **Unique ID** (check 0/O and 1/I) → Continue → read the summary → **Begin Test** → screenshot → **Start Test** (the timer starts here).
2. Find the instructions: taskbar > **PT Activity:** → tick **Top**. Check the heading says **High School**.
3. Read **all** the instructions once before touching anything. Note which devices are locked (clouds/ISP): you just match their settings.
4. Work device by device **in the order the instructions list them**. After each device: verify → `end` → `write mem` (or `copy run start`) → **Ctrl+S**.
5. Physical tab: power on anything that's off (click the power switch).
6. Verify end-to-end (section D). Then Ctrl+S → close Packet Tracer → **Yes** to save → **End Test** (wait up to a minute) → screenshot the Confirmation ID.
7. Never: Save As, rename the file, close the testing window, suspend the VM.

### Point-earning habits
- Type values **exactly** as written (hostnames and passwords are case-sensitive: `C1sc0rocks` ≠ `Cisco rocks`).
- Each "configure X" line in the instructions is usually its own scored check. Do the easy ones (hostname, passwords, banner, IPs) first everywhere, then routing.
- After `no shutdown`, the link should go green (switch ports take ~30 s: orange → green).
- Ctrl+S often. A crash = only saved work counts.

</details>

<details>
<summary><b>B. Device order and what each usually needs</b> (+ cable cheat sheet)</summary>

| Device | Typical tasks | Template |
|---|---|---|
| Router | hostname, enable secret, console/vty passwords, banner, interface IPs + `no shut`, routing (static / EIGRP / OSPF), SSH | `01`, `02`, `04`, `05` |
| Layer 3 switch (3560/3650) | `ip routing`, SVIs per VLAN, routed ports (`no switchport`), trunks (`encapsulation dot1q` on 3560), routing | `03`, `04` |
| Layer 2 switch (2960) | hostname, passwords, VLANs, access ports, trunks, VLAN 1 management IP + `ip default-gateway`, port security, unused ports shut | `01`, `03`, `05` |
| PC / server | Desktop > IP Configuration: IP, mask, gateway, DNS; Config > Display Name; server Services tab (HTTP/FTP/DNS on/off) | `02` |
| New device to add | End Devices → drag in; **lightning bolt → solid black "Copper Straight-Through"** → click device → pick a port → click switch → pick a free port | — |

Cable cheat sheet: PC↔switch, switch↔router = **straight-through** (solid black). Switch↔switch, router↔router, PC↔router = crossover (dashed), though Packet Tracer auto-MDIX usually forgives straight-through. Serial (red ⚡) for WAN serial ports.

</details>

<details>
<summary><b>C. Troubleshooting table</b> (symptom → check → fix)</summary>

| Symptom | Check | Fix |
|---|---|---|
| Red link triangles | `show ip interface brief` → "administratively down" | `interface X` → `no shutdown` |
| Orange triangles | spanning tree is still starting | wait 30 s |
| PC can't ping its gateway | PC IP/mask typo; wrong VLAN on its switch port | Desktop > IP Config; `show vlan brief` |
| Gateway OK, remote network fails | router missing a route | `show ip route`; add a static route / the routing `network` line |
| Routing protocol has no neighbors | `show ip eigrp neighbors` / `show ip ospf neighbor` empty | same AS / process area; `network` statements cover the link subnets; interfaces up |
| Ping works but website/FTP by name fails | DNS | PC DNS server = the address given; server DNS service on |
| VLANs can't talk across switches | trunk not up or VLAN not allowed | `show interfaces trunk`; `switchport trunk allowed vlan 1,10,20` |
| L3 switch won't route | `ip routing` missing | `ip routing` |
| Password prompts locked you out | you set the password before finishing | it's the password from the instructions |
| First ping drops 1-2 packets | ARP warming up | ping again |

</details>

<details>
<summary><b>D. Verification commands</b> (memorise)</summary>

```
show ip interface brief        ! every interface: IP + up/up?
show running-config            ! everything you configured
show ip route                  ! C = connected, S = static, D = EIGRP, O = OSPF
show vlan brief                ! which ports in which VLAN
show interfaces trunk          ! trunk ports + allowed VLANs
show ip eigrp neighbors / show ip ospf neighbor
show ip ssh                    ! SSH version/enabled
show port-security interface fa0/1
```
PC: `ping <gateway>` → `ping <remote host>` → `ping <DNS name>` → browser `http://name` → `ftp <ip>`.

</details>

<details>
<summary><b>E. Subnetting sheet</b> (masks, wildcards, hosts, private ranges)</summary>

| Prefix | Mask | Wildcard | Hosts |
|---|---|---|---|
| /24 | 255.255.255.0 | 0.0.0.255 | 254 |
| /25 | 255.255.255.128 | 0.0.0.127 | 126 |
| /26 | 255.255.255.192 | 0.0.0.63 | 62 |
| /27 | 255.255.255.224 | 0.0.0.31 | 30 |
| /28 | 255.255.255.240 | 0.0.0.15 | 14 |
| /29 | 255.255.255.248 | 0.0.0.7 | 6 |
| /30 | 255.255.255.252 | 0.0.0.3 | 2 (router-to-router links) |
| /16 | 255.255.0.0 | 0.0.255.255 | 65,534 |

Wildcard = 255.255.255.255 − mask. Network address = first address; broadcast = last; usable = the ones in between.
Private ranges: `10.0.0.0/8`, `172.16.0.0/12` (172.16–172.31), `192.168.0.0/16`. `169.254.x.x` = APIPA (DHCP failed). `127.x` = loopback.

</details>

<details>
<summary><b>F. Quiz (NetAcad) study map</b> + 30 practice questions</summary>

CP19 gives the "CyberPatriot Content" course. Each round adds modules; questions come from the newest ones.

| Round | Topics |
|---|---|
| Round 1 | networking basics, network media, OSI/TCP-IP layers, Ethernet + MAC, switching, IPv4 addressing + subnetting, IOS CLI + basic device config, router security (passwords, SSH), static routing |
| Round 2 | VLANs, trunks, inter-VLAN routing (router-on-a-stick, L3 switch SVIs), STP/RSTP (PortFast, BPDU Guard), EtherChannel, DHCP, OSPF single-area, port security |
| State+ | ACLs, NAT, IPv6, wireless, WAN, network security threats |

### Practice questions
1. Which device type forwards frames using MAC addresses?
2. What is the subnet mask for /27?
3. Which address is NOT private: 10.254.1.1, 172.32.10.200, 192.168.5.5?
4. A PC shows 169.254.100.30. What happened?
5. A Layer 2 broadcast frame's destination MAC is…?
6. Which OSI layer adds source/destination IP addresses?
7. Which command saves the running config so it survives a reboot?
8. `Router>` vs `Router#`: which mode is each?
9. Which command encrypts all plain-text passwords in the config?
10. Why is `enable secret` better than `enable password`?
11. What two things must exist before `crypto key generate rsa` works?
12. On a 2960 switch, where does the management IP go?
13. What does `switchport mode access` + `switchport access vlan 20` do?
14. A trunk carries traffic for multiple VLANs using which tagging standard?
15. Why might VLAN 10 PCs on two switches fail to talk even though both have VLAN 10?
16. What must you enable on a 3650 switch before it routes between SVIs?
17. Administrative distance: which is preferred, a static route (1) or OSPF (110)?
18. What does `ip route 0.0.0.0 0.0.0.0 10.1.1.1` create?
19. In OSPF, what is the best source for a stable router ID?
20. What does PortFast do, and where should it never be used?
21. What does BPDU Guard do when a BPDU arrives?
22. Port security violation mode that drops traffic AND shuts the port?
23. When a router forwards a packet between two Ethernet networks, which addresses change?
24. Which protocol finds the MAC address of the next-hop IP?
25. What does `show ip interface brief` "administratively down" mean?
26. TCP vs UDP: which is connection-oriented?
27. Well-known ports: HTTP, HTTPS, SSH, Telnet, FTP, DNS?
28. What does DHCP's DORA stand for?
29. Which cable connects a PC to a switch?
30. Why is Telnet insecure compared to SSH?

<details>
<summary>Answers</summary>

1. Switch (Layer 2).
2. 255.255.255.224.
3. 172.32.10.200 (private 172 range stops at 172.31).
4. APIPA: no DHCP server answered, so it self-assigned.
5. FF:FF:FF:FF:FF:FF (all binary ones).
6. Network layer (Layer 3).
7. `copy running-config startup-config` (or `write mem`).
8. `>` = user EXEC, `#` = privileged EXEC.
9. `service password-encryption`.
10. `secret` stores a strong hash; `password` is plain text (or weak type-7 encryption).
11. A hostname (not the default) and `ip domain-name`.
12. On `interface vlan 1` (an SVI), plus `ip default-gateway`.
13. Makes the port a non-trunk port in VLAN 20.
14. IEEE 802.1Q.
15. The link between the switches isn't a trunk, or the trunk doesn't allow VLAN 10.
16. `ip routing`.
17. Static (lower AD wins).
18. A default route (gateway of last resort) to 10.1.1.1.
19. A loopback interface (or a manually set `router-id`).
20. Skips the STP listening/learning states on access ports; never use it on links to other switches.
21. Err-disables (shuts) the port.
22. `shutdown` (the default).
23. Source + destination **MAC** change; the IPs stay the same (without NAT).
24. ARP.
25. Someone typed `shutdown` → fix with `no shutdown`.
26. TCP.
27. 80, 443, 22, 23, 21 (20 for data), 53.
28. Discover, Offer, Request, Acknowledge.
29. Straight-through.
30. Telnet sends everything, passwords included, in clear text; SSH encrypts it.

</details>

Study sources: the NetAcad course, Jeremy's IT Lab videos (the club's module map follows them), the club's Packet Tracer practice files (`2.5.5 Configure Initial Switch Settings`, `CCNA2 practice final`, "Baby Steps PKA").

</details>
