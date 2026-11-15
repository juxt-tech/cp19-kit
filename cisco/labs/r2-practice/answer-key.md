# Round 2 Packet Tracer practice: answer key (corrected)

Lab: Campus network (Core_Router ISR4331, 2x 3650 distribution, 2x 2960 access) + remote site
(2911 Remote_Router, 2960 Remote_Switch). First attempt scored **11.12/20** even though every
connectivity test passed. Changes from that attempt are marked **NEW**.

Status: suspected fixes. Confirm against Check Results -> Assessment Items and update
`checklists/cisco.md` section G (confirmed vs suspected) with what was actually red.

## Facts found during the lab (check these first next time)
| Question | How to check | Answer in this lab |
|---|---|---|
| Which switch ports link the switches? | `show cdp neighbors` on every switch | Dist Gi1/0/2 <-> Access Fa0/1; Access1 Fa0/2 <-> Access2 Fa0/2; Dist1 Gi1/0/3 <-> Dist2 Gi1/0/3 (routed) |
| Which Core link is the internet (don't touch)? | `show ip route static` -> `S* 0.0.0.0/0 via ...` | via 10.60.0.2 = VLAN60 / Gi0/2/0 |
| Which ports are layer 2 (for DTP)? | `show interfaces switchport` | every port listed there |

## Ambiguous spec lines (decide, then write down why)
- **ACL name** is spelled `Block_Communicaton` (missing "i"). Copy it exactly.
- **Remote VLAN 200 gateway**: L3 section says "router .2", addressing says `50.100.0.129/25`. .2 isn't in that subnet, so .129.
- **Dist2 backup root "VLANs 200 and 200"** = 100 and 200.
- **AD 255 floating route** never gets installed on real IOS. Type it anyway; the spec asks for it.
- **"Exclude .2"**: only `.2` is required. The `.1` exclusions below stop DHCP handing out the gateway
  address, but are extra lines. If Assessment Items marks the DHCP exclusions red, remove the `.1` lines.
- **"All layer 2 switch ports ... turn off DTP"** = every port, including unused ones. **NEW**

## Rules used when typing these blocks
- No `exit` right after a line that might be rejected (`vlan 199` on a router). If the line errors, the
  `exit` drops you out of config mode and every later line fails silently. **NEW**
- VLANs on switches in one line: `vlan 100,200,300,400`.
- After pasting, scroll up and look for `%`. Then run the checker (`cisco/lint/README.md`).

---

## Core_Router
Already done in the attempt: ACL `Block_Communicaton` on Gi0/0/0 and Gi0/0/1 inbound.
```
enable
conf t
enable secret C1sc0Rock5
interface g0/0/0
 ip address 10.10.0.1 255.255.255.0
 no shutdown
interface g0/0/1
 ip address 10.20.0.1 255.255.255.0
 no shutdown
interface g0/1/0
 switchport mode access
 switchport access vlan 199
 switchport nonegotiate
 no shutdown
interface g0/2/1
 switchport mode access
 switchport access vlan 200
 switchport nonegotiate
 no shutdown
interface vlan 199
 ip address 10.199.0.1 255.255.255.0
 no shutdown
interface vlan 200
 ip address 10.200.0.1 255.255.255.0
 no shutdown
ip dhcp excluded-address 10.100.0.1
ip dhcp excluded-address 10.100.0.2
ip dhcp excluded-address 20.100.0.1
ip dhcp excluded-address 20.100.0.2
ip dhcp excluded-address 30.100.0.1
ip dhcp excluded-address 30.100.0.2
ip dhcp excluded-address 40.100.0.1
ip dhcp excluded-address 40.100.0.2
ip dhcp pool VLAN100
 network 10.100.0.0 255.255.255.0
 default-router 10.100.0.1
 dns-server 100.100.100.1
ip dhcp pool VLAN200
 network 20.100.0.0 255.255.255.0
 default-router 20.100.0.1
 dns-server 100.100.100.1
ip dhcp pool VLAN300
 network 30.100.0.0 255.255.255.0
 default-router 30.100.0.1
 dns-server 100.100.100.1
ip dhcp pool VLAN400
 network 40.100.0.0 255.255.255.0
 default-router 40.100.0.1
 dns-server 100.100.100.1
router ospf 1
 network 10.10.0.1 0.0.0.0 area 0
 network 10.20.0.1 0.0.0.0 area 0
 network 10.199.0.1 0.0.0.0 area 0
 network 10.200.0.1 0.0.0.0 area 0
 default-information originate
ip route 50.100.0.0 255.255.255.128 10.199.0.2
ip route 50.100.0.128 255.255.255.128 10.199.0.2
ip route 50.100.0.0 255.255.255.128 10.200.0.2 25
ip route 50.100.0.128 255.255.255.128 10.200.0.2 25
end
wr
```
**NEW, unused switch-module ports:** run `show interfaces switchport` first. For every port listed
except Gi0/1/0, Gi0/2/1 and the internet port Gi0/2/0 (don't touch it), e.g. if it lists Gi0/1/1-3 and Gi0/2/2-3:
```
conf t
interface range g0/1/1 - 3 , g0/2/2 - 3
 switchport mode access
 switchport nonegotiate
end
wr
```

## Campus_Distribution1 (Distribution2: swap the values in the table below)
```
enable
conf t
enable secret C1sc0Rock5
ip routing
vlan 100,200,300,400
spanning-tree mode rapid-pvst
spanning-tree vlan 100,200 priority 4096
spanning-tree vlan 300,400 priority 8192
interface g1/0/1
 no switchport
 ip address 10.10.0.2 255.255.255.0
 no shutdown
interface g1/0/3
 no switchport
 ip address 10.30.0.1 255.255.255.0
 no shutdown
interface g1/0/2
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,400
 switchport nonegotiate
 no shutdown
interface range g1/0/4 - 24 , g1/1/1 - 4
 switchport mode access
 switchport nonegotiate
interface vlan 100
 ip address 10.100.0.1 255.255.255.0
 ip helper-address 10.10.0.1
 no shutdown
interface vlan 200
 ip address 20.100.0.1 255.255.255.0
 ip helper-address 10.10.0.1
 no shutdown
interface vlan 300
 ip address 30.100.0.2 255.255.255.0
 ip helper-address 10.10.0.1
 no shutdown
interface vlan 400
 ip address 40.100.0.2 255.255.255.0
 ip helper-address 10.10.0.1
 no shutdown
router ospf 1
 network 10.10.0.2 0.0.0.0 area 0
 network 10.30.0.1 0.0.0.0 area 0
 network 10.100.0.1 0.0.0.0 area 0
 network 20.100.0.1 0.0.0.0 area 0
 network 30.100.0.2 0.0.0.0 area 0
 network 40.100.0.2 0.0.0.0 area 0
end
wr
```
The `interface range g1/0/4 - 24 , g1/1/1 - 4` block is **NEW** (unused ports). If `encapsulation dot1q` is rejected, ignore it.

| Value | Distribution1 | Distribution2 |
|---|---|---|
| Priority 4096 VLANs | 100,200 | 300,400 |
| Priority 8192 VLANs | 300,400 | 100,200 |
| Gi1/0/1 | 10.10.0.2 | 10.20.0.2 |
| Gi1/0/3 | 10.30.0.1 | 10.30.0.2 |
| VLAN100 / 200 / 300 / 400 | .1 / .1 / .2 / .2 | .2 / .2 / .1 / .1 |
| helper-address | 10.10.0.1 | 10.20.0.1 |

## Campus_Access1 (Access2: fa0/3 = VLAN 300, fa0/4 = VLAN 400)
```
enable
conf t
enable secret C1sc0Rock5
vlan 100,200,300,400
spanning-tree mode rapid-pvst
interface range fa0/1 - 2
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,400
 switchport nonegotiate
 no shutdown
interface fa0/3
 switchport mode access
 switchport access vlan 100
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
interface fa0/4
 switchport mode access
 switchport access vlan 200
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
interface range fa0/5 - 24 , g0/1 - 2
 switchport mode access
 switchport nonegotiate
end
wr
```
The last `interface range` block is **NEW**. The first attempt's trunk ports were Fa0/1-2, not Gi0/1-2 (found with CDP).

## Remote_Router
```
enable
conf t
enable secret C1sc0Rock5
ip access-list extended Block_Communicaton
 deny ip 50.100.0.0 0.0.0.127 10.100.0.0 0.0.0.255
 deny ip 50.100.0.0 0.0.0.127 20.100.0.0 0.0.0.255
 deny ip 50.100.0.0 0.0.0.127 30.100.0.0 0.0.0.255
 deny ip 50.100.0.0 0.0.0.127 40.100.0.0 0.0.0.255
 deny ip 50.100.0.128 0.0.0.127 10.100.0.0 0.0.0.255
 deny ip 50.100.0.128 0.0.0.127 20.100.0.0 0.0.0.255
 deny ip 50.100.0.128 0.0.0.127 30.100.0.0 0.0.0.255
 deny ip 50.100.0.128 0.0.0.127 40.100.0.0 0.0.0.255
 permit ip any any
interface g0/0
 ip address 10.50.0.2 255.255.255.252
 no shutdown
interface g0/2
 ip address 10.50.0.6 255.255.255.252
 no shutdown
interface g0/1
 no shutdown
interface g0/1.1
 encapsulation dot1Q 100
 ip address 50.100.0.1 255.255.255.128
 ip access-group Block_Communicaton in
interface g0/1.2
 encapsulation dot1Q 200
 ip address 50.100.0.129 255.255.255.128
 ip access-group Block_Communicaton in
ip route 0.0.0.0 0.0.0.0 10.50.0.1
ip route 0.0.0.0 0.0.0.0 10.50.0.5 255
end
wr
```

## Remote_Switch
```
enable
conf t
enable secret C1sc0Rock5
vlan 100,200
interface fa0/1
 switchport mode trunk
 switchport trunk allowed vlan 100,200
 switchport nonegotiate
 no shutdown
interface fa0/2
 switchport mode access
 switchport access vlan 100
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
interface fa0/3
 switchport mode access
 switchport access vlan 200
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
interface range fa0/4 - 24 , g0/1 - 2
 switchport mode access
 switchport nonegotiate
end
wr
```
The last `interface range` block is **NEW**.

## PCs
PC1-PC4: Desktop -> IP Configuration -> DHCP. PC5/PC6: leave static.

## Verification that passed in the first attempt (necessary, not sufficient)
OSPF: 4 neighbors FULL on Core. DHCP: 4 bindings, none .1/.2. STP: Dist1 root VLAN 100, Dist2 root VLAN 300.
All PCs browse www.cp.com. PC1 -> PC5 blocked at Core (ACL line 10 matches); PC5 -> PC1 blocked at Remote_Router.
**Still 11.12/20.** Working is not the same as matching the grader.
