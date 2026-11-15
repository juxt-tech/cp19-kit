# What Packet Tracer can grade (Assessment Items)

Source: Cisco's Packet Tracer Activity Wizard help, "Assessment Items"
(https://tutorials.ptnetacad.net/help/default/activityWizard_assessmentItems.htm), checked 2026-11-14.

## How grading works
- The lab author builds an **answer network** and ticks which settings count. Your network is compared
  against those ticked items, setting by setting. Pings don't matter unless there's a separate
  connectivity test.
- Every value is compared **as a string**. Numbers, IPs and booleans are strings underneath, so
  `C1sc0Rock5` and `c1sc0rock5` are different answers.
- Authors can swap a value for a variable, but the compare is still value against value.

## Gradable settings that matter for Round 2 topics
Each line is a separate leaf, so it's potentially its own point.

| Area | Graded per... | Leaves (what's compared) |
|---|---|---|
| Switch port | **every port** | Access VLAN, **Nonegotiate**, Port Mode, Dynamic Mode, PortFast, Bpduguard, Native VLAN, Trunk VLANs (each allowed VLAN), Voice VLAN, Root guard, port security |
| Routed vs switched | every port | whether it's a switchport (`no switchport` changes it) |
| Spanning tree | device | RSTP on/off, PortFast default, and **per VLAN**: VLAN number + priority |
| DHCP server | device | enabled, each **excluded-address entry**, each pool |
| DHCP pool | pool | name, network/start IP, subnet mask, default gateway, DNS server, max users |
| OSPF | process | each network statement, default-information, passive interfaces, router ID, areas |
| ACL | ACL | the ACL's entries as text (spelling and order matter) |
| Port (any) | every port | description, duplex/speed, clock rate, and what it connects to |

## What this means
1. **DTP on unused ports is gradable port by port.** If the author ticked `Nonegotiate` on all 24
   ports of a switch, a switch with only 4 configured ports loses 20 items. Most likely cause of the
   R2 practice 11.12/20 (still unconfirmed for that lab; check Assessment Items).
2. **Port Mode is graded too.** Unused ports set to `switchport mode access` change Port Mode. In the
   R2 answer key that's needed anyway, because `nonegotiate` requires an explicit mode.
3. **Excluded addresses are compared entry by entry.** `10.100.0.2` and the range `10.100.0.1 10.100.0.2`
   are different entries. Type exclusions exactly as the spec words them.
4. **Spanning-tree priority is graded per VLAN**, so every VLAN listed in the spec needs its line.
5. **ACLs are compared as text.** Name spelling (`Block_Communicaton`) and line order both count.

## Gemini research results, checked 2026-11-14
| Resource | Verdict |
|---|---|
| PT Activity Wizard help (above) | **Real and very useful**: the only official word on grading |
| Medium, "Cisco Networking in CyberPatriot" (Taiyu Chen, Apr 2023) | Real, by a 3-year nationals competitor. Tips: do the NetAcad course's **.pka** labs (that's where points come from); quiz first in under 20 minutes; keep notepad config scripts; know the 3 quiz question types (vocab, commands, conceptual topology questions) |
| Discovery Middle School "training materials" | Just a link list (NetAcad course + CyberPatriot site). Skip |
| ciscoconfparse2, Batfish, ntc-templates | Real tools, but more than needed: `cisco/lint` already covers the checks that matter, with no installs. Batfish needs Java/Docker |
| "SRWE/ENSA skills assessments", "Cisco Community", "public quizlets" | No specific links given. Not verified |
