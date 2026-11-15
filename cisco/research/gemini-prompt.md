# Gemini research prompt: Cisco resources for CyberPatriot

Paste everything below the line into Gemini (Deep Research mode if available).

---

I'm a high-school CyberPatriot competitor (CyberPatriot 19, 2026-27 season, Open/High School division) and I handle the **Cisco Networking Challenge** for my team. It has two parts: a NetAcad quiz from the "CyberPatriot Content" course, and a **Cisco Packet Tracer activity** (.pka) graded automatically by Assessment Items. I passed every connectivity test on a practice lab and still scored 11.12/20, because the grader checks config lines that pings never test (likely: DTP not disabled on unused ports, extra commands not in the spec).

Round 2 topics: VLANs, 802.1Q trunks, inter-VLAN routing (router-on-a-stick, L3 switch SVIs), STP/Rapid PVST+ (root priority, PortFast, BPDU Guard), DTP (`switchport nonegotiate`), DHCP server + relay (`ip helper-address`), single-area OSPF, floating static routes, named extended ACLs. Upcoming rounds add NAT, IPv6, port security, SSH, wireless, WAN.

**Find practice resources I can use to improve. Practice only: I am not asking for answers to any live or current competition round.** Search GitHub, GitLab, Reddit (r/CyberPatriot, r/ccna, r/networking), Cisco Learning Network, NetAcad community, YouTube, club/school websites, and blogs.

## What to find
1. **CyberPatriot Cisco checklists, playbooks, and writeups**: team or club notes on the Packet Tracer challenge (any season, CP-12 through CP-19), lists of common point losses, "what the grader checks" notes, round-by-round topic lists, NetAcad quiz study guides.
2. **Scripts that check a Cisco config after I paste in output** (`show running-config`, `show interfaces switchport`, `show ip interface brief`, and similar), working offline on plain text. Examples to evaluate: `ciscoconfparse` / `ciscoconfparse2`, Batfish, `ntc-templates` (TextFSM), Genie/pyATS parsers, CIS Cisco IOS benchmark audit scripts, any small "config linter" or "packet tracer checker" repos. For each: does it run on Windows with only pip (no Docker, no live device)? What would it catch for my topics?
3. **Packet Tracer practice labs similar to mine** (.pka with Assessment Items): CCNA2 SRWE and CCNA3 ENSA Packet Tracer skills assessments, "PT practice skills assessment" labs that combine OSPF + DHCP relay + router-on-a-stick + STP + ACLs, and any CyberPatriot practice .pka files shared publicly.
4. **How Packet Tracer Assessment Items grade**: exact-string vs. functional checks, case sensitivity, whether extra commands cost points, how per-port checks are scored, how "Check Results" is computed. Include Cisco documentation on the Activity Wizard if it exists.
5. **Quiz prep**: question banks or flashcards for the NetAcad "CyberPatriot Content" course modules, or the matching CCNA ITN/SRWE module exams.

## Already have (skip these)
- github.com/troy-cyber/cisco-share-resources
- Jeremy's IT Lab CCNA videos
- My own playbook: rules, templates, a show-run linter for DTP/PortFast/BPDU Guard/trunk lists/ACL names/`ip routing`/subinterfaces/DHCP pools/OSPF wildcards

## Output format
A table per category with: **name, URL, what it is, last updated (year), how it helps me (1 line), relevance 1-5**. Then a top 5 overall, in the order I should use them.

Rules for you:
- Only include links you actually found. **Do not invent URLs, repo names, or file names.** If you're unsure a link still works, say so.
- Flag anything older than 2022, or for an old Packet Tracer version.
- Flag anything that looks like leaked answers to a live CyberPatriot round, and leave it out.
- For scripts, say the install command and whether it needs network access or a real device.
