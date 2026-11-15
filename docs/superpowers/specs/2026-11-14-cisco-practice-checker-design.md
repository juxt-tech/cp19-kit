# Cisco practice checker + spec-reading rules (design)

Date: 2026-11-14. Status: approved by Sanh in chat.

## Why
The Round 2 Packet Tracer practice lab scored 11.12/20 although every connectivity test
passed (pings, DHCP, browsing, ACL blocks). The lost points are config details the grader
checks but pings never exercise (most likely: DTP left on for unused ports). Scored rounds
allow no AI, so the fix has to train Sanh to catch these himself.

## Goals
1. `checklists/cisco.md` gains section **G. Spec-reading rules + gotchas**. Each gotcha is
   tagged *confirmed* (seen as a red X in Assessment Items) or *suspected*.
2. `cisco/labs/r2-practice/` holds the corrected answer key for the practice lab, with the
   ambiguous spec lines called out.
3. `cisco/lint/lint_showrun.py`: stdlib-only Python. Input: a folder of pasted outputs,
   `<device>.txt` (`show running-config`) and optional `<device>.switchport.txt`
   (`show interfaces switchport`). Output: FAIL / WARN lines per device, exit code 1 on any FAIL.
4. Tests (stdlib `unittest`) with sample configs, including the Round 2 configs as built,
   proving the unused-port DTP miss is caught.

## Checks
| Check | Level | Source |
|---|---|---|
| L2 port with DTP on (`Negotiation of Trunking: On`) | FAIL | switchport file (authoritative, covers router NIM ports) |
| Switch port with no `switchport nonegotiate` (routed `no switchport` ports skipped) | FAIL | show run (fallback when no switchport file) |
| PortFast without BPDU Guard, or the reverse | WARN | show run |
| Trunk with no `switchport trunk allowed vlan` | WARN | show run |
| No `enable secret`; `enable password` present | FAIL / WARN | show run |
| `ip access-group X` where ACL X is not defined | FAIL | show run |
| ACL defined but never applied | WARN | show run |
| SVIs with IPs but no `ip routing` (switch) | FAIL | show run |
| Subinterface without `encapsulation dot1Q` | FAIL | show run |
| DHCP pool missing `default-router` / `dns-server` | WARN | show run |
| Interface with an IP that is `shutdown` | WARN | show run |
| OSPF `network` wildcard not `0.0.0.0` | WARN | show run |

Pasted text is cleaned of Packet Tracer `--More--` prompts and backspace junk.

## Non-goals / anti-goals
- No config generator; no lab-specific answers inside the linter (rules, not values).
- Not for use during scored rounds.
- Must not create false confidence: every run ends with
  "Rules only. The Assessment Items list is the real grade."

## Approaches considered
- A. Docs only: cheapest, usable on paper, but nothing catches misses during practice.
- **B. Docs + practice linter (picked):** same docs plus automatic feedback on pasted configs.
- C. Spec-driven config generator: dropped; can't run inside the locked VM and teaches nothing.

## Builder's calls
- Device type: a device is a switch if its config has `FastEthernet0/` ports or
  `GigabitEthernet1/0/` ports; otherwise a router. On routers, an interface counts as L2
  only if it carries `switchport` lines (show-run fallback limitation, fixed by the
  switchport file).
- Interface names in the switchport file are matched by normalised short name (`Fa0/1`, `Gi1/0/2`).
