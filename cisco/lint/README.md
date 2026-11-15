# Cisco practice checker (`lint_showrun.py`)

Practice only. **Not for scored rounds** (no AI, and usually no outside tools).
It checks rules that graders score but pings never test. It does not know a lab's
answers, so **Check Results -> Assessment Items is still the real grade.**

## 1. Capture the output in Packet Tracer
On every device (CLI tab, from the `#` prompt):

```
terminal length 0
show running-config
show interfaces switchport
```

`terminal length 0` stops the `--More--` pauses. If your device rejects it, press
Space through the pages; the checker strips leftover `--More--` junk.

## 2. Save one folder, two files per device
```
r2-practice/
  Core_Router.txt                  <- show running-config
  Core_Router.switchport.txt       <- show interfaces switchport (optional, recommended)
  Campus_Access1.txt
  Campus_Access1.switchport.txt
  ...
```
The switchport file is what lets it check **every** layer 2 port, including router
switch-module ports and unused ports. Without it, router module ports aren't checked.

## 3. Run
```
python cisco/lint/lint_showrun.py r2-practice
```
Exit code 0 = no FAIL, 1 = at least one FAIL, 2 = bad folder.

Example (Round 2 practice, Campus_Access1 as built):
```
== Campus_Access1 (switch) ==
FAIL  DTP still on (no 'switchport nonegotiate'): Fa0/5-24, Gi0/1-2
-- 1 FAIL, 0 WARN

Rules only. The Assessment Items list is the real grade.
```

## What it checks
| Level | Check |
|---|---|
| FAIL | DTP on for any layer 2 port (unused ones too) |
| FAIL | no `enable secret` |
| FAIL | `ip access-group` / `access-class` names an ACL that doesn't exist (typos) |
| FAIL | layer 3 switch config without `ip routing` |
| FAIL | subinterface without `encapsulation dot1Q` |
| WARN | PortFast without BPDU Guard, or the reverse |
| WARN | trunk with no `allowed vlan` list |
| WARN | `enable password` present; ACL defined but never applied |
| WARN | DHCP pool missing `default-router` / `dns-server` |
| WARN | interface with an IP that is shut down |
| WARN | OSPF `network` wildcard isn't `0.0.0.0` |

A WARN can be correct for a given lab. Read the spec, then decide.

## Tests
```
python -m unittest discover -s cisco/lint -v
```
