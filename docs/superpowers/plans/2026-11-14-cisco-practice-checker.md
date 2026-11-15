# Cisco Practice Checker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stdlib Python linter that flags grader-relevant mistakes in pasted Packet Tracer `show run` / `show interfaces switchport` output, plus the rules/gotchas docs and the R2 practice answer key.

**Architecture:** One script `cisco/lint/lint_showrun.py` with three layers: parse (clean paste junk, split config into global lines / interface blocks / named sections), checks (pure functions returning `Finding`s), CLI (scan folder, print per device, exit code). Docs live beside the existing playbook.

**Tech Stack:** Python 3 stdlib only (`re`, `dataclasses`, `pathlib`, `unittest`). No pip installs.

**Spec:** `docs/superpowers/specs/2026-11-14-cisco-practice-checker-design.md`

## Global Constraints
- Stdlib only; must run with plain `python lint_showrun.py <folder>` on Windows (Python 3.10+).
- Output ASCII only (cp1252 consoles).
- Every run ends with the exact line: `Rules only. The Assessment Items list is the real grade.`
- Exit codes: 0 = no FAIL, 1 = at least one FAIL, 2 = usage error (bad folder / no `.txt` show-run files).
- Linter holds no lab-specific values.

## Review Focus
1. CRLF line endings, tabs, trailing spaces in pasted files -> parsed identically to clean LF text.
2. `--More--` prompts (with or without backspace chars) splitting a line -> cleaned before parsing.
3. Prompt lines (`Switch#show run`), `Building configuration...`, `Current configuration : N bytes` -> ignored.
4. Folder with no show-run files -> exit 2 with a readable message, no traceback.
5. `<device>.switchport.txt` with no matching `<device>.txt` -> WARN line, not a crash.

---

### Task 1: Parser

**Files:**
- Create: `cisco/lint/lint_showrun.py`
- Test: `cisco/lint/test_lint_showrun.py`

**Interfaces:**
- Produces:
  - `clean(text: str) -> list[str]` — normalised lines (CRLF->LF, `--More--` and `\b` removed, rstrip, prompt/header lines dropped).
  - `short_name(name: str) -> str` — `"FastEthernet0/1"->"Fa0/1"`, `"GigabitEthernet1/0/2"->"Gi1/0/2"`, `"Vlan100"->"Vlan100"`, `"GigabitEthernet0/1.1"->"Gi0/1.1"`, short names pass through.
  - `@dataclass Device: name: str; is_switch: bool; globals: list[str]; interfaces: dict[str, list[str]]; sections: dict[str, list[str]]` — `interfaces` keyed by short name, values = stripped body lines; `sections` keyed by header line (`"router ospf 1"`, `"ip dhcp pool VLAN100"`, `"ip access-list extended X"`).
  - `parse_config(text: str, fallback_name: str) -> Device` — name from `hostname`, else `fallback_name`; `is_switch` = any interface short name starts with `Fa0/` or `Gi1/0/`.
  - `parse_switchport(text: str) -> dict[str, bool]` — short port name -> True if `Negotiation of Trunking: On`.
  - `compress_ports(names: list[str]) -> str` — `["Fa0/5","Fa0/6","Fa0/7","Gi0/1"] -> "Fa0/5-7, Gi0/1"`.

- [ ] **Step 1: failing tests** `test_clean_strips_more_and_crlf` (input `"a\r\n --More-- \b\b\bb\r\n"` -> `["a","b"]`), `test_clean_drops_prompts_and_headers`, `test_short_name_cases` (the five cases above), `test_parse_config_blocks` (hostname, two interfaces, `router ospf 1` section with its `network` lines, `is_switch` True for `FastEthernet0/1`), `test_parse_switchport` (two `Name:` blocks, On/Off), `test_compress_ports`.
- [ ] **Step 2:** `python -m unittest discover -s cisco/lint -v` -> FAIL (import error).
- [ ] **Step 3:** implement the six names above. A block starts at a non-indented line and owns following indented lines; `!` lines end blocks.
- [ ] **Step 4:** rerun -> PASS.
- [ ] **Step 5:** commit `feat(cisco): show-run parser for practice linter`.

### Task 2: Checks

**Files:** Modify `cisco/lint/lint_showrun.py`; Test `cisco/lint/test_lint_showrun.py`; Create `cisco/lint/fixtures/r2/Campus_Access1.txt`, `cisco/lint/fixtures/clean/SW1.txt`.

**Interfaces:**
- Consumes: `Device`, `compress_ports`.
- Produces: `@dataclass Finding: level: str  # "FAIL"|"WARN"; message: str` and `run_checks(dev: Device, switchport: dict[str, bool] | None) -> list[Finding]`.

Rules (each its own small function, called by `run_checks`):
| Rule | Level | Logic |
|---|---|---|
| DTP | FAIL | with `switchport`: ports mapped True. Without: L2 interfaces lacking `switchport nonegotiate`. L2 = switch interface that is not `Vlan*`/`Loopback*`/subinterface and has no `no switchport`; on routers, any interface with a `switchport` line. One finding, ports via `compress_ports`. Without switchport file on a router, also WARN `router switch-module ports not checked; paste show interfaces switchport`. |
| PortFast/BPDU | WARN | `spanning-tree portfast` (any suffix) without `spanning-tree bpduguard enable`, and reverse. |
| Trunk list | WARN | `switchport mode trunk` without `switchport trunk allowed vlan`. |
| Enable | FAIL / WARN | no global `enable secret` -> FAIL; `enable password` -> WARN. |
| ACL refs | FAIL / WARN | `ip access-group X` / `access-class X` with X not defined (named section or `access-list X` global) -> FAIL; defined but never referenced -> WARN. |
| ip routing | FAIL | switch, no global `ip routing`, and (>=2 SVIs with `ip address` or any `no switchport`). |
| Subinterface | FAIL | name contains `.` and no line starting `encapsulation dot1q` (case-insensitive). |
| DHCP pool | WARN | pool section missing `default-router` or `dns-server`. |
| Shut with IP | WARN | has `ip address <x>` and `shutdown`. |
| OSPF wildcard | WARN | `network A W area N` in `router ospf` with W != `0.0.0.0`. |

- [ ] **Step 1: failing tests** one per rule, plus `test_r2_access1_flags_unused_ports` (fixture: fa0/1-4 configured as in the R2 answer, fa0/5-24 and gi0/1-2 bare) asserting exactly one DTP FAIL whose message contains `Fa0/5-24, Gi0/1-2`, and `test_clean_fixture_no_fail`. Also `test_switchport_file_overrides` (show run says nonegotiate missing, switchport says Off -> no DTP FAIL).
- [ ] **Step 2:** run -> FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run -> PASS.
- [ ] **Step 5:** commit `feat(cisco): linter rule checks`.

### Task 3: CLI

**Files:** Modify `cisco/lint/lint_showrun.py`; Test same file; Create `cisco/lint/README.md`.

**Interfaces:** Produces `main(argv: list[str]) -> int`.

Output per device:
```
== <name> (switch|router) ==
FAIL  <message>
WARN  <message>
-- N FAIL, M WARN
```
then a blank line and the footer line. `<device>.switchport.txt` pairs with `<device>.txt`; orphan -> `WARN  <file>: no matching show run file`.

- [ ] **Step 1: failing tests** `test_main_exit_codes` (clean dir -> 0, r2 dir -> 1, empty dir -> 2, missing dir -> 2), `test_main_footer_printed`, `test_main_orphan_switchport_warns` (use `tempfile.TemporaryDirectory`, capture stdout via `contextlib.redirect_stdout`).
- [ ] **Step 2:** run -> FAIL. **Step 3:** implement + README (how to capture outputs in PT, file naming, example run). **Step 4:** PASS.
- [ ] **Step 5:** commit `feat(cisco): linter CLI + usage doc`.

### Task 4: Docs

**Files:** Modify `checklists/cisco.md` (new section G before end), `README.md` (cisco row links linter); Create `cisco/labs/r2-practice/answer-key.md`.

- Section G: spec-reading rules (all = every port incl. unused; type exactly, nothing extra; done = Assessment Items all green; scroll back after each paste for `%`; no `exit` straight after a line that may error; check prompt mode before typing; ACL/pool names copied character-for-character incl. typos) and gotchas table tagged confirmed/suspected (R2 suspects from chat: unused-port DTP, paste drops, mode trap, extra exclusions, Core NIM ports, works != graded).
- Answer key: final per-device blocks from the R2 session, Fa0/1-2 trunk fix, unused-port DTP ranges per model (2960: `fa0/5 - 24 , g0/1 - 2`; 3650: `g1/0/4 - 24 , g1/1/1 - 4`; Remote_Switch `fa0/4 - 24 , g0/1 - 2`), ambiguity notes (VLAN60 = internet, AD 255 never installs, `.2` vs `.129`, ACL name typo).
- [ ] Step: run `bash cisco/check-templates.sh` (still OK) and unittest suite -> PASS. Commit `docs(cisco): spec-reading rules, gotchas, R2 answer key`.
