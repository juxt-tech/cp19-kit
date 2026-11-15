"""Practice-time linter for Cisco Packet Tracer configs (CyberPatriot).

Paste each device's `show running-config` into <device>.txt (and optionally its
`show interfaces switchport` into <device>.switchport.txt), then run:

    python lint_showrun.py <folder>

Rules only. It does not know lab-specific answers; Assessment Items is the real grade.
Stdlib only, ASCII output. Not for use during scored rounds.
"""
import re
from dataclasses import dataclass, field

MORE_RE = re.compile(r"[ ]*--More--[ ]*")
BACKSPACE_RE = re.compile(r"\x08(?:[\x08 ]*\x08)?")
PROMPT_RE = re.compile(r"^[A-Za-z0-9_.()-]+[#>]")
HEADER_RES = (re.compile(r"^Building configuration"), re.compile(r"^Current configuration\s*:"))
SECTION_PREFIXES = ("router ", "ip dhcp pool ", "ip access-list ", "line ")
SHORT_PREFIXES = (
    ("tengigabitethernet", "Te"),
    ("gigabitethernet", "Gi"),
    ("fastethernet", "Fa"),
    ("port-channel", "Po"),
    ("serial", "Se"),
    ("loopback", "Loopback"),
    ("vlan", "Vlan"),
)


def clean(text):
    """Normalise pasted terminal output into config lines."""
    out = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = MORE_RE.sub("", raw)
        line = BACKSPACE_RE.sub("", line)
        line = line.replace("\t", " ").rstrip()
        if not line.strip():
            continue
        if PROMPT_RE.match(line) or any(h.match(line) for h in HEADER_RES):
            continue
        out.append(line)
    return out


def short_name(name):
    name = name.strip()
    low = name.lower()
    for long, short in SHORT_PREFIXES:
        if low.startswith(long):
            return short + name[len(long):].strip()
    return name


@dataclass
class Device:
    name: str
    is_switch: bool
    globals: list = field(default_factory=list)
    interfaces: dict = field(default_factory=dict)
    sections: dict = field(default_factory=dict)


def parse_config(text, fallback_name):
    globals_, interfaces, sections = [], {}, {}
    body = None
    for line in clean(text):
        if line.startswith(" "):
            if body is not None:
                body.append(line.strip())
            continue
        body = None
        if line.startswith("!") or line == "end":
            continue
        if line.startswith("interface "):
            body = interfaces.setdefault(short_name(line[len("interface "):]), [])
        elif line.startswith(SECTION_PREFIXES):
            body = sections.setdefault(line, [])
        else:
            globals_.append(line)
    name = fallback_name
    for g in globals_:
        if g.startswith("hostname "):
            name = g.split(None, 1)[1]
    is_switch = any(i.startswith(("Fa0/", "Gi1/0/")) for i in interfaces)
    return Device(name, is_switch, globals_, interfaces, sections)


def parse_switchport(text):
    """Map short port name -> True when DTP ('Negotiation of Trunking') is On."""
    result, current = {}, None
    for line in clean(text):
        s = line.strip()
        if s.startswith("Name:"):
            current = short_name(s.split(":", 1)[1])
            result.setdefault(current, False)
        elif s.startswith("Negotiation of Trunking:") and current:
            result[current] = s.split(":", 1)[1].strip().lower() == "on"
    return result


def _port_key(name):
    m = re.match(r"^(.*?)(\d+)$", name)
    return (m.group(1), int(m.group(2))) if m else (name, -1)


def compress_ports(names):
    """['Fa0/5','Fa0/6','Fa0/7','Gi0/1'] -> 'Fa0/5-7, Gi0/1'."""
    parts, run = [], None
    for prefix, num in sorted(_port_key(n) for n in set(names)):
        if run and run[0] == prefix and num == run[2] + 1:
            run[2] = num
            continue
        if run:
            parts.append(run)
        run = [prefix, num, num]
    if run:
        parts.append(run)
    return ", ".join(f"{p}{a}" if a == b else f"{p}{a}-{b}" for p, a, b in parts)


@dataclass
class Finding:
    level: str  # "FAIL" or "WARN"
    message: str


def _has(lines, prefix):
    return any(l.lower().startswith(prefix.lower()) for l in lines)


def _has_ip(lines):
    return any(l.startswith("ip address ") for l in lines)


def _is_l2(dev, name, lines):
    if dev.is_switch:
        if name.startswith(("Vlan", "Loopback")) or "." in name:
            return False
        return "no switchport" not in lines
    return _has(lines, "switchport ")


def check_dtp(dev, switchport):
    if switchport is not None:
        on = [p for p, is_on in switchport.items() if is_on]
        if on:
            return [Finding("FAIL", "DTP still on ('Negotiation of Trunking: On'): " + compress_ports(on))]
        return []
    out = []
    missing = [n for n, l in dev.interfaces.items() if _is_l2(dev, n, l) and "switchport nonegotiate" not in l]
    if missing:
        out.append(Finding("FAIL", "DTP still on (no 'switchport nonegotiate'): " + compress_ports(missing)))
    if not dev.is_switch:
        out.append(Finding("WARN", "router switch-module ports not checked; paste 'show interfaces switchport' "
                                   f"as {dev.name}.switchport.txt"))
    return out


def check_portfast(dev, _sp):
    pf_only, bg_only = [], []
    for n, l in dev.interfaces.items():
        pf = _has(l, "spanning-tree portfast")
        bg = "spanning-tree bpduguard enable" in l
        if pf and not bg:
            pf_only.append(n)
        if bg and not pf:
            bg_only.append(n)
    out = []
    if pf_only:
        out.append(Finding("WARN", "PortFast without BPDU Guard: " + compress_ports(pf_only)))
    if bg_only:
        out.append(Finding("WARN", "BPDU Guard without PortFast: " + compress_ports(bg_only)))
    return out


def check_trunks(dev, _sp):
    bad = [n for n, l in dev.interfaces.items()
           if "switchport mode trunk" in l and not _has(l, "switchport trunk allowed vlan")]
    return [Finding("WARN", "trunk with no 'switchport trunk allowed vlan' list: " + compress_ports(bad))] if bad else []


def check_enable(dev, _sp):
    out = []
    if not _has(dev.globals, "enable secret"):
        out.append(Finding("FAIL", "no 'enable secret' set"))
    if _has(dev.globals, "enable password"):
        out.append(Finding("WARN", "'enable password' present (only use enable secret unless the spec asks)"))
    return out


def check_acls(dev, _sp):
    defined = {h.split()[-1] for h in dev.sections if h.startswith("ip access-list ")}
    defined |= {g.split()[1] for g in dev.globals if g.startswith("access-list ")}
    used = set()
    for lines in list(dev.interfaces.values()) + list(dev.sections.values()):
        for l in lines:
            m = re.match(r"^(?:ip access-group|access-class)\s+(\S+)", l)
            if m:
                used.add(m.group(1))
    out = [Finding("FAIL", f"ACL '{a}' applied but not defined (check spelling)") for a in sorted(used - defined)]
    out += [Finding("WARN", f"ACL '{a}' defined but never applied") for a in sorted(defined - used)]
    return out


def check_ip_routing(dev, _sp):
    if not dev.is_switch or "ip routing" in dev.globals:
        return []
    svis = [n for n, l in dev.interfaces.items() if n.startswith("Vlan") and _has_ip(l)]
    routed = [n for n, l in dev.interfaces.items() if "no switchport" in l]
    if len(svis) >= 2 or routed:
        return [Finding("FAIL", "layer 3 switch config (SVIs / routed ports) without 'ip routing'")]
    return []


def check_subinterfaces(dev, _sp):
    return [Finding("FAIL", f"{n}: subinterface without 'encapsulation dot1Q <vlan>'")
            for n, l in dev.interfaces.items() if "." in n and not _has(l, "encapsulation dot1q")]


def check_dhcp(dev, _sp):
    out = []
    for h, lines in dev.sections.items():
        if h.startswith("ip dhcp pool "):
            pool = h.split()[-1]
            for need in ("default-router", "dns-server"):
                if not _has(lines, need):
                    out.append(Finding("WARN", f"DHCP pool {pool}: missing {need}"))
    return out


def check_shutdown(dev, _sp):
    return [Finding("WARN", f"{n}: has an IP address but is shutdown")
            for n, l in dev.interfaces.items() if _has_ip(l) and "shutdown" in l]


def check_ospf(dev, _sp):
    out = []
    for h, lines in dev.sections.items():
        if h.startswith("router ospf"):
            for l in lines:
                p = l.split()
                if len(p) >= 5 and p[0] == "network" and p[2] != "0.0.0.0":
                    out.append(Finding("WARN", f"OSPF network uses wildcard {p[2]} (spec may want the interface IP "
                                               f"with 0.0.0.0): {l}"))
    return out


CHECKS = (check_enable, check_dtp, check_portfast, check_trunks, check_acls, check_ip_routing,
          check_subinterfaces, check_dhcp, check_shutdown, check_ospf)


def run_checks(dev, switchport=None):
    findings = []
    for c in CHECKS:
        findings.extend(c(dev, switchport))
    return findings


FOOTER = "Rules only. The Assessment Items list is the real grade."
USAGE = "usage: python lint_showrun.py <folder with <device>.txt and optional <device>.switchport.txt>"


def _say(text=""):
    print(text.encode("ascii", "replace").decode("ascii"))


def _read(path):
    return path.read_text(encoding="utf-8", errors="replace")


def main(argv):
    from pathlib import Path
    if len(argv) != 1 or not Path(argv[0]).is_dir():
        _say(USAGE)
        return 2
    folder = Path(argv[0])
    configs = sorted(p for p in folder.glob("*.txt") if not p.name.endswith(".switchport.txt"))
    if not configs:
        _say(f"no show-run files (*.txt) found in {folder}")
        _say(USAGE)
        return 2
    stems = {p.stem for p in configs}
    any_fail = False
    for p in configs:
        sp_path = folder / f"{p.stem}.switchport.txt"
        switchport = parse_switchport(_read(sp_path)) if sp_path.exists() else None
        dev = parse_config(_read(p), p.stem)
        findings = run_checks(dev, switchport)
        fails = sum(f.level == "FAIL" for f in findings)
        any_fail = any_fail or fails > 0
        _say(f"== {dev.name} ({'switch' if dev.is_switch else 'router'}) ==")
        for f in sorted(findings, key=lambda f: f.level != "FAIL"):
            _say(f"{f.level:<5} {f.message}")
        _say(f"-- {fails} FAIL, {len(findings) - fails} WARN")
        _say()
    for sp in sorted(folder.glob("*.switchport.txt")):
        if sp.name[: -len(".switchport.txt")] not in stems:
            _say(f"WARN  {sp.name}: no matching show run file")
    _say(FOOTER)
    return 1 if any_fail else 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
