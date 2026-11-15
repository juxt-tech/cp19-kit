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
