import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint_showrun as L  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


class CleanTests(unittest.TestCase):
    def test_clean_strips_more_and_crlf(self):
        self.assertEqual(L.clean("a\r\n --More-- \b\b\bb\r\n"), ["a", "b"])

    def test_clean_strips_tabs_and_trailing_space(self):
        self.assertEqual(L.clean("interface Fa0/1   \n\tswitchport nonegotiate\t\n"),
                         ["interface Fa0/1", " switchport nonegotiate"])

    def test_clean_drops_prompts_and_headers(self):
        text = ("Switch1#show running-config\nBuilding configuration...\n\n"
                "Current configuration : 1234 bytes\n!\nhostname SW1\nSW1#\n")
        self.assertEqual(L.clean(text), ["!", "hostname SW1"])


class ShortNameTests(unittest.TestCase):
    def test_short_name_cases(self):
        cases = {
            "FastEthernet0/1": "Fa0/1",
            "GigabitEthernet1/0/2": "Gi1/0/2",
            "Vlan100": "Vlan100",
            "GigabitEthernet0/1.1": "Gi0/1.1",
            "Fa0/3": "Fa0/3",
        }
        for long, short in cases.items():
            self.assertEqual(L.short_name(long), short, long)


CONFIG = """\
hostname SW1
!
enable secret 5 $1$abc
!
interface FastEthernet0/1
 switchport mode access
 switchport nonegotiate
!
interface Vlan1
 no ip address
!
router ospf 1
 network 10.0.0.1 0.0.0.0 area 0
!
end
"""


class ParseConfigTests(unittest.TestCase):
    def test_parse_config_blocks(self):
        d = L.parse_config(CONFIG, "fallback")
        self.assertEqual(d.name, "SW1")
        self.assertTrue(d.is_switch)
        self.assertEqual(d.interfaces["Fa0/1"], ["switchport mode access", "switchport nonegotiate"])
        self.assertEqual(d.interfaces["Vlan1"], ["no ip address"])
        self.assertEqual(d.sections["router ospf 1"], ["network 10.0.0.1 0.0.0.0 area 0"])
        self.assertIn("enable secret 5 $1$abc", d.globals)

    def test_parse_config_fallback_name_and_router(self):
        d = L.parse_config("interface GigabitEthernet0/0/0\n ip address 1.1.1.1 255.0.0.0\n", "R1")
        self.assertEqual(d.name, "R1")
        self.assertFalse(d.is_switch)

    def test_parse_config_crlf_same_as_lf(self):
        a = L.parse_config(CONFIG, "x")
        b = L.parse_config(CONFIG.replace("\n", "\r\n"), "x")
        self.assertEqual(a, b)


SWITCHPORT = """\
Name: Fa0/1
Switchport: Enabled
Administrative Mode: static access
Negotiation of Trunking: Off

Name: Gi0/1
Switchport: Enabled
Administrative Mode: dynamic auto
Negotiation of Trunking: On
"""


class ParseSwitchportTests(unittest.TestCase):
    def test_parse_switchport(self):
        self.assertEqual(L.parse_switchport(SWITCHPORT), {"Fa0/1": False, "Gi0/1": True})


class CompressTests(unittest.TestCase):
    def test_compress_ports(self):
        self.assertEqual(L.compress_ports(["Fa0/5", "Fa0/6", "Fa0/7", "Gi0/1"]), "Fa0/5-7, Gi0/1")

    def test_compress_ports_unsorted_and_gaps(self):
        self.assertEqual(L.compress_ports(["Fa0/10", "Fa0/2", "Fa0/3", "Gi1/0/4", "Gi1/0/6"]),
                         "Fa0/2-3, Fa0/10, Gi1/0/4, Gi1/0/6")


if __name__ == "__main__":
    unittest.main()
