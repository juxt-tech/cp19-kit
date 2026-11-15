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


def check(text, switchport=None, name="dev"):
    return L.run_checks(L.parse_config(text, name), switchport)


def by_level(findings, level):
    return [f.message for f in findings if f.level == level]


def dtp(findings):
    return [f for f in findings if f.message.startswith("DTP")]


SECRET = "enable secret 5 $1$x\n"


class DtpTests(unittest.TestCase):
    def test_dtp_fallback_flags_missing_nonegotiate(self):
        f = dtp(check(SECRET + "interface FastEthernet0/1\n!\ninterface FastEthernet0/2\n switchport nonegotiate\n"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].level, "FAIL")
        self.assertIn("Fa0/1", f[0].message)
        self.assertNotIn("Fa0/2", f[0].message)

    def test_dtp_skips_routed_svi_and_subinterfaces(self):
        cfg = SECRET + ("ip routing\ninterface GigabitEthernet1/0/1\n no switchport\n ip address 1.1.1.1 255.255.255.0\n"
                        "interface GigabitEthernet1/0/2\n switchport nonegotiate\ninterface Vlan100\n ip address 2.2.2.2 255.0.0.0\n")
        self.assertEqual(dtp(check(cfg)), [])

    def test_dtp_router_counts_only_switchport_interfaces(self):
        cfg = SECRET + ("interface GigabitEthernet0/0/0\n ip address 1.1.1.1 255.0.0.0\n"
                        "interface GigabitEthernet0/1/0\n switchport mode access\n")
        found = check(cfg)
        self.assertEqual(len(dtp(found)), 1)
        self.assertIn("Gi0/1/0", dtp(found)[0].message)
        self.assertNotIn("Gi0/0/0", dtp(found)[0].message)
        self.assertTrue(any("not checked" in m for m in by_level(found, "WARN")))

    def test_switchport_file_overrides_show_run(self):
        cfg = SECRET + "interface FastEthernet0/1\n!\n"
        self.assertEqual(dtp(check(cfg, {"Fa0/1": False})), [])
        f = dtp(check(cfg, {"Fa0/1": True, "Gi0/1": True}))
        self.assertEqual(len(f), 1)
        self.assertIn("Fa0/1, Gi0/1", f[0].message)

    def test_router_with_switchport_file_has_no_not_checked_warn(self):
        found = check(SECRET + "interface GigabitEthernet0/0/0\n ip address 1.1.1.1 255.0.0.0\n", {"Gi0/1/0": False})
        self.assertFalse(any("not checked" in m for m in by_level(found, "WARN")))


class RuleTests(unittest.TestCase):
    def test_portfast_without_bpduguard_warns(self):
        w = by_level(check(SECRET + "interface FastEthernet0/3\n switchport nonegotiate\n spanning-tree portfast\n"), "WARN")
        self.assertTrue(any("PortFast without BPDU Guard: Fa0/3" in m for m in w))

    def test_bpduguard_without_portfast_warns(self):
        w = by_level(check(SECRET + "interface FastEthernet0/3\n switchport nonegotiate\n spanning-tree bpduguard enable\n"), "WARN")
        self.assertTrue(any("BPDU Guard without PortFast: Fa0/3" in m for m in w))

    def test_trunk_without_allowed_list_warns(self):
        w = by_level(check(SECRET + "interface FastEthernet0/1\n switchport mode trunk\n switchport nonegotiate\n"), "WARN")
        self.assertTrue(any("allowed vlan" in m and "Fa0/1" in m for m in w))

    def test_enable_secret_missing_fails(self):
        self.assertTrue(any("enable secret" in m for m in by_level(check("hostname R1\n"), "FAIL")))

    def test_enable_password_warns(self):
        self.assertTrue(any("enable password" in m for m in by_level(check(SECRET + "enable password cisco\n"), "WARN")))

    def test_acl_applied_but_undefined_fails_and_unused_warns(self):
        cfg = SECRET + ("ip access-list extended Block_Communicaton\n deny ip any any\n"
                        "interface GigabitEthernet0/0/0\n ip address 1.1.1.1 255.0.0.0\n"
                        " ip access-group Block_Communication in\n")
        found = check(cfg)
        self.assertTrue(any("'Block_Communication'" in m for m in by_level(found, "FAIL")))
        self.assertTrue(any("'Block_Communicaton'" in m for m in by_level(found, "WARN")))

    def test_numbered_acl_on_vty_is_fine(self):
        cfg = SECRET + "access-list 10 permit any\nline vty 0 4\n access-class 10 in\n"
        self.assertEqual([m for m in by_level(check(cfg), "FAIL") + by_level(check(cfg), "WARN") if "ACL" in m], [])

    def test_l3_switch_without_ip_routing_fails(self):
        cfg = SECRET + "interface GigabitEthernet1/0/1\n no switchport\n ip address 1.1.1.1 255.0.0.0\n"
        self.assertTrue(any("ip routing" in m for m in by_level(check(cfg), "FAIL")))
        self.assertFalse(any("ip routing" in m for m in by_level(check("ip routing\n" + cfg), "FAIL")))

    def test_2960_management_svi_does_not_need_ip_routing(self):
        cfg = SECRET + "interface FastEthernet0/1\n switchport nonegotiate\ninterface Vlan1\n ip address 1.1.1.2 255.0.0.0\n"
        self.assertFalse(any("ip routing" in m for m in by_level(check(cfg), "FAIL")))

    def test_subinterface_without_encapsulation_fails(self):
        cfg = SECRET + "interface GigabitEthernet0/1.1\n ip address 1.1.1.1 255.0.0.0\n"
        self.assertTrue(any("Gi0/1.1" in m and "encapsulation" in m for m in by_level(check(cfg), "FAIL")))
        ok = SECRET + "interface GigabitEthernet0/1.1\n encapsulation dot1Q 100\n ip address 1.1.1.1 255.0.0.0\n"
        self.assertFalse(any("encapsulation" in m for m in by_level(check(ok), "FAIL")))

    def test_dhcp_pool_missing_fields_warns(self):
        w = by_level(check(SECRET + "ip dhcp pool VLAN100\n network 10.100.0.0 255.255.255.0\n"), "WARN")
        self.assertTrue(any("VLAN100" in m and "default-router" in m for m in w))
        self.assertTrue(any("VLAN100" in m and "dns-server" in m for m in w))

    def test_shutdown_interface_with_ip_warns(self):
        w = by_level(check(SECRET + "interface GigabitEthernet0/0\n ip address 1.1.1.1 255.0.0.0\n shutdown\n"), "WARN")
        self.assertTrue(any("Gi0/0" in m and "shutdown" in m for m in w))

    def test_ospf_wildcard_not_zero_warns(self):
        w = by_level(check(SECRET + "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n network 10.1.0.1 0.0.0.0 area 0\n"), "WARN")
        self.assertEqual(len([m for m in w if "OSPF" in m]), 1)
        self.assertTrue(any("10.0.0.0 0.0.0.255" in m for m in w))


class FixtureTests(unittest.TestCase):
    def test_r2_access1_flags_unused_ports(self):
        text = (FIXTURES / "r2" / "Campus_Access1.txt").read_text()
        found = check(text, name="Campus_Access1")
        f = dtp(found)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].level, "FAIL")
        self.assertIn("Fa0/5-24, Gi0/1-2", f[0].message)

    def test_clean_fixture_no_fail(self):
        found = check((FIXTURES / "clean" / "SW1.txt").read_text())
        self.assertEqual(by_level(found, "FAIL"), [])


def run_main(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = L.main(args)
    return code, buf.getvalue()


class MainTests(unittest.TestCase):
    def test_main_exit_codes(self):
        self.assertEqual(run_main([str(FIXTURES / "clean")])[0], 0)
        self.assertEqual(run_main([str(FIXTURES / "r2")])[0], 1)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_main([d])[0], 2)
        self.assertEqual(run_main([str(FIXTURES / "does-not-exist")])[0], 2)
        self.assertEqual(run_main([])[0], 2)

    def test_main_footer_printed(self):
        out = run_main([str(FIXTURES / "r2")])[1]
        self.assertIn("== Campus_Access1 (switch) ==", out)
        self.assertIn("-- 1 FAIL, 0 WARN", out)
        self.assertTrue(out.rstrip().endswith("Rules only. The Assessment Items list is the real grade."))

    def test_main_uses_switchport_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "SW.txt").write_text(SECRET + "interface FastEthernet0/1\n!\n")
            Path(d, "SW.switchport.txt").write_text("Name: Fa0/1\nNegotiation of Trunking: Off\n")
            code, out = run_main([d])
        self.assertEqual(code, 0, out)

    def test_main_orphan_switchport_warns(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "SW1.txt").write_text((FIXTURES / "clean" / "SW1.txt").read_text())
            Path(d, "Ghost.switchport.txt").write_text("Name: Fa0/1\nNegotiation of Trunking: On\n")
            code, out = run_main([d])
        self.assertEqual(code, 0)
        self.assertIn("Ghost.switchport.txt: no matching show run file", out)

    def test_main_output_is_ascii(self):
        out = run_main([str(FIXTURES / "r2")])[1]
        out.encode("ascii")


if __name__ == "__main__":
    unittest.main()
