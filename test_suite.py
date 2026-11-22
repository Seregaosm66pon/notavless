"""
Unit and integration test suite for Nota Vless Health Checker & Tester Engine.
"""

from __future__ import annotations

import asyncio
import unittest

from checker import (
    NodeCheckResult,
    build_health_report,
    classify_russian_tier,
    classify_tier,
    detect_country_info,
    get_security_tag,
    make_sparkline,
)
from protocols import ParsedConfig, parse_any_proxy_url


class TestCountryDetection(unittest.TestCase):
    def test_russian_remarks(self):
        cases = [
            ("[Ультра] Польша #1 NOTAVLESS", "pl", "🇵🇱", "Польша"),
            ("[Быстрый] Германия #1 NOTAVLESS", "de", "🇩🇪", "Германия"),
            ("[Базовый] Нидерланды #1 NOTAVLESS", "nl", "🇳🇱", "Нидерланды"),
            ("[Базовый] Гондурас #1 NOTAVLESS", "hn", "🇭🇳", "Гондурас"),
            ("[Стандарт] США #4 NOTAVLESS", "us", "🇺🇸", "США"),
            ("[Быстрый] Россия #1 NOTAVLESS", "ru", "🇷🇺", "Россия"),
            ("[Быстрый] Беларусь #1 NOTAVLESS", "by", "🇧🇾", "Беларусь"),
            ("[Базовый] Турция #1 NOTAVLESS", "tr", "🇹🇷", "Турция"),
            ("[Базовый] Албания #1 NOTAVLESS", "al", "🇦🇱", "Албания"),
            ("[Быстрый] Швеция #1 NOTAVLESS", "se", "🇸🇪", "Швеция"),
            ("[Базовый] Финляндия #1 NOTAVLESS", "fi", "🇫🇮", "Финляндия"),
            ("[Базовый] Канада #1 NOTAVLESS", "ca", "🇨🇦", "Канада"),
            ("[Быстрый] Сингапур #1 NOTAVLESS", "sg", "🇸🇬", "Сингапур"),
            ("[Базовый] AU #1 NOTAVLESS", "au", "🇦🇺", "Австралия"),
            ("[Стандарт] Украина #1 NOTAVLESS", "ua", "🇺🇦", "Украина"),
        ]
        for rem, exp_code, exp_flag, exp_name in cases:
            code, flag, name = detect_country_info(rem)
            self.assertEqual(code, exp_code, f"Failed code for {rem}")
            self.assertEqual(flag, exp_flag, f"Failed flag for {rem}")
            self.assertEqual(name, exp_name, f"Failed name for {rem}")

    def test_direct_flag_emojis(self):
        rem = "🇩🇪 Frankfurt High Speed"
        code, flag, name = detect_country_info(rem)
        self.assertEqual(code, "de")
        self.assertEqual(flag, "🇩🇪")
        self.assertEqual(name, "Германия")

    def test_domain_cues(self):
        code, flag, name = detect_country_info("Node", host="server.de", sni="de2.node.net")
        self.assertEqual(code, "de")
        self.assertEqual(flag, "🇩🇪")


class TestTiersAndSparklines(unittest.TestCase):
    def test_tiers(self):
        self.assertEqual(classify_tier(50.0, True), "⚡ ULTRA")
        self.assertEqual(classify_tier(120.0, True), "🟢 FAST")
        self.assertEqual(classify_tier(250.0, True), "🟡 NORMAL")
        self.assertEqual(classify_tier(450.0, True), "🔴 SLOW")
        self.assertEqual(classify_tier(50.0, False), "💀 DEAD")

    def test_russian_tier_classification(self):
        self.assertEqual(classify_russian_tier(50.0), "Ультра")
        self.assertEqual(classify_russian_tier(120.0), "Быстрый")
        self.assertEqual(classify_russian_tier(250.0), "Стандарт")
        self.assertEqual(classify_russian_tier(450.0), "Базовый")

    def test_sparklines(self):
        # Empty
        self.assertEqual(make_sparkline([]), "───")
        # Constant
        self.assertEqual(make_sparkline([50.0, 50.0]), "▅▅")
        # Ascending
        spark = make_sparkline([10.0, 50.0, 100.0])
        self.assertEqual(len(spark), 3)
        self.assertEqual(spark[0], " ")
        self.assertEqual(spark[-1], "█")


class TestSecurityTag(unittest.TestCase):
    def test_reality_vision(self):
        cfg = ParsedConfig(
            protocol="vless",
            uuid="1234",
            host="1.2.3.4",
            port=443,
            remark="test",
            security="reality",
            network_type="tcp",
            path="",
            host_header="",
            sni="google.com",
            alpn="",
            fingerprint="chrome",
            public_key="abc",
            short_id="12",
            raw_url="vless://1234@1.2.3.4:443?security=reality&flow=xtls-rprx-vision",
            flow="xtls-rprx-vision",
        )
        tag = get_security_tag(cfg)
        self.assertEqual(tag, "Reality (XTLS-Vision)")

    def test_tls(self):
        cfg = ParsedConfig(
            protocol="trojan",
            uuid="pass",
            host="1.2.3.4",
            port=443,
            remark="test",
            security="tls",
            network_type="tcp",
            path="",
            host_header="",
            sni="google.com",
            alpn="",
            fingerprint="",
            public_key="",
            short_id="",
            raw_url="trojan://pass@1.2.3.4:443",
        )
        tag = get_security_tag(cfg)
        self.assertEqual(tag, "TLS 1.3")


class TestReportGeneration(unittest.TestCase):
    def test_build_report(self):
        cfg = ParsedConfig(
            protocol="vless",
            uuid="1234",
            host="1.2.3.4",
            port=443,
            remark="[Ультра] Германия #1",
            security="reality",
            network_type="tcp",
            path="",
            host_header="",
            sni="test.com",
            alpn="",
            fingerprint="",
            public_key="",
            short_id="",
            raw_url="vless://...",
        )
        res1 = NodeCheckResult(
            config=cfg,
            alive=True,
            latency_ms=45.0,
            tls_ok=True,
            country_code="de",
            country_flag="🇩🇪",
            country_name="Германия",
            quality_tier="⚡ ULTRA",
            jitter_ms=1.2,
            security_tag="Reality (XTLS-Vision)",
            sparkline=" █",
        )
        res2 = NodeCheckResult(
            config=cfg,
            alive=False,
            latency_ms=9999.0,
            tls_ok=False,
            country_code="de",
            country_flag="🇩🇪",
            country_name="Германия",
            quality_tier="💀 DEAD",
            error_msg="Timeout",
        )
        rep = build_health_report([res1, res2])
        self.assertEqual(rep["total"], 2)
        self.assertEqual(rep["alive"], 1)
        self.assertEqual(rep["dead"], 1)
        self.assertEqual(rep["success_rate_pct"], 50.0)
        self.assertEqual(rep["min_ping_ms"], 45.0)
        self.assertEqual(rep["avg_ping_ms"], 45.0)
        self.assertEqual(rep["tiers"]["ultra"], 1)
        self.assertEqual(len(rep["fastest_nodes"]), 1)
        self.assertIn("http_verified", rep)
        self.assertEqual(rep["http_verified"], 0)


class TestExecutableLocators(unittest.TestCase):
    def test_find_sing_box(self):
        from checker import find_sing_box_executable
        sb = find_sing_box_executable()
        # On this environment, Happ sing-box exists
        self.assertTrue(sb is not None and len(sb) > 0)

    def test_find_xray(self):
        from checker import find_xray_executable
        xr = find_xray_executable()
        self.assertTrue(xr is not None and len(xr) > 0)


class TestHttpProbeStructures(unittest.TestCase):
    def test_node_result_http_fields(self):
        cfg = ParsedConfig(
            protocol="vless",
            uuid="1234",
            host="1.2.3.4",
            port=443,
            remark="test",
            security="reality",
            network_type="tcp",
            path="",
            host_header="",
            sni="google.com",
            alpn="",
            fingerprint="",
            public_key="",
            short_id="",
            raw_url="vless://...",
        )
        res = NodeCheckResult(
            config=cfg,
            alive=True,
            latency_ms=50.0,
            tls_ok=True,
            country_code="de",
            country_flag="🇩🇪",
            country_name="Германия",
            quality_tier="⚡ ULTRA",
            http_ok=True,
            http_delay_ms=145.0,
            http_probe_msg="204 OK",
        )
        self.assertTrue(res.http_ok)
        self.assertEqual(res.http_delay_ms, 145.0)
        self.assertIn("[HTTP ✔]", res.display_tag)


if __name__ == "__main__":
    unittest.main()
