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

    def test_percent_encoded_remarks(self):
        # Russian word "Россия" percent-encoded
        code, flag, name = detect_country_info("%D0%A0%D0%BE%D1%81%D1%81%D0%B8%D1%8F")
        self.assertEqual(code, "ru")
        self.assertEqual(flag, "🇷🇺")
        self.assertEqual(name, "Россия")

        # Percent-encoded German flag %F0%9F%87%A9%F0%9F%87%AA
        code, flag, name = detect_country_info("%F0%9F%87%A9%F0%9F%87%AA%20Server")
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
    def test_find_sing_box_behavior(self):
        from checker import find_sing_box_executable
        import unittest.mock as mock

        sb = find_sing_box_executable()
        if sb is not None:
            self.assertTrue(len(sb) > 0)

        with mock.patch("os.path.isfile", return_value=False), mock.patch("shutil.which", return_value=None):
            self.assertIsNone(find_sing_box_executable())

        with mock.patch.dict("os.environ", {"SING_BOX_PATH": "/custom/sing-box"}):
            with mock.patch("os.path.isfile", side_effect=lambda p: p == "/custom/sing-box"):
                self.assertEqual(find_sing_box_executable(), "/custom/sing-box")

    def test_find_xray_behavior(self):
        from checker import find_xray_executable
        import unittest.mock as mock

        xr = find_xray_executable()
        if xr is not None:
            self.assertTrue(len(xr) > 0)

        with mock.patch("os.path.isfile", return_value=False), mock.patch("shutil.which", return_value=None):
            self.assertIsNone(find_xray_executable())

        with mock.patch.dict("os.environ", {"XRAY_PATH": "/custom/xray"}):
            with mock.patch("os.path.isfile", side_effect=lambda p: p == "/custom/xray"):
                self.assertEqual(find_xray_executable(), "/custom/xray")


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


class TestConfigParsing(unittest.TestCase):
    def test_env_empty_and_default_helpers(self):
        import os
        from config import _get_bool, _get_float, _get_int, _get_str

        # Empty string handling
        os.environ["TEST_EMPTY"] = ""
        self.assertEqual(_get_str("TEST_EMPTY", "default_val"), "default_val")
        self.assertEqual(_get_int("TEST_EMPTY", 42), 42)
        self.assertEqual(_get_float("TEST_EMPTY", 3.14), 3.14)
        self.assertTrue(_get_bool("TEST_EMPTY", True))
        self.assertFalse(_get_bool("TEST_EMPTY", False))

        # Whitespace handling
        os.environ["TEST_WS"] = "   "
        self.assertEqual(_get_str("TEST_WS", "fallback"), "fallback")
        self.assertEqual(_get_int("TEST_WS", 10), 10)
        self.assertEqual(_get_float("TEST_WS", 1.5), 1.5)

        # Malformed handling
        os.environ["TEST_BAD_NUM"] = "not_a_number"
        self.assertEqual(_get_int("TEST_BAD_NUM", 99), 99)
        self.assertEqual(_get_float("TEST_BAD_NUM", 9.9), 9.9)

        # Valid values
        os.environ["TEST_VALID_INT"] = " 123 "
        self.assertEqual(_get_int("TEST_VALID_INT", 0), 123)
        os.environ["TEST_VALID_FLOAT"] = " 4.56 "
        self.assertEqual(_get_float("TEST_VALID_FLOAT", 0.0), 4.56)
        os.environ["TEST_VALID_BOOL"] = "false"
        self.assertFalse(_get_bool("TEST_VALID_BOOL", True))

    def test_config_import_with_gh_actions_empty_secrets(self):
        import os
        import importlib
        import config

        orig_env = os.environ.copy()
        try:
            # Simulate GitHub Actions runner with empty secrets
            os.environ["TG_API_ID"] = ""
            os.environ["TG_API_HASH"] = ""
            os.environ["TG_SESSION_STRING"] = ""
            os.environ["VPN_SOURCE_CHANNELS"] = ""
            os.environ["TG_BOT_TOKEN"] = ""
            os.environ["TG_NOTIFY_TOKEN"] = ""
            os.environ["TG_NOTIFY_CHANNEL"] = ""

            reloaded_config = importlib.reload(config)
            self.assertEqual(reloaded_config.TG_API_ID, 0)
            self.assertEqual(reloaded_config.TG_API_HASH, "")
            self.assertEqual(reloaded_config.TG_BOT_TOKEN, reloaded_config.DEFAULT_BOT_TOKEN)
            self.assertEqual(reloaded_config.TG_NOTIFY_CHANNEL, "@notavless")
            self.assertEqual(reloaded_config.VPN_SOURCE_CHANNELS, [])
        finally:
            os.environ.clear()
            os.environ.update(orig_env)
            importlib.reload(config)


class TestProtocolParsing(unittest.TestCase):
    def test_vless_parsing_reality(self):
        from protocols import parse_vless_url

        url = (
            "vless://98765432-1234-1234-1234-123456789abc@198.51.100.1:443"
            "?security=reality&sni=dl.google.com&fp=chrome&pbk=fakePub123&sid=1234"
            "&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%A9%F0%9F%87%AA%20Frankfurt"
        )
        cfg = parse_vless_url(url, added_by="@tester")
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.protocol, "vless")
        self.assertEqual(cfg.uuid, "98765432-1234-1234-1234-123456789abc")
        self.assertEqual(cfg.host, "198.51.100.1")
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.security, "reality")
        self.assertEqual(cfg.sni, "dl.google.com")
        self.assertEqual(cfg.fingerprint, "chrome")
        self.assertEqual(cfg.public_key, "fakePub123")
        self.assertEqual(cfg.short_id, "1234")
        self.assertEqual(cfg.flow, "xtls-rprx-vision")
        self.assertEqual(cfg.remark, "🇩🇪 Frankfurt")
        self.assertEqual(cfg.added_by, "@tester")

    def test_vless_rejections(self):
        from protocols import parse_vless_url
        from checker import build_sing_box_outbound, build_xray_outbound
        from protocols import ParsedConfig

        # Invalid port
        self.assertIsNone(parse_vless_url("vless://user@host:0"))
        self.assertIsNone(parse_vless_url("vless://user@host:99999"))
        # Iranian host & Iranian SNI
        self.assertIsNone(parse_vless_url("vless://98765432-1234-1234-1234-123456789abc@server.ir:443"))
        self.assertIsNone(parse_vless_url("vless://98765432-1234-1234-1234-123456789abc@1.2.3.4:443?security=tls&sni=node.soft10.ir"))
        # Truncated / corrupt transport (e.g. ellipsis '…')
        self.assertIsNone(parse_vless_url("vless://98765432-1234-1234-1234-123456789abc@1.2.3.4:443?type=…&security=reality&pbk=abc"))
        # Spam query filter (case-insensitive)
        self.assertIsNone(parse_vless_url("vless://98765432-1234-1234-1234-123456789abc@server.com:443?fear_config=1"))
        self.assertIsNone(parse_vless_url("vless://98765432-1234-1234-1234-123456789abc@server.com:443?path=/?VPsave"))
        # Outbound builder guards against unknown transport
        bad_cfg = ParsedConfig(
            protocol="vless", uuid="u1", host="1.2.3.4", port=443,
            remark="bad", security="reality", network_type="…", path="",
            host_header="", sni="s.com", alpn="", fingerprint="chrome",
            public_key="abc", short_id="", raw_url="vless://...",
        )
        self.assertIsNone(build_sing_box_outbound(bad_cfg))
        self.assertIsNone(build_xray_outbound(bad_cfg))

    def test_trojan_parsing(self):
        from protocols import parse_trojan_url

        url = "trojan://mypassword@example.com:443?security=tls&sni=example.com#MyTrojan"
        cfg = parse_trojan_url(url)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.protocol, "trojan")
        self.assertEqual(cfg.uuid, "mypassword")
        self.assertEqual(cfg.host, "example.com")
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.sni, "example.com")
        self.assertEqual(cfg.remark, "MyTrojan")

    def test_hysteria2_parsing(self):
        from protocols import parse_hysteria2_url

        url1 = "hysteria2://myauth@example.com:8443?sni=example.com#Hy2Node"
        cfg1 = parse_hysteria2_url(url1)
        self.assertIsNotNone(cfg1)
        self.assertEqual(cfg1.protocol, "hysteria2")
        self.assertEqual(cfg1.uuid, "myauth")
        self.assertEqual(cfg1.port, 8443)

        url2 = "hy2://myauth@example.com:8443?sni=example.com#Hy2Node"
        cfg2 = parse_hysteria2_url(url2)
        self.assertIsNotNone(cfg2)
        self.assertEqual(cfg2.protocol, "hysteria2")

    def test_extract_and_sanitize_urls(self):
        from protocols import extract_all_proxy_urls

        raw_text = (
            "Here are configs:\n"
            "*vless://98765432-1234-1234-1234-123456789abc@1.2.3.4:443?security=reality#Node1*\n"
            "_trojan://pass@5.6.7.8:443?security=tls#Node2_\n"
            "hy2://pass@9.10.11.12:443#Node3,\n"
        )
        urls = extract_all_proxy_urls(raw_text)
        self.assertEqual(len(urls), 3)
        self.assertFalse(urls[0].endswith("*"))
        self.assertFalse(urls[1].endswith("_"))
        self.assertFalse(urls[2].endswith(","))

    def test_decode_base64_subscription(self):
        import base64
        from protocols import decode_maybe_base64

        plain = "vless://98765432-1234-1234-1234-123456789abc@1.2.3.4:443?security=reality#Test\n"
        b64 = base64.b64encode(plain.encode("utf-8")).decode("ascii")
        decoded = decode_maybe_base64(b64)
        self.assertIn("vless://", decoded)


class TestDeduplicationAndNormalization(unittest.TestCase):
    def test_dedupe_configs(self):
        from refresh_vless_repo import dedupe_configs
        from protocols import ParsedConfig

        cfg1 = ParsedConfig(
            protocol="vless", uuid="u1", host="1.1.1.1", port=443,
            remark="r1", security="reality", network_type="tcp", path="",
            host_header="", sni="s1", alpn="", fingerprint="", public_key="",
            short_id="", raw_url="vless://u1@1.1.1.1:443",
        )
        cfg2 = ParsedConfig(
            protocol="vless", uuid="u2", host="1.1.1.1", port=443,
            remark="r2", security="reality", network_type="tcp", path="",
            host_header="", sni="s1", alpn="", fingerprint="", public_key="",
            short_id="", raw_url="vless://u2@1.1.1.1:443",
        )
        cfg3 = ParsedConfig(
            protocol="vless", uuid="u3", host="1.1.1.1", port=443,
            remark="r3", security="reality", network_type="tcp", path="",
            host_header="", sni="s1", alpn="", fingerprint="", public_key="",
            short_id="", raw_url="vless://u3@1.1.1.1:443",
        )
        # Duplicate of cfg1
        dup = ParsedConfig(
            protocol="vless", uuid="u1", host="1.1.1.1", port=443,
            remark="r1_diff_remark", security="reality", network_type="tcp", path="",
            host_header="", sni="s1", alpn="", fingerprint="", public_key="",
            short_id="", raw_url="vless://u1@1.1.1.1:443",
        )

        deduped = dedupe_configs([cfg1, dup, cfg2, cfg3], max_per_host_port=2)
        # Exact duplicate filtered out, and max_per_host_port limits total to 2
        self.assertEqual(len(deduped), 2)
        self.assertEqual(deduped[0].uuid, "u1")
        self.assertEqual(deduped[1].uuid, "u2")

    def test_normalize_urls_sni_injection(self):
        from refresh_vless_repo import normalize_urls
        from protocols import ParsedConfig

        cfg = ParsedConfig(
            protocol="vless", uuid="u1", host="1.2.3.4", port=443,
            remark="[Ультра] Германия #1 NOTAVLESS", security="reality", network_type="tcp",
            path="", host_header="", sni="sni.example.com", alpn="", fingerprint="",
            public_key="", short_id="", raw_url="vless://u1@1.2.3.4:443?type=tcp",
        )
        normalized = normalize_urls([cfg])
        self.assertEqual(len(normalized), 1)
        self.assertIn("sni=sni.example.com", normalized[0])
        self.assertIn("NOTAVLESS", normalized[0])

    def test_split_lte_wifi(self):
        from refresh_vless_repo import split_lte_wifi
        from protocols import ParsedConfig

        lte_cfg = ParsedConfig(
            protocol="vless", uuid="u1", host="1.2.3.4", port=443,
            remark="Megafon RU Mobile", security="reality", network_type="tcp",
            path="", host_header="", sni="", alpn="", fingerprint="",
            public_key="", short_id="", raw_url="vless://...",
        )
        wifi_cfg = ParsedConfig(
            protocol="vless", uuid="u2", host="5.6.7.8", port=443,
            remark="Frankfurt Home", security="reality", network_type="tcp",
            path="", host_header="", sni="", alpn="", fingerprint="",
            public_key="", short_id="", raw_url="vless://...",
        )
        lte, wifi = split_lte_wifi([lte_cfg, wifi_cfg])
        self.assertEqual(len(lte), 1)
        self.assertEqual(lte[0].uuid, "u1")
        self.assertEqual(len(wifi), 1)
        self.assertEqual(wifi[0].uuid, "u2")

    def test_select_diverse_fastest_limits_cluster(self):
        from refresh_vless_repo import select_diverse_fastest
        from protocols import ParsedConfig

        cfgs = [
            ParsedConfig(
                protocol="vless", uuid="sameuuid12345678", host=f"198.51.100.{i}", port=443,
                remark="Germany", security="reality", network_type="tcp", path="",
                host_header="", sni="s.com", alpn="", fingerprint="chrome",
                public_key="abc", short_id="", raw_url=f"vless://u@198.51.100.{i}:443",
            )
            for i in range(1, 7)
        ] + [
            ParsedConfig(
                protocol="vless", uuid="otheruuid1234567", host="203.0.113.10", port=443,
                remark="Netherlands", security="reality", network_type="tcp", path="",
                host_header="", sni="n.com", alpn="", fingerprint="chrome",
                public_key="abc", short_id="", raw_url="vless://u2@203.0.113.10:443",
            )
        ]
        lats = {(c.protocol, c.host, c.port): 50.0 for c in cfgs}
        picked = select_diverse_fastest(cfgs, lats, limit=3, max_per_cluster=2)
        self.assertEqual(len(picked), 3)
        hosts = [c.host for c in picked]
        self.assertIn("203.0.113.10", hosts)


class TestGitPublicationLogic(unittest.TestCase):
    def test_push_if_changed_empty(self):
        from refresh_vless_repo import push_if_changed

        status = push_if_changed([])
        self.assertEqual(status, "skip: no changed files")


class TestRKPAndHardcoreIntegration(unittest.TestCase):
    def test_extract_yaml_and_nested_base64_preserves_remarks(self):
        import base64
        from protocols import extract_all_proxy_urls

        raw_vless = "vless://11111111-1111-1111-1111-111111111111@198.51.100.7:443?security=reality&sni=google.com&pbk=abc&type=tcp#Super%20RU%20Node"
        b64_payload = base64.b64encode(raw_vless.encode("utf-8")).decode("ascii")
        urls = extract_all_proxy_urls(b64_payload)
        self.assertTrue(any("#Super%20RU%20Node" in u for u in urls), urls)

        clash_yaml = (
            "proxies:\n"
            "  - name: Berlin Reality\n"
            "    type: vless\n"
            "    server: 203.0.113.55\n"
            "    port: 443\n"
            "    uuid: 22222222-2222-2222-2222-222222222222\n"
            "    tls: true\n"
            "    servername: ya.ru\n"
            "    reality-opts:\n"
            "      public-key: pub123\n"
            "      short-id: ab12\n"
        )
        yaml_urls = extract_all_proxy_urls(clash_yaml)
        self.assertTrue(any("203.0.113.55:443" in u and "Berlin" in u for u in yaml_urls), yaml_urls)

    def test_whitelist_asn_detection(self):
        from checker import is_whitelist_asn, load_whitelist_asns

        asns = load_whitelist_asns()
        self.assertGreater(len(asns), 100)
        hit, org = is_whitelist_asn("AS9123 Timeweb Ltd.")
        self.assertTrue(hit)
        self.assertIn("Timeweb", org)
        miss, _ = is_whitelist_asn("AS15169 Google LLC")
        self.assertFalse(miss)

    def test_compute_node_grade(self):
        from checker import NodeCheckResult, compute_node_grade
        from protocols import ParsedConfig

        cfg = ParsedConfig(
            protocol="vless", uuid="u1", host="198.51.100.1", port=443,
            remark="DE", security="reality", network_type="tcp",
            path="", host_header="", sni="google.com", alpn="", fingerprint="chrome",
            public_key="abc", short_id="", raw_url="vless://...",
        )
        s_plus = NodeCheckResult(
            config=cfg, alive=True, latency_ms=45.0, tls_ok=True,
            country_code="de", country_flag="🇩🇪", country_name="Германия",
            quality_tier="⚡ ULTRA", http_ok=True, http_delay_ms=110.0,
            speed_mbps=42.0, multi_ok=3, multi_total=3, wl_asn=True,
        )
        self.assertEqual(compute_node_grade(s_plus), "🏆 S+")

        dead = NodeCheckResult(
            config=cfg, alive=False, latency_ms=9999.0, tls_ok=False,
            country_code="xx", country_flag="🌐", country_name="Неизвестно",
            quality_tier="💀 DEAD",
        )
        self.assertEqual(compute_node_grade(dead), "💀 D")

    def test_select_sources_for_run_rotation(self):
        from refresh_vless_repo import _select_sources_for_run

        items = [("https://priority.example/1.txt", "@serega")] + [
            (f"https://rkp.example/{i}.txt", "@RKP_channel") for i in range(500)
        ]
        priority, bulk = _select_sources_for_run(items, max_bulk_per_run=50)
        self.assertEqual(priority, [("https://priority.example/1.txt", "@serega")])
        self.assertEqual(len(bulk), 50)
        all_priority, all_bulk = _select_sources_for_run(items, max_bulk_per_run=0)
        self.assertEqual(len(all_priority), 1)
        self.assertEqual(len(all_bulk), 500)


if __name__ == "__main__":
    unittest.main()
