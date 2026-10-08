import unittest
import json
import tempfile
from pathlib import Path

import yaml

from app.runner import (
    ADAPTERS_PATH,
    FFUF_WORDLIST_RUNNER_PATH,
    build_command,
    parse_amass_names,
    parse_spiderfoot_hosts,
    parse_theharvester_hosts,
    write_dnsrecon_output,
    write_dnsx_output,
    write_massdns_output,
)


BASE_URL = "https://authorized.example.test/?id=1"


class AdapterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapters = yaml.safe_load(ADAPTERS_PATH.read_text(encoding="utf-8"))["adapters"]

    def command_for(self, tool_id):
        return build_command(
            tool_id,
            BASE_URL,
            self.adapters[tool_id],
            excluded_paths=["/logout", "/payments"],
            dns_resolver="1.1.1.1:53",
        )

    def test_every_configured_adapter_builds_a_command(self):
        for tool_id in sorted(self.adapters):
            with self.subTest(tool_id=tool_id):
                command = self.command_for(tool_id)
                self.assertIsInstance(command, list)
                self.assertTrue(command)
                self.assertTrue(all(isinstance(value, str) for value in command))
                empty_indexes = [index for index, value in enumerate(command) if not value]
                self.assertEqual(
                    empty_indexes,
                    [command.index("--status-codes-blacklist") + 1]
                    if "--status-codes-blacklist" in command else [],
                )

    def test_every_adapter_image_is_pinned_by_sha256_digest(self):
        for tool_id, adapter in sorted(self.adapters.items()):
            with self.subTest(tool_id=tool_id):
                self.assertRegex(
                    adapter.get("image", ""),
                    r"^[^\s@]+@sha256:[0-9a-f]{64}$",
                )

    def test_sqlmap_remains_low_risk_and_non_destructive(self):
        command = self.command_for("sqlmap-controlled")
        joined = " ".join(command)
        self.assertIn("--level 1", joined)
        self.assertIn("--risk 1", joined)
        self.assertIn("--threads 1", joined)
        for forbidden in ("--os-shell", "--os-pwn", "--dump", "--passwords", "--file-write"):
            self.assertNotIn(forbidden, command)

    def test_nuclei_uses_only_reviewed_non_interactive_templates(self):
        adapter = self.adapters["nuclei-reviewed"]
        command = self.command_for("nuclei-reviewed")
        template_values = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "-t"]
        self.assertEqual(template_values, [f"/templates/{path}" for path in adapter["templates"]])
        self.assertIn("-disable-unsigned-templates", command)
        self.assertIn("-no-interactsh", command)
        self.assertEqual(command[command.index("-rate-limit") + 1], "5")

    def test_zap_profiles_have_explicit_time_bounds(self):
        expected = {"zap-passive": "3", "zap-baseline": "5", "zap-full": "15"}
        for tool_id, minutes in expected.items():
            with self.subTest(tool_id=tool_id):
                command = self.command_for(tool_id)
                self.assertEqual(command[command.index("-T") + 1], minutes)
                self.assertIn("-s", command)

    def test_dns_adapters_require_an_approved_resolver(self):
        for tool_id in ("dnsx", "dnsrecon"):
            with self.subTest(tool_id=tool_id):
                with self.assertRaises(ValueError):
                    build_command(tool_id, BASE_URL, self.adapters[tool_id], [], None)

    def test_active_discovery_commands_remain_rate_limited(self):
        checks = {
            "httpx": ("-rate-limit", "5"),
            "naabu": ("-rate", "50"),
            "katana": ("-rate-limit", "5"),
            "ffuf": ("-rate", "5"),
            "feroxbuster": ("--rate-limit", "4"),
            "arjun": ("--rate-limit", "5"),
        }
        for tool_id, (flag, maximum) in checks.items():
            with self.subTest(tool_id=tool_id):
                command = self.command_for(tool_id)
                self.assertEqual(command[command.index(flag) + 1], maximum)

    def test_content_discovery_rejects_excluded_wordlist_routes(self):
        candidate = next(
            line.strip().lstrip("/")
            for line in FFUF_WORDLIST_RUNNER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        for tool_id in ("ffuf", "gobuster", "feroxbuster"):
            with self.subTest(tool_id=tool_id, excluded=candidate):
                with self.assertRaisesRegex(ValueError, "intersects excluded path"):
                    build_command(
                        tool_id,
                        BASE_URL,
                        self.adapters[tool_id],
                        excluded_paths=[f"/{candidate}"],
                        dns_resolver="1.1.1.1:53",
                    )

    def test_schemathesis_receives_every_excluded_path(self):
        command = self.command_for("schemathesis")
        exclusions = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "--exclude-path"
        ]
        self.assertEqual(exclusions, ["/logout", "/payments"])

    def test_amass_parser_rejects_suffix_confusion(self):
        malicious_only = "api.authorized.example.test.evil.invalid\nnotauthorized.example.test\n"
        self.assertEqual(parse_amass_names(malicious_only, "authorized.example.test"), [])
        scoped = "authorized.example.test\nAPI.AUTHORIZED.EXAMPLE.TEST.\n"
        self.assertEqual(
            parse_amass_names(scoped, "authorized.example.test"),
            ["api.authorized.example.test", "authorized.example.test"],
        )

    def test_theharvester_parser_keeps_only_valid_scoped_hosts(self):
        payload = {"hosts": [
            "api.authorized.example.test:443",
            "api.authorized.example.test.evil.invalid",
            "notauthorized.example.test",
            "bad_label.authorized.example.test",
            123,
        ]}
        self.assertEqual(
            parse_theharvester_hosts(payload, "authorized.example.test"),
            ["api.authorized.example.test"],
        )

    def test_spiderfoot_parser_requires_crt_module_type_and_scope(self):
        payload = [
            {"module": "sfp_crt", "type": "Internet Name", "data": "*.api.authorized.example.test"},
            {"module": "sfp_dns", "type": "Internet Name", "data": "dns.authorized.example.test"},
            {"module": "sfp_crt", "type": "IP Address", "data": "other.authorized.example.test"},
            {"module": "sfp_crt", "type": "Domain Name", "data": "api.authorized.example.test.evil.invalid"},
        ]
        self.assertEqual(
            parse_spiderfoot_hosts(payload, "authorized.example.test"),
            ["api.authorized.example.test"],
        )

    def test_dnsx_writer_rejects_unexpected_hosts(self):
        raw = b'\n'.join([
            json.dumps({"host": "authorized.example.test", "a": ["192.0.2.10"]}).encode(),
            json.dumps({"host": "evil.invalid", "a": ["192.0.2.66"]}).encode(),
        ])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dnsx.json"
            write_dnsx_output(raw, output, "authorized.example.test")
            results = json.loads(output.read_text())["results"]
        self.assertEqual([item["host"] for item in results], ["authorized.example.test"])

    def test_massdns_writer_rejects_unexpected_hosts(self):
        def record(host, address):
            return json.dumps({
                "name": host,
                "type": "A",
                "data": {"answers": [{"type": "A", "data": address, "ttl": 60}]},
            })
        raw = (record("authorized.example.test", "192.0.2.10") + "\n" + record("evil.invalid", "192.0.2.66")).encode()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "massdns.json"
            write_massdns_output(raw, output, "authorized.example.test")
            results = json.loads(output.read_text())["results"]
        self.assertEqual([item["host"] for item in results], ["authorized.example.test"])

    def test_dnsrecon_writer_rejects_out_of_scope_suffixes(self):
        payload = [
            {"type": "A", "name": "api.authorized.example.test", "address": "192.0.2.10"},
            {"type": "A", "name": "api.authorized.example.test.evil.invalid", "address": "192.0.2.66"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "dnsrecon-raw.json"
            output = Path(directory) / "dnsrecon.json"
            raw.write_text(json.dumps(payload), encoding="utf-8")
            write_dnsrecon_output(raw, output, "authorized.example.test")
            results = json.loads(output.read_text())["results"]
        self.assertEqual([item["host"] for item in results], ["api.authorized.example.test"])


if __name__ == "__main__":
    unittest.main()
