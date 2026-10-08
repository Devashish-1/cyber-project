import unittest

import yaml

from app.runner import ADAPTERS_PATH, build_command


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


if __name__ == "__main__":
    unittest.main()
