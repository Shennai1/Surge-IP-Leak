"""Offline regression tests for normalization, source parsing and publication."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import build


def manifest(**sites):
    return json.dumps({"sites": sites})


class RuleTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(build.normalize_domain("IPINFO.IO."), "ipinfo.io")
        self.assertEqual(build.normalize_domain("例子.测试"), "xn--fsqu00a.xn--0zwm56d")
        rules = build.parse_supplement("DOMAIN,IP.EXAMPLE.COM.\n")
        self.assertEqual(rules, [build.Rule("DOMAIN", "ip.example.com")])

    def test_semantic_deduplication_and_label_boundaries(self):
        rules = build.parse_supplement(
            "DOMAIN-SUFFIX,aapq.net\n"
            "DOMAIN-SUFFIX,aapq.net\n"
            "DOMAIN-SUFFIX,child.aapq.net\n"
            "DOMAIN,fcd09628a76x.aapq.net\n"
            "DOMAIN,aapq.net\n"
            "DOMAIN,not-aapq.net\n"
            "DOMAIN,ip.example.com\n"
        )
        self.assertEqual(
            build.semantic_deduplicate(rules),
            (["ip.example.com", "not-aapq.net"], ["aapq.net"]),
        )
        self.assertFalse(build.suffix_covers("aapq.net.attacker.example", {"aapq.net"}))

    def test_supplement_rejects_invalid_rows(self):
        for row in (
            "", "# only comments", "aapq.net", "DOMAIN-SUFFIX,.aapq.net",
            "DOMAIN,*.example.com", "DOMAIN,example.com,Proxy", "IP-CIDR,1.2.3.0/24",
            "DOMAIN,https://example.com", "DOMAIN,1.2.3.4", "DOMAIN,foo..example",
            "DOMAIN,-foo.example", "DOMAIN,foo_bar.example", "DOMAIN,foo:443.example",
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                build.parse_supplement(row)

    def test_includes_full_rules_and_attribute_selectors(self):
        sources = {
            "root": "include:child @keep @-drop\nfull:ROOT.EXAMPLE.\n",
            "child": "full:exact.example @keep\nsuffix.example @keep\n"
                     "drop.example @keep @drop\nother.example @other\n",
        }
        with patch.object(build, "fetch", side_effect=lambda url: sources[url.rsplit("/", 1)[1]]):
            actual = build.V2FlyResolver().resolve("root")
        self.assertEqual(
            {(rule.kind, rule.domain) for rule in actual},
            {("DOMAIN", "exact.example"), ("DOMAIN-SUFFIX", "suffix.example"),
             ("DOMAIN", "root.example")},
        )

    def test_include_cycle_is_rejected(self):
        with patch.object(build, "fetch", return_value="include:loop"), self.assertRaises(ValueError):
            build.V2FlyResolver().resolve("loop")


class ProbeTests(unittest.TestCase):
    def test_only_visible_probe_hosts_are_collected(self):
        text = manifest(
            active={"site": "provider.example", "provider": "ignored.example",
                    "v4": "https://V4.provider.example./image.png",
                    "v6": "http://v6.provider.example:8080/image.png"},
            hidden={"hide": True, "v4": "https://hidden.example/a",
                    "v6": "https://hidden6.example/a"},
        )
        self.assertEqual(
            build.parse_ipv6_probes(text),
            [build.Rule("DOMAIN", "v4.provider.example"),
             build.Rule("DOMAIN", "v6.provider.example")],
        )

    def test_invalid_manifest_fails_closed(self):
        for text in ("not json", "[]", "{}", '{"sites": []}', manifest(),
                     manifest(hidden={"hide": True}), manifest(bad={"hide": "false"}),
                     manifest(bad=[]), manifest(bad={"v4": "https://v4.example/"})):
            with self.subTest(text=text), self.assertRaises(ValueError):
                build.parse_ipv6_probes(text)

    def test_invalid_probe_urls_are_rejected(self):
        for url in ("ftp://probe.example/a", "https://1.2.3.4/a", "https://[::1]/a",
                    "https://user:secret@probe.example/a", "https://bad_host.example/a",
                    "https://probe.example:bad/a", "https://probe.example:99999/a",
                    "https://probe.example/white space", "//probe.example/a", ""):
            with self.subTest(url=url), self.assertRaises(ValueError):
                build.parse_ipv6_probes(manifest(bad={"v4": url, "v6": "https://v6.example/"}))

    def test_parent_suffix_removes_redundant_probes(self):
        probes = build.parse_ipv6_probes(manifest(
            mirror={"v4": "https://v4.test-ipv6.example/a", "v6": "https://v6.test-ipv6.example/a"}
        ))
        self.assertEqual(
            build.semantic_deduplicate([*probes, build.Rule("DOMAIN-SUFFIX", "test-ipv6.example")]),
            ([], ["test-ipv6.example"]),
        )


class BuildTests(unittest.TestCase):
    def fake_fetch(self, url):
        if url.startswith(build.V2FLY_DATA_BASE):
            return "\n".join(f"fixture{index}.example" for index in range(110))
        if url == build.IPV6_PROBES_URL:
            return manifest(probe={"v4": "https://v4.probe.example/a", "v6": "https://v6.probe.example/a"})
        return "DOMAIN-SUFFIX,external.example\n"

    def test_build_preserves_curated_additions_and_is_stable(self):
        with patch.object(build, "fetch", side_effect=self.fake_fetch):
            first = build.build()
            second = build.build()
        self.assertEqual(first, second)
        self.assertIn("DOMAIN-SUFFIX,aapq.net\n", first)
        self.assertIn("DOMAIN,cdnperf-rum.cdnetworks.net\n", first)
        self.assertIn("DOMAIN,v4.probe.example\n", first)

    def test_supplement_path_is_independent_of_working_directory(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            try:
                os.chdir(temporary)
                with patch.object(build, "fetch", side_effect=self.fake_fetch):
                    self.assertIn("DOMAIN-SUFFIX,aapq.net\n", build.build())
            finally:
                os.chdir(original)

    def test_missing_supplement_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(build, "SUPPLEMENT", Path(temporary) / "missing.list"), \
                 patch.object(build, "fetch", side_effect=self.fake_fetch), \
                 self.assertRaises(FileNotFoundError):
                build.build()

    def test_failed_source_does_not_overwrite_published_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "IPLeak.list"
            output.write_text("previous good output\n", encoding="utf-8")
            with patch.object(build.sys, "argv", ["build.py", "--output", str(output)]), \
                 patch.object(build, "fetch", side_effect=ValueError("malformed upstream")), \
                 self.assertRaises(ValueError):
                build.main()
            self.assertEqual(output.read_text(encoding="utf-8"), "previous good output\n")

    def test_order_and_attributes_do_not_change_output(self):
        rules = [build.Rule("DOMAIN", "exact.example", frozenset({"one"})),
                 build.Rule("DOMAIN-SUFFIX", "suffix.example"),
                 build.Rule("DOMAIN", "sub.suffix.example")]
        self.assertEqual(
            build.render(*build.semantic_deduplicate(rules)),
            build.render(*build.semantic_deduplicate(list(reversed(rules)) + rules)),
        )


if __name__ == "__main__":
    unittest.main()
