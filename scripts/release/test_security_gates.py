"""Keep the named SCA and isolated DAST release gates fail closed."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/ci.yml").read_text()
DELIVERY = (ROOT / ".github/workflows/delivery.yml").read_text()


def job(name: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", CI)
    if not match:
        raise AssertionError(f"missing workflow job: {name}")
    return match.group(1)


class SecurityGateWorkflowTests(unittest.TestCase):
    def test_sca_is_named_complete_and_release_blocking(self):
        sca = job("vulnerability-scan")
        self.assertIn("name: SCA (source dependencies)", sca)
        self.assertIn("govulncheck production and application fixture source modules", sca)
        self.assertIn("npm audit --audit-level=high", sca)
        self.assertIn("name: sca-results", sca)
        release = job("auto-release")
        self.assertRegex(release, r"needs: \[[^\]]*vulnerability-scan[^\]]*\]")
        self.assertIn("name: Release SCA and artifact verification", DELIVERY)
        for scanner in ("grype", "syft", "govulncheck"):
            self.assertIn(scanner, DELIVERY)

    def test_dast_is_pinned_isolated_and_release_blocking(self):
        dast = job("dast")
        self.assertIn("name: DAST (OWASP ZAP baseline)", dast)
        self.assertRegex(dast, r"uses: zaproxy/action-baseline@[0-9a-f]{40}")
        self.assertRegex(dast, r"docker_name: ghcr\.io/zaproxy/zaproxy:stable@sha256:[0-9a-f]{64}")
        self.assertIn("rules_file_name: .zap/rules.tsv", dast)
        self.assertIn("target: http://127.0.0.1:18081", dast)
        self.assertIn("docker run -d --name veyport-dast", dast)
        self.assertIn("fail_action: true", dast)
        self.assertIn("allow_issue_writing: false", dast)
        self.assertIn("if: always()", dast)
        for forbidden in ("secrets.VEYPORT", "veyport.yiucloud.com", "E2E_PASSWORD", "API_TOKEN"):
            self.assertNotIn(forbidden, dast)
        release = job("auto-release")
        self.assertRegex(release, r"needs: \[[^\]]*dast[^\]]*\]")

    def test_every_current_zap_disposition_is_reviewed(self):
        rules = (ROOT / ".zap/rules.tsv").read_text().splitlines()
        self.assertTrue(rules)
        for line in rules:
            fields = line.split("\t", 2)
            self.assertEqual(len(fields), 3)
            self.assertRegex(fields[0], r"^\d+$")
            self.assertEqual(fields[1], "INFO")
            self.assertIn("reviewed 2026-10-29", fields[2])


if __name__ == "__main__":
    unittest.main()
