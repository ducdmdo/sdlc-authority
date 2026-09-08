from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")


class RepositoryPolicyTest(unittest.TestCase):
    def test_all_actions_are_pinned_to_full_commit(self) -> None:
        for workflow in WORKFLOWS.glob("*.yml"):
            uses_lines = [
                line.strip()
                for line in workflow.read_text(encoding="utf-8").splitlines()
                if line.strip().startswith("uses:") or " uses:" in line
            ]
            with self.subTest(workflow=workflow.name):
                self.assertTrue(uses_lines)
                for line in uses_lines:
                    self.assertRegex(line, PINNED_ACTION)

    def test_authority_workflow_has_fail_closed_controls(self) -> None:
        workflow = (WORKFLOWS / "issue-authority-receipt.yml").read_text(
            encoding="utf-8"
        )
        required = (
            "environment: human-approval",
            "github.ref_protected",
            "github-actions[bot]",
            "github.event_name == 'repository_dispatch'",
            "/actions/runs/",
            "/approvals",
            "can_admins_bypass",
            '"canAdminsBypass": False',
            'env.get("id") == 21443284760',
            "28857207",
            "attestations: write",
            "id-token: write",
            "retention-days: 1",
            "actions/attest-build-provenance",
            "SOURCE_DEPLOY_KEY",
            "SOURCE_COMMITMENT_SALT",
            "bubblewrap=0.9.0-1ubuntu0.1",
            'test "$(command -v bwrap)" = "/usr/bin/bwrap"',
            'test "$(/usr/bin/bwrap --version)" = "bubblewrap 0.9.0"',
            "--unshare-all",
            "private-verification.log",
        )
        for control in required:
            with self.subTest(control=control):
                self.assertIn(control, workflow)
        provision = workflow.index("Provision reviewed isolation dependency")
        private_verify = workflow.index("Verify exact private source")
        self.assertLess(provision, private_verify)

    def test_authority_workflow_binds_exact_environment(self) -> None:
        workflow = (WORKFLOWS / "issue-authority-receipt.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(workflow.count("21443284760"), 3)
        self.assertIn('"environmentId": environment.get("id")', workflow)
        self.assertIn('"environmentId": 21443284760', workflow)
        self.assertIn('"canAdminsBypass": environment.get(', workflow)

    def test_isolation_diagnostic_is_protected_and_secret_free(self) -> None:
        workflow = (WORKFLOWS / "isolation-diagnostic.yml").read_text(
            encoding="utf-8"
        )
        required = (
            "github.ref == 'refs/heads/main'",
            "github.ref_protected",
            "runs-on: ubuntu-24.04",
            "permissions: {}",
            "bubblewrap=0.9.0-1ubuntu0.1",
            "--unshare-all",
            "--unshare-net",
        )
        for control in required:
            with self.subTest(control=control):
                self.assertIn(control, workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("environment:", workflow)

    def test_workflows_do_not_use_dangerous_triggers(self) -> None:
        forbidden = ("pull_request_target:", "issue_comment:")
        for workflow in WORKFLOWS.glob("*.yml"):
            content = workflow.read_text(encoding="utf-8")
            for trigger in forbidden:
                with self.subTest(workflow=workflow.name, trigger=trigger):
                    self.assertNotIn(trigger, content)

    def test_only_authority_workflow_accepts_repository_dispatch(self) -> None:
        for workflow in WORKFLOWS.glob("*.yml"):
            content = workflow.read_text(encoding="utf-8")
            expected = workflow.name == "issue-authority-receipt.yml"
            self.assertEqual("repository_dispatch:" in content, expected)

    def test_authority_workflow_does_not_echo_inputs(self) -> None:
        workflow = (WORKFLOWS / "issue-authority-receipt.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("echo $", workflow)
        self.assertNotIn("set -x", workflow)

    def test_private_identifiers_are_not_public_inputs(self) -> None:
        workflow = (WORKFLOWS / "issue-authority-receipt.yml").read_text(
            encoding="utf-8"
        )
        inputs = workflow.split("permissions: {}", 1)[0]
        for forbidden in ("source_repository", "source_revision", "source_path"):
            self.assertNotIn(forbidden, inputs)

    def test_public_files_do_not_name_private_product_or_repository(self) -> None:
        product = "my" + "sugar"
        forbidden = (product, "/".join(("ducdmdo", product)))
        for path in ROOT.rglob("*"):
            excluded = ".git" in path.parts or "__pycache__" in path.parts
            if not path.is_file() or excluded:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore").lower()
            for token in forbidden:
                with self.subTest(path=path, token=token):
                    self.assertNotIn(token, content)


if __name__ == "__main__":
    unittest.main()
