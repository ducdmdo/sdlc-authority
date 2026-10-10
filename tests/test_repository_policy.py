from __future__ import annotations

import re
import subprocess
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")


class RepositoryPolicyTest(unittest.TestCase):
    def test_every_run_block_parses_as_shell(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            workflow = path.read_text()
            blocks = re.findall(r"(?m)^        run: \|\n"
                r"((?:          .*\n|\n)+)", workflow)
            for block in blocks:
                result = subprocess.run(["bash", "-n"],
                    input=textwrap.dedent(block), text=True,
                    capture_output=True)
                self.assertEqual(result.returncode, 0,
                                 (path.name, result.stderr))

    def test_review_package_and_independent_proof_block_issuance(self) -> None:
        workflow = (WORKFLOWS / "issue-authority-receipt.yml").read_text()
        private = workflow.split("Verify exact private source", 1)[1].split(
            "Reconstruct and validate opaque request", 1)[0]
        required = (
            "SOURCE_REVIEW_PACKAGE: ${{ secrets.SOURCE_REVIEW_PACKAGE }}",
            "SOURCE_INDEPENDENT_VERIFIER: "
            "${{ secrets.SOURCE_INDEPENDENT_VERIFIER }}",
            "python3 scripts/private_review.py prepare",
            "scripts/private_review.py proof",
            '--ro-bind "$review_dir" /review',
            '--bind "$proof_dir" /proof',
            "/usr/bin/python3 /review/verify.py",
            "--clearenv",
            "unset SOURCE_REVIEW_PACKAGE SOURCE_INDEPENDENT_VERIFIER",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, private)
        self.assertLess(private.index("private_review.py prepare"),
                        private.index("unset SOURCE_DEPLOY_KEY"))
        self.assertLess(private.index("unset SOURCE_REVIEW_PACKAGE"),
                        private.index("/review/verify.py"))
        self.assertLess(private.index("private_review.py proof"),
                        private.index("/workspace/.sdlc-authority/verify"))
        candidate = private.split("private_review.py proof", 1)[1]
        self.assertNotIn("--ro-bind \"$review_dir\"", candidate)
        self.assertNotIn("--bind \"$proof_dir\"", candidate)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("always()", workflow)
        self.assertEqual(private.count("--clearenv"), 2)
        self.assertEqual(private.count("--unshare-net"), 2)
        self.assertEqual(private.count("timeout 240"), 2)

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
            "sudo --non-interactive /usr/bin/bwrap",
            'sudo chgrp 0 "$source_dir"',
            'chmod 0750 "$source_dir"',
            "--unshare-all",
            "private-verification.log",
        )
        for control in required:
            with self.subTest(control=control):
                self.assertIn(control, workflow)
        provision = workflow.index("Provision reviewed isolation dependency")
        private_verify = workflow.index("Verify exact private source")
        self.assertLess(provision, private_verify)
        private_step = workflow[private_verify:]
        invocation = (
            "sudo --non-interactive /usr/bin/bwrap \\\n"
            "            --unshare-all \\\n"
            "            --unshare-net"
        )
        self.assertIn(invocation, private_step)

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
            "sudo --non-interactive /usr/bin/bwrap",
            'probe_dir="$(mktemp -d)"',
            'sudo chgrp 0 "$probe_dir"',
            'chmod 0750 "$probe_dir"',
            '--ro-bind "$probe_dir" /workspace',
            "/workspace/verify",
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
