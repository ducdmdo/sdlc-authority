from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import re
import tempfile
import textwrap
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
OWNER = {"id": 28857207, "login": "ducdmdo", "type": "User"}
ENVIRONMENT_ID = 21443284760


def approval_script() -> str:
    workflow = (ROOT / ".github/workflows/issue-authority-receipt.yml").read_text()
    block = workflow.split("Bind protected environment approval", 1)[1]
    source = re.search(r"python3 - <<'PY'\n(.*?)\n          PY", block, re.S)
    if source is None:
        raise AssertionError("Actual workflow approval program is missing")
    return textwrap.dedent(source.group(1))


def environment() -> dict:
    return {
        "id": ENVIRONMENT_ID, "name": "human-approval",
        "can_admins_bypass": False,
        "deployment_branch_policy": {
            "protected_branches": True, "custom_branch_policies": False,
        },
        "protection_rules": [{
            "type": "required_reviewers", "prevent_self_review": False,
            "reviewers": [{"type": "User", "reviewer": copy.deepcopy(OWNER)}],
        }],
    }


def approved_review() -> list:
    return [{
        "state": "approved", "user": copy.deepcopy(OWNER),
        "environments": [{"id": ENVIRONMENT_ID, "name": "human-approval"}],
    }]


def execute_approval(config: dict, reviews: list) -> str:
    def response(request):
        payload = reviews if request.full_url.endswith("/approvals") else config
        return io.StringIO(json.dumps(payload))

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "output"
        values = {"GH_TOKEN": "synthetic", "GH_REPOSITORY": "owner/authority",
                  "AUTHORITY_RUN_ID": "123", "AUTHORITY_RUN_ATTEMPT": "2",
                  "GITHUB_OUTPUT": str(output)}
        with patch.dict(os.environ, values, clear=True):
            with patch("urllib.request.urlopen", side_effect=response):
                exec(compile(approval_script(), "workflow-approval", "exec"), {})
        return output.read_text()


class SoloOwnerApprovalTest(unittest.TestCase):
    def test_solo_owner_configuration_emits_bound_digests(self) -> None:
        output = execute_approval(environment(), approved_review())
        self.assertRegex(output, r"config_digest=sha256:[a-f0-9]{64}\n")
        self.assertRegex(output, r"review_digest=sha256:[a-f0-9]{64}\n")

    def test_approval_is_still_required(self) -> None:
        with self.assertRaisesRegex(SystemExit, "approval is missing"):
            execute_approval(environment(), [])

    def test_other_reviewer_cannot_approve(self) -> None:
        reviews = approved_review()
        reviews[0]["user"]["id"] = 1
        with self.assertRaisesRegex(SystemExit, "approval is missing"):
            execute_approval(environment(), reviews)

    def test_other_environment_cannot_approve(self) -> None:
        reviews = approved_review()
        reviews[0]["environments"][0]["id"] = 1
        with self.assertRaisesRegex(SystemExit, "approval is missing"):
            execute_approval(environment(), reviews)

    def test_rejected_review_cannot_approve(self) -> None:
        reviews = approved_review()
        reviews[0]["state"] = "rejected"
        with self.assertRaisesRegex(SystemExit, "approval is missing"):
            execute_approval(environment(), reviews)

    def test_admin_bypass_cannot_be_enabled(self) -> None:
        config = environment()
        config["can_admins_bypass"] = True
        with self.assertRaisesRegex(SystemExit, "configuration is invalid"):
            execute_approval(config, approved_review())

    def test_unprotected_branches_cannot_deploy(self) -> None:
        config = environment()
        config["deployment_branch_policy"]["protected_branches"] = False
        with self.assertRaisesRegex(SystemExit, "configuration is invalid"):
            execute_approval(config, approved_review())

    def test_missing_reviewer_rule_rejects(self) -> None:
        config = environment()
        config["protection_rules"] = []
        with self.assertRaisesRegex(SystemExit, "configuration is invalid"):
            execute_approval(config, approved_review())

    def test_legacy_configuration_is_not_silently_accepted(self) -> None:
        config = environment()
        config["protection_rules"][0]["prevent_self_review"] = True
        with self.assertRaisesRegex(SystemExit, "configuration is invalid"):
            execute_approval(config, approved_review())

    def test_extra_reviewer_is_not_silently_accepted(self) -> None:
        config = environment()
        config["protection_rules"][0]["reviewers"].append({
            "type": "User", "reviewer": {"id": 1, "login": "other"},
        })
        with self.assertRaisesRegex(SystemExit, "configuration is invalid"):
            execute_approval(config, approved_review())
