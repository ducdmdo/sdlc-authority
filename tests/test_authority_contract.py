from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.authority_contract import (
    AUTHORITY_REPOSITORY,
    ContractError,
    issue_decision,
    new_request,
    validate_decision,
    validate_request,
    write_canonical,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 8, 2, 0, tzinfo=timezone.utc)
SUBJECT = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64
CONFIG_DIGEST = "sha256:" + "d" * 64
REVIEW_DIGEST = "sha256:" + "e" * 64


class AuthorityContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.request = new_request(
            "req-20260908-opaque",
            "nonce-20260908opaque001",
            SUBJECT,
            POLICY,
            NOW,
        )
        self.decision = issue_decision(
            self.request,
            "101",
            "1",
            "c" * 40,
            "202",
            "1",
            CONFIG_DIGEST,
            REVIEW_DIGEST,
            NOW + timedelta(minutes=1),
        )

    def test_valid_request_and_decision(self) -> None:
        self.assertEqual(validate_request(self.request, NOW), self.request)
        self.assertEqual(
            validate_decision(self.decision, NOW + timedelta(minutes=2)),
            self.decision,
        )
        self.assertEqual(
            self.decision["authority"]["repository"], AUTHORITY_REPOSITORY
        )

    def test_request_rejects_extra_field(self) -> None:
        request = {**self.request, "sourcePath": "forbidden"}
        with self.assertRaises(ContractError):
            validate_request(request, NOW)

    def test_request_rejects_non_opaque_commitment(self) -> None:
        request = {**self.request, "subjectCommitment": "private/repository/main"}
        with self.assertRaises(ContractError):
            validate_request(request, NOW)

    def test_request_rejects_old_and_future_timestamps(self) -> None:
        for requested_at, now in (
            (NOW, NOW + timedelta(hours=24, seconds=1)),
            (NOW + timedelta(minutes=6), NOW),
        ):
            request = {**self.request, "requestedAt": _utc(requested_at)}
            with self.subTest(requested_at=requested_at):
                with self.assertRaises(ContractError):
                    validate_request(request, now)

    def test_decision_rejects_untrusted_authority_bindings(self) -> None:
        mutations = {
            "repository": "someone/else",
            "workflow": ".github/workflows/other.yml",
            "environment": "unreviewed",
            "ref": "refs/heads/unprotected",
            "refProtected": False,
            "actor": "ducdmdo",
        }
        for field, value in mutations.items():
            decision = copy.deepcopy(self.decision)
            decision["authority"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(ContractError):
                    validate_decision(decision, NOW + timedelta(minutes=2))

    def test_decision_rejects_untrusted_relay(self) -> None:
        decision = copy.deepcopy(self.decision)
        decision["relay"]["actor"] = "other-user"
        with self.assertRaises(ContractError):
            validate_decision(decision, NOW + timedelta(minutes=2))

    def test_decision_rejects_expiry_and_excess_lifetime(self) -> None:
        with self.assertRaises(ContractError):
            validate_decision(self.decision, NOW + timedelta(hours=24, minutes=1))
        decision = copy.deepcopy(self.decision)
        decision["expiresAt"] = _utc(NOW + timedelta(hours=25))
        with self.assertRaises(ContractError):
            validate_decision(decision, NOW + timedelta(minutes=2))

    def test_decision_rejects_unverified_private_source(self) -> None:
        decision = copy.deepcopy(self.decision)
        decision["verification"]["result"] = "failed"
        with self.assertRaises(ContractError):
            validate_decision(decision, NOW + timedelta(minutes=2))

    def test_decision_rejects_invalid_approval_evidence(self) -> None:
        decision = copy.deepcopy(self.decision)
        decision["approvalEvidence"]["reviewDigest"] = "unverified"
        with self.assertRaises(ContractError):
            validate_decision(decision, NOW + timedelta(minutes=2))

    def test_decision_never_serializes_private_source_identity(self) -> None:
        encoded = json.dumps(self.decision, sort_keys=True)
        private_source_revision = "0123456789abcdef0123456789abcdef01234567"
        self.assertNotIn("private-product", encoded)
        self.assertNotIn(private_source_revision, encoded)

    def test_canonical_output_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            write_canonical(output, self.decision)
            encoded = output.read_text(encoding="utf-8")
        self.assertTrue(encoded.endswith("\n"))
        expected = json.dumps(
            self.decision,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual(encoded, expected + "\n")

    def test_cli_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            decision = Path(directory) / "decision.json"
            self._run(
                "request",
                "--request-id",
                "req-20260908-opaque",
                "--nonce",
                "nonce-20260908opaque001",
                "--subject-commitment",
                SUBJECT,
                "--policy-commitment",
                POLICY,
                "--requested-at",
                _utc(NOW),
                "--output",
                str(request),
            )
            self._run(
                "issue",
                "--request",
                str(request),
                "--relay-run-id",
                "101",
                "--relay-run-attempt",
                "1",
                "--authority-commit-sha",
                "c" * 40,
                "--authority-run-id",
                "202",
                "--authority-run-attempt",
                "1",
                "--approval-config-digest",
                CONFIG_DIGEST,
                "--approval-review-digest",
                REVIEW_DIGEST,
                "--issued-at",
                _utc(NOW + timedelta(minutes=1)),
                "--output",
                str(decision),
            )
            self._run(
                "validate",
                "--kind",
                "decision",
                "--artifact",
                str(decision),
                "--now",
                _utc(NOW + timedelta(minutes=2)),
            )

    def _run(self, *arguments: str) -> None:
        subprocess.run(
            ["python3", "scripts/authority_contract.py", *arguments],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )


def _utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    unittest.main()
