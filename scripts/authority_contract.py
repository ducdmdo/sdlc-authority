#!/usr/bin/env python3
"""Generate and strictly validate opaque SDLC authority artifacts."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0.0"
AUTHORITY_REPOSITORY = "ducdmdo/sdlc-authority"
AUTHORITY_WORKFLOW = ".github/workflows/issue-authority-receipt.yml"
AUTHORITY_ENVIRONMENT = "human-approval"
AUTHORITY_REF = "refs/heads/main"
AUTHORITY_ACTOR = "github-actions[bot]"
RELAY_ACTOR = "ducdmdo"
PRIVACY_PROFILE = "opaque-commitments-only-v1"
MAX_LIFETIME = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)

REQUEST_KEYS = {
    "schemaVersion",
    "requestId",
    "nonce",
    "subjectCommitment",
    "policyCommitment",
    "requestedAt",
}
DECISION_KEYS = {
    "schemaVersion",
    "request",
    "relay",
    "authority",
    "decision",
    "verification",
    "approvalEvidence",
    "issuedAt",
    "expiresAt",
    "privacyProfile",
}
APPROVAL_KEYS = {"configDigest", "reviewDigest"}
RELAY_KEYS = {"runId", "runAttempt", "actor"}
AUTHORITY_KEYS = {
    "repository",
    "workflow",
    "environment",
    "commitSha",
    "ref",
    "refProtected",
    "runId",
    "runAttempt",
    "actor",
}
VERIFICATION_KEYS = {"result", "isolation", "entrypointContract"}

REQUEST_ID = re.compile(r"req-[a-z0-9](?:[a-z0-9-]{6,62}[a-z0-9])\Z")
NONCE = re.compile(r"nonce-[a-z0-9]{16,64}\Z")
COMMITMENT = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*\Z")


class ContractError(ValueError):
    """Raised when an artifact violates the public authority contract."""


def parse_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContractError(f"{field} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise ContractError(f"{field} must use UTC")
    return parsed


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def require_keys(value: Any, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{field} must be an object")
    if set(value) != expected:
        raise ContractError(f"{field} fields do not match the strict contract")
    return value


def require_pattern(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"{field} has an invalid format")
    return value


def validate_request(data: Any, now: datetime | None = None) -> dict[str, Any]:
    request = require_keys(data, REQUEST_KEYS, "request")
    if request["schemaVersion"] != SCHEMA_VERSION:
        raise ContractError("request schemaVersion is unsupported")
    require_pattern(request["requestId"], REQUEST_ID, "requestId")
    require_pattern(request["nonce"], NONCE, "nonce")
    require_pattern(request["subjectCommitment"], COMMITMENT, "subjectCommitment")
    require_pattern(request["policyCommitment"], COMMITMENT, "policyCommitment")
    requested_at = parse_utc(request["requestedAt"], "requestedAt")
    current = now or datetime.now(timezone.utc)
    if requested_at > current + MAX_CLOCK_SKEW:
        raise ContractError("requestedAt is too far in the future")
    if current - requested_at > MAX_LIFETIME:
        raise ContractError("request is older than 24 hours")
    return request


def validate_decision(data: Any, now: datetime | None = None) -> dict[str, Any]:
    decision = require_keys(data, DECISION_KEYS, "decision")
    current = now or datetime.now(timezone.utc)
    request = validate_request(decision["request"], current)
    relay = require_keys(decision["relay"], RELAY_KEYS, "relay")
    authority = require_keys(decision["authority"], AUTHORITY_KEYS, "authority")
    verification = require_keys(
        decision["verification"], VERIFICATION_KEYS, "verification"
    )
    approval = require_keys(
        decision["approvalEvidence"], APPROVAL_KEYS, "approvalEvidence"
    )
    _validate_relay(relay)
    _validate_authority(authority)
    if decision["schemaVersion"] != SCHEMA_VERSION:
        raise ContractError("decision schemaVersion is unsupported")
    if decision["decision"] != "accepted":
        raise ContractError("decision must be accepted")
    expected_verification = {
        "result": "passed",
        "isolation": "bubblewrap-network-none-v1",
        "entrypointContract": "fixed-v1",
    }
    if verification != expected_verification:
        raise ContractError("private verification did not pass the fixed contract")
    require_pattern(approval["configDigest"], COMMITMENT, "approval config digest")
    require_pattern(approval["reviewDigest"], COMMITMENT, "approval review digest")
    if decision["privacyProfile"] != PRIVACY_PROFILE:
        raise ContractError("privacy profile is unsupported")
    issued_at = parse_utc(decision["issuedAt"], "issuedAt")
    expires_at = parse_utc(decision["expiresAt"], "expiresAt")
    requested_at = parse_utc(request["requestedAt"], "requestedAt")
    if not requested_at <= issued_at < expires_at:
        raise ContractError("decision timestamps are not ordered")
    if expires_at - issued_at > MAX_LIFETIME:
        raise ContractError("decision lifetime exceeds 24 hours")
    if issued_at > current + MAX_CLOCK_SKEW:
        raise ContractError("issuedAt is too far in the future")
    if current >= expires_at:
        raise ContractError("decision has expired")
    return decision


def _validate_relay(relay: dict[str, Any]) -> None:
    require_pattern(relay["runId"], POSITIVE_INTEGER, "relay.runId")
    require_pattern(relay["runAttempt"], POSITIVE_INTEGER, "relay.runAttempt")
    if relay["actor"] != RELAY_ACTOR:
        raise ContractError("relay actor is not authorized")


def _validate_authority(authority: dict[str, Any]) -> None:
    exact = {
        "repository": AUTHORITY_REPOSITORY,
        "workflow": AUTHORITY_WORKFLOW,
        "environment": AUTHORITY_ENVIRONMENT,
        "ref": AUTHORITY_REF,
        "actor": AUTHORITY_ACTOR,
    }
    for field, expected in exact.items():
        if authority[field] != expected:
            raise ContractError(f"authority.{field} is not trusted")
    if authority["refProtected"] is not True:
        raise ContractError("authority ref is not protected")
    require_pattern(authority["commitSha"], COMMIT_SHA, "authority.commitSha")
    require_pattern(authority["runId"], POSITIVE_INTEGER, "authority.runId")
    require_pattern(authority["runAttempt"], POSITIVE_INTEGER, "authority.runAttempt")


def new_request(
    request_id: str,
    nonce: str,
    subject_commitment: str,
    policy_commitment: str,
    requested_at: datetime,
) -> dict[str, Any]:
    request = {
        "schemaVersion": SCHEMA_VERSION,
        "requestId": request_id,
        "nonce": nonce,
        "subjectCommitment": subject_commitment,
        "policyCommitment": policy_commitment,
        "requestedAt": format_utc(requested_at),
    }
    return validate_request(request, requested_at)


def issue_decision(
    request: dict[str, Any],
    relay_run_id: str,
    relay_run_attempt: str,
    authority_commit_sha: str,
    authority_run_id: str,
    authority_run_attempt: str,
    approval_config_digest: str,
    approval_review_digest: str,
    issued_at: datetime,
) -> dict[str, Any]:
    decision = {
        "schemaVersion": SCHEMA_VERSION,
        "request": request,
        "relay": {
            "runId": relay_run_id,
            "runAttempt": relay_run_attempt,
            "actor": RELAY_ACTOR,
        },
        "authority": {
            "repository": AUTHORITY_REPOSITORY,
            "workflow": AUTHORITY_WORKFLOW,
            "environment": AUTHORITY_ENVIRONMENT,
            "commitSha": authority_commit_sha,
            "ref": AUTHORITY_REF,
            "refProtected": True,
            "runId": authority_run_id,
            "runAttempt": authority_run_attempt,
            "actor": AUTHORITY_ACTOR,
        },
        "decision": "accepted",
        "verification": {
            "result": "passed",
            "isolation": "bubblewrap-network-none-v1",
            "entrypointContract": "fixed-v1",
        },
        "approvalEvidence": {
            "configDigest": approval_config_digest,
            "reviewDigest": approval_review_digest,
        },
        "issuedAt": format_utc(issued_at),
        "expiresAt": format_utc(issued_at + MAX_LIFETIME),
        "privacyProfile": PRIVACY_PROFILE,
    }
    return validate_decision(decision, issued_at)


def write_canonical(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError("artifact is not valid UTF-8 JSON") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request")
    request.add_argument("--request-id", required=True)
    request.add_argument("--nonce", required=True)
    request.add_argument("--subject-commitment", required=True)
    request.add_argument("--policy-commitment", required=True)
    request.add_argument("--requested-at", required=True)
    request.add_argument("--output", type=Path, required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("--request", type=Path, required=True)
    issue.add_argument("--relay-run-id", required=True)
    issue.add_argument("--relay-run-attempt", required=True)
    issue.add_argument("--authority-commit-sha", required=True)
    issue.add_argument("--authority-run-id", required=True)
    issue.add_argument("--authority-run-attempt", required=True)
    issue.add_argument("--approval-config-digest", required=True)
    issue.add_argument("--approval-review-digest", required=True)
    issue.add_argument("--issued-at", required=True)
    issue.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--kind", choices=("request", "decision"), required=True)
    validate.add_argument("--artifact", type=Path, required=True)
    validate.add_argument("--now")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "request":
        requested_at = parse_utc(args.requested_at, "requestedAt")
        artifact = new_request(
            args.request_id,
            args.nonce,
            args.subject_commitment,
            args.policy_commitment,
            requested_at,
        )
        write_canonical(args.output, artifact)
        return 0
    if args.command == "issue":
        issued_at = parse_utc(args.issued_at, "issuedAt")
        request = validate_request(read_json(args.request), issued_at)
        artifact = issue_decision(
            request,
            args.relay_run_id,
            args.relay_run_attempt,
            args.authority_commit_sha,
            args.authority_run_id,
            args.authority_run_attempt,
            args.approval_config_digest,
            args.approval_review_digest,
            issued_at,
        )
        write_canonical(args.output, artifact)
        return 0
    now = parse_utc(args.now, "now") if args.now else None
    artifact = read_json(args.artifact)
    if args.kind == "request":
        validate_request(artifact, now)
    else:
        validate_decision(artifact, now)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        raise SystemExit(f"authority contract rejected: {error}") from error
