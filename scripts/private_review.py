#!/usr/bin/env python3
"""Fail-closed private review bridge; never serialize private data publicly."""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from datetime import datetime, timezone

BINDINGS = {"sourceRevision", "candidateDigest", "baselineDigest",
            "policyDigest", "scopeDigest"}
STAGES = {"review-ready", "implementation-ready", "verified",
          "activation-ready"}
PACKAGE_KEYS = {"version", "policyDomain", "bundle", "protectedChanges",
                "execution"}
PROOF_KEYS = {"challenge", "requirementBindings", "protectedChangeDigest",
              "executionDigest", "required", "completed", "failed", "skipped",
              "privateSuiteEvidence"}


class ReviewError(ValueError):
    """Generic rejection without private coordinates or parsing details."""


def require(condition):
    if not condition:
        raise ReviewError("private review rejected")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def object_value(value):
    require(isinstance(value, dict))
    return value


def coordinate(value, length=64):
    return isinstance(value, str) and re.fullmatch(
        "[a-f0-9]{" + str(length) + "}", value) is not None


def validate_bindings(bindings):
    object_value(bindings)
    require(set(bindings) == BINDINGS | {"stage"})
    require(bindings["stage"] in STAGES)
    for field in BINDINGS:
        require(coordinate(bindings[field], 40 if field == "sourceRevision"
                           else 64))


def validate_package(package, request, salt, repository, revision,
                     verifier_encoded, candidate_digest):
    object_value(package)
    require(set(package) == PACKAGE_KEYS and package["version"] == "1.0.0")
    require(re.fullmatch(rb"[a-f0-9]{64}", salt) is not None)
    bundle = object_value(package["bundle"])
    policy = object_value(bundle.get("policyBundle"))
    bindings = bundle.get("requirementBindings")
    validate_bindings(bindings)
    require(policy.get("requirementBindings") == bindings)
    _validate_subject(bundle, request, salt, repository, revision)
    require(bindings["candidateDigest"] == candidate_digest)
    _validate_policy(package, request, salt)
    _validate_evidence(package)
    return _verifier_bytes(verifier_encoded, policy)


def _validate_subject(bundle, request, salt, repository, revision):
    require(isinstance(repository, str) and re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None)
    require(coordinate(revision, 40))
    require(bundle.get("targetRepository") == repository)
    require(bundle.get("targetCommit") == revision)
    require(bundle["requirementBindings"]["sourceRevision"] == revision)
    for field in ("requestId", "nonce"):
        require(bundle.get(field) == request.get(field))
    body = b"\0".join((b"sdlc-authority-subject-v1", salt,
                         repository.encode(), revision.encode()))
    _commitment(request.get("subjectCommitment"), body)


def _validate_policy(package, request, salt):
    domain = package["policyDomain"]
    require(isinstance(domain, str) and 1 <= len(domain) <= 256)
    require("\0" not in domain)
    body = domain.encode("utf-8") + b"\0" + salt + b"\0"
    body += canonical(package["bundle"]["policyBundle"])
    _commitment(request.get("policyCommitment"), body)


def _commitment(supplied, body):
    expected = "sha256:" + hashlib.sha256(body).hexdigest()
    require(isinstance(supplied, str)
            and hmac.compare_digest(supplied, expected))


def _verifier_bytes(encoded, policy):
    config = object_value(policy.get("independentVerification"))
    require(set(config) == {"protocol", "verifierDigest", "requiredCases"})
    require(config["protocol"] == "owner-private-verifier-v1")
    require(coordinate(config["verifierDigest"]))
    require(type(config["requiredCases"]) is int
            and config["requiredCases"] > 0)
    try:
        verifier = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ReviewError("private review rejected") from error
    require(bool(verifier) and len(verifier) <= 1048576)
    require(hashlib.sha256(verifier).hexdigest() == config["verifierDigest"])
    return verifier


def _validate_evidence(package):
    policy = package["bundle"]["policyBundle"]
    changes = package["protectedChanges"]
    if changes is not None:
        require(isinstance(changes, list) and bool(changes))
        require(policy.get("protectedChangeDigest") == digest(changes))
    else:
        require("protectedChangeDigest" not in policy)
    execution = package["execution"]
    higher = package["bundle"]["requirementBindings"]["stage"] in {
        "verified", "activation-ready"}
    require(not higher or execution is not None)
    if execution is not None:
        _validate_execution(package, execution)
    else:
        require("executionDigest" not in policy)


def _validate_execution(package, execution):
    object_value(execution)
    policy = package["bundle"]["policyBundle"]
    bindings = package["bundle"]["requirementBindings"]
    require(policy.get("executionDigest") == digest(execution))
    require(all(execution.get(k) == bindings[k] for k in BINDINGS))
    require(execution.get("passed") is True)
    require(bool(execution.get("cases") or execution.get("nonTestEvidence")))


def validate_proof(proof, package, challenge):
    object_value(proof)
    require(set(proof) == PROOF_KEYS)
    require(coordinate(challenge) and proof["challenge"] == challenge)
    policy = package["bundle"]["policyBundle"]
    bindings = package["bundle"]["requirementBindings"]
    require(proof["requirementBindings"] == bindings)
    for field in ("protectedChangeDigest", "executionDigest"):
        require(proof[field] == policy.get(field))
    count = policy["independentVerification"]["requiredCases"]
    _passing_counts(proof, count)
    suite = proof["privateSuiteEvidence"]
    require(suite == policy.get("privateSuiteEvidence"))
    if bindings["stage"] == "activation-ready":
        _validate_suite(suite, bindings)
    elif suite is not None:
        _validate_suite(suite, bindings)


def _passing_counts(proof, count):
    require(type(count) is int and count > 0)
    expected = dict(required=count, completed=count, failed=0, skipped=0)
    require(all(type(proof.get(k)) is int and proof[k] == v
                for k, v in expected.items()))


def _validate_suite(suite, bindings):
    object_value(suite)
    require(set(suite) == {"protocol", "suiteDigest", "required", "completed",
                           "failed", "skipped", "bindings", "expiresAt"})
    require(isinstance(suite["protocol"], str) and bool(suite["protocol"]))
    require(coordinate(suite["suiteDigest"]))
    require(suite["bindings"] == {k: bindings[k] for k in BINDINGS})
    _passing_counts(suite, suite["required"])
    try:
        expiry = datetime.fromisoformat(suite["expiresAt"])
        require(expiry.tzinfo is not None
                and expiry > datetime.now(timezone.utc))
    except (ValueError, TypeError) as error:
        raise ReviewError("private review rejected") from error


def _strict_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def read_object(text):
    return object_value(json.loads(text, object_pairs_hook=_strict_pairs,
        parse_constant=lambda _: require(False)))


def source_digest(source):
    paths = subprocess.check_output(
        ["git", "-C", str(source), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard"])
    values = {}
    for relative in sorted(set(p.decode() for p in paths.split(b"\0") if p)):
        path = source / relative
        if path.is_symlink():
            values[relative] = "symlink:" + str(path.readlink())
        else:
            values[relative] = (hashlib.sha256(path.read_bytes()).hexdigest()
                                if path.is_file() else "deleted")
    return digest(values)


def prepare(args):
    package = read_object(os.environ["SOURCE_REVIEW_PACKAGE"])
    request = read_object(args.request.read_text(encoding="utf-8"))
    revision = subprocess.check_output(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip()
    require(revision == os.environ["SOURCE_REVISION"])
    verifier = validate_package(package, request,
        os.environ["SOURCE_COMMITMENT_SALT"].encode("ascii"),
        os.environ["SOURCE_REPOSITORY"], revision,
        os.environ["SOURCE_INDEPENDENT_VERIFIER"], source_digest(args.source))
    args.private_dir.joinpath("review.json").write_bytes(canonical(package))
    args.private_dir.joinpath("verify.py").write_bytes(verifier)
    args.private_dir.joinpath("challenge").write_text(secrets.token_hex(32))


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--request", type=Path, required=True)
    preparation.add_argument("--source", type=Path, required=True)
    preparation.add_argument("--private-dir", type=Path, required=True)
    proof = commands.add_parser("proof")
    proof.add_argument("--private-dir", type=Path, required=True)
    proof.add_argument("--proof", type=Path, required=True)
    return parser


def main():
    args = build_parser().parse_args()
    if args.command == "prepare":
        prepare(args)
    else:
        package = read_object((args.private_dir / "review.json").read_text())
        challenge = (args.private_dir / "challenge").read_text()
        require(not args.proof.is_symlink() and args.proof.is_file())
        require(args.proof.stat().st_size <= 1048576)
        validate_proof(read_object(args.proof.read_text()), package, challenge)


if __name__ == "__main__":
    try:
        main()
    except (ReviewError, OSError, ValueError, TypeError, KeyError,
            subprocess.SubprocessError):
        raise SystemExit("private review rejected") from None
