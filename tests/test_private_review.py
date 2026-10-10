"""Synthetic contract probes; these are not an independent private suite."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from scripts.private_review import (
    ReviewError,
    canonical,
    validate_package,
    validate_proof,
    read_object,
    source_digest,
)


class PrivateReviewTest(unittest.TestCase):
    def test_duplicate_keys_and_nonfinite_json_reject(self):
        for value in ('{"opaque":1,"opaque":2}', '{"opaque":NaN}'):
            with self.subTest(value=value), self.assertRaises(ReviewError):
                read_object(value)

    def setUp(self):
        self.salt = b"a" * 64
        self.verifier = b"#!/usr/bin/python3\nraise SystemExit(1)\n"
        bindings = {k: "b" * 64 for k in (
            "candidateDigest", "baselineDigest", "policyDigest", "scopeDigest"
        )}
        bindings.update(sourceRevision="c" * 40, stage="implementation-ready")
        policy = dict(requirementBindings=bindings, independentVerification={
            "protocol": "owner-private-verifier-v1",
            "verifierDigest": hashlib.sha256(self.verifier).hexdigest(),
            "requiredCases": 3,
        })
        self.package = dict(version="1.0.0", policyDomain="fixture-domain-v1",
            bundle=dict(requestId="req-opaque-example",
                nonce="nonce-0123456789abcdef",
                targetRepository="opaque/fixture",
                targetCommit="c" * 40, requirementBindings=bindings,
                policyBundle=policy), protectedChanges=None, execution=None)
        self.request = dict(requestId="req-opaque-example",
            nonce="nonce-0123456789abcdef")
        self.refresh()
        self.proof = dict(challenge="d" * 64, requirementBindings=bindings,
            protectedChangeDigest=None, executionDigest=None,
            required=3, completed=3, failed=0, skipped=0,
            privateSuiteEvidence=None)

    def refresh(self):
        bundle = self.package["bundle"]
        domain = self.package["policyDomain"].encode() + b"\0"
        self.request["policyCommitment"] = "sha256:" + hashlib.sha256(
            domain + self.salt + b"\0" + canonical(bundle["policyBundle"])
        ).hexdigest()
        self.request["subjectCommitment"] = "sha256:" + hashlib.sha256(
            b"\0".join((b"sdlc-authority-subject-v1", self.salt,
                bundle["targetRepository"].encode(),
                bundle["targetCommit"].encode()))
        ).hexdigest()

    def validate(self):
        return validate_package(self.package, self.request, self.salt,
            "opaque/fixture", "c" * 40,
            base64.b64encode(self.verifier).decode(), "b" * 64)

    def test_valid_review_and_fresh_proof(self):
        self.validate()
        validate_proof(self.proof, self.package, "d" * 64)

    def test_missing_bundle_or_independent_verifier_rejects(self):
        for package, verifier in (({}, self.verifier), (self.package, b"")):
            with self.subTest(package=bool(package)):
                with self.assertRaises(ReviewError):
                    validate_package(package, self.request, self.salt,
                        "opaque/fixture", "c" * 40,
                        base64.b64encode(verifier).decode(), "b" * 64)

    def test_tampered_or_uncommitted_policy_rejects(self):
        self.package["bundle"]["policyBundle"]["scopeDigest"] = "e" * 64
        with self.assertRaises(ReviewError):
            self.validate()

    def test_every_binding_and_stage_mutation_rejects(self):
        for field in self.package["bundle"]["requirementBindings"]:
            original = copy.deepcopy(self.package)
            self.package["bundle"]["requirementBindings"][field] = "e" * 64
            with self.subTest(field=field):
                with self.assertRaises(ReviewError):
                    self.validate()
            self.package = original

    def test_matching_policy_but_stale_source_digest_rejects(self):
        for field in ("sourceRevision", "candidateDigest"):
            package = copy.deepcopy(self.package)
            bindings = self.package["bundle"]["requirementBindings"]
            bindings[field] = "e" * (40 if field == "sourceRevision" else 64)
            self.refresh()
            with self.subTest(field=field):
                with self.assertRaises(ReviewError):
                    self.validate()
            self.package = package
            self.refresh()

    def test_wrong_subject_salt_nonce_and_verifier_rejects(self):
        mutations = (("targetRepository", "other/fixture"),
            ("targetCommit", "e" * 40), ("requestId", "req-another-id"),
            ("nonce", "nonce-fedcba9876543210"))
        for field, value in mutations:
            package = copy.deepcopy(self.package)
            self.package["bundle"][field] = value
            with self.subTest(field=field), self.assertRaises(ReviewError):
                self.validate()
            self.package = package
        self.salt = b"f" * 64
        with self.assertRaises(ReviewError):
            self.validate()
        self.salt = b"a" * 64
        self.verifier += b"#changed\n"
        with self.assertRaises(ReviewError):
            self.validate()

    def test_protected_changes_require_committed_exact_digest(self):
        self.package["protectedChanges"] = [{"opaque": "change"}]
        with self.assertRaises(ReviewError):
            self.validate()
        policy = self.package["bundle"]["policyBundle"]
        policy["protectedChangeDigest"] = hashlib.sha256(
            canonical(self.package["protectedChanges"])).hexdigest()
        self.refresh()
        self.validate()

    def test_higher_stages_require_execution_digest(self):
        for stage in ("verified", "activation-ready"):
            self.package["bundle"]["requirementBindings"]["stage"] = stage
            self.refresh()
            with self.subTest(stage=stage), self.assertRaises(ReviewError):
                self.validate()

    def test_execution_digest_and_binding_are_checked(self):
        bundle = self.package["bundle"]
        bundle["requirementBindings"]["stage"] = "verified"
        self.package["execution"] = dict(
            **{k: v for k, v in bundle["requirementBindings"].items()
               if k != "stage"}, passed=True, cases=[{"id": "opaque"}])
        bundle["policyBundle"]["executionDigest"] = hashlib.sha256(
            canonical(self.package["execution"])).hexdigest()
        self.refresh()
        self.validate()
        self.package["execution"]["scopeDigest"] = "f" * 64
        self.refresh()
        with self.assertRaises(ReviewError):
            self.validate()

    def test_fresh_independent_proof_checks_all_bindings_and_counts(self):
        for field, value in (("challenge", "e" * 64), ("completed", 2),
                             ("failed", 1), ("skipped", 1), ("required", True)):
            proof = copy.deepcopy(self.proof)
            proof[field] = value
            with self.subTest(field=field), self.assertRaises(ReviewError):
                validate_proof(proof, self.package, "d" * 64)
        for field in self.proof["requirementBindings"]:
            proof = copy.deepcopy(self.proof)
            proof["requirementBindings"][field] = "e" * 64
            with self.subTest(field=field), self.assertRaises(ReviewError):
                validate_proof(proof, self.package, "d" * 64)

    def test_activation_requires_bounded_unexpired_suite_proof(self):
        self.package["bundle"]["requirementBindings"].update(
            stage="activation-ready")
        proof = copy.deepcopy(self.proof)
        with self.assertRaises(ReviewError):
            validate_proof(proof, self.package, "d" * 64)
        bindings = {k: v for k, v in proof["requirementBindings"].items()
                    if k != "stage"}
        suite = dict(protocol="opaque-v1", suiteDigest="f" * 64,
            required=3, completed=3, failed=0, skipped=0, bindings=bindings,
            expiresAt=(datetime.now(timezone.utc)
                       + timedelta(hours=1)).isoformat())
        proof["privateSuiteEvidence"] = suite
        self.package["bundle"]["policyBundle"]["privateSuiteEvidence"] = suite
        validate_proof(proof, self.package, "d" * 64)
        suite["expiresAt"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(ReviewError):
            validate_proof(proof, self.package, "d" * 64)

    def test_missing_environment_cli_rejects_without_private_output(self):
        result = subprocess.run(["python3", "scripts/private_review.py",
            "prepare", "--request", "unavailable", "--source", "unavailable",
            "--private-dir", "unavailable"], env={"PATH": os.environ["PATH"]},
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "private review rejected\n")

    def test_prepare_cli_matches_exact_git_file_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            source.joinpath("opaque").write_text("fixture")
            subprocess.run(["git", "-C", str(source), "add", "opaque"],
                check=True)
            subprocess.run(["git", "-C", str(source), "-c",
                "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-qm", "fixture"], check=True)
            bindings = self.package["bundle"]["requirementBindings"]
            bindings["candidateDigest"] = source_digest(source)
            bindings["sourceRevision"] = subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                text=True).strip()
            self.package["bundle"]["targetCommit"] = bindings["sourceRevision"]
            self.refresh()
            self._prepare_cli(Path(temporary), source)

    def _prepare_cli(self, temporary, source):
        private = temporary / "private"
        private.mkdir()
        request = temporary / "request.json"
        request.write_text(json.dumps(self.request))
        environment = dict(os.environ, SOURCE_REVIEW_PACKAGE=json.dumps(
            self.package), SOURCE_REPOSITORY="opaque/fixture",
            SOURCE_REVISION=self.package["bundle"]["targetCommit"],
            SOURCE_COMMITMENT_SALT=self.salt.decode(),
            SOURCE_INDEPENDENT_VERIFIER=base64.b64encode(
                self.verifier).decode())
        result = subprocess.run(["python3", "scripts/private_review.py",
            "prepare", "--request", str(request), "--source", str(source),
            "--private-dir", str(private)], env=environment,
            capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, "", ""))
        self.assertEqual(private.joinpath("verify.py").read_bytes(),
                         self.verifier)
        self.assertRegex(private.joinpath("challenge").read_text(),
                         r"^[a-f0-9]{64}$")
