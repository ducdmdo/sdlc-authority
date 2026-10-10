# Pending owner provisioning contract

This document describes an engineering candidate. It does not authorize secret
installation, repository settings, workflow dispatch, signing, trusted consumer
installation, merge, or activation. All remain separate owner actions.

The owner must privately review the exact candidate and independently prepared
evidence, provide a verifier from a trust plane outside that candidate, and
provision the following values in the protected `human-approval` environment.
The public repository contains no private suite and cannot manufacture one.
Its synthetic contract tests do not count as independent acceptance evidence.

The existing four secrets retain their meaning. `SOURCE_COMMITMENT_SALT` must
be exactly 64 lowercase hexadecimal ASCII characters and match the consumer's
salt file byte-for-byte, with no newline or hex decoding.

## Private review package

`SOURCE_REVIEW_PACKAGE` is UTF-8 JSON with exactly these keys:

| Key | Private value |
| --- | --- |
| `version` | `1.0.0` |
| `policyDomain` | Consumer commitment domain, without its terminating null |
| `bundle` | Exact private consumer bundle |
| `protectedChanges` | Exact protected change records, or `null` when absent |
| `execution` | Exact execution evidence, or `null` before higher stages |

`bundle` carries `requestId`, `nonce`, `targetRepository`, `targetCommit`,
`requirementBindings`, and `policyBundle` from the private consumer protocol.
The two copies of `requirementBindings` must contain exactly `sourceRevision`,
`candidateDigest`, `baselineDigest`, `policyDigest`, `scopeDigest`, and `stage`.
Stages are `review-ready`, `implementation-ready`, `verified`, and
`activation-ready`. Source revision must match both the protected secret and
the fetched commit. Candidate digest is recomputed from the fetched tracked
files with the consumer's canonical file-map protocol, including symlink text.
The independent verifier must independently derive the remaining coordinates.

The committed `policyBundle` additionally contains `independentVerification`:

| Key | Required value |
| --- | --- |
| `protocol` | `owner-private-verifier-v1` |
| `verifierDigest` | 64 lowercase SHA-256 hex characters over verifier bytes |
| `requiredCases` | Positive integer, independently approved suite count |

`protectedChangeDigest` is required when protected changes are present and
must equal the canonical SHA-256 digest of `protectedChanges`. Omitting a real
protected change is forbidden: the independent verifier must discover actual
protected changes from owner-supplied trusted policy and reject such omission.
`executionDigest` must equal the canonical digest of `execution`; evidence
must bind all five coordinates, pass, and contain actual test or non-test
records. Both `verified` and `activation-ready` require execution evidence.
The verifier must validate exact cases and their results independently.

`activation-ready` additionally requires `privateSuiteEvidence` inside the
committed policy, with exactly `protocol`, `suiteDigest`, `required`,
`completed`, `failed`, `skipped`, `bindings`, and `expiresAt`. Its suite digest
and protocol must match the privately trusted suite registration. All required
cases must complete, with zero failures/skips; five bindings must match; expiry
must be in the future. Passing a candidate-owned test runner cannot substitute
for this proof. The consumer still applies its own trusted activation policy.

The authority computes the public policy commitment from `policyBundle`,
using the consumer's private domain, the same salt bytes, and canonical JSON.
Neither the review package nor domain may be placed in public inputs or files.

## Independent verifier

`SOURCE_INDEPENDENT_VERIFIER` is strict base64 of a self-contained Python
verifier supplied and reviewed by the owner. No archive extraction occurs.
Its raw bytes must hash to the committed `verifierDigest`. The source must be
independent of the candidate's test code and obtain any trusted baseline,
policy, expected suite registration, and oracle data from its privately
provisioned contents. Standard-library-only execution is available; source
dependencies, network calls, and runtime dependency installation are absent.
GitHub secret size limits apply; oversized provisioned suites fail closed and
require a separately reviewed private delivery mechanism before activation.

The workflow invokes it as follows inside an isolated sandbox:

```text
/usr/bin/python3 /review/verify.py
  --review /review/review.json
  --challenge <fresh unpredictable 64-character hex value>
  --output /proof/proof.json
```

Source is read-only at `/workspace`; the private package and verifier are
read-only at `/review`; `/proof` is the only persistent writable output.
The process has no network and only `HOME` and `PATH` environment values.
Exit status must be zero within 240 seconds. Stdout and stderr are discarded.

The proof must contain exactly `challenge`, `requirementBindings`,
`protectedChangeDigest`, `executionDigest`, `required`, `completed`, `failed`,
`skipped`, and `privateSuiteEvidence`. Counts must match committed
`requiredCases`, complete in full, and have zero failures/skips. Bindings and
digests must be independently computed and equal the reviewed values. Absent
change/execution/suite evidence uses `null`; activation suite proof must equal
the committed `privateSuiteEvidence` exactly. The challenge must be echoed
from this invocation; an old proof or package-provided proof cannot be reused.
Merely echoing package coordinates or passing counts is not a valid verifier.

## Owner actions still required

1. Independently review the private requirement baseline, protected changes,
   candidate coordinates, exact stage, and applicable execution evidence.
2. Prepare and review the separate private verifier and suite; register its
   protocol, digest, expected count, and trusted baseline in the private plane.
3. Privately prepare the complete bundle, matching domain and salt; compute
   both public commitments using the consumer protocol; provision the two new
   secrets together with the existing exact source secrets.
4. Review and merge the authority code, pin that exact workflow commit in the
   trusted consumer installation, and confirm protected server controls.
5. Only after that separate authorization, dispatch the opaque relay request,
   review the protected deployment, consume the attested short-lived artifact
   through the consumer's durable replay boundary, and separately decide any
   activation. No workflow run or accepted receipt has been produced here.
