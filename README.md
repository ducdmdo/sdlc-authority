# SDLC Authority

This repository is a public, metadata-only authority plane for projects that
cannot use protected branches or protected environments in a private GitHub
Free repository.

Its public inputs and outputs never contain source code, repository names,
source paths, branch names, commit messages, test logs, product language, or
user data. A request contains a fresh nonce and two opaque SHA-256 commitments.
A protected workflow pauses at the `human-approval` environment and emits a
short-lived `accepted` decision only after approval and isolated private
verification.

## Trust boundary

- Repository: `ducdmdo/sdlc-authority`
- Protected branch: `main`
- Authority workflow: `.github/workflows/issue-authority-receipt.yml`
- Protected environment: `human-approval`
- Artifact: `authority-decision/authority-decision.json`
- Artifact retention: one day
- Artifact authenticity: GitHub artifact attestation
- Shared application secrets: none
- Protected credentials: a read-only deploy key, source target, privacy salt,
  owner-reviewed package, and independent verifier

The public decision does not reveal what was reviewed. Consumers independently
calculate the same subject and policy commitments, then require an exact match.
A consumer also rejects a previously used nonce. A decision expires after 24
hours and is bound to the protected workflow run, workflow commit, relay run,
repository, and environment.

## Request flow

1. An authorized operator manually starts `Relay Authority Request` with an
   opaque request identifier and two `sha256:<64 lowercase hex>` commitments.
2. The relay validates the inputs and uses its run-scoped `GITHUB_TOKEN` to
   dispatch `Issue Authority Receipt`. GitHub documents `repository_dispatch` as
   an exception that can create a second run from `GITHUB_TOKEN`.
3. The authority run must be requested by `github-actions[bot]`, execute from
   protected `main`, and wait at `human-approval`.
4. The repository owner reviews the private evidence outside this repository
   and approves or rejects the environment deployment.
5. After approval, a secret-backed job fetches one exact source revision and
   checks both salted commitments against the privately provisioned package.
   It checks the five source coordinates and stage, protected changes when
   present, and execution evidence for higher stages. It removes credentials
   and runs an owner-provided independent verifier in a separate Bubblewrap
   sandbox. A fresh challenge, exact bindings, and complete passing counts
   are required. Activation also requires the committed private suite proof.
   It then runs the fixed `.sdlc-authority/verify` candidate entrypoint in its
   own sandbox with no review package or independent verifier mounted.
   Both sandboxes have no network, clear their environments, and discard logs.
6. The same approved job produces a canonical JSON decision, validates it,
   uploads it for one day, and creates a GitHub artifact attestation.

The final approval workflow must not be dispatched until the exact private
commitment has been independently reviewed.

The protected environment must define `SOURCE_REPOSITORY`, `SOURCE_REVISION`,
`SOURCE_DEPLOY_KEY`, `SOURCE_COMMITMENT_SALT`, `SOURCE_REVIEW_PACKAGE`, and
`SOURCE_INDEPENDENT_VERIFIER`. These values are never public inputs.
The subject commitment is SHA-256 over a versioned, null-delimited
preimage containing the random salt, canonical source target, and exact source
revision. The private trust plane must calculate it with the same contract.

The policy commitment is SHA-256 over the consumer's private protocol domain,
a null byte, the salt, a null byte, and the canonical `policyBundle` object.
Canonical JSON sorts keys, uses UTF-8 without ASCII escaping, and omits
whitespace. The salt is exactly 64 lowercase hexadecimal ASCII bytes, used
as bytes without hex decoding. Both bundle copies of `requirementBindings`
must match. The owner supplies the consumer's exact domain privately; this
repository does not name or encode a private consumer protocol identity.
The preimage remains private and the decision preserves its commitment.

```text
SHA256(
  UTF8("sdlc-authority-subject-v1") || 0x00 ||
  UTF8(SOURCE_COMMITMENT_SALT)      || 0x00 ||
  UTF8(SOURCE_REPOSITORY)           || 0x00 ||
  UTF8(SOURCE_REVISION)
)
```

The job fails closed when a secret, independent verifier/proof, Bubblewrap,
fixed entrypoint, or any verification condition is unavailable.

## Solo-owner deployment review

The owner approved solo development review on 2026-10-11. The
`human-approval` environment retains `ducdmdo` as its required reviewer,
protected-branch-only deployment and disabled administrator bypass. It permits
the owner to approve a deployment they initiated. The workflow requires this
exact configuration and an actual approved review event for its current run.
It still rejects missing approval, a different reviewer or environment,
administrator bypass and unprotected branches.

This is an owner review, not an independent second-person review. GitHub does
not permit PR authors to approve their own PRs. Changing mandatory PR approval
counts is a separate repository-policy decision; this workflow change does not
grant a PR approval or change branch protection. Private verification and
attestation remain required. No launch or consumer activation is granted.

This engineering candidate is not installed or activated. See the
[owner provisioning contract](docs/owner-provisioning.md) for the exact pending
private actions. Public contract fixtures test rejection behavior; they do
not provide independent review authority or a private acceptance suite.

## Local verification

```sh
python3 -m unittest discover -s tests -v
```

See [the privacy contract](docs/privacy-contract.md) before changing any input,
artifact, log, or workflow.
