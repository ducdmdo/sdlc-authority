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
- Protected credentials: a read-only deploy key, source target, and privacy salt

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
5. After approval, a secret-backed job fetches one exact source revision,
   checks its salted opaque commitment, removes its credential, and runs the
   fixed `.sdlc-authority/verify` entrypoint in a Bubblewrap sandbox without
   network access. Its output is discarded.
6. The same approved job produces a canonical JSON decision, validates it,
   uploads it for one day, and creates a GitHub artifact attestation.

The final approval workflow must not be dispatched until the exact private
commitment has been independently reviewed.

The protected environment must define `SOURCE_REPOSITORY`, `SOURCE_REVISION`,
`SOURCE_DEPLOY_KEY`, and `SOURCE_COMMITMENT_SALT`. These values are never public
inputs. The subject commitment is SHA-256 over a versioned, null-delimited
preimage containing the random salt, canonical source target, and exact source
revision. The private trust plane must calculate it with the same contract.

The policy commitment is the SHA-256 commitment of the complete canonical
private evidence bundle reviewed by the human. The bundle and its preimage
remain private. The public authority preserves that commitment byte-for-byte
in the accepted decision.

```text
SHA256(
  UTF8("sdlc-authority-subject-v1") || 0x00 ||
  UTF8(SOURCE_COMMITMENT_SALT)      || 0x00 ||
  UTF8(SOURCE_REPOSITORY)           || 0x00 ||
  UTF8(SOURCE_REVISION)
)
```

The job fails closed when a secret, Bubblewrap, the fixed entrypoint, or any
verification condition is unavailable.

## Local verification

```sh
python3 -m unittest discover -s tests -v
```

See [the privacy contract](docs/privacy-contract.md) before changing any input,
artifact, log, or workflow.
