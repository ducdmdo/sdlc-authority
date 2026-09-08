# Public Authority Privacy Contract

This repository's public surface cannot accept private source material. Its
only public subject inputs are fixed-shape cryptographic commitments. The
approved verification step may transiently fetch one exact private revision
through protected environment credentials and discards it before completion.

## Allowed public request data

- A non-semantic request identifier matching `req-[a-z0-9-]+`
- A non-semantic replay nonce matching `nonce-[a-z0-9]+`
- One opaque subject commitment in `sha256:<64 lowercase hex>` form
- One opaque policy commitment in `sha256:<64 lowercase hex>` form
- UTC timestamps
- GitHub authority-run identifiers, approval digests, and public authority metadata

## Forbidden data

- Source code or patches
- Source repository owner or name
- Source commit SHA, branch, tag, path, or filename
- Commit messages, pull request titles, issue text, or review prose
- Product, domain, feature, customer, patient, or clinical language
- Test names, test output, screenshots, logs, stack traces, or device details
- Credentials, tokens, keys, environment values, or encoded secrets
- Personal, health, analytics, telemetry, or customer data

The opaque commitment must be calculated in the private trust plane. The
canonical preimage remains private. This public repository stores no mapping
from a commitment to its private meaning.

The nonce must be fresh for each request. Private consumers retain accepted
nonces and reject reuse. The policy commitment binds the complete canonical
private evidence bundle that the human reviewed.

Four protected-environment secrets are permitted only inside the isolated
verification job: `SOURCE_REPOSITORY`, `SOURCE_REVISION`, a read-only
`SOURCE_DEPLOY_KEY`, and `SOURCE_COMMITMENT_SALT`. They are never passed to
receipt steps, written to an artifact, printed, or exposed as workflow inputs.
The deploy key and salt are deleted or unset before private code executes.

## Logging rule

Workflows must not echo inputs. Step names and failure messages must remain
generic. Artifacts contain only the fields defined by the strict schemas.
GitHub Actions debug logging must remain disabled for authority runs.
Private verification stdout and stderr are redirected to an ephemeral file,
never printed or uploaded, and deleted before the job ends.

## Retention rule

The decision artifact uses the minimum supported one-day retention. Its GitHub
artifact attestation and workflow-run metadata form the durable public proof.
Consumers archive only the exact decision required by their private audit
policy.

## Change rule

Any expansion of accepted fields or public output is a privacy-sensitive
change. It requires protected-branch review and a passing contract test.
