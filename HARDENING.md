# Implementation hardening — September 2026

Enforce actor continuity and deterministic historical delegation checks.

## Changes

A child delegation actor must equal its parent subject. Existing scope IDs cannot be replaced to reset revocation. Repeated revocations preserve the earliest revocation time. Historical operations use the recorded at timestamp, and expected-denial mismatches fail in both replay and verify-only mode.

## Validation

```sh
python -m pytest -q
```

## Compatibility and remaining limits

Replay delegation/action/path-check records now require at; revocations require at or revoked_at. Missing historical time is reported rather than inferred from the current clock. This remains a reference authority model, not an IAM or identity verifier.

## Follow-up hardening

Resource checks reject dot segments, backslashes, and encoded traversal. Expiry is exclusive at expires_at; actor continuity, repeated revocation, and duplicate scope protections from the original hardening remain in place.
