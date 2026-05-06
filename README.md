# jep-authority-runtime

Reference runtime for JEP authority scope, delegation boundaries, attenuation, revocation, and replay verification.

This project is intentionally **not** real IAM and does not replace OAuth, X.509, DID, or any production authorization protocol. It is a small JEP-compatible reference runtime for making delegation semantics replayable and verifiable.

## AuthorityScope

`AuthorityScope` models the authority passed along a delegation chain:

- `actor`: principal that issued the scope.
- `subject`: principal receiving the scope.
- `allowed_actions`: actions the subject may perform.
- `denied_actions`: actions explicitly forbidden and inherited by descendants.
- `resource_scope`: resource prefix the scope applies to (`*` means every resource).
- `expires_at`: optional UTC expiration timestamp.
- `parent_scope`: optional parent scope id for delegated or attenuated authority.
- `attenuation_rules`: reference metadata describing how authority was narrowed.

The runtime also stores `scope_id` and `revoked_at` so archives can refer to scopes deterministically and model revocation.

## DelegationRuntime

`DelegationRuntime` provides:

- `create_scope()` for root authority grants.
- `delegate_scope()` for child scopes that must be narrower than their parent.
- `attenuate_scope()` as a convenience wrapper for narrower delegation.
- `revoke_scope()` to invalidate a scope and its descendants for later checks.
- `verify_scope()` to check action, resource, expiration, revocation, and chain validity.
- `verify_delegation_path()` to check parent continuity and attenuation constraints.

A child scope is valid only when it does not add actions, omit inherited denials, widen resources, outlive its parent, or rely on a missing/revoked/expired parent.

## Replay archive format

Archives are JSON Lines (`archive.jsonl`). Each line is an event with an `event` field:

```json
{"event":"create_scope","scope_id":"human-search","actor":"human:alice","subject":"agent:searcher","allowed_actions":["search"],"denied_actions":["payment"],"resource_scope":"web/search","expires_at":"2030-01-01T00:00:00Z"}
{"event":"delegate_scope","scope_id":"agent-news","parent_scope":"human-search","actor":"agent:searcher","subject":"agent:sub-searcher","allowed_actions":["search"],"resource_scope":"web/search/news"}
{"event":"action","scope_id":"agent-news","action":"search","resource":"web/search/news/politics","at":"2028-01-01T00:00:00Z"}
{"event":"revoke_scope","scope_id":"human-search","revoked_at":"2028-06-01T00:00:00Z"}
```

Replay checks whether propagation or actions are invalid because authority is exceeded, a scope is expired, a scope or ancestor is revoked, a child exceeds the parent scope, or the delegation chain is broken.

## CLI

Install in editable mode:

```sh
python -m pip install -e .
```

Replay an archive:

```sh
jep-authority replay examples/archive.jsonl
```

Verify an archive and emit JSON:

```sh
jep-authority verify examples/archive.jsonl --json
```

Both commands exit with status `0` when the report has no violations and `1` when violations are found.

## Example scenario

`examples/archive.jsonl` demonstrates:

1. A human delegates limited `search` permission to an agent.
2. The agent delegates narrower `web/search/news` permission to a sub-agent.
3. The sub-agent performs an allowed search.
4. The sub-agent attempts a forbidden `payment` action.
5. Revocation of the parent invalidates a later delegated action.
