import json
import pytest
from jep_authority.runtime import AuthorityError, DelegationRuntime, replay_archive


def test_actor_binding_and_scope_ids_cannot_be_replaced():
    runtime = DelegationRuntime()
    runtime.create_scope(scope_id="root", actor="owner", subject="worker", allowed_actions=["read"])
    with pytest.raises(AuthorityError, match="parent subject"):
        runtime.delegate_scope(parent_scope="root", actor="stranger", subject="child")
    runtime.revoke_scope("root", "2020-01-01T00:00:00Z")
    with pytest.raises(AuthorityError, match="already exists"):
        runtime.create_scope(scope_id="root", actor="owner", subject="worker", allowed_actions=["read"])


def test_historical_delegation_uses_recorded_time(tmp_path):
    rows = [
        {"event": "create_scope", "scope_id": "root", "actor": "owner", "subject": "worker", "allowed_actions": ["read"], "expires_at": "2021-01-01T00:00:00Z"},
        {"event": "delegate_scope", "scope_id": "child", "parent_scope": "root", "actor": "worker", "subject": "child", "at": "2020-01-01T00:00:00Z"},
        {"event": "action", "scope_id": "child", "action": "read", "resource": "file", "at": "2020-02-01T00:00:00Z"},
    ]
    path = tmp_path / "archive.jsonl"
    path.write_text("\n".join(map(json.dumps, rows)))
    assert replay_archive(path).ok
    rows[-1]["expect"] = "deny"
    path.write_text("\n".join(map(json.dumps, rows)))
    assert not replay_archive(path, verify_only=True).ok
