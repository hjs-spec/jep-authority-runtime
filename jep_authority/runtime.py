"""Reference authority semantics for JEP delegation archives.

This module intentionally does not implement real IAM and does not replace
OAuth, X.509, DID, or any production identity/security protocol.  It provides a
small deterministic runtime for checking JEP-compatible authority propagation:
allowed/denied actions, resource attenuation, expiration, revocation, and
parent-chain continuity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class AuthorityError(ValueError):
    """Raised when an authority operation violates scope semantics."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse_time(value: str | datetime | None) -> datetime | None:
    """Parse UTC-ish timestamps accepted by archive events."""
    if value is None or isinstance(value, datetime):
        return value
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def format_time(value: datetime | None) -> str | None:
    """Format timestamps as stable UTC strings."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime(ISO_FORMAT)


def _as_set(values: Iterable[str] | None) -> set[str]:
    return set(values or [])


def _resource_within(child: str, parent: str) -> bool:
    """Return whether child resource scope is equal to or narrower than parent.

    The reference runtime uses simple prefix resource semantics.  The wildcard
    "*" grants every resource; otherwise a child resource is in scope when it is
    equal to the parent resource or is a slash-delimited descendant of it.
    """
    if parent == "*":
        return True
    if child == parent:
        return True
    normalized_parent = parent.rstrip("/") + "/"
    return child.startswith(normalized_parent)


@dataclass(slots=True)
class AuthorityScope:
    """Delegable authority scope used by the reference runtime."""

    actor: str
    subject: str
    allowed_actions: set[str] = field(default_factory=set)
    denied_actions: set[str] = field(default_factory=set)
    resource_scope: str = "*"
    expires_at: datetime | None = None
    parent_scope: str | None = None
    attenuation_rules: dict[str, Any] = field(default_factory=dict)
    scope_id: str = field(default_factory=lambda: f"scope-{uuid4().hex}")
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        self.allowed_actions = _as_set(self.allowed_actions)
        self.denied_actions = _as_set(self.denied_actions)
        self.expires_at = parse_time(self.expires_at)
        self.revoked_at = parse_time(self.revoked_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "actor": self.actor,
            "subject": self.subject,
            "allowed_actions": sorted(self.allowed_actions),
            "denied_actions": sorted(self.denied_actions),
            "resource_scope": self.resource_scope,
            "expires_at": format_time(self.expires_at),
            "parent_scope": self.parent_scope,
            "attenuation_rules": self.attenuation_rules,
            "revoked_at": format_time(self.revoked_at),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuthorityScope":
        return cls(
            scope_id=str(payload.get("scope_id") or f"scope-{uuid4().hex}"),
            actor=str(payload["actor"]),
            subject=str(payload["subject"]),
            allowed_actions=set(payload.get("allowed_actions") or []),
            denied_actions=set(payload.get("denied_actions") or []),
            resource_scope=str(payload.get("resource_scope") or "*"),
            expires_at=parse_time(payload.get("expires_at")),
            parent_scope=payload.get("parent_scope"),
            attenuation_rules=dict(payload.get("attenuation_rules") or {}),
            revoked_at=parse_time(payload.get("revoked_at")),
        )

    def permits(self, action: str, resource: str, at: datetime | None = None) -> tuple[bool, str]:
        checked_at = at or _utc_now()
        if self.revoked_at is not None and checked_at >= self.revoked_at:
            return False, "scope revoked"
        if self.expires_at is not None and checked_at > self.expires_at:
            return False, "scope expired"
        if action in self.denied_actions:
            return False, "action denied"
        if action not in self.allowed_actions:
            return False, "action not allowed"
        if not _resource_within(resource, self.resource_scope):
            return False, "resource out of scope"
        return True, "ok"


@dataclass(slots=True)
class VerificationResult:
    ok: bool
    reason: str = "ok"


class DelegationRuntime:
    """In-memory authority runtime for scopes, attenuation, and revocation."""

    def __init__(self) -> None:
        self.scopes: dict[str, AuthorityScope] = {}

    def create_scope(
        self,
        *,
        actor: str,
        subject: str,
        allowed_actions: Iterable[str],
        denied_actions: Iterable[str] | None = None,
        resource_scope: str = "*",
        expires_at: str | datetime | None = None,
        attenuation_rules: Mapping[str, Any] | None = None,
        scope_id: str | None = None,
    ) -> AuthorityScope:
        scope = AuthorityScope(
            scope_id=scope_id or f"scope-{uuid4().hex}",
            actor=actor,
            subject=subject,
            allowed_actions=set(allowed_actions),
            denied_actions=set(denied_actions or []),
            resource_scope=resource_scope,
            expires_at=parse_time(expires_at),
            parent_scope=None,
            attenuation_rules=dict(attenuation_rules or {}),
        )
        self.scopes[scope.scope_id] = scope
        return scope

    def delegate_scope(
        self,
        *,
        parent_scope: str,
        actor: str,
        subject: str,
        allowed_actions: Iterable[str] | None = None,
        denied_actions: Iterable[str] | None = None,
        resource_scope: str | None = None,
        expires_at: str | datetime | None = None,
        attenuation_rules: Mapping[str, Any] | None = None,
        scope_id: str | None = None,
    ) -> AuthorityScope:
        parent = self._require_scope(parent_scope)
        allowed = set(allowed_actions) if allowed_actions is not None else set(parent.allowed_actions)
        denied = parent.denied_actions | set(denied_actions or [])
        child_resource = resource_scope or parent.resource_scope
        child_expires = parse_time(expires_at) or parent.expires_at
        child = AuthorityScope(
            scope_id=scope_id or f"scope-{uuid4().hex}",
            actor=actor,
            subject=subject,
            allowed_actions=allowed,
            denied_actions=denied,
            resource_scope=child_resource,
            expires_at=child_expires,
            parent_scope=parent.scope_id,
            attenuation_rules={**parent.attenuation_rules, **dict(attenuation_rules or {})},
        )
        result = self.verify_delegation_path(child)
        if not result.ok:
            raise AuthorityError(result.reason)
        self.scopes[child.scope_id] = child
        return child

    def attenuate_scope(self, scope_id: str, **updates: Any) -> AuthorityScope:
        existing = self._require_scope(scope_id)
        return self.delegate_scope(
            parent_scope=scope_id,
            actor=updates.get("actor", existing.subject),
            subject=updates["subject"],
            allowed_actions=updates.get("allowed_actions", existing.allowed_actions),
            denied_actions=updates.get("denied_actions", set()),
            resource_scope=updates.get("resource_scope", existing.resource_scope),
            expires_at=updates.get("expires_at", existing.expires_at),
            attenuation_rules=updates.get("attenuation_rules", {}),
            scope_id=updates.get("scope_id"),
        )

    def revoke_scope(self, scope_id: str, revoked_at: str | datetime | None = None) -> AuthorityScope:
        scope = self._require_scope(scope_id)
        scope.revoked_at = parse_time(revoked_at) or _utc_now()
        return scope

    def verify_scope(
        self,
        scope_id: str,
        *,
        action: str,
        resource: str,
        at: str | datetime | None = None,
    ) -> VerificationResult:
        scope = self._require_scope(scope_id)
        ok, reason = scope.permits(action, resource, parse_time(at))
        if not ok:
            return VerificationResult(False, reason)
        path = self.verify_delegation_path(scope, at=parse_time(at))
        if not path.ok:
            return path
        return VerificationResult(True)

    def verify_delegation_path(
        self,
        scope_or_id: AuthorityScope | str,
        *,
        at: str | datetime | None = None,
    ) -> VerificationResult:
        scope = self._require_scope(scope_or_id) if isinstance(scope_or_id, str) else scope_or_id
        checked_at = parse_time(at) or _utc_now()
        if scope.revoked_at is not None and checked_at >= scope.revoked_at:
            return VerificationResult(False, "scope revoked")
        if scope.expires_at is not None and checked_at > scope.expires_at:
            return VerificationResult(False, "scope expired")
        seen: set[str] = set()
        child = scope
        while child.parent_scope is not None:
            if child.scope_id in seen:
                return VerificationResult(False, "delegation chain cycle")
            seen.add(child.scope_id)
            parent = self.scopes.get(child.parent_scope)
            if parent is None:
                return VerificationResult(False, "delegation chain broken")
            if parent.revoked_at is not None and checked_at >= parent.revoked_at:
                return VerificationResult(False, "parent scope revoked")
            if parent.expires_at is not None and checked_at > parent.expires_at:
                return VerificationResult(False, "parent scope expired")
            if not child.allowed_actions <= parent.allowed_actions:
                return VerificationResult(False, "child allows actions outside parent scope")
            if not parent.denied_actions <= child.denied_actions:
                return VerificationResult(False, "child omits parent denied actions")
            if child.allowed_actions & parent.denied_actions:
                return VerificationResult(False, "child allows parent-denied action")
            if not _resource_within(child.resource_scope, parent.resource_scope):
                return VerificationResult(False, "child resource outside parent scope")
            if parent.expires_at is not None and (child.expires_at is None or child.expires_at > parent.expires_at):
                return VerificationResult(False, "child expires after parent")
            child = parent
        return VerificationResult(True)

    def _require_scope(self, scope_id: str) -> AuthorityScope:
        try:
            return self.scopes[scope_id]
        except KeyError as exc:
            raise AuthorityError(f"unknown scope: {scope_id}") from exc


@dataclass(slots=True)
class ReplayEvent:
    line: int
    event: str
    payload: dict[str, Any]


@dataclass(slots=True)
class ReplayViolation:
    line: int
    event: str
    reason: str
    payload: dict[str, Any]


@dataclass(slots=True)
class ReplayReport:
    ok: bool
    events: int
    violations: list[ReplayViolation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "events": self.events,
            "violations": [
                {
                    "line": violation.line,
                    "event": violation.event,
                    "reason": violation.reason,
                    "payload": violation.payload,
                }
                for violation in self.violations
            ],
        }


def load_archive(path: str | Path) -> list[ReplayEvent]:
    events: list[ReplayEvent] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            stripped = raw.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            event = str(payload.get("event") or payload.get("type") or "")
            events.append(ReplayEvent(line_number, event, payload))
    return events


def replay_archive(path: str | Path, *, verify_only: bool = False) -> ReplayReport:
    """Replay an archive.jsonl and report authority propagation violations."""
    runtime = DelegationRuntime()
    violations: list[ReplayViolation] = []
    events = load_archive(path)

    for item in events:
        try:
            _apply_event(runtime, item, verify_only=verify_only)
        except (AuthorityError, KeyError, TypeError, ValueError) as exc:
            violations.append(ReplayViolation(item.line, item.event, str(exc), item.payload))

    return ReplayReport(ok=not violations, events=len(events), violations=violations)


def _apply_event(runtime: DelegationRuntime, item: ReplayEvent, *, verify_only: bool) -> None:
    payload = item.payload
    event = item.event
    if event == "create_scope":
        runtime.create_scope(
            scope_id=payload.get("scope_id"),
            actor=payload["actor"],
            subject=payload["subject"],
            allowed_actions=payload.get("allowed_actions") or [],
            denied_actions=payload.get("denied_actions") or [],
            resource_scope=payload.get("resource_scope") or "*",
            expires_at=payload.get("expires_at"),
            attenuation_rules=payload.get("attenuation_rules") or {},
        )
        return
    if event in {"delegate_scope", "attenuate_scope"}:
        runtime.delegate_scope(
            scope_id=payload.get("scope_id"),
            parent_scope=payload["parent_scope"],
            actor=payload["actor"],
            subject=payload["subject"],
            allowed_actions=payload.get("allowed_actions"),
            denied_actions=payload.get("denied_actions") or [],
            resource_scope=payload.get("resource_scope"),
            expires_at=payload.get("expires_at"),
            attenuation_rules=payload.get("attenuation_rules") or {},
        )
        return
    if event == "revoke_scope":
        runtime.revoke_scope(payload["scope_id"], payload.get("revoked_at") or payload.get("at"))
        return
    if event in {"action", "verify_scope"}:
        result = runtime.verify_scope(
            payload["scope_id"],
            action=payload["action"],
            resource=payload["resource"],
            at=payload.get("at"),
        )
        expected = payload.get("expect")
        if expected in {"deny", "denied", False}:
            if result.ok and not verify_only:
                raise AuthorityError("expected denial but action was allowed")
            return
        if not result.ok:
            raise AuthorityError(result.reason)
        return
    if event == "verify_delegation_path":
        result = runtime.verify_delegation_path(payload["scope_id"], at=payload.get("at"))
        if not result.ok:
            raise AuthorityError(result.reason)
        return
    raise AuthorityError(f"unknown event: {event}")
