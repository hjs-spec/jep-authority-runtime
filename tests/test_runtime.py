from pathlib import Path
import tempfile
import unittest

from jep_authority.runtime import AuthorityError, DelegationRuntime, replay_archive


class AuthorityRuntimeTests(unittest.TestCase):
    def test_delegation_and_verification(self):
        runtime = DelegationRuntime()
        parent = runtime.create_scope(
            scope_id="human-search",
            actor="human:alice",
            subject="agent:searcher",
            allowed_actions=["search"],
            denied_actions=["payment"],
            resource_scope="web/search",
            expires_at="2030-01-01T00:00:00Z",
        )
        child = runtime.delegate_scope(
            scope_id="agent-news",
            parent_scope=parent.scope_id,
            actor="agent:searcher",
            subject="agent:sub-searcher",
            allowed_actions=["search"],
            resource_scope="web/search/news",
            expires_at="2029-01-01T00:00:00Z",
        )

        self.assertTrue(
            runtime.verify_scope(
                child.scope_id,
                action="search",
                resource="web/search/news/politics",
                at="2028-01-01T00:00:00Z",
            ).ok
        )
        payment = runtime.verify_scope(
            child.scope_id,
            action="payment",
            resource="payments/card",
            at="2028-01-01T00:00:00Z",
        )
        self.assertFalse(payment.ok)
        self.assertEqual(payment.reason, "action denied")

    def test_delegate_cannot_exceed_parent_scope(self):
        runtime = DelegationRuntime()
        runtime.create_scope(
            scope_id="parent",
            actor="human:alice",
            subject="agent:a",
            allowed_actions=["search"],
            resource_scope="web/search",
        )
        with self.assertRaisesRegex(AuthorityError, "outside parent"):
            runtime.delegate_scope(
                scope_id="child",
                parent_scope="parent",
                actor="agent:a",
                subject="agent:b",
                allowed_actions=["payment"],
                resource_scope="web/search",
            )

    def test_replay_reports_revocation_violation(self):
        archive = "\n".join(
            [
                '{"event":"create_scope","scope_id":"s1","actor":"human","subject":"agent","allowed_actions":["search"],"resource_scope":"web/search"}',
                '{"event":"revoke_scope","scope_id":"s1","revoked_at":"2028-01-01T00:00:00Z"}',
                '{"event":"action","scope_id":"s1","action":"search","resource":"web/search/news","at":"2028-01-02T00:00:00Z"}',
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "archive.jsonl"
            path.write_text(archive, encoding="utf-8")
            report = replay_archive(path)
        self.assertFalse(report.ok)
        self.assertEqual(report.violations[0].reason, "scope revoked")

    def test_replay_reports_broken_chain(self):
        archive = '{"event":"delegate_scope","scope_id":"orphan","parent_scope":"missing","actor":"a","subject":"b","allowed_actions":["search"],"resource_scope":"web/search"}\n'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "archive.jsonl"
            path.write_text(archive, encoding="utf-8")
            report = replay_archive(path)
        self.assertFalse(report.ok)
        self.assertIn("unknown scope", report.violations[0].reason)


if __name__ == "__main__":
    unittest.main()
