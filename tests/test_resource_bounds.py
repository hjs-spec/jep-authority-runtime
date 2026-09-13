from datetime import datetime, timezone
from jep_authority.runtime import AuthorityScope


def test_resources_do_not_escape_by_path_traversal():
    scope = AuthorityScope(actor="a", subject="b", allowed_actions={"read"}, resource_scope="repo/private")
    for resource in ["repo/private/../public", "repo/private/%2e%2e/public", "repo/private/..\\public", "repo/private2"]:
        assert not scope.permits("read", resource)[0]
    assert scope.permits("read", "repo/private/file")[0]


def test_expiry_is_exclusive():
    end = datetime(2026, 1, 1, tzinfo=timezone.utc)
    scope = AuthorityScope(actor="a", subject="b", allowed_actions={"read"}, expires_at=end)
    assert not scope.permits("read", "anything", end)[0]
