"""Verify the post-apply verification step. Not part of the shipped tool."""
from runlog import RunLogEntry
from validation import verify_creation


class FakeClient:
    def __init__(self, apps=None, policies=None, tags=None):
        self.apps = apps or []
        self.policies = policies or []
        self.tags = tags or []
        self.calls = 0

    def list_private_apps(self):
        self.calls += 1
        return self.apps

    def list_npa_policies(self):
        return self.policies

    def list_private_app_tags(self):
        return self.tags


def test_all_verified():
    entries = [
        RunLogEntry(type="private_app", id="1", name="App-A", created_at="x"),
        RunLogEntry(type="npa_policy", id="10", name="Policy-A", created_at="x"),
    ]
    client = FakeClient(
        apps=[{"id": "1", "app_name": "App-A"}],
        policies=[{"id": "10", "rule_name": "Policy-A"}],
    )
    report = verify_creation(client, entries, retries=3, delay_seconds=0)
    assert report.all_verified
    assert client.calls == 1, "should succeed on the first pull, no retries needed"
    print("PASS: all objects verified present on first check")


def test_missing_after_retries_reported():
    entries = [
        RunLogEntry(type="private_app", id="1", name="App-A", created_at="x"),
        RunLogEntry(type="private_app", id="2", name="App-B", created_at="x"),
    ]
    # App-B never shows up, simulating a create that silently didn't stick
    client = FakeClient(apps=[{"id": "1", "app_name": "App-A"}])
    report = verify_creation(client, entries, retries=3, delay_seconds=0)
    assert not report.all_verified
    assert [e.name for e in report.missing] == ["App-B"]
    assert [e.name for e in report.verified] == ["App-A"]
    assert client.calls == 3, "should retry up to the configured max before giving up"
    msgs = report.describe_missing()
    assert "App-B" in msgs[0]
    print("PASS: a genuinely missing object is retried, then correctly reported as missing")


def test_appears_on_a_later_retry():
    entries = [RunLogEntry(type="private_app", id="1", name="App-A", created_at="x")]

    class SlowFakeClient(FakeClient):
        def list_private_apps(self):
            self.calls += 1
            # Not visible on first pull, visible from the second pull onward
            return [{"id": "1", "app_name": "App-A"}] if self.calls >= 2 else []

    client = SlowFakeClient()
    report = verify_creation(client, entries, retries=3, delay_seconds=0)
    assert report.all_verified
    assert client.calls == 2
    print("PASS: an object that only appears after a propagation delay is still confirmed (via retry)")


def test_matches_by_name_if_id_type_differs():
    # Some tenants might return an int id while the run log stored it as a
    # string (or vice versa) -- name matching is the fallback.
    entries = [RunLogEntry(type="npa_policy", id="999-does-not-match", name="Policy-A", created_at="x")]
    client = FakeClient(policies=[{"id": 42, "rule_name": "Policy-A"}])
    report = verify_creation(client, entries, retries=1, delay_seconds=0)
    assert report.all_verified
    print("PASS: falls back to name match when id doesn't line up")


def test_empty_created_list_short_circuits():
    client = FakeClient()
    report = verify_creation(client, [], retries=3, delay_seconds=0)
    assert report.all_verified
    assert client.calls == 0, "should not even call the API if nothing was created"
    print("PASS: nothing created -> no verification calls, trivially verified")


if __name__ == "__main__":
    test_all_verified()
    test_missing_after_retries_reported()
    test_appears_on_a_later_retry()
    test_matches_by_name_if_id_type_differs()
    test_empty_created_list_short_circuits()
    print("\nALL VERIFICATION CHECKS PASSED")
