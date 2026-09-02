"""Verify list_private_apps() normalizes id (real field is "app_id", not
"id") and strips the brackets Netskope wraps app_name in -- confirmed
against a real tenant. Before this fix, a genuinely created private app
was reported "not found" by post-apply verification (id never matched
since only "app_id" exists on list results; name never matched since the
list returns "[Corp-Intranet]" but the plan recorded "Corp-Intranet"), and
-- more seriously -- the pre-flight conflict check could have missed a
real pre-existing app with a colliding name for the same reason. Not part
of the shipped tool."""
from unittest.mock import patch

from netskope_client import NetskopeClient
from validation import check_for_conflicts, verify_creation
from mapper import PublisherRef, PrivateAppPlan, MigrationPlan
from runlog import RunLogEntry


# Real (redacted) shapes confirmed from a live tenant.
REAL_CREATE_RESPONSE = {
    "data": {
        "app_id": 215,
        "app_name": "[Corp-Intranet]",
        "id": 215,
        "name": "[Corp-Intranet]",
        "host": "intranet.corp.example.com",
    },
    "status": "success",
}

REAL_LIST_RESPONSE = {
    "data": {
        "private_apps": [
            {
                "app_id": 215,
                "app_name": "[Corp-Intranet]",
                "host": "intranet.corp.example.com",
                # NOTE: no "id" key at all -- confirmed, unlike the create response.
            },
            {
                "app_id": 7,
                "app_name": "[NPA-Demo]",
                "host": "192.168.68.97",
            },
        ]
    },
    "status": "success",
}


def _client():
    return NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok", dry_run=False)


def test_list_private_apps_normalizes_app_id_to_id():
    c = _client()
    with patch.object(c, "_request", return_value=REAL_LIST_RESPONSE):
        result = c.list_private_apps()
    assert result[0]["id"] == 215, f"expected app_id normalized onto id, got {result[0]}"
    assert result[0]["app_id"] == 215, "original app_id field preserved too"
    print("PASS: list_private_apps() normalizes the real 'app_id' field onto 'id'")


def test_list_private_apps_strips_brackets_from_app_name():
    c = _client()
    with patch.object(c, "_request", return_value=REAL_LIST_RESPONSE):
        result = c.list_private_apps()
    assert result[0]["app_name"] == "Corp-Intranet", f"expected brackets stripped, got {result[0]['app_name']!r}"
    assert result[1]["app_name"] == "NPA-Demo"
    print("PASS: list_private_apps() strips the brackets Netskope wraps app_name in")


def test_find_private_app_by_name_works_against_bracketed_tenant_data():
    c = _client()
    with patch.object(c, "_request", return_value=REAL_LIST_RESPONSE):
        found = c.find_private_app_by_name("Corp-Intranet")
    assert found is not None, "a plain plan name must still find the bracketed real app"
    assert found["id"] == 215
    print("PASS: find_private_app_by_name() matches a plain name against the tenant's bracketed app_name")


def test_conflict_check_now_detects_a_colliding_bracketed_app_name():
    # This is the more serious half of the bug: before stripping brackets,
    # a real pre-existing app named "Corp-Intranet" (stored as
    # "[Corp-Intranet]") would NOT have been flagged as a conflict, risking
    # a duplicate create. Confirm it's caught now.
    c = _client()
    with patch.object(c, "_request", return_value=REAL_LIST_RESPONSE):
        existing_apps = c.list_private_apps()

    plan = MigrationPlan(private_apps=[
        PrivateAppPlan(
            source_profile="Corp-Intranet", app_name="Corp-Intranet", host="intranet.corp.example.com",
            protocols=[], clientless_access=False, publishers=[PublisherRef("1", "p1")], tags=[],
        )
    ])
    report = check_for_conflicts(plan, existing_apps, [])
    assert report.has_conflicts
    assert "Corp-Intranet" in report.conflicting_app_names
    print("PASS: the pre-flight conflict check now correctly detects a colliding bracketed app name")


def test_verification_now_confirms_a_real_create_by_id():
    c = _client()
    with patch.object(c, "list_private_apps", return_value=[
        {"id": 215, "app_id": 215, "app_name": "Corp-Intranet"},
    ]), patch.object(c, "list_npa_policies", return_value=[]):
        entry = RunLogEntry(type="private_app", id="215", name="Corp-Intranet", created_at="2026-08-31T20:08:04Z")
        report = verify_creation(c, [entry], retries=1, delay_seconds=0)
    assert report.all_verified, f"expected verification to succeed, missing: {report.missing}"
    print("PASS: verify_creation() now correctly confirms a real private app create by id")


def test_create_private_app_id_extraction_handles_the_real_response_shape():
    # Sanity check on the actual confirmed create response shape (both id
    # and app_id present, with brackets on the name -- id extraction should
    # be unaffected by the bracket issue since it never looks at app_name).
    from netskope_client import _first
    data = REAL_CREATE_RESPONSE["data"]
    app_id = _first(data, "id", "app_id", "appId")
    assert app_id == 215
    print("PASS: the real create response's id is extracted correctly regardless of the app_name bracket issue")


if __name__ == "__main__":
    test_list_private_apps_normalizes_app_id_to_id()
    test_list_private_apps_strips_brackets_from_app_name()
    test_find_private_app_by_name_works_against_bracketed_tenant_data()
    test_conflict_check_now_detects_a_colliding_bracketed_app_name()
    test_verification_now_confirms_a_real_create_by_id()
    test_create_private_app_id_extraction_handles_the_real_response_shape()
    print("\nALL PRIVATE-APP ID/NAME FIX CHECKS PASSED")
