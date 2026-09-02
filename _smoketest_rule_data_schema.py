"""Verify the NPA policy create payload matches the real schema confirmed
from a live tenant's GET /api/v2/policy/npa/rules response, and that a 2xx
HTTP response with an error-shaped body is treated as a failure instead of
a silent success. Not part of the shipped tool.

Root cause this covers: earlier versions of to_payload() sent privateApps/
userGroups/etc. as top-level fields with no "rule_data" wrapper. The real
API accepted the HTTP request (200 OK) but rejected the payload with
{"status": "error", "message": "Missing rule_data when creating a policy"}
in the body -- which the client didn't check, so the tool logged
"Created policy ... (id=None)" and moved on even though nothing was
created. Both halves of the fix are covered here: the payload shape, and
the response-body error detection.
"""
from unittest.mock import patch

from mapper import NpaPolicyPlan
from netskope_client import NetskopeApiError, NetskopeClient


def test_policy_payload_wraps_fields_in_rule_data():
    pol = NpaPolicyPlan(
        rule_name="ivanti-import-Employees-Full",
        private_app_names=["Corp-Intranet", "SSH-Bastion"],
        user_groups=["Employees-Full"],
        description="test",
    )
    payload = pol.to_payload(group_id="10", group_name="Ivanti Import")

    # Top-level shape matches the real object: rule_name/enabled/policy_type
    # at top level, everything else nested under rule_data.
    assert payload["rule_name"] == "ivanti-import-Employees-Full"
    assert payload["enabled"] == "1"
    assert payload["policy_type"] == "private-app"
    assert "rule_data" in payload, "rule_data wrapper is required -- its absence is exactly what broke this before"
    assert payload["group_id"] == "10" and payload["group_name"] == "Ivanti Import"

    rd = payload["rule_data"]
    assert rd["policy_type"] == "private-app"
    assert rd["match_criteria_action"] == {"action_name": "allow"}
    assert rd["access_method"] == ["Client"]
    assert rd["userType"] == "user"
    assert rd["json_version"] == 3
    # Private app names are wrapped in brackets in the real object
    # ("[AWS-RDP]", not "AWS-RDP") -- reproduced here for fidelity.
    assert rd["privateApps"] == ["[Corp-Intranet]", "[SSH-Bastion]"]
    assert rd["userGroups"] == ["Employees-Full"]
    print("PASS: policy payload nests fields under rule_data, matching the confirmed real schema")


def test_user_group_objects_sent_alongside_user_groups():
    # Confirmed real schema (AWS-RDP, rule_id 67 -- a rule the operator
    # verified is in a real Policy Group and scoped to a real user group):
    # userGroups (names) and userGroupObjects (id+name) are both present.
    pol = NpaPolicyPlan(
        rule_name="ivanti-import-Employees-Full",
        private_app_names=["Corp-Intranet"],
        user_groups=["Employees-Full"],
        description="test",
    )
    payload = pol.to_payload(
        user_group_objects=[{"id": "207", "name": "Employees-Full"}],
    )
    rd = payload["rule_data"]
    assert rd["userGroups"] == ["Employees-Full"]
    assert rd["userGroupObjects"] == [{"id": "207", "name": "Employees-Full"}]
    print("PASS: userGroupObjects (id+name) is sent alongside userGroups when the caller supplies it")


def test_no_user_group_objects_when_not_supplied():
    pol = NpaPolicyPlan(
        rule_name="x", private_app_names=["A"], user_groups=["G"], description="",
    )
    payload = pol.to_payload()  # no user_group_objects passed
    assert "userGroupObjects" not in payload["rule_data"]
    print("PASS: userGroupObjects is omitted (not sent as an empty/null field) when the caller has nothing to give it")


def test_omit_user_groups_still_nested_correctly():
    pol = NpaPolicyPlan(
        rule_name="ivanti-import-Partner-LimitedAccess",
        private_app_names=["Finance-App-DB"],
        user_groups=["Partner-LimitedAccess"],
        description="test",
    )
    payload = pol.to_payload(omit_user_groups=True)
    assert "userGroups" not in payload["rule_data"]
    assert "rule_data" in payload
    print("PASS: an open (no-group) policy still gets a valid rule_data wrapper, just without userGroups inside it")


def test_2xx_error_body_raises_instead_of_silently_succeeding():
    # This is the actual response body reported from a real tenant when the
    # rule_data wrapper was missing -- HTTP 200, but an error in the JSON.
    client = NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok", dry_run=False)

    class FakeResp:
        status_code = 200
        content = b'{"status": "error", "message": "Missing rule_data when creating a policy"}'
        text = content.decode()
        def json(self):
            return {"status": "error", "message": "Missing rule_data when creating a policy"}

    with patch.object(client._session, "request", return_value=FakeResp()):
        try:
            client.create_npa_policy({"rule_name": "x"})
            raised = False
        except NetskopeApiError as e:
            raised = True
            assert "Missing rule_data" in str(e)
    assert raised, "a 200 response with an error-shaped body must raise, not be treated as a success"
    print("PASS: HTTP 200 + {'status': 'error', ...} body now raises NetskopeApiError instead of looking like a success")


def test_2xx_success_body_still_passes_through_normally():
    client = NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok", dry_run=False)

    class FakeResp:
        status_code = 200
        content = b'{"data": {"rule_id": "67"}, "status": "success"}'
        text = content.decode()
        def json(self):
            return {"data": {"rule_id": "67"}, "status": "success"}

    with patch.object(client._session, "request", return_value=FakeResp()):
        result = client.create_npa_policy({"rule_name": "x"})
    assert result["data"]["rule_id"] == "67"
    print("PASS: a normal 200 + success body is unaffected by the new error-body check")


def test_list_npa_policies_normalizes_rule_id_to_id():
    client = NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok", dry_run=False)
    with patch.object(client, "_request", return_value={"data": [{"rule_id": "67", "rule_name": "AWS-RDP"}]}):
        result = client.list_npa_policies()
    assert result[0]["id"] == "67", "rule_id must be normalized onto 'id' the same way publishers/groups are"
    assert result[0]["rule_id"] == "67", "original field is preserved too"
    print("PASS: list_npa_policies() normalizes the real 'rule_id' field onto 'id' for id-based matching")


if __name__ == "__main__":
    test_policy_payload_wraps_fields_in_rule_data()
    test_user_group_objects_sent_alongside_user_groups()
    test_no_user_group_objects_when_not_supplied()
    test_omit_user_groups_still_nested_correctly()
    test_2xx_error_body_raises_instead_of_silently_succeeding()
    test_2xx_success_body_still_passes_through_normally()
    test_list_npa_policies_normalizes_rule_id_to_id()
    print("\nALL RULE_DATA SCHEMA / SILENT-FAILURE CHECKS PASSED")
