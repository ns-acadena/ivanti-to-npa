"""Verify list_* methods tolerate both wrapped-dict and plain-list response
shapes (real tenant returned the plain-list shape for NPA rules, which
previously crashed). Not part of the shipped tool."""
from unittest.mock import patch

from netskope_client import NetskopeClient


def _client():
    return NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok", dry_run=False)


def test_npa_rules_as_plain_list_shape():
    # list_npa_policies() also normalizes an "id" field onto every item now
    # (real rule objects use "rule_id", not "id" -- see
    # _smoketest_rule_data_schema.py), so check the meaningful fields rather
    # than exact dict equality.
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"rule_name": "r1"}, {"rule_name": "r2"}]}):
        result = c.list_npa_policies()
    assert [r["rule_name"] for r in result] == ["r1", "r2"]
    print("PASS: list_npa_policies handles {'data': [...]} (the shape the real tenant returned)")


def test_npa_rules_as_wrapped_dict_shape():
    c = _client()
    with patch.object(c, "_request", return_value={"data": {"rules": [{"rule_name": "r1"}]}}):
        result = c.list_npa_policies()
    assert [r["rule_name"] for r in result] == ["r1"]
    print("PASS: list_npa_policies still handles {'data': {'rules': [...]}}")


def test_private_apps_both_shapes():
    # list_private_apps() also normalizes "app_id" onto "id" and strips
    # brackets from app_name now (see _smoketest_private_app_id_name_fix.py
    # for full coverage) -- check the meaningful field, not exact equality.
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"app_name": "a1"}]}):
        assert [a["app_name"] for a in c.list_private_apps()] == ["a1"]
    with patch.object(c, "_request", return_value={"data": {"private_apps": [{"app_name": "a2"}]}}):
        assert [a["app_name"] for a in c.list_private_apps()] == ["a2"]
    print("PASS: list_private_apps handles both shapes")


def test_publishers_both_shapes():
    # list_publishers() normalizes id/name onto every item (see
    # _smoketest_publisher_aliases.py for full alias-matching coverage) --
    # here we're only confirming both list-vs-wrapped-dict response shapes
    # are extracted correctly, so we just check the normalized "name".
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"name": "p1"}]}):
        result = c.list_publishers()
        assert [p["name"] for p in result] == ["p1"]
    with patch.object(c, "_request", return_value={"data": {"publishers": [{"name": "p2"}]}}):
        result = c.list_publishers()
        assert [p["name"] for p in result] == ["p2"]
    print("PASS: list_publishers handles both shapes")


def test_empty_or_missing_data_key_does_not_crash():
    c = _client()
    with patch.object(c, "_request", return_value={}):
        assert c.list_npa_policies() == []
        assert c.list_private_apps() == []
        assert c.list_publishers() == []
    print("PASS: missing 'data' key returns [] instead of crashing")


if __name__ == "__main__":
    test_npa_rules_as_plain_list_shape()
    test_npa_rules_as_wrapped_dict_shape()
    test_private_apps_both_shapes()
    test_publishers_both_shapes()
    test_empty_or_missing_data_key_does_not_crash()
    print("\nALL RESPONSE-SHAPE CHECKS PASSED")
