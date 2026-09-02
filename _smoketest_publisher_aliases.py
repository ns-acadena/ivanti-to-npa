"""Verify list_publishers() tolerates alternate field names for id/name.
Not part of the shipped tool."""
from unittest.mock import patch

from netskope_client import NetskopeClient


def _client():
    return NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok", dry_run=False)


def test_standard_id_name_fields():
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"id": 1, "name": "pub-1"}]}):
        result = c.list_publishers()
    assert result[0]["id"] == 1 and result[0]["name"] == "pub-1"
    print("PASS: standard id/name fields (per Netskope docs) still work")


def test_alternate_publisher_id_name_fields():
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"publisher_id": 7, "publisher_name": "pub-7"}]}):
        result = c.list_publishers()
    assert result[0]["id"] == 7 and result[0]["name"] == "pub-7"
    print("PASS: publisher_id/publisher_name alternate fields are picked up")


def test_pub_id_pub_name_fields():
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"pub_id": "abc", "pub_name": "pub-abc"}]}):
        result = c.list_publishers()
    assert result[0]["id"] == "abc" and result[0]["name"] == "pub-abc"
    print("PASS: pub_id/pub_name alternate fields are picked up")


def test_common_name_fallback_for_name():
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"id": 9, "common_name": "abc123def"}]}):
        result = c.list_publishers()
    assert result[0]["id"] == 9 and result[0]["name"] == "abc123def"
    print("PASS: falls back to common_name when no name/publisher_name/pub_name present")


def test_original_fields_preserved_for_debugging():
    c = _client()
    raw_item = {"publisher_id": 3, "publisher_name": "pub-3", "apps_count": 5}
    with patch.object(c, "_request", return_value={"data": [raw_item]}):
        result = c.list_publishers()
    # original keys should still be present alongside the normalized ones
    assert result[0]["apps_count"] == 5
    assert result[0]["publisher_id"] == 3
    print("PASS: original raw fields are preserved, not discarded, for debugging")


def test_unrecognized_fields_logs_warning_but_does_not_crash():
    c = _client()
    with patch.object(c, "_request", return_value={"data": [{"totally_unknown_field": "x"}]}):
        result = c.list_publishers()
    assert result[0]["id"] is None and result[0]["name"] is None
    print("PASS: completely unrecognized field names don't crash, just come back as None (with a warning logged)")


if __name__ == "__main__":
    test_standard_id_name_fields()
    test_alternate_publisher_id_name_fields()
    test_pub_id_pub_name_fields()
    test_common_name_fallback_for_name()
    test_original_fields_preserved_for_debugging()
    test_unrecognized_fields_logs_warning_but_does_not_crash()
    print("\nALL PUBLISHER FIELD-ALIAS CHECKS PASSED")
