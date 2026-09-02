"""Verify every generated NPA policy's description carries a long-format
UTC 'Imported <date>' timestamp, computed once per plan build so plan.json
(the preview) and the actual --apply create calls agree. Not part of the
shipped tool."""
from datetime import datetime, timezone

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan, _format_imported_at


def build_plan(imported_at=None):
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], imported_at=imported_at)


def test_long_format_matches_expected_style():
    dt = datetime(2026, 8, 31, 16, 5, 0, tzinfo=timezone.utc)
    assert _format_imported_at(dt) == "Monday, August 31, 2026 at 04:05 PM UTC"
    print("PASS: _format_imported_at renders the expected long-format string")


def test_every_policy_description_includes_the_timestamp():
    dt = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    plan = build_plan(imported_at=dt)
    assert plan.policies, "no policies to check"
    expected = "Imported Thursday, January 15, 2026 at 09:00 AM UTC."
    for pol in plan.policies:
        assert expected in pol.description, f"missing/wrong timestamp in: {pol.description!r}"
    print("PASS: every generated policy's description includes the same import timestamp")


def test_naive_local_time_is_converted_to_utc():
    # A naive datetime (no tzinfo) should still work via astimezone(), which
    # treats it as local time and converts -- but to keep this test
    # deterministic across machines, only check that it doesn't crash and
    # produces a well-formed string ending in "UTC".
    dt = datetime(2026, 6, 1, 12, 0, 0)  # naive
    result = _format_imported_at(dt)
    assert result.endswith("UTC"), f"expected a UTC-suffixed string, got {result!r}"
    print("PASS: a naive datetime doesn't crash formatting and still renders a UTC-suffixed string")


def test_defaults_to_now_when_not_given():
    before = datetime.now(timezone.utc)
    plan = build_plan()  # no imported_at passed
    after = datetime.now(timezone.utc)
    assert plan.policies
    # Just confirm SOME "Imported ..." text landed in the description and
    # the run didn't crash -- exact-second matching would be flaky.
    assert "Imported " in plan.policies[0].description
    assert before.year == after.year, "sanity check that the test itself ran fast, not a real assertion on formatting"
    print("PASS: omitting imported_at defaults to the current time without crashing")


def test_same_plan_reused_for_json_and_apply_has_one_consistent_timestamp():
    # Simulates main.py's actual usage: build_migration_plan() is called
    # ONCE, and its result is used both to write plan.json and later to
    # create the real policies -- the timestamp must be identical in both,
    # not recomputed at apply time.
    dt = datetime(2026, 3, 3, 3, 3, 3, tzinfo=timezone.utc)
    plan = build_plan(imported_at=dt)
    payload_1 = plan.policies[0].to_payload()  # e.g. what plan.json would write
    payload_2 = plan.policies[0].to_payload()  # e.g. what apply_plan() would send
    assert payload_1["description"] == payload_2["description"]
    assert "Imported Tuesday, March 03, 2026 at 03:03 AM UTC." in payload_1["description"]
    print("PASS: the same plan object yields an identical timestamp whether written to plan.json or sent on --apply")


if __name__ == "__main__":
    test_long_format_matches_expected_style()
    test_every_policy_description_includes_the_timestamp()
    test_naive_local_time_is_converted_to_utc()
    test_defaults_to_now_when_not_given()
    test_same_plan_reused_for_json_and_apply_has_one_consistent_timestamp()
    print("\nALL DESCRIPTION-TIMESTAMP CHECKS PASSED")
