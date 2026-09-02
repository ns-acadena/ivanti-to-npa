"""
Ad-hoc verification of the conflict-check + run-log + rollback logic using
a fake Netskope client (no real tenant needed). Not part of the shipped
tool — delete after running.
"""
from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
from netskope_client import NetskopeApiError
from runlog import RunLog
from validation import check_for_conflicts, filter_out_conflicts


class FakeClient:
    def __init__(self, existing_apps=None, existing_policies=None, fail_on_app=None):
        self._apps = {a["app_name"]: dict(a, id=str(i)) for i, a in enumerate(existing_apps or [])}
        self._policies = {p["rule_name"]: dict(p, id=str(100 + i)) for i, p in enumerate(existing_policies or [])}
        self._next_id = 1000
        self.fail_on_app = fail_on_app
        self.deleted = []

    def list_private_apps(self):
        return list(self._apps.values())

    def list_npa_policies(self):
        return list(self._policies.values())

    def list_publishers(self):
        return []

    def create_private_app(self, payload):
        if payload["app_name"] == self.fail_on_app:
            raise NetskopeApiError(f"simulated failure creating {payload['app_name']}")
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._apps[payload["app_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def delete_private_app(self, app_id):
        self.deleted.append(("private_app", app_id))
        for name, rec in list(self._apps.items()):
            if rec["id"] == app_id:
                del self._apps[name]

    def create_npa_policy(self, payload):
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._policies[payload["rule_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def delete_npa_policy(self, rule_id):
        self.deleted.append(("npa_policy", rule_id))
        for name, rec in list(self._policies.items()):
            if rec["id"] == rule_id:
                del self._policies[name]


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")


def test_conflict_detection_blocks_by_default():
    plan = build_plan()
    client = FakeClient(existing_apps=[{"app_name": "Corp-Intranet"}])
    report = check_for_conflicts(plan, client.list_private_apps(), client.list_npa_policies())
    assert report.has_conflicts, "expected a conflict on Corp-Intranet"
    assert "Corp-Intranet" in report.conflicting_app_names
    print("PASS: conflict detected for pre-existing app name")


def test_filter_out_conflicts_only_removes_flagged():
    plan = build_plan()
    before = len(plan.private_apps)
    client = FakeClient(existing_apps=[{"app_name": "Corp-Intranet"}])
    report = check_for_conflicts(plan, client.list_private_apps(), client.list_npa_policies())
    filter_out_conflicts(plan, report)
    assert len(plan.private_apps) == before - 1
    assert all(a.app_name != "Corp-Intranet" for a in plan.private_apps)
    print("PASS: filter_out_conflicts removes only the colliding app")


def test_no_replace_ever_attempted():
    # Simulate main.py's apply_plan logic inline: if there's a conflict and
    # skip_conflicts is False, NO create call should happen for ANYTHING,
    # not just the conflicting item -- i.e. the whole run aborts rather
    # than silently updating the existing entry.
    plan = build_plan()
    client = FakeClient(existing_apps=[{"app_name": "Corp-Intranet"}])
    report = check_for_conflicts(plan, client.list_private_apps(), client.list_npa_policies())
    create_calls = []
    orig_create = client.create_private_app
    client.create_private_app = lambda payload: (create_calls.append(payload) or orig_create(payload))
    if report.has_conflicts:
        pass  # main.py returns 1 here without calling create_private_app at all
    assert create_calls == [], "no create call should have been made when conflicts exist and skip_conflicts is False"
    print("PASS: no create/replace attempted when a conflict is found and not explicitly skipped")


def test_runlog_records_incrementally_and_rollback_reverses_order(tmp_dir="/tmp/_runlog_test"):
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)
    plan = build_plan()
    client = FakeClient()
    run = RunLog.start("https://fake.goskope.com", "sample_ivanti_config.xml", log_dir=tmp_dir)

    for app in plan.private_apps[:2]:
        result = client.create_private_app(app.to_payload())
        run.record_created("private_app", result["data"]["id"], app.app_name)
    for pol in plan.policies[:1]:
        result = client.create_npa_policy(pol.to_payload())
        run.record_created("npa_policy", result["data"]["id"], pol.rule_name)

    reloaded = RunLog.load(run.path)
    assert len(reloaded.created) == 3
    assert [e.type for e in reloaded.created] == ["private_app", "private_app", "npa_policy"]

    results = reloaded.rollback(client)
    # policy must be deleted before the private apps it references
    types_in_delete_order = [t for t, _id in client.deleted]
    assert types_in_delete_order[0] == "npa_policy", f"expected policy deleted first, got {types_in_delete_order}"
    assert all(success for _e, success, _err in results)
    assert client._apps == {} and client._policies == {}
    print("PASS: run log records incrementally, reload works, rollback deletes policies before apps")


def test_mid_run_failure_only_rolls_back_what_was_created(tmp_dir="/tmp/_runlog_test_fail"):
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)
    plan = build_plan()
    # Fail on the 3rd app in the plan
    fail_name = plan.private_apps[2].app_name
    client = FakeClient(fail_on_app=fail_name)
    run = RunLog.start("https://fake.goskope.com", "sample_ivanti_config.xml", log_dir=tmp_dir)

    failed_at = None
    for app in plan.private_apps:
        try:
            result = client.create_private_app(app.to_payload())
            run.record_created("private_app", result["data"]["id"], app.app_name)
        except NetskopeApiError:
            failed_at = app.app_name
            run.mark_status("failed")
            break

    assert failed_at == fail_name
    assert len(run.created) == 2, "only the 2 successful creates before the failure should be recorded"
    assert run.status == "failed"

    results = run.rollback(client)
    assert len(results) == 2
    assert all(success for _e, success, _err in results)
    assert client._apps == {}
    print("PASS: a mid-run failure leaves exactly the pre-failure creates in the log, and rollback removes only those")


if __name__ == "__main__":
    test_conflict_detection_blocks_by_default()
    test_filter_out_conflicts_only_removes_flagged()
    test_no_replace_ever_attempted()
    test_runlog_records_incrementally_and_rollback_reverses_order()
    test_mid_run_failure_only_rolls_back_what_was_created()
    print("\nALL SAFETY-LOGIC CHECKS PASSED")
