"""Verify NPA Policy Group reuse (never create) and payload wiring. Not
part of the shipped tool.

This tool does NOT create new NPA Policy Groups -- only an existing one can
be selected/reused. That's a deliberate restriction (see resolve_policy_group()
in main.py), so create_npa_policy_group is intentionally left out of
FakeClient entirely: if any code path here ever calls it, that's a bug and
these tests should fail loudly with an AttributeError rather than silently
"creating" a group.
"""
import argparse

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
import main as main_mod


class FakeClient:
    def __init__(self, existing_groups=None):
        self._apps = {}
        self._policies = {}
        self._groups = {g["name"]: dict(g, id=g.get("id", str(900 + i))) for i, g in enumerate(existing_groups or [])}
        self._next_id = 2000
        self.policy_payloads = []
        self.delete_call_order = []

    def list_private_apps(self):
        return list(self._apps.values())

    def list_npa_policies(self):
        return list(self._policies.values())

    def list_private_app_tags(self):
        return []

    def list_publishers(self):
        return []

    def list_npa_policy_groups(self):
        return list(self._groups.values())

    # Deliberately NO create_npa_policy_group() method -- see module
    # docstring. Any code path that still tries to create a group will
    # raise AttributeError here instead of silently succeeding.

    def create_private_app(self, payload):
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._apps[payload["app_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def create_npa_policy(self, payload):
        self.policy_payloads.append(payload)
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._policies[payload["rule_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def delete_npa_policy(self, rule_id):
        self.delete_call_order.append("npa_policy")
        for name, p in list(self._policies.items()):
            if p["id"] == rule_id:
                del self._policies[name]

    def delete_private_app(self, app_id):
        for name, a in list(self._apps.items()):
            if a["id"] == app_id:
                del self._apps[name]


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")


def _base_args(**overrides):
    base = dict(
        tenant_url="https://fake.goskope.com", api_token="tok", auth_mode="api-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None, oauth_scope=None,
        skip_policies=False, skip_conflicts=False, snapshot_dir="/tmp/_pg_snap",
        run_log_dir="/tmp/_pg_runlogs", yes=True, auto_rollback_on_failure=False,
        no_rollback_prompt=True, skip_verification=True,
        verify_retries=1, verify_delay=0, config="sample_ivanti_config.xml",
        policy_group_name="ivanti-import", no_policy_group=False, tag="ivanti-import",
        skip_group_check=True,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_reuses_existing_group_and_attaches_to_every_policy():
    plan = build_plan()
    args = _base_args()
    fake = FakeClient(existing_groups=[{"name": "ivanti-import", "id": "700"}])
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig

    assert rc == 0
    assert fake.policy_payloads, "no policies were created to check"
    for payload in fake.policy_payloads:
        assert payload["group_id"] == "700"
        assert payload["group_name"] == "ivanti-import"
    print(f"PASS: an existing group is reused and its id is attached to all {len(fake.policy_payloads)} policies")


def test_reuses_existing_group_without_recreating():
    plan = build_plan()
    args = _base_args(policy_group_name="my-existing-group")
    fake = FakeClient(existing_groups=[{"name": "my-existing-group", "id": "555"}])
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig

    assert rc == 0
    for payload in fake.policy_payloads:
        assert payload["group_id"] == "555"
    print("PASS: an existing group is reused (by name)")


def test_fails_cleanly_when_named_group_does_not_exist():
    # This tool never creates a new group -- a --policy-group-name that
    # doesn't match anything in the tenant must fail the run, not silently
    # create one.
    plan = build_plan()
    args = _base_args(policy_group_name="does-not-exist-anywhere")
    fake = FakeClient()  # no existing groups at all
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig
    assert rc == 1
    assert fake._policies == {}, "no policies should be created when the named group doesn't exist"
    assert len(fake._apps) == 9, "apps created before the group step should still exist (5 resource-profile + 4 network-connect-acl derived)"
    print("PASS: a --policy-group-name that doesn't match any existing group fails cleanly instead of creating one")


def test_skip_policies_means_no_group_lookup_needed():
    plan = build_plan()
    args = _base_args(skip_policies=True)
    fake = FakeClient()  # no groups exist, and none should be needed
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig
    assert rc == 0
    assert fake._groups == {}
    print("PASS: --skip-policies means the group step (and its existence requirement) never runs at all")


def test_prompts_for_group_name_when_not_given():
    # Superseded by the interactive menu in policy_group_ui.py -- the menu
    # itself (including the fact that it can ONLY select an existing group,
    # never type a new name) is covered by _smoketest_policy_group_menu.py.
    # This just confirms apply_plan() calls it and uses whatever EXISTING
    # group name it resolves to.
    from unittest.mock import patch
    plan = build_plan()
    args = _base_args(policy_group_name=None)
    fake = FakeClient(existing_groups=[{"name": "picked-from-menu", "id": "800"}])
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        with patch("main.select_policy_group_interactive", return_value="picked-from-menu") as mock_menu:
            rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig
    assert rc == 0
    mock_menu.assert_called_once()
    for payload in fake.policy_payloads:
        assert payload["group_id"] == "800"
    print("PASS: an omitted --policy-group-name defers to the interactive menu, and its (existing-group) result is used")


def test_errors_cleanly_when_name_missing_and_not_interactive():
    from unittest.mock import patch
    plan = build_plan()
    args = _base_args(policy_group_name=None)
    fake = FakeClient()
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        with patch("main.select_policy_group_interactive", return_value=None):  # simulates no tty / abort
            rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig
    assert rc == 1
    assert fake._policies == {}, "no policies should be created without a resolved group name"
    assert len(fake._apps) == 9, "apps created before the group step should still exist (5 resource-profile + 4 network-connect-acl derived)"
    print("PASS: missing name + no terminal to prompt on fails cleanly, apps already created are left alone")


def test_no_policy_group_flag_skips_grouping_entirely():
    from unittest.mock import patch
    plan = build_plan()
    args = _base_args(policy_group_name=None, no_policy_group=True)
    fake = FakeClient()  # no groups exist, and none should be needed
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        with patch("main.select_policy_group_interactive") as mock_menu:
            rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig
    assert rc == 0
    mock_menu.assert_not_called()
    for payload in fake.policy_payloads:
        assert "group_id" not in payload and "group_name" not in payload
    print("PASS: --no-policy-group skips the menu entirely and creates policies ungrouped")


if __name__ == "__main__":
    test_reuses_existing_group_and_attaches_to_every_policy()
    test_reuses_existing_group_without_recreating()
    test_fails_cleanly_when_named_group_does_not_exist()
    test_prompts_for_group_name_when_not_given()
    test_errors_cleanly_when_name_missing_and_not_interactive()
    test_no_policy_group_flag_skips_grouping_entirely()
    test_skip_policies_means_no_group_lookup_needed()
    print("\nALL POLICY-GROUP CHECKS PASSED")
