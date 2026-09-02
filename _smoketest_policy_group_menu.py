"""Verify the interactive policy-group menu (select an EXISTING group
ONLY -- no "type a new name" option, this tool never creates groups), and
its wiring into apply_plan(). Not part of the shipped tool."""
import argparse
from unittest.mock import patch

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
from policy_group_ui import select_policy_group_interactive
import main as main_mod


class FakeClient:
    def __init__(self, existing_groups=None):
        self._apps = {}
        self._policies = {}
        self._groups = {g["name"]: dict(g) for g in (existing_groups or [])}
        self._next_id = 3000
        self.policy_payloads = []

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

    # Deliberately NO create_npa_policy_group() method -- this tool never
    # creates a group, so any code path that still tries to would raise
    # AttributeError here instead of silently succeeding.


GROUPS = [
    {"id": "10", "name": "Ivanti Import"},
    {"id": "11", "name": "Contractors"},
    {"id": "12", "name": "Finance Team"},
]


def test_menu_select_existing_by_number():
    client = FakeClient(existing_groups=GROUPS)
    with patch("policy_group_ui.sys.stdin.isatty", return_value=True):
        name = select_policy_group_interactive(client, input_func=lambda _: "2")
    assert name == "Contractors"
    print("PASS: selecting by number returns the existing group's name")


def test_menu_non_numeric_input_rejected_not_treated_as_new_name():
    # This tool never creates a group -- typing free text must be rejected,
    # not silently treated as a new group name to create.
    client = FakeClient(existing_groups=GROUPS)
    with patch("policy_group_ui.sys.stdin.isatty", return_value=True):
        name = select_policy_group_interactive(client, input_func=lambda _: "Brand New Group")
    assert name is None
    print("PASS: typing free text is rejected, not treated as a new group name to create")


def test_menu_out_of_range_number_rejected():
    client = FakeClient(existing_groups=GROUPS)
    with patch("policy_group_ui.sys.stdin.isatty", return_value=True):
        name = select_policy_group_interactive(client, input_func=lambda _: "99")
    assert name is None
    print("PASS: an out-of-range number is rejected, not silently treated as a new name")


def test_menu_empty_tenant_returns_none_without_prompting_for_a_new_name():
    # No groups to select from, and this tool won't create one -- must
    # return None (and log an error) rather than asking for a new name.
    client = FakeClient(existing_groups=[])
    called = []
    with patch("policy_group_ui.sys.stdin.isatty", return_value=True):
        name = select_policy_group_interactive(client, input_func=lambda p: called.append(p) or "First Group Ever")
    assert name is None
    assert called == [], "should never prompt for a name to create when there's nothing to select from"
    print("PASS: an empty tenant (no existing groups) returns None instead of asking for a new name to create")


def test_menu_empty_input_returns_none():
    client = FakeClient(existing_groups=GROUPS)
    with patch("policy_group_ui.sys.stdin.isatty", return_value=True):
        name = select_policy_group_interactive(client, input_func=lambda _: "")
    assert name is None
    print("PASS: empty input returns None (caller treats this as abort)")


def test_menu_not_a_tty_returns_none_without_prompting():
    client = FakeClient(existing_groups=GROUPS)
    called = []
    with patch("policy_group_ui.sys.stdin.isatty", return_value=False):
        name = select_policy_group_interactive(client, input_func=lambda p: called.append(p) or "2")
    assert name is None
    assert called == [], "should never even attempt to read input when there's no real terminal"
    print("PASS: non-interactive contexts return None immediately, no input() call attempted")


def test_apply_plan_uses_menu_when_name_omitted():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    plan = build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")

    args = argparse.Namespace(
        tenant_url="https://fake.goskope.com", api_token="tok", auth_mode="api-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None, oauth_scope=None,
        skip_policies=False, skip_conflicts=False, snapshot_dir="/tmp/_pgmenu_snap",
        run_log_dir="/tmp/_pgmenu_runlogs", yes=True, auto_rollback_on_failure=False,
        no_rollback_prompt=True, skip_verification=True,
        verify_retries=1, verify_delay=0, config="sample_ivanti_config.xml",
        policy_group_name=None, no_policy_group=False, tag="ivanti-import",
        skip_group_check=True,
    )
    fake = FakeClient(existing_groups=GROUPS)
    orig_build = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        with patch("main.select_policy_group_interactive", return_value="Finance Team") as mock_menu:
            rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig_build

    assert rc == 0
    mock_menu.assert_called_once()
    for payload in fake.policy_payloads:
        assert payload["group_name"] == "Finance Team"
        assert payload["group_id"] == "12"
    print("PASS: apply_plan() calls the interactive menu when --policy-group-name is omitted, and uses its result")


if __name__ == "__main__":
    test_menu_select_existing_by_number()
    test_menu_non_numeric_input_rejected_not_treated_as_new_name()
    test_menu_out_of_range_number_rejected()
    test_menu_empty_tenant_returns_none_without_prompting_for_a_new_name()
    test_menu_empty_input_returns_none()
    test_menu_not_a_tty_returns_none_without_prompting()
    test_apply_plan_uses_menu_when_name_omitted()
    print("\nALL POLICY-GROUP MENU CHECKS PASSED")
