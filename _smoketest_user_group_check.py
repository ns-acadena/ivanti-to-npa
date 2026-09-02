"""Verify the pre-policy-creation user-group existence check: a policy whose
Ivanti role name isn't a real IdP group in the tenant is still created, just
without a userGroups restriction, instead of blocking the run. Not part of
the shipped tool."""
import argparse

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
from netskope_client import NetskopeApiError
import main as main_mod


class FakeClient:
    def __init__(self, user_groups=None, raise_on_groups=False):
        self._apps = {}
        self._policies = {}
        # This tool never creates a Policy Group -- "ivanti-import" (the
        # name _base_args() below uses) must already exist for apply_plan()
        # to succeed.
        self._groups = {"ivanti-import": {"id": "700", "name": "ivanti-import"}}
        self._user_groups = user_groups if user_groups is not None else []
        self._raise_on_groups = raise_on_groups
        self._next_id = 4000
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

    def list_user_groups(self):
        if self._raise_on_groups:
            raise NetskopeApiError("simulated: /api/v2/scim/groups not available on this tenant")
        return [{"id": str(i), "name": n} for i, n in enumerate(self._user_groups)]

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
    # creates a group.


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")


def _base_args(**overrides):
    base = dict(
        tenant_url="https://fake.goskope.com", api_token="tok", auth_mode="api-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None, oauth_scope=None,
        skip_policies=False, skip_conflicts=False, snapshot_dir="/tmp/_ugc_snap",
        run_log_dir="/tmp/_ugc_runlogs", yes=True, auto_rollback_on_failure=False,
        no_rollback_prompt=True, skip_verification=True,
        verify_retries=1, verify_delay=0, config="sample_ivanti_config.xml",
        policy_group_name="ivanti-import", no_policy_group=False, tag="ivanti-import",
        skip_group_check=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _run(args, fake):
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        return main_mod.apply_plan(args, build_plan())
    finally:
        main_mod.build_netskope_client = orig


def test_known_group_keeps_user_groups_restriction():
    # sample_ivanti_config.xml's roles include "Employees-Full" etc. -- pretend
    # ALL of those role names are real IdP groups already synced in.
    plan_roles = {name for pol in build_plan().policies for name in pol.user_groups}
    fake = FakeClient(user_groups=sorted(plan_roles))
    rc = _run(_base_args(), fake)
    assert rc == 0
    assert fake.policy_payloads, "no policies were created to check"
    for payload in fake.policy_payloads:
        rule_data = payload["rule_data"]
        assert "userGroups" in rule_data and rule_data["userGroups"], f"expected userGroups kept, got {payload}"
        # Confirmed real schema sends both userGroups (names) and
        # userGroupObjects (id+name) side by side when the group is known.
        assert "userGroupObjects" in rule_data, f"expected userGroupObjects alongside userGroups, got {payload}"
        for obj in rule_data["userGroupObjects"]:
            assert obj.get("id") and obj.get("name"), f"userGroupObjects entries need id+name, got {obj}"
    print("PASS: role names that match a real tenant group keep their userGroups restriction (+ userGroupObjects)")


def test_unknown_group_falls_back_to_open_policy_not_a_failure():
    # Tenant has NO matching groups at all -- every role name is "unknown".
    fake = FakeClient(user_groups=["some-other-group-not-related"])
    rc = _run(_base_args(), fake)
    assert rc == 0, "an unmatched role name must not fail the whole run"
    assert fake.policy_payloads, "policies should still have been created"
    for payload in fake.policy_payloads:
        assert "userGroups" not in payload["rule_data"], f"expected userGroups omitted (open policy), got {payload}"
    print("PASS: an Ivanti role with no matching IdP group still gets its policy created, just without userGroups")


def test_skip_group_check_flag_bypasses_lookup_entirely():
    fake = FakeClient(user_groups=[])  # would fail every group if checked
    rc = _run(_base_args(skip_group_check=True), fake)
    assert rc == 0
    for payload in fake.policy_payloads:
        assert "userGroups" in payload["rule_data"], "with --skip-group-check, userGroups should be kept unverified, exactly like before this feature existed"
    print("PASS: --skip-group-check never calls list_user_groups() and keeps the raw role name")


def test_lookup_failure_is_treated_as_cannot_verify_not_as_missing():
    # If the groups endpoint itself errors out (e.g. wrong/unsupported path on
    # this tenant), the tool must NOT interpret that as "every group is
    # missing" and strip userGroups from everything -- it should fall back to
    # the pre-existing (unverified) behavior instead.
    fake = FakeClient(raise_on_groups=True)
    rc = _run(_base_args(), fake)
    assert rc == 0
    for payload in fake.policy_payloads:
        assert "userGroups" in payload["rule_data"], "a failed lookup should leave userGroups untouched, not strip it"
    print("PASS: a failed group lookup degrades to unverified (pre-existing) behavior, not to stripping every policy")


if __name__ == "__main__":
    test_known_group_keeps_user_groups_restriction()
    test_unknown_group_falls_back_to_open_policy_not_a_failure()
    test_skip_group_check_flag_bypasses_lookup_entirely()
    test_lookup_failure_is_treated_as_cannot_verify_not_as_missing()
    print("\nALL USER-GROUP CHECK TESTS PASSED")
