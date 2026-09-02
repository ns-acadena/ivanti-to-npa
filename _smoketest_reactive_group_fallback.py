"""Verify the reactive fallback for an invalid userGroups value: when the
pre-flight group-existence check can't run (e.g. list_user_groups() hits a
404 on a real tenant, as confirmed against washington.goskope.com) and the
tenant's OWN policy-create validation later rejects the role name, the tool
retries that one policy without a userGroups restriction instead of
aborting the whole run. Not part of the shipped tool.

This is the exact failure sequence seen in production:
1. GET /api/v2/scim/groups -> 404 "no Route matched with those values"
   -> pre-flight check skipped, existing_groups_by_name stays None.
2. POST /api/v2/policy/npa/rules with userGroups=["Employees-Full"] -> 200
   + {"status": "error", "message": "Invalid values from users, userGroups
   or organization_units:{'Employees-Full'}"} -> netskope_client.py raises
   NetskopeApiError for this (task #22's 2xx-error-body fix).
3. Before this fix, step 2's error aborted the whole run and offered
   rollback of the 5 apps already created. After this fix, that specific
   error triggers one retry without userGroups instead.
"""
import argparse

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
from netskope_client import NetskopeApiError
import main as main_mod


class FakeClient:
    def __init__(self, reject_groups=None, groups_endpoint_404=True):
        self._apps = {}
        self._policies = {}
        # This tool never creates a Policy Group -- "ivanti-import" (the
        # name _base_args() below uses) must already exist.
        self._groups = {"ivanti-import": {"id": "700", "name": "ivanti-import"}}
        self._next_id = 5000
        self.policy_payloads = []
        self.create_attempts = []
        # Which userGroups values the fake tenant considers invalid --
        # mirrors a real tenant rejecting a role name that isn't a synced
        # IdP group.
        self._reject_groups = set(reject_groups or [])
        self._groups_endpoint_404 = groups_endpoint_404

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
        if self._groups_endpoint_404:
            raise NetskopeApiError('GET /api/v2/scim/groups failed [404]: {"message": "no Route matched with those values"}')
        return []

    def create_private_app(self, payload):
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._apps[payload["app_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def create_npa_policy(self, payload):
        self.create_attempts.append(payload)
        rule_data = payload.get("rule_data", {})
        bad = set(rule_data.get("userGroups", [])) & self._reject_groups
        if bad:
            raise NetskopeApiError(
                f"POST /api/v2/policy/npa/rules returned HTTP 200 but an error body: "
                f"Invalid values from users, userGroups or organization_units:{bad}"
            )
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
        skip_policies=False, skip_conflicts=False, snapshot_dir="/tmp/_reactive_snap",
        run_log_dir="/tmp/_reactive_runlogs", yes=True, auto_rollback_on_failure=False,
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


def test_reproduces_the_reported_failure_sequence_and_recovers():
    # Pre-flight check 404s (like the real tenant), AND the tenant's
    # create-time validation rejects "Employees-Full" specifically.
    fake = FakeClient(reject_groups={"Employees-Full"}, groups_endpoint_404=True)
    rc = _run(_base_args(), fake)
    assert rc == 0, "the run should recover and succeed, not abort with a rollback prompt"
    assert len(fake._apps) == 9, "all apps should still be created (5 resource-profile + 4 network-connect-acl derived)"

    created_names = set(fake._policies.keys())
    assert "ivanti-import-Employees-Full" in created_names, "the previously-failing policy must still get created"

    # It should have been attempted twice: once with userGroups (rejected),
    # once without (accepted).
    attempts_for_this_rule = [a for a in fake.create_attempts if a["rule_name"] == "ivanti-import-Employees-Full"]
    assert len(attempts_for_this_rule) == 2, f"expected exactly one retry, got {len(attempts_for_this_rule)} attempts"
    assert "userGroups" in attempts_for_this_rule[0]["rule_data"]
    assert "userGroups" not in attempts_for_this_rule[1]["rule_data"]

    # The other policies (not rejected) should be untouched -- created once,
    # with their userGroups intact.
    other_policy = fake._policies["ivanti-import-Employees-Contractors"]
    assert "userGroups" in other_policy["rule_data"]
    print("PASS: the exact reported failure (404 pre-flight + tenant-rejected group) now self-heals instead of aborting the run")


def test_a_genuinely_different_error_still_aborts_normally():
    # Make sure this fix doesn't accidentally swallow unrelated failures --
    # only this specific error message triggers the retry-without-groups
    # behavior; anything else still aborts the run as before.
    class BrokenClient(FakeClient):
        def create_npa_policy(self, payload):
            raise NetskopeApiError("POST /api/v2/policy/npa/rules failed [500]: internal server error")

    fake = BrokenClient(groups_endpoint_404=True)
    rc = _run(_base_args(), fake)
    assert rc == 1, "an unrelated server error should still fail the run, not be silently retried"
    print("PASS: an unrelated create failure is NOT mistaken for the invalid-group case, and still aborts normally")


if __name__ == "__main__":
    test_reproduces_the_reported_failure_sequence_and_recovers()
    test_a_genuinely_different_error_still_aborts_normally()
    print("\nALL REACTIVE GROUP-FALLBACK CHECKS PASSED")
