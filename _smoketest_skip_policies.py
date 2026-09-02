"""Verify --skip-policies: apply_plan() should never touch NPA Policies,
and the pre-flight conflict check should ignore them too. Not part of the
shipped tool."""
import argparse

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
import main as main_mod


class FakeClient:
    def __init__(self, existing_apps=None, existing_policies=None):
        self._apps = {a["app_name"]: dict(a, id=str(i)) for i, a in enumerate(existing_apps or [])}
        self._policies = {p["rule_name"]: dict(p, id=str(100 + i)) for i, p in enumerate(existing_policies or [])}
        self._next_id = 1000
        self.policy_create_calls = 0

    def list_private_apps(self):
        return list(self._apps.values())

    def list_npa_policies(self):
        return list(self._policies.values())

    def list_private_app_tags(self):
        return []

    def list_publishers(self):
        return []

    def create_private_app(self, payload):
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._apps[payload["app_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def create_npa_policy(self, payload):
        self.policy_create_calls += 1
        raise AssertionError("create_npa_policy should NEVER be called when --skip-policies is set")


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")


def test_apply_plan_skips_policy_creation():
    plan = build_plan()
    assert plan.policies, "sanity check: the sample config should produce at least one policy normally"
    n_policies_before = len(plan.policies)

    args = argparse.Namespace(
        tenant_url="https://fake.goskope.com", api_token="tok", auth_mode="api-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None, oauth_scope=None,
        skip_policies=True, skip_conflicts=False, snapshot_dir="/tmp/_skip_pol_snap",
        run_log_dir="/tmp/_skip_pol_runlogs", yes=True, auto_rollback_on_failure=False,
        no_rollback_prompt=True, skip_verification=True,
        verify_retries=1, verify_delay=0, config="sample_ivanti_config.xml",
    )

    fake = FakeClient()
    orig_build_client = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        rc = main_mod.apply_plan(args, plan)
    finally:
        main_mod.build_netskope_client = orig_build_client

    assert rc == 0, f"apply_plan should succeed, got rc={rc}"
    assert fake.policy_create_calls == 0
    assert len(fake._apps) == len(plan.private_apps) or len(fake._apps) > 0, "apps should still be created"
    assert plan.policies == [], "plan.policies should have been cleared by --skip-policies before conflict-checking"
    print(f"PASS: --skip-policies created {len(fake._apps)} app(s), 0 polic(y/ies) "
          f"(plan originally had {n_policies_before} policy/policies before the flag zeroed it out)")


def test_check_conflicts_ignores_policies_when_skip_policies_set():
    plan = build_plan()
    args = argparse.Namespace(
        tenant_url="https://fake.goskope.com", api_token="tok", auth_mode="api-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None, oauth_scope=None,
        skip_policies=True,
    )
    # Pretend a policy with a colliding name already exists -- should NOT
    # be flagged as a conflict since we're not touching policies at all.
    colliding_name = plan.policies[0].rule_name
    fake = FakeClient(existing_policies=[{"rule_name": colliding_name}])
    orig_build_client = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        rc = main_mod.do_check_conflicts(args, plan)
    finally:
        main_mod.build_netskope_client = orig_build_client
    assert rc == 0, "no conflicts should be reported since policies are excluded from the check"
    print("PASS: --skip-policies excludes policies from the conflict check too")


if __name__ == "__main__":
    test_apply_plan_skips_policy_creation()
    test_check_conflicts_ignores_policies_when_skip_policies_set()
    print("\nALL --skip-policies CHECKS PASSED")
