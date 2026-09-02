"""Verify a resource profile with an ICS deny rule generates a companion
NPA BLOCK policy (scoped to the same role(s) as the profile) instead of
just a warning. Not part of the shipped tool."""
from datetime import datetime, timezone

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan, _DEFAULT_BLOCK_TEMPLATE


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    dt = datetime(2026, 8, 31, 16, 5, 0, tzinfo=timezone.utc)
    return build_migration_plan(cfg, default_publishers=[pub], imported_at=dt)


def test_deny_profile_generates_a_block_policy():
    # sample_ivanti_config.xml's Finance-App-DB profile has a deny
    # autopolicy on 10.20.8.99:5432 and is attached to Employees-Full.
    # (The sample also has a deny-action Network Connect ACL,
    # "legacy-telnet-block", generating ITS OWN block policy -- see
    # _smoketest_namespace_and_network_connect.py -- so this test filters
    # to the resource-profile-derived one specifically rather than
    # asserting a total block-policy count.)
    plan = build_plan()
    pol = next(p for p in plan.policies if p.rule_name == "ivanti-import-Finance-App-DB-block")
    assert pol.action == "block"
    assert pol.private_app_names == ["Finance-App-DB"]
    assert pol.user_groups == ["Employees-Full"], "block policy should be scoped to the SAME role(s) as the profile"
    print("PASS: a resource profile with a deny rule generates a companion block policy scoped to the same role(s)")


def test_allow_policies_unaffected():
    # Policies are now grouped by app/server (one per resource profile / ACL),
    # not by role -- sample_ivanti_config.xml has 5 supported resource
    # profiles + 2 allow-action Network Connect ACLs (vpn-jumpbox01-rdp,
    # dc-subnet-access) = 7 allow policies.
    plan = build_plan()
    allow_policies = [p for p in plan.policies if p.action == "allow"]
    assert len(allow_policies) == 7, f"expected 7 app/server-grouped allow policies untouched, got {len(allow_policies)}"
    for pol in allow_policies:
        assert pol.action == "allow"
    print("PASS: the existing allow policies are unaffected by the new block-policy generation")


def test_block_payload_has_correct_match_criteria_action():
    plan = build_plan()
    block = next(p for p in plan.policies if p.rule_name == "ivanti-import-Finance-App-DB-block")
    payload = block.to_payload()
    mca = payload["rule_data"]["match_criteria_action"]
    assert mca["action_name"] == "block"
    assert mca["template"] == _DEFAULT_BLOCK_TEMPLATE
    assert mca["emit_alert"] is True
    assert payload["rule_data"]["privateApps"] == ["[Finance-App-DB]"]
    assert payload["rule_data"]["userGroups"] == ["Employees-Full"]
    print("PASS: the block policy's payload has action_name=block + template + emit_alert, per Netskope's documented block-rule schema")


def test_allow_payload_still_defaults_to_allow_action():
    plan = build_plan()
    allow = next(p for p in plan.policies if p.action == "allow")
    payload = allow.to_payload()
    assert payload["rule_data"]["match_criteria_action"] == {"action_name": "allow"}
    assert "template" not in payload["rule_data"]["match_criteria_action"]
    print("PASS: allow policies still get the plain {'action_name': 'allow'} shape, no template/emit_alert added")


def test_warning_mentions_the_block_policy_and_template():
    plan = build_plan()
    matching = [w for w in plan.warnings if "Finance-App-DB" in w and "BLOCK policy" in w]
    assert matching, f"expected a warning about the generated block policy, got: {plan.warnings}"
    assert any(_DEFAULT_BLOCK_TEMPLATE in w for w in matching), "warning should flag the unconfirmed template name"
    print("PASS: a warning flags the generated block policy and its unconfirmed notification template")


def test_deny_profile_with_no_roles_falls_back_to_warning_only():
    # If a denied profile has no attached roles, there's nothing to scope
    # a block policy to -- must not generate one, and must not crash.
    from ivanti_parser import IvantiConfig, ResourceProfile, ResourcePolicy
    cfg = IvantiConfig(resource_profiles=[
        ResourceProfile(
            name="Orphan-Denied-App", profile_type="web", host="orphan.example.com",
            port=None, path=None, roles=[],  # no roles at all
            policies=[ResourcePolicy(action="deny", host="orphan.example.com", port="8080", path=None)],
        )
    ])
    pub = PublisherRef(publisher_id="1", publisher_name="p1")
    plan = build_migration_plan(cfg, default_publishers=[pub])
    assert not any(p.action == "block" for p in plan.policies), "no roles to scope to -- no block policy should be generated"
    assert any("no roles attached" in w for w in plan.warnings)
    print("PASS: a denied profile with no attached roles falls back to a warning instead of crashing or over-blocking")


if __name__ == "__main__":
    test_deny_profile_generates_a_block_policy()
    test_allow_policies_unaffected()
    test_block_payload_has_correct_match_criteria_action()
    test_allow_payload_still_defaults_to_allow_action()
    test_warning_mentions_the_block_policy_and_template()
    test_deny_profile_with_no_roles_falls_back_to_warning_only()
    print("\nALL BLOCK-POLICY CHECKS PASSED")
