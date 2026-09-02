"""
Verify intra-ACL host merging: within a SINGLE ACL, resources sharing the
same effective_host (different protocol/ports each) merge into ONE
private app with a combined, multi-entry `protocols` list, instead of
becoming separate numbered apps.

CONFIRMED against the operator's real 433-ACL export (policies-1.xml): 48
of 979 resources across 11 ACLs were this pattern -- most strikingly
`cdmms-ssh-web`, which lists 12 distinct hosts, each appearing TWICE (once
for a TCP port list, once for a single UDP port), previously becoming 24
separate numbered apps and now 12.

This is deliberately a DIFFERENT mechanism from the cross-ACL exact-
duplicate sharing in _smoketest_acl_resource_dedup.py: that one reuses an
app when TWO DIFFERENT ACLs specify an identical resource; this one
merges MULTIPLE resources belonging to the SAME ACL. Both can now compose
together (an ACL's merged multi-protocol group can itself be shared
across ACLs if another ACL specifies the exact same host + the exact same
SET of protocol/port pairs).

Not part of the shipped tool.
"""
import os
import tempfile

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan

NAMESPACE = "http://xml.pulsesecure.net/ive-sa/22.7R2.10"


def _write(xml: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w") as f:
        f.write(xml)
    return path


def _acl_xml(name: str, resources: list[str], roles: list[str], action: str = "allow") -> str:
    res_tags = "\n".join(f"    <resource>{r}</resource>" for r in resources)
    role_tags = "\n".join(f"    <roles>{r}</roles>" for r in roles)
    return f"""  <network-connect-acl>
    <name>{name}</name>
{res_tags}
{role_tags}
    <action>{action}</action>
  </network-connect-acl>"""


def _config_xml(acl_blocks: list[str]) -> str:
    acls_joined = "\n".join(acl_blocks)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="{NAMESPACE}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <users>
    <resource-policies>
      <network-connect-policies>
        <network-connect-acls>
{acls_joined}
        </network-connect-acls>
      </network-connect-policies>
    </resource-policies>
  </users>
</configuration>
"""


def _parse(acl_blocks):
    path = _write(_config_xml(acl_blocks))
    try:
        return parse_ivanti_config(path)
    finally:
        os.remove(path)


def _build_plan(cfg, publisher_overrides=None):
    pub = PublisherRef(publisher_id="1", publisher_name="p1")
    return build_migration_plan(cfg, default_publishers=[pub], publisher_overrides=publisher_overrides)


def test_same_host_two_protocols_in_one_acl_merges_to_one_app():
    cfg = _parse([
        _acl_xml("cdmms-ssh-web", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-a"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.51.3.130"]
    assert len(apps) == 1, f"expected one merged app, got {len(apps)}: {[a.app_name for a in apps]}"
    app = apps[0]
    assert len(app.protocols) == 2, f"expected 2 protocol entries (TCP+UDP), got {app.protocols}"
    types = {p["type"] for p in app.protocols}
    assert types == {"tcp", "udp"}
    print("PASS: two resources on the same host within one ACL merge into one app with 2 protocol entries")


def test_merged_app_keeps_acl_derived_name_when_not_cross_acl_shared():
    cfg = _parse([
        _acl_xml("cdmms-ssh-web", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-a"]),
    ])
    plan = _build_plan(cfg)
    app = next(a for a in plan.private_apps if a.host == "10.51.3.130")
    assert app.app_name == "cdmms-ssh-web", f"a single-host ACL (even if merged) keeps the plain ACL name, got '{app.app_name}'"
    print("PASS: a merged app not shared across ACLs keeps the ACL-derived name (no host-slug, no suffix)")


def test_multiple_hosts_each_merged_get_numbered_suffixes():
    cfg = _parse([
        _acl_xml("cdmms-ssh-web", [
            "tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623",
            "tcp://10.51.28.2:80,443,22,873", "udp://10.51.28.2:623",
        ], ["role-a"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_profiles == ["cdmms-ssh-web"]]
    assert len(apps) == 2, f"two distinct hosts (each internally merged) should be two apps, not four, got {len(apps)}"
    names = {a.app_name for a in apps}
    assert names == {"cdmms-ssh-web-1", "cdmms-ssh-web-2"}
    for app in apps:
        assert len(app.protocols) == 2
    print("PASS: 4 resources (2 hosts x 2 protocols) become 2 numbered apps, each with both protocol entries")


def test_single_resource_per_host_is_unaffected():
    cfg = _parse([
        _acl_xml("solo-acl", ["tcp://10.30.9.1:443"], ["role-c"]),
    ])
    plan = _build_plan(cfg)
    assert len(plan.private_apps) == 1
    app = plan.private_apps[0]
    assert app.app_name == "solo-acl"
    assert len(app.protocols) == 1
    print("PASS: a single-resource ACL is completely unaffected by the intra-ACL merge logic")


def test_role_and_policy_wiring_unaffected_by_merge():
    # Policies are grouped by app/server (one per ACL), not by role -- both
    # roles attached to this ACL land in the SAME policy's userGroups list.
    cfg = _parse([
        _acl_xml("cdmms-ssh-web", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-a", "role-b"]),
    ])
    plan = _build_plan(cfg)
    app = plan.private_apps[0]
    pol = next(p for p in plan.policies if p.rule_name == "ivanti-import-cdmms-ssh-web")
    assert set(pol.user_groups) == {"role-a", "role-b"}
    assert app.app_name in pol.private_app_names
    print("PASS: both roles on the ACL are granted the single merged app via one shared policy")


def test_deny_acl_also_merges_intra_acl_but_stays_unshared():
    cfg = _parse([
        _acl_xml("cdmms-ssh-web", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-a"], action="deny"),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.51.3.130"]
    assert len(apps) == 1, "intra-ACL merging applies to deny ACLs too"
    assert len(apps[0].protocols) == 2
    block_pol = next(p for p in plan.policies if p.action == "block")
    assert apps[0].app_name in block_pol.private_app_names
    print("PASS: a deny ACL also merges same-host resources internally, and the block policy covers the merged app")


def test_merged_group_can_still_be_shared_across_acls_with_identical_signature():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-a"]),
        _acl_xml("second-acl", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-b"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.51.3.130"]
    assert len(apps) == 1, "two ACLs with the IDENTICAL merged resource set on a host should still share one app"
    assert set(apps[0].source_profiles) == {"first-acl", "second-acl"}
    assert len(apps[0].protocols) == 2
    print("PASS: an intra-ACL-merged group is still eligible for cross-ACL sharing when another ACL matches it exactly")


def test_merged_group_not_shared_when_signature_differs_across_acls():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.51.3.130:80,443,22,873", "udp://10.51.3.130:623"], ["role-a"]),
        # Same host, only ONE of the two protocol/port specs -- not an
        # identical signature, so this must NOT be treated as a duplicate
        # of first-acl's (larger) merged group.
        _acl_xml("second-acl", ["tcp://10.51.3.130:80,443,22,873"], ["role-b"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.51.3.130"]
    assert len(apps) == 2, "a partial signature match must NOT be merged with the fuller group -- exact match only"
    print("PASS: a same-host resource with a DIFFERENT (partial) protocol/port signature is not falsely shared")


if __name__ == "__main__":
    test_same_host_two_protocols_in_one_acl_merges_to_one_app()
    test_merged_app_keeps_acl_derived_name_when_not_cross_acl_shared()
    test_multiple_hosts_each_merged_get_numbered_suffixes()
    test_single_resource_per_host_is_unaffected()
    test_role_and_policy_wiring_unaffected_by_merge()
    test_deny_acl_also_merges_intra_acl_but_stays_unshared()
    test_merged_group_can_still_be_shared_across_acls_with_identical_signature()
    test_merged_group_not_shared_when_signature_differs_across_acls()
    print("\nALL INTRA-ACL HOST MERGE CHECKS PASSED")
