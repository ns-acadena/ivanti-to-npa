"""
Verify Network Connect ACL private-app consolidation: an EXACT duplicate
resource (same host, protocol, AND ports) specified by more than one ACL
reuses a single shared private app instead of creating a redundant one.

CONFIRMED against the operator's real 433-ACL export (policies-1.xml): 80
of 979 resources (69 distinct hosts/keys, absorbing 149 total resource
references) were exact duplicates this way, each previously becoming its
own separate app. This file uses small synthetic fixtures (not the real
data) to pin down the exact behavior:

1. Two ACLs specifying the identical resource share ONE private app,
   named from the HOST (not either ACL's name) -- deterministic naming
   independent of which ACL happens to be processed first, and the same
   scheme a future, bigger consolidation (merge by host alone regardless
   of port -- not implemented) would also need.
2. A non-shared resource is completely unaffected -- still gets the
   existing, more legible ACL-name-derived app name.
3. Both ACLs' roles end up granted access to the SAME shared app (not two
   separate apps), via role_to_apps.
4. A resource that's "shared" only by DIFFERING port keeps two separate
   apps (not a false-positive merge) -- exact key match only.
5. Two ACLs sharing a resource but specifying DIFFERENT publisher
   overrides get a warning (first one wins) instead of a silent conflict.
6. A shared app's report.py row shows every contributing ACL, not just
   the one that created it.
7. Deny-action ACLs are excluded from the sharing pool entirely, even
   against an otherwise-identical allow-ACL resource.

Not part of the shipped tool.
"""
import os
import tempfile

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
from report import build_app_rows

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


def test_exact_duplicate_resource_reuses_one_shared_app():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.20.8.15:3389"], ["role-a"]),
        _acl_xml("second-acl", ["tcp://10.20.8.15:3389"], ["role-b"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.20.8.15"]
    assert len(apps) == 1, f"expected exactly one shared app, got {len(apps)}: {[a.app_name for a in apps]}"
    app = apps[0]
    assert app.app_name == "10-20-8-15", f"shared app should be host-derived, got '{app.app_name}'"
    assert set(app.source_profiles) == {"first-acl", "second-acl"}
    print("PASS: an exact duplicate resource across two ACLs shares one host-named app")


def test_both_roles_granted_the_shared_app():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.20.8.15:3389"], ["role-a"]),
        _acl_xml("second-acl", ["tcp://10.20.8.15:3389"], ["role-b"]),
    ])
    plan = _build_plan(cfg)
    shared_app_name = next(a.app_name for a in plan.private_apps if a.host == "10.20.8.15")
    pol_a = next(p for p in plan.policies if p.user_groups == ["role-a"])
    pol_b = next(p for p in plan.policies if p.user_groups == ["role-b"])
    assert shared_app_name in pol_a.private_app_names
    assert shared_app_name in pol_b.private_app_names
    print("PASS: both ACLs' roles are granted the SAME shared app, not two separate ones")


def test_non_shared_resource_keeps_acl_derived_name():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.20.8.15:3389"], ["role-a"]),
        _acl_xml("second-acl", ["tcp://10.20.8.15:3389"], ["role-b"]),
        _acl_xml("solo-acl", ["tcp://10.30.9.1:443"], ["role-c"]),
    ])
    plan = _build_plan(cfg)
    solo_app = next(a for a in plan.private_apps if a.host == "10.30.9.1")
    assert solo_app.app_name == "solo-acl", f"a non-shared resource should keep the ACL-name-derived scheme, got '{solo_app.app_name}'"
    assert solo_app.source_profiles == ["solo-acl"]
    print("PASS: a resource used by only one ACL is completely unaffected (ACL-name-derived, unshared)")


def test_same_host_different_ports_are_not_merged():
    cfg = _parse([
        _acl_xml("rdp-acl", ["tcp://10.20.8.15:3389"], ["role-a"]),
        _acl_xml("sftp-acl", ["tcp://10.20.8.15:22"], ["role-b"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.20.8.15"]
    assert len(apps) == 2, "different ports on the same host is NOT an exact-key match -- must stay two separate apps"
    assert {a.app_name for a in apps} == {"rdp-acl", "sftp-acl"}, "neither is shared, so both keep their ACL-derived names"
    print("PASS: same host but different ports are two separate apps, not a false-positive merge")


def test_conflicting_publisher_override_warns_and_keeps_first():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.20.8.15:3389"], ["role-a"]),
        _acl_xml("second-acl", ["tcp://10.20.8.15:3389"], ["role-b"]),
    ])
    pub_a = PublisherRef(publisher_id="111", publisher_name="publisher-a")
    pub_b = PublisherRef(publisher_id="222", publisher_name="publisher-b")
    plan = _build_plan(cfg, publisher_overrides={"first-acl": pub_a, "second-acl": pub_b})
    app = next(a for a in plan.private_apps if a.host == "10.20.8.15")
    assert app.publishers == [pub_a], "should keep the publisher from whichever ACL created the app first"
    assert any(
        "different publisher override" in w and "first-acl" in w and "second-acl" in w
        for w in plan.warnings
    ), "should warn about the conflicting publisher override instead of silently dropping one"
    print("PASS: conflicting publisher overrides on a shared resource warn and keep the first")


def test_deny_acl_never_shares_with_an_allow_acl():
    cfg = _parse([
        _acl_xml("allow-acl", ["tcp://10.20.8.15:3389"], ["role-a"], action="allow"),
        _acl_xml("deny-acl", ["tcp://10.20.8.15:3389"], ["role-b"], action="deny"),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.20.8.15"]
    assert len(apps) == 2, "a deny-action ACL must never share an app with an allow-action ACL, even for an identical resource"
    names = {a.app_name for a in apps}
    assert names == {"allow-acl", "deny-acl"}
    print("PASS: deny-action ACLs are excluded from the sharing pool entirely")


def test_report_row_shows_all_contributing_acls_for_a_shared_app():
    cfg = _parse([
        _acl_xml("first-acl", ["tcp://10.20.8.15:3389"], ["role-a"]),
        _acl_xml("second-acl", ["tcp://10.20.8.15:3389"], ["role-b"]),
    ])
    plan = _build_plan(cfg)
    rows = build_app_rows(cfg, plan)
    row = next(r for r in rows if r["host"] == "10.20.8.15")
    assert row["ivanti_profile"] == "first-acl, second-acl"
    assert "role-a" in row["ivanti_roles"] and "role-b" in row["ivanti_roles"]
    print("PASS: a shared app's report row lists every contributing ACL and unions their roles")


def test_three_way_duplicate_all_share_one_app():
    cfg = _parse([
        _acl_xml("acl-1", ["tcp://10.1.1.1:80"], ["role-a"]),
        _acl_xml("acl-2", ["tcp://10.1.1.1:80"], ["role-b"]),
        _acl_xml("acl-3", ["tcp://10.1.1.1:80"], ["role-c"]),
    ])
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.host == "10.1.1.1"]
    assert len(apps) == 1
    assert set(apps[0].source_profiles) == {"acl-1", "acl-2", "acl-3"}
    print("PASS: three ACLs sharing the identical resource all collapse into one app")


if __name__ == "__main__":
    test_exact_duplicate_resource_reuses_one_shared_app()
    test_both_roles_granted_the_shared_app()
    test_non_shared_resource_keeps_acl_derived_name()
    test_same_host_different_ports_are_not_merged()
    test_conflicting_publisher_override_warns_and_keeps_first()
    test_deny_acl_never_shares_with_an_allow_acl()
    test_report_row_shows_all_contributing_acls_for_a_shared_app()
    test_three_way_duplicate_all_share_one_app()
    print("\nALL ACL RESOURCE DEDUP CHECKS PASSED")
