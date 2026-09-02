"""
Verify parsing and conversion of REAL Ivanti/Pulse Secure Network Connect
ACLs (confirmed against the operator's uploaded "policies-1.xml") plus the
namespace-stripping fix that made parsing them possible at all.

1. Real exports declare a firmware-version-specific default XML namespace
   (xmlns="http://xml.pulsesecure.net/ive-sa/22.7R2.10") that the parser
   never handled before -- every XPATHS lookup would silently match
   nothing against a real file, even one with a <resource-profile> the
   tool otherwise fully supports. sample_ivanti_config.xml (handcrafted,
   unnamespaced) never exposed this.
2. Network Connect ACLs are now CONVERTED into Private Apps, one per
   resource (not per ACL, since an NPA app is one host and a real ACL's
   resources are overwhelmingly single-host -- 962 of 979 in the real
   file). CIDR resources are converted too UNLESS broader than Netskope's
   documented /8 floor (or malformed), which are skipped and warned about.
   A deny-action ACL gets a companion BLOCK policy instead of feeding the
   normal allow-policy pipeline.

Not part of the shipped tool.
"""
import os
import tempfile

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan, _WILDCARD_PORT_RANGE

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


def _config_xml(acl_blocks: list[str], include_resource_profile: bool = False) -> str:
    profile_block = ""
    if include_resource_profile:
        profile_block = """
  <user-realms>
    <realm name="Employees">
      <role-mapping-rules>
        <rule role="Employees-Full"/>
      </role-mapping-rules>
    </realm>
  </user-realms>
  <resource-profiles>
    <resource-profile name="Corp-Intranet" type="web">
      <resource>intranet.corp.example.com:443</resource>
      <roles>
        <role name="Employees-Full"/>
      </roles>
      <autopolicies/>
    </resource-profile>
  </resource-profiles>"""
    acls_joined = "\n".join(acl_blocks)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="{NAMESPACE}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
{profile_block}
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


def _build_plan(cfg):
    pub = PublisherRef(publisher_id="1", publisher_name="p1")
    return build_migration_plan(cfg, default_publishers=[pub])


def test_namespaced_export_still_parses_realms_and_profiles():
    xml = _config_xml(
        [_acl_xml("dpu-networks-datacenter-policy", ["10.128.0.0/15:*", "10.64.0.0/15:*"], ["nti-role", "oss-role"])],
        include_resource_profile=True,
    )
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    assert len(cfg.realms) == 1, f"expected 1 realm despite the namespace, got {len(cfg.realms)}"
    assert cfg.realms[0].roles == ["Employees-Full"]
    assert len(cfg.resource_profiles) == 1, f"expected 1 resource profile despite the namespace, got {len(cfg.resource_profiles)}"
    profile = cfg.resource_profiles[0]
    assert profile.host == "intranet.corp.example.com" and profile.port == "443"
    print("PASS: a namespaced export (like the real one) still parses realms/resource-profiles correctly")


def test_resources_are_parsed_with_structure_scheme_and_bare_forms():
    xml = _config_xml([
        _acl_xml("mixed-form-acl", ["10.128.0.0/15:*", "tcp://10.65.19.116:22,5432", "216.220.181.2"], ["some-role"]),
    ])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    acl = cfg.network_connect_acls[0]
    assert len(acl.resources) == 3
    r0, r1, r2 = acl.resources
    assert r0.host == "10.128.0.0/15" and r0.ports == "*" and r0.is_cidr and r0.protocol == "tcp"
    assert r1.host == "10.65.19.116" and r1.ports == "22,5432" and not r1.is_cidr and r1.protocol == "tcp"
    assert r2.host == "216.220.181.2" and r2.ports is None and not r2.is_cidr
    print("PASS: both bare ('10.x/15:*') and scheme-prefixed ('tcp://host:ports') resource forms parse correctly")


def test_single_resource_allow_acl_converts_to_one_app_and_feeds_role_policy():
    xml = _config_xml([_acl_xml("vpn-irmawebtst01-rdp", ["tcp://10.20.8.99:3389"], ["vpn-irmawebtst01-rdp"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    assert len(apps) == 1
    app = apps[0]
    assert app.app_name == "vpn-irmawebtst01-rdp", "a single-resource ACL should NOT get a numeric suffix"
    assert app.host == "10.20.8.99"
    assert app.protocols == [{"type": "tcp", "port": "3389"}]
    pol = next(p for p in plan.policies if p.rule_name == "ivanti-import-vpn-irmawebtst01-rdp")
    assert pol.private_app_names == ["vpn-irmawebtst01-rdp"]
    assert pol.action == "allow"
    print("PASS: a single-resource allow ACL becomes one app (no suffix) and feeds the normal role-policy pipeline")


def test_multi_resource_acl_becomes_numbered_apps_under_one_policy():
    xml = _config_xml([_acl_xml(
        "dpu-networks-datacenter-policy",
        ["tcp://10.1.1.1:22", "tcp://10.1.1.2:22", "tcp://10.1.1.3:22"],
        ["nti-role"],
    )])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    names = sorted(a.app_name for a in apps)
    assert names == [
        "dpu-networks-datacenter-policy-1",
        "dpu-networks-datacenter-policy-2",
        "dpu-networks-datacenter-policy-3",
    ], f"expected 3 numbered apps, got {names}"
    # Policies are grouped by app/server (one per ACL), not by role -- the
    # rule_name is derived from the ACL's own name, not "nti-role".
    pol = next(p for p in plan.policies if p.rule_name == "ivanti-import-dpu-networks-datacenter-policy")
    assert sorted(pol.private_app_names) == names, "one policy should grant all 3 apps from the multi-resource ACL"
    assert pol.user_groups == ["nti-role"]
    print("PASS: a multi-resource ACL becomes numbered apps ('-1', '-2', '-3'), all granted by one ACL-named policy")


def test_cidr_resource_within_the_slash_8_floor_is_converted():
    xml = _config_xml([_acl_xml("subnet-acl", ["10.6.0.0/16:80,443"], ["role-a"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    assert len(apps) == 1 and apps[0].host == "10.6.0.0/16"
    assert apps[0].protocols == [{"type": "tcp", "ports": "80,443"}]
    print("PASS: a CIDR resource at /16 (narrower than the /8 floor) is converted normally")


def test_cidr_resource_broader_than_slash_8_is_skipped_and_warned():
    # /7 is broader than Netskope's documented /8 floor ("10/8 is allowed,
    # but 1/7 is not allowed") -- must be skipped, not sent.
    xml = _config_xml([_acl_xml("too-broad-acl", ["10.0.0.0/7:*"], ["role-a"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    assert apps == [], "a /7 CIDR block must NOT be converted into a private app"
    assert any("too-broad-acl" in w and "/8" in w for w in plan.warnings), "expected a warning naming the skipped ACL and the /8 rule"
    print("PASS: a CIDR resource broader than /8 is skipped (not sent) and warned about, per Netskope's documented host rules")


def test_misaligned_cidr_host_is_normalized_not_rejected():
    # CONFIRMED against a real tenant: POST /api/v2/steering/apps/private
    # rejected "10.51.150.1/24" with {"status": "error", "message": "...
    # 10.51.150.1/24 is not a valid host"} -- a /24 network address must
    # end in .0. Must be normalized to 10.51.150.0/24, not sent as-is or
    # dropped.
    xml = _config_xml([_acl_xml("datacenter-oob-mgmt-policy", ["tcp://10.51.150.1/24:*"], ["nti-role"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    assert len(apps) == 1, "the resource must still be converted, not dropped"
    assert apps[0].host == "10.51.150.0/24", f"expected the normalized network address, got {apps[0].host!r}"
    assert any("10.51.150.1/24" in w and "10.51.150.0/24" in w for w in plan.warnings), (
        "expected a warning naming both the original and normalized host"
    )
    print("PASS: a CIDR host with non-zero host bits (confirmed real Netskope rejection) is normalized to the correct network address, not dropped or sent as-is")


def test_already_aligned_cidr_is_not_flagged_as_normalized():
    xml = _config_xml([_acl_xml("aligned-acl", ["tcp://10.6.0.0/16:*"], ["role-c"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    assert apps[0].host == "10.6.0.0/16"
    assert not any("normalized to a proper network address" in w for w in plan.warnings), (
        "an already-canonical CIDR should not trigger a spurious normalization warning"
    )
    print("PASS: an already-aligned CIDR host is converted unchanged, with no spurious normalization warning")


def test_icmp_resource_is_skipped_not_mis_parsed():
    # CONFIRMED against a real export: icmp:// resources exist alongside
    # tcp://udp:// ones. Before recognizing "icmp" as a scheme, the whole
    # string "icmp://10.6.0.0/16" fell through as a bare (unscheme'd) host,
    # producing a garbage host="icmp" -- must instead be recognized,
    # cleanly skipped (no confirmed ICMP protocols mapping), and never
    # silently corrupted into an invalid create call.
    xml = _config_xml([_acl_xml(
        "bbts-readers-telnet-icmp",
        ["tcp://10.52.0.0/18:23", "icmp://10.52.0.0/18:*"],
        ["vpn-bbts-readers-telnet-icmp"],
    )])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    acl = cfg.network_connect_acls[0]
    icmp_resource = next(r for r in acl.resources if r.protocol == "icmp")
    assert icmp_resource.host == "10.52.0.0/18", f"icmp:// must be recognized as a scheme, not left in the host: got {icmp_resource.host!r}"

    plan = _build_plan(cfg)
    apps = [a for a in plan.private_apps if a.source_type == "network_connect_acl"]
    assert len(apps) == 1, "only the tcp:// resource should convert; the icmp:// one must be skipped, not create a bogus app"
    assert apps[0].host == "10.52.0.0/18"
    assert any("ICMP" in w and "bbts-readers-telnet-icmp" in w for w in plan.warnings)
    print("PASS: icmp:// is recognized as a scheme (not mis-parsed into the host) and cleanly skipped with a warning")


def test_deny_acl_gets_its_own_block_policy_not_merged_into_allow_policies():
    xml = _config_xml([
        _acl_xml("allowed-acl", ["tcp://10.2.2.2:443"], ["shared-role"], action="allow"),
        _acl_xml("denied-acl", ["tcp://10.3.3.3:443"], ["shared-role"], action="deny"),
    ])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    allow_policies = [p for p in plan.policies if p.action == "allow"]
    block_policies = [p for p in plan.policies if p.action == "block"]
    assert len(block_policies) == 1
    block = block_policies[0]
    assert block.rule_name == "ivanti-import-denied-acl-block"
    assert block.private_app_names == ["denied-acl"]
    assert block.user_groups == ["shared-role"]
    # the allowed-acl's own policy must only carry the allowed app, never the denied one
    # (policies are grouped by ACL/app now, not by role -- "shared-role" is
    # attached to both ACLs, but each ACL still gets its own policy).
    allowed_policy = next(p for p in allow_policies if p.rule_name == "ivanti-import-allowed-acl")
    assert allowed_policy.private_app_names == ["allowed-acl"]
    assert allowed_policy.user_groups == ["shared-role"]
    print("PASS: a deny-action ACL gets its own BLOCK policy and is never merged into the allow-ACL's policy")


def test_deny_acl_with_no_roles_warns_instead_of_crashing():
    xml = _config_xml([_acl_xml("orphan-deny-acl", ["tcp://10.4.4.4:443"], [], action="deny")])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    assert not any(p.action == "block" for p in plan.policies)
    assert any("orphan-deny-acl" in w and "no roles" in w for w in plan.warnings)
    print("PASS: a deny-action ACL with no roles warns instead of generating an unscoped block policy")


def test_wildcard_and_missing_ports_get_the_placeholder_range_and_a_warning():
    xml = _config_xml([_acl_xml("wildcard-acl", ["tcp://10.5.5.5:*", "10.5.5.6"], ["role-b"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    plan = _build_plan(cfg)
    apps = {a.app_name: a for a in plan.private_apps if a.source_type == "network_connect_acl"}
    assert apps["wildcard-acl-1"].protocols == [{"type": "tcp", "ports": _WILDCARD_PORT_RANGE}]
    assert apps["wildcard-acl-2"].protocols == [{"type": "tcp", "ports": _WILDCARD_PORT_RANGE}]
    assert any(_WILDCARD_PORT_RANGE in w and "UNCONFIRMED" in w for w in plan.warnings)
    print("PASS: a wildcard ('*') or missing port spec gets the placeholder port range, flagged as unconfirmed")


def test_a_file_with_only_network_connect_acls_reports_clearly_instead_of_looking_empty():
    # Mirrors the real uploaded file: no <resource-profiles>/<user-realms>
    # at all, only network-connect-acls.
    xml = _config_xml([_acl_xml("only-acl", ["10.0.0.0/8:*"], ["some-role"])])
    path = _write(xml)
    try:
        cfg = parse_ivanti_config(path)
    finally:
        os.remove(path)
    assert len(cfg.realms) == 0
    assert len(cfg.resource_profiles) == 0
    assert len(cfg.network_connect_acls) == 1
    assert any("Network Connect ACL" in w for w in cfg.warnings), (
        "a Network-Connect-only file must explain itself, not just silently report 0/0"
    )
    print("PASS: a file with ONLY Network Connect ACLs (like the real upload) reports what it found instead of looking like an empty/broken parse")


if __name__ == "__main__":
    test_namespaced_export_still_parses_realms_and_profiles()
    test_resources_are_parsed_with_structure_scheme_and_bare_forms()
    test_single_resource_allow_acl_converts_to_one_app_and_feeds_role_policy()
    test_multi_resource_acl_becomes_numbered_apps_under_one_policy()
    test_cidr_resource_within_the_slash_8_floor_is_converted()
    test_cidr_resource_broader_than_slash_8_is_skipped_and_warned()
    test_misaligned_cidr_host_is_normalized_not_rejected()
    test_already_aligned_cidr_is_not_flagged_as_normalized()
    test_icmp_resource_is_skipped_not_mis_parsed()
    test_deny_acl_gets_its_own_block_policy_not_merged_into_allow_policies()
    test_deny_acl_with_no_roles_warns_instead_of_crashing()
    test_wildcard_and_missing_ports_get_the_placeholder_range_and_a_warning()
    test_a_file_with_only_network_connect_acls_reports_clearly_instead_of_looking_empty()
    print("\nALL NAMESPACE + NETWORK-CONNECT-ACL CONVERSION CHECKS PASSED")
