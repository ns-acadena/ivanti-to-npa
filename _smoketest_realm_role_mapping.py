"""
Verify realm role-mapping-rule parsing against the CONFIRMED real shape,
found in a real export (policy-export.xml, 5 realms / 410 role-mapping
rules): the role name lives in a <roles> (PLURAL) child element's text --

    <rule>
        <name>is-access</name>
        <custom-expression><expressions>is-access</expressions></custom-expression>
        <roles>vpn-is-role</roles>
        <stop-rules-processing>false</stop-rules-processing>
    </rule>

-- not a `role=` attribute or a singular <role> child, which is what
ivanti_parser.py originally (and incorrectly) assumed based only on
Ivanti's documented data model. That mismatch meant EVERY realm parsed
with 0 roles no matter how many role-mapping-rules it actually had (all
410 real rules went completely unseen; only affects the analysis report's
cosmetic "Realms & Role-Mapping Reference" table -- mapper.py never reads
Realm.roles for the actual conversion).

Not part of the shipped tool.
"""
import os
import tempfile

from ivanti_parser import parse_ivanti_config

NAMESPACE = "http://xml.pulsesecure.net/ive-sa/22.7R2.10"


def _write(xml: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w") as f:
        f.write(xml)
    return path


def _realm_xml(name: str, rules_xml: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="{NAMESPACE}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <users>
    <user-realms>
      <realm>
        <name>{name}</name>
        <role-mapping-rules>
{rules_xml}
        </role-mapping-rules>
      </realm>
    </user-realms>
  </users>
</configuration>
"""


def _parse(name, rules_xml):
    path = _write(_realm_xml(name, rules_xml))
    try:
        return parse_ivanti_config(path)
    finally:
        os.remove(path)


def test_confirmed_real_roles_child_element_shape():
    cfg = _parse("datacenter-azure-realm", """
        <rule>
            <name>is-access</name>
            <roles>vpn-is-role</roles>
            <stop-rules-processing>false</stop-rules-processing>
        </rule>
        <rule>
            <name>grp-is-dbadmin</name>
            <roles>vpn-grp-is-dbadmin</roles>
            <stop-rules-processing>false</stop-rules-processing>
        </rule>
    """)
    assert len(cfg.realms) == 1
    assert cfg.realms[0].roles == ["vpn-is-role", "vpn-grp-is-dbadmin"]
    print("PASS: the confirmed real <roles> child-element shape is parsed correctly")


def test_multiple_roles_children_on_one_rule():
    # Not seen in the tested real export (all 410 rules had exactly one),
    # but ICS's admin console does support assigning more than one role
    # from a single rule -- handled defensively.
    cfg = _parse("multi-role-realm", """
        <rule>
            <name>combo</name>
            <roles>role-a</roles>
            <roles>role-b</roles>
        </rule>
    """)
    assert cfg.realms[0].roles == ["role-a", "role-b"]
    print("PASS: a rule with more than one <roles> child captures all of them")


def test_fallback_role_attribute_shape_still_works():
    # The originally-assumed (pre-fix) shape -- kept as a fallback in case
    # a DIFFERENT real export uses it instead of <roles>.
    cfg = _parse("legacy-shape-realm", '<rule role="Employees-Full"/>')
    assert cfg.realms[0].roles == ["Employees-Full"]
    print("PASS: the originally-assumed role= attribute shape still works as a fallback")


def test_fallback_singular_role_child_shape_still_works():
    cfg = _parse("legacy-shape-realm-2", "<rule><role>Employees-Full</role></rule>")
    assert cfg.realms[0].roles == ["Employees-Full"]
    print("PASS: the originally-assumed singular <role> child shape still works as a fallback")


def test_realm_with_no_rules_has_empty_roles_not_a_crash():
    cfg = _parse("empty-realm", "")
    assert cfg.realms[0].roles == []
    print("PASS: a realm with no role-mapping rules parses with an empty roles list, no crash")


def test_rule_with_blank_roles_text_is_skipped():
    cfg = _parse("blank-role-realm", "<rule><roles>   </roles></rule>")
    assert cfg.realms[0].roles == []
    print("PASS: a <roles> element with only whitespace text doesn't produce a bogus blank role")


if __name__ == "__main__":
    test_confirmed_real_roles_child_element_shape()
    test_multiple_roles_children_on_one_rule()
    test_fallback_role_attribute_shape_still_works()
    test_fallback_singular_role_child_shape_still_works()
    test_realm_with_no_rules_has_empty_roles_not_a_crash()
    test_rule_with_blank_roles_text_is_skipped()
    print("\nALL REALM ROLE-MAPPING CHECKS PASSED")
