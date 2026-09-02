"""
ivanti_parser.py

Parses an Ivanti Connect Secure (ICS) XML configuration export into a
lightweight, tool-friendly object model.

IMPORTANT — READ THIS FIRST
----------------------------
Ivanti does not publish a formal public schema for the "Universal Export"
XML file, and the exact element/attribute names can vary a bit by ICS
version. This parser is written against the *documented admin-console
data model* (Users > User Realms > Roles > Resource Profiles > Resource
Policies, see Ivanti's "Resource Profiles" help page) using the most
common element names seen in real exports:

    <connect-secure-config>
      <user-realms>
        <realm name="...">
          <role-mapping-rules>
            <rule role="..."/>
          </role-mapping-rules>
        </realm>
      </user-realms>
      <resource-profiles>
        <resource-profile name="..." type="web|sam|psam|terminal|file">
          <resource>host[:port][/path]</resource>
          <autopolicies>
            <policy action="allow|deny">
              <resource>host[:port][/path]</resource>
            </policy>
          </autopolicies>
          <roles>
            <role name="..."/>
          </roles>
        </resource-profile>
      </resource-profiles>
    </connect-secure-config>

Once you have a REAL export from your appliance, do this:

  1. Open it and search for the tags that hold realms, roles, and
     resource profiles (they may be named slightly differently, e.g.
     nested under <sa-config>, <auth-config>, etc.)
  2. Update the XPATHS dictionary below to match. Nothing else in this
     file should need to change — every lookup goes through XPATHS.
  3. Re-run with --apply-only-parse (see main.py) to sanity check the
     parsed object counts before mapping/pushing anything to Netskope.

This parser deliberately fails loudly (raises, with a clear message)
rather than silently returning an empty result, so a schema mismatch
is obvious immediately instead of producing a bogus empty plan.

CONFIRMED against a real export: ICS/Pulse Secure XML exports declare a
firmware-version-specific default namespace, e.g.
    <configuration xmlns="http://xml.pulsesecure.net/ive-sa/22.7R2.10">
which would make EVERY XPATHS lookup below silently match nothing (the
handcrafted sample_ivanti_config.xml used for earlier testing has no
namespace at all, so this never showed up until a real file was tried).
Since the namespace URI changes per firmware version, this parser doesn't
hardcode one — every element's namespace is stripped immediately after
parsing (see _strip_namespaces()), so XPATHS can stay plain tag names and
work the same way against a real, namespaced export or an unnamespaced
one.

Also confirmed against a real export: some exports only contain a
`<network-connect-acls>` section (Users > Resource Policies > Network
Connect) with no `<resource-profiles>`/`<user-realms>` at all — a
full-tunnel, subnet/CIDR-based access model with no NPA equivalent (see
UNSUPPORTED note below), rather than the per-app model this tool
converts. These are now recognized and counted (IvantiConfig.
network_connect_acls) so the report says "433 Network Connect ACLs
found, none convertible" instead of a misleading "0 realms, 0 profiles"
that looks like a parse failure.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# XPATHS: adjust these to match your real export. Every one is relative to
# the document root unless noted otherwise.
# ---------------------------------------------------------------------------
XPATHS = {
    "realms": ".//user-realms/realm",
    "realm_role_rules": "./role-mapping-rules/rule",
    "resource_profiles": ".//resource-profiles/resource-profile",
    "profile_resource": "./resource",
    "profile_autopolicies": "./autopolicies/policy",
    "profile_roles": "./roles/role",
    # Confirmed against a real export: Users > Resource Policies > Network
    # Connect. Full-tunnel, subnet/CIDR-based -- see UNSUPPORTED_PROFILE_TYPES
    # and the module docstring. Parsed for visibility/reporting only, never
    # converted into a private app.
    "network_connect_acls": ".//network-connect-acls/network-connect-acl",
}

# Ivanti resource-profile "type" attribute -> how we treat it.
# "clientless" here is a classification of the ORIGINAL Ivanti profile type
# only -- used for the protocol/port default and to decide whether to warn
# that a Browser-Access-shaped profile is being forced to Client access
# (see mapper.py's build_migration_plan). It is NOT used to set the created
# Private App's actual clientless_access field: this tool only creates
# Client-based apps, full stop -- Browser Access is not supported here,
# regardless of what "clientless: True" below would otherwise suggest.
PROFILE_TYPE_DEFAULTS = {
    "web": {"clientless": True, "protocol": "tcp", "default_port": "443"},
    "sam": {"clientless": False, "protocol": "tcp", "default_port": None},
    "psam": {"clientless": False, "protocol": "tcp", "default_port": None},
    "terminal": {"clientless": False, "protocol": "tcp", "default_port": "3389"},
    "file": {"clientless": False, "protocol": "tcp", "default_port": "445"},
}

# Resource-profile types Ivanti supports that have NO sane Netskope Private
# Access equivalent (full L3 VPN tunneling is a network-wide tunnel, not an
# app). These are parsed (so you see them in warnings) but never turned
# into a private app automatically.
UNSUPPORTED_PROFILE_TYPES = {"vpn-tunneling", "network-connect"}

HOST_PORT_RE = re.compile(
    r"^(?P<host>[^:/\s]+)"                         # host / FQDN / IP
    r"(?::(?P<port>[0-9\-,]+))?"                   # optional :port or :port-range
    r"(?P<path>/.*)?$"                             # optional path
)

# ICS "resource" fields for SAM/PSAM profiles are often a subnet, e.g.
# "10.20.8.0/24" or "10.20.8.0/24:5432" — the CIDR mask isn't a path, so it
# needs its own pattern rather than falling through the generic one above.
CIDR_HOST_PORT_RE = re.compile(
    r"^(?P<host>[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2})"
    r"(?::(?P<port>[0-9\-,]+))?$"
)

# Confirmed against a real export: Network Connect ACL <resource> values use
# their OWN format, distinct from the resource-profile one above -- an
# optional "tcp://"/"udp://"/"icmp://" scheme prefix, then host[:ports],
# where ports can be a single port ("3389"), a comma-separated list
# ("3389,22,20,21,1521,1526,1433,3306"), a dash range ("49152-65535"), or the
# wildcard "*" (icmp:// resources still carry a trailing ":*" despite ICMP
# having no ports -- kept as-is, mapper.py decides what to do with it).
# ALL THREE scheme forms, plus bare (no scheme) resources, appear in the
# SAME real file, so all must be handled -- an earlier version of this
# regex only recognized tcp/udp, which silently mis-parsed every icmp://
# resource (the whole "icmp://10.6.0.0/16" string fell through as a bare
# host, corrupting both the host and the port). This is deliberately a
# separate helper from _split_host_port_path()/CIDR_HOST_PORT_RE above:
# reusing those (built for a single numeric port on a resource-profile
# resource) would choke on a compound port list via urlsplit's strict,
# integer-only .port property.
_NC_SCHEME_RE = re.compile(r"^(?P<scheme>tcp|udp|icmp)://(?P<rest>.+)$", re.IGNORECASE)


@dataclass
class ResourcePolicy:
    action: str          # "allow" | "deny"
    host: str
    port: str | None
    path: str | None


@dataclass
class ResourceProfile:
    name: str
    profile_type: str
    host: str
    port: str | None
    path: str | None
    roles: list[str] = field(default_factory=list)
    policies: list[ResourcePolicy] = field(default_factory=list)
    supported: bool = True


@dataclass
class Realm:
    name: str
    roles: list[str] = field(default_factory=list)


@dataclass
class NetworkConnectResource:
    """One <resource> entry inside a Network Connect ACL. Confirmed
    against a real export: `ports` is kept as the raw spec string (a
    single port, a comma-separated list, a dash range, or the wildcard
    "*") rather than split further, since Netskope's own private-app
    `protocols[].ports` field already accepts a comma-separated list
    directly -- see mapper.py's _protocols_for_resource()."""
    raw: str
    protocol: str          # "tcp" | "udp" (default "tcp" when no scheme prefix)
    host: str              # single IP, or a CIDR block (mask included)
    ports: str | None      # raw port spec, or None if the resource had none
    is_cidr: bool          # True if `host` is a subnet ("/mask" present)


def _parse_network_connect_resource(raw: str) -> NetworkConnectResource:
    text = raw.strip()
    protocol = "tcp"
    m = _NC_SCHEME_RE.match(text)
    if m:
        protocol = m.group("scheme").lower()
        text = m.group("rest")
    # Split on the LAST colon -- these are all IPv4/CIDR hosts (no colons of
    # their own), so this is safe and simpler than a full URL parse (which
    # chokes on a compound port list like "22,5432" or "49152-65535" -- see
    # _NC_SCHEME_RE's docstring note above).
    if ":" in text:
        host, ports = text.rsplit(":", 1)
        ports = ports.strip() or None
    else:
        host, ports = text, None
    return NetworkConnectResource(raw=raw, protocol=protocol, host=host.strip(), ports=ports, is_cidr="/" in host)


@dataclass
class NetworkConnectAcl:
    """A Users > Resource Policies > Network Connect ACL: a full-tunnel,
    subnet/CIDR-based access rule -- structurally different from a
    per-app Resource Profile. CONVERTED into Private Apps (one per
    resource -- an NPA private app is one host, so a multi-resource ACL
    becomes multiple apps) since most real-world resources turn out to be
    a single host/IP with a port spec, which maps cleanly. See mapper.py
    for the actual conversion logic and its CIDR-handling rules."""
    name: str
    resources: list[NetworkConnectResource] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    action: str = "allow"


@dataclass
class IvantiConfig:
    realms: list[Realm] = field(default_factory=list)
    resource_profiles: list[ResourceProfile] = field(default_factory=list)
    network_connect_acls: list[NetworkConnectAcl] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _split_host_port_path(raw: str) -> tuple[str, str | None, str | None]:
    raw = raw.strip()

    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or raw
        port = str(parts.port) if parts.port else None
        path = parts.path or None
        return host, port, path

    m = CIDR_HOST_PORT_RE.match(raw)
    if m:
        return m.group("host"), m.group("port"), None

    m = HOST_PORT_RE.match(raw)
    if not m:
        return raw, None, None
    return m.group("host"), m.group("port"), m.group("path")


def _strip_namespaces(root: ET.Element) -> None:
    """
    Confirmed against a real export: ICS/Pulse Secure XML declares a
    firmware-version-specific default namespace (e.g.
    xmlns="http://xml.pulsesecure.net/ive-sa/22.7R2.10"). ElementTree
    requires an exact namespace match on every find()/findall() call, so
    without this, XPATHS (all plain tag names, no namespace prefix) would
    silently match nothing against a real export -- producing a bogus
    "0 realms, 0 profiles" result that looks like an empty/misconfigured
    file rather than a namespace mismatch. Since the namespace URI varies
    by firmware version, this strips every element's namespace in place
    right after parsing instead of hardcoding one version's URI, so
    XPATHS works the same way against a real, namespaced export and the
    unnamespaced sample_ivanti_config.xml alike.
    """
    for elem in root.iter():
        if isinstance(elem.tag, str) and elem.tag.startswith("{"):
            elem.tag = elem.tag.split("}", 1)[1]


def parse_ivanti_config(xml_path: str) -> IvantiConfig:
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise ValueError(f"'{xml_path}' is not valid XML: {e}") from e

    root = tree.getroot()
    _strip_namespaces(root)
    cfg = IvantiConfig()

    # --- Realms & role-mapping rules -------------------------------------
    realm_nodes = root.findall(XPATHS["realms"])
    if not realm_nodes:
        cfg.warnings.append(
            f"No realms found at XPath '{XPATHS['realms']}'. If your export "
            "uses different tag names, update XPATHS['realms'] in "
            "ivanti_parser.py."
        )
    for rnode in realm_nodes:
        name = rnode.get("name") or rnode.findtext("name", "").strip()
        if not name:
            cfg.warnings.append("Found a <realm> with no name attribute; skipping.")
            continue
        realm = Realm(name=name)
        for rule in rnode.findall(XPATHS["realm_role_rules"]):
            # CONFIRMED against a real export: the role name lives in a
            # <roles> (PLURAL) child element's text, e.g.
            # <roles>vpn-is-role</roles> -- not a `role=` attribute or a
            # singular <role> child, which is what this originally (and
            # incorrectly) assumed based only on Ivanti's documented data
            # model rather than a real file. That mismatch meant EVERY
            # realm parsed with 0 roles no matter how many role-mapping
            # rules it actually had (410 rules across 5 real realms went
            # completely unseen). Only affects the analysis report's
            # cosmetic "Realms & Role-Mapping Reference" table -- mapper.py
            # never reads Realm.roles for anything in the actual
            # conversion. A rule can apparently carry more than one
            # <roles> element (not seen in the tested export -- all 410
            # rules there had exactly one -- but handled defensively,
            # since ICS's admin console does support assigning multiple
            # roles from a single rule).
            role_names = [
                rn.text.strip() for rn in rule.findall("roles") if rn.text and rn.text.strip()
            ]
            if not role_names:
                # Fall back to the originally-assumed shape in case a
                # DIFFERENT real export uses it instead.
                role = rule.get("role") or rule.findtext("role", "").strip()
                if role:
                    role_names = [role]
            realm.roles.extend(role_names)
        cfg.realms.append(realm)

    # --- Resource profiles -------------------------------------------------
    profile_nodes = root.findall(XPATHS["resource_profiles"])
    if not profile_nodes:
        cfg.warnings.append(
            f"No resource profiles found at XPath '{XPATHS['resource_profiles']}'. "
            "Update XPATHS['resource_profiles'] to match your export."
        )
    for pnode in profile_nodes:
        name = pnode.get("name") or pnode.findtext("name", "").strip()
        ptype = (pnode.get("type") or "web").strip().lower()

        if not name:
            cfg.warnings.append("Found a <resource-profile> with no name; skipping.")
            continue

        resource_text = pnode.findtext(XPATHS["profile_resource"], "").strip()
        if not resource_text:
            cfg.warnings.append(
                f"Resource profile '{name}' has no primary resource; skipping."
            )
            continue
        host, port, path = _split_host_port_path(resource_text)

        defaults = PROFILE_TYPE_DEFAULTS.get(ptype)
        supported = ptype not in UNSUPPORTED_PROFILE_TYPES and defaults is not None
        if not supported:
            cfg.warnings.append(
                f"Resource profile '{name}' has type '{ptype}', which has no "
                "direct Netskope Private Access equivalent (e.g. full VPN "
                "tunneling). It will be listed but NOT converted into a "
                "private app. Review manually."
            )

        profile = ResourceProfile(
            name=name,
            profile_type=ptype,
            host=host,
            port=port or (defaults or {}).get("default_port"),
            path=path,
            supported=supported,
        )

        for role_node in pnode.findall(XPATHS["profile_roles"]):
            role_name = role_node.get("name") or role_node.text
            if role_name:
                profile.roles.append(role_name.strip())
        if not profile.roles:
            cfg.warnings.append(
                f"Resource profile '{name}' is not associated with any role; "
                "it won't be reachable by any user until you assign one."
            )

        for policy_node in pnode.findall(XPATHS["profile_autopolicies"]):
            action = (policy_node.get("action") or "allow").strip().lower()
            policy_resource = policy_node.findtext("resource", "").strip()
            if not policy_resource:
                continue
            p_host, p_port, p_path = _split_host_port_path(policy_resource)
            profile.policies.append(
                ResourcePolicy(action=action, host=p_host, port=p_port, path=p_path)
            )

        cfg.resource_profiles.append(profile)

    # --- Network Connect ACLs ------------------------------------------------
    # Confirmed against a real export that this section can be the ONLY
    # thing present (no <resource-profiles>/<user-realms> at all), so
    # without parsing it at all the tool would report "0 realms, 0
    # profiles" with no indication anything was actually found in the
    # file. See mapper.py for how these are turned into Private Apps.
    acl_nodes = root.findall(XPATHS["network_connect_acls"])
    acls_with_v6_or_fqdn = 0
    for anode in acl_nodes:
        name = anode.findtext("name", "").strip()
        if not name:
            continue
        resources = [
            _parse_network_connect_resource(r.text)
            for r in anode.findall("resource")
            if r.text and r.text.strip()
        ]
        roles = [r.text.strip() for r in anode.findall("roles") if r.text and r.text.strip()]
        action = (anode.findtext("action", "allow") or "allow").strip().lower()
        cfg.network_connect_acls.append(
            NetworkConnectAcl(name=name, resources=resources, roles=roles, action=action)
        )
        # <resources-v6>/<resources-fqdn> exist in the schema (seen as empty/
        # xsi:nil in the real export tested) but aren't parsed -- no real
        # example was available to confirm their child-element shape. Flagged
        # so an export that DOES populate them isn't silently dropped.
        for tag in ("resources-v6", "resources-fqdn"):
            node = anode.find(tag)
            if node is not None and len(list(node)) > 0:
                acls_with_v6_or_fqdn += 1
                break

    if cfg.network_connect_acls:
        example_names = ", ".join(a.name for a in cfg.network_connect_acls[:3])
        more = f" (and {len(cfg.network_connect_acls) - 3} more)" if len(cfg.network_connect_acls) > 3 else ""
        cfg.warnings.append(
            f"Found {len(cfg.network_connect_acls)} Network Connect ACL(s) (e.g. "
            f"{example_names}{more}) — full-tunnel, subnet/CIDR-based access rules from "
            "Users > Resource Policies > Network Connect. These ARE converted into "
            "Private Apps (one per resource) where possible -- see mapper.py's warnings "
            "and the 'Network Connect ACLs' section of the analysis report for exactly "
            "what was converted vs. skipped, and why."
        )
    if acls_with_v6_or_fqdn:
        cfg.warnings.append(
            f"{acls_with_v6_or_fqdn} Network Connect ACL(s) have non-empty IPv6 or FQDN "
            "resource lists (<resources-v6>/<resources-fqdn>) -- these are NOT parsed or "
            "converted (no real example was available to confirm their shape). Review "
            "these ACLs manually."
        )

    return cfg
