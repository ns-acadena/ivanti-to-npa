"""
mapper.py

Translates parsed Ivanti Connect Secure objects (ivanti_parser.IvantiConfig)
into Netskope Private Access API v2 request payloads.

WHY THIS IS A TRANSLATION, NOT A 1:1 IMPORT
--------------------------------------------
Ivanti Connect Secure (a VPN gateway) and Netskope Private Access (a ZTNA
service) are architecturally different, so a few things can't be
auto-converted and are flagged in `plan.warnings` instead of silently
guessed:

1. Publishers. ICS has no equivalent of an NPA Publisher (a lightweight
   connector you deploy near each app). You must tell this tool which
   Publisher(s) to attach new Private Apps to — it will not invent one.

2. Identity / groups. ICS realms map users to roles via its own
   role-mapping rules (AD/LDAP/RADIUS attributes, certs, etc.). Netskope
   Private Access policies scope access to *IdP group names* already
   known to your Netskope tenant via SSO/SCIM. This tool carries the
   Ivanti role *name* straight into the policy's userGroups field as a
   starting point — you must confirm that name matches (or remap it to)
   a real group in your IdP before trusting the policy.

   Policies are generated ONE PER APP/SERVER GROUP (one resource profile,
   or one Network Connect ACL), not one per role. Each policy's rule_name
   is derived from that profile/ACL's (sanitized) name, and its userGroups
   is the full list of role(s) attached to that profile/ACL. Before this,
   policies were grouped by role instead -- one role with access to many
   unrelated apps/ACLs produced a single large policy naming all of them,
   which obscured which app/server the policy was actually about and
   meant a role attached to N profiles/ACLs needed N nearly-identical
   role-named policies if any of those apps were also shared with other
   roles. Grouping by app/server instead keeps a policy's name and scope
   tied to the thing it protects; multiple roles on the same profile/ACL
   still collapse into ONE policy (userGroups is a list), so this doesn't
   multiply policy count for the common multi-role-per-app case.

3. Network Connect ACLs (full-tunnel, subnet/CIDR-based access rules) are
   converted -- one Private App PER RESOURCE, since an NPA app is one
   host and a real ACL's resources turn out to be overwhelmingly
   single-host (confirmed against a real export: 962 of 979 resources
   across 433 ACLs were a single IP/host with a port spec; the other 17
   were CIDR blocks, none broader than Netskope's documented /8 floor).
   A multi-resource ACL becomes multiple numbered apps
   ("<acl-name>-1", "<acl-name>-2", ...) all granted by the same
   ACL-named policy (see point 2 above). A CIDR resource broader than /8, or exactly
   "0/0"/"::"-style any-address, is skipped and warned about rather than
   sent (Netskope explicitly disallows these). See
   _protocols_for_resource() and the Network Connect ACL section of
   build_migration_plan() for the full conversion logic.

   CONFIRMED against that same real export: the same exact resource (host,
   protocol, AND ports all identical) is specified by more than one ACL --
   80 of 979 resources (179 of 706 distinct hosts) were duplicates this
   way, each previously becoming its own separate, redundant private app.
   These are now consolidated: the first ACL to specify a given exact
   resource creates its private app; every later ACL specifying the
   IDENTICAL resource reuses that same app instead of creating another
   one. A shared app is named from its HOST (_host_derived_app_name())
   rather than from whichever ACL happened to create it first, which is
   both deterministic (independent of ACL processing order) and the same
   naming scheme a bigger, NOT-yet-implemented consolidation (merging by
   host alone regardless of port, combining multiple protocol entries
   into one app) would also need -- adopting it now for shared apps avoids
   renaming anything again later. A non-shared resource keeps the
   existing, more legible ACL-name-derived scheme, unaffected. Deny-action
   ACLs are excluded from this sharing pool entirely (always get their own
   unshared app) -- see build_migration_plan()'s Network Connect ACL
   section for why.

4. "Deny" autopolicies. NPA real-time policies are evaluated in order
   with allow/block actions; ICS's per-resource allow/deny list doesn't
   map cleanly to a single NPA rule. Deny policies are surfaced as
   warnings for manual policy-ordering review rather than auto-created.

5. Access method. Every Private App this tool creates is Client-based
   (clientless_access=False) -- Browser Access is not supported here, by
   design, regardless of the app. An Ivanti "web" profile would otherwise
   map naturally to Netskope's clientless/Browser Access mode, so those
   are forced to Client access instead and flagged with a warning. Set up
   Browser Access manually in the UI afterward if a given app needs it.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ivanti_parser import (
    IvantiConfig,
    NetworkConnectResource,
    PROFILE_TYPE_DEFAULTS,
    ResourceProfile,
)


def _format_imported_at(dt: datetime) -> str:
    """Long-format timestamp for policy descriptions, e.g. 'Monday, August
    31, 2026 at 03:45 PM UTC'. Always UTC regardless of the caller's local
    time, so descriptions are unambiguous no matter where the tool runs."""
    return dt.astimezone(timezone.utc).strftime("%A, %B %d, %Y at %I:%M %p UTC")


@dataclass
class PublisherRef:
    publisher_id: str | None = None
    publisher_name: str | None = None

    def to_payload(self) -> dict:
        d = {}
        if self.publisher_id:
            d["publisher_id"] = self.publisher_id
        if self.publisher_name:
            d["publisher_name"] = self.publisher_name
        return d


@dataclass
class PrivateAppPlan:
    source_profile: str
    app_name: str
    host: str
    protocols: list[dict]
    clientless_access: bool
    publishers: list[PublisherRef]
    tags: list[str]
    # "resource_profile" (the default) or "network_connect_acl" -- lets
    # report.py look the source up in the right IvantiConfig list and show
    # the correct type/roles, since the two have different shapes.
    source_type: str = "resource_profile"
    # ALL Ivanti objects that map to this one app -- almost always just
    # [source_profile] (auto-filled below if left empty), but a Network
    # Connect ACL app can be shared by more than one ACL when they specify
    # an EXACT duplicate resource (same host, protocol, and ports) --
    # confirmed real: 80 of 979 resources across a real 433-ACL export
    # were exact duplicates of another ACL's resource, each previously
    # creating its own separate, redundant private app. report.py uses
    # this instead of source_profile alone so a shared app's analysis-
    # report row doesn't silently show only the first contributing ACL.
    # See mapper.py's Network Connect ACL consolidation logic below.
    source_profiles: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.source_profiles:
            self.source_profiles = [self.source_profile]

    def to_payload(self) -> dict:
        return {
            "app_name": self.app_name,
            "host": self.host,
            "protocols": self.protocols,
            "clientless_access": self.clientless_access,
            "publishers": [p.to_payload() for p in self.publishers],
            "tags": [{"tag_name": t} for t in self.tags],
            "use_publisher_dns": False,
            "trust_self_signed_certs": False,
        }


_DEFAULT_BLOCK_TEMPLATE = "Default Template"


@dataclass
class NpaPolicyPlan:
    rule_name: str
    private_app_names: list[str]
    user_groups: list[str]
    description: str
    # "allow" (the default -- ICS's per-resource allow rules) or "block"
    # (generated for a resource profile that had an ICS "deny" autopolicy;
    # see build_migration_plan()). block_template names the User
    # Notification template shown to blocked users -- required by
    # Netskope's block-policy schema (confirmed via Netskope's own
    # netskopeoss/terraform-provider-netskope example: match_criteria_action
    # needs action_name="block" + template + emit_alert). Defaults to
    # "Default Template", UNCONFIRMED against any specific tenant -- if
    # that name doesn't exist on yours, the create call will fail with a
    # clear error naming the problem; tell me the real template name from
    # Policies > User Notification and this default can be corrected or
    # made a --block-policy-template flag.
    action: str = "allow"
    block_template: str = _DEFAULT_BLOCK_TEMPLATE

    def to_payload(
        self,
        group_id: str | int | None = None,
        group_name: str | None = None,
        omit_user_groups: bool = False,
        user_group_objects: list[dict] | None = None,
    ) -> dict:
        """
        Confirmed against TWO real rules pulled from a live tenant (GET
        /api/v2/policy/npa/rules): an ungrouped/unscoped one, and
        "AWS-RDP" (rule_id 67) -- confirmed by the operator to actually be a
        member of an NPA Policy Group AND scoped to a real user group:

            {
              "enabled": "1",
              "policy_type": "private-app",
              "rule_data": {
                "access_method": ["Client"],
                "external_dlp": false,
                "json_version": 3,
                "match_criteria_action": {"action_name": "allow"},
                "policy_type": "private-app",
                "privateApps": ["[AWS-RDP]"],
                "show_dlp_profile_action_table": false,
                "userGroupObjects": [{"disabled": "", "id": "207", "name": "Netskope User Provisioning"}],
                "userGroups": ["Netskope User Provisioning"],
                "userType": "user",
                "version": 2
              },
              "rule_id": "67",
              "rule_name": "AWS-RDP"
            }

        Earlier versions of this tool sent privateApps/userGroups/etc. as
        top-level fields with no "rule_data" wrapper at all, which the API
        rejected with {"status": "error", "message": "Missing rule_data
        when creating a policy"} -- returned as an HTTP 200, so it looked
        like a success until someone checked the tenant. netskope_client.py
        now also treats that error-shaped body as a failure regardless of
        HTTP status, so this class of bug fails loudly instead of silently
        next time.

        - **userGroups** is confirmed: a plain list of group name strings,
          nested inside rule_data.
        - **userGroupObjects** is also sent alongside userGroups (id+name
          objects) since the confirmed real rule carries both side by side
          and it's unclear which one the API actually keys off of for the
          restriction -- sending both maximizes the odds this actually
          takes effect. `user_group_objects` is built by the caller (see
          main.py's group-existence check, which already has each matched
          group's id) and only included when every group could be matched.
        - **group_id/group_name are still sent at the TOP level**, unchanged
          from before this fix. AWS-RDP's GET response above shows NEITHER
          field despite being in a real Policy Group -- initially read as
          evidence that group_id doesn't work, but Netskope's own
          netskopeoss/terraform-provider-netskope schema documents
          `group_id` on `netskope_npa_rules` as **write-only** (accepted on
          create, never echoed back by GET) and `group_name` as a *computed*
          (server-derived) convenience field. That fully explains the
          absence here without meaning group_id is ignored. Net effect:
          keep sending group_id as the real link, group_name is extra and
          probably ignored. Because GET can't confirm this either way,
          **the only real verification is checking the Netskope UI after a
          create** to confirm the new rule actually landed in the intended
          group -- do that once before trusting this at scale.
        - Private app names appear wrapped in brackets in the real object
          ("[AWS-RDP]", not "AWS-RDP") -- reproduced here for fidelity.

        `self.action` selects "allow" (default) or "block". A block policy's
        match_criteria_action needs "template" (a User Notification template
        name shown to blocked users) and "emit_alert" in addition to
        action_name -- per Netskope's own netskopeoss/terraform-provider-netskope
        example, since no real block-rule GET response has been confirmed
        against a live tenant the way the allow-rule shape above was.
        """
        if self.action == "block":
            match_criteria_action = {
                "action_name": "block",
                "template": self.block_template,
                "emit_alert": True,
            }
        else:
            match_criteria_action = {"action_name": "allow"}

        rule_data = {
            "policy_type": "private-app",
            "match_criteria_action": match_criteria_action,
            "privateApps": [f"[{name}]" for name in self.private_app_names],
            "access_method": ["Client"],
            "userType": "user",
            "json_version": 3,
            "external_dlp": False,
            "show_dlp_profile_action_table": False,
            "version": 1,
        }
        # omit_user_groups=True means none of self.user_groups could be
        # confirmed as a real IdP group in the tenant -- rather than fail the
        # create or scope the policy to a group that will match nobody, the
        # policy is created with no userGroups restriction at all (open to any
        # authenticated user). Caller is responsible for warning loudly about
        # this; see main.py's group-existence check.
        if not omit_user_groups:
            rule_data["userGroups"] = self.user_groups
            # Sent alongside userGroups (not instead of it) -- see the
            # docstring note on why both are included.
            if user_group_objects:
                rule_data["userGroupObjects"] = user_group_objects

        payload = {
            "rule_name": self.rule_name,
            "description": self.description,
            "enabled": "1",
            "policy_type": "private-app",
            "rule_data": rule_data,
        }
        if group_id is not None:
            payload["group_id"] = group_id
        if group_name is not None:
            payload["group_name"] = group_name
        return payload


@dataclass
class MigrationPlan:
    private_apps: list[PrivateAppPlan] = field(default_factory=list)
    policies: list[NpaPolicyPlan] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped_profiles: list[str] = field(default_factory=list)


def _sanitize_app_name(name: str) -> str:
    return name.strip().replace(" ", "-")


def _host_derived_app_name(host: str) -> str:
    """
    Used ONLY for a Network Connect ACL resource that turns out to be
    shared across more than one ACL (see the consolidation logic in
    build_migration_plan()) -- an app name derived from whichever ACL
    happened to create it first would be arbitrary and order-dependent.
    Naming it from the host instead is deterministic regardless of ACL
    processing order, and is deliberately the SAME scheme a future,
    bigger consolidation (merging by host alone, regardless of port --
    not implemented here, see module docstring point 3) would also need,
    so adopting it now for shared apps avoids renaming anything again
    later. Non-shared resources are unaffected -- they keep the existing,
    more legible ACL-name-derived scheme.
    """
    return _sanitize_app_name(host).replace(".", "-").replace("/", "_").replace(":", "_")


def _protocols_for_profile(profile: ResourceProfile) -> list[dict]:
    ptype_defaults = PROFILE_TYPE_DEFAULTS.get(profile.profile_type, {})
    proto_type = ptype_defaults.get("protocol", "tcp")

    # Prefer explicit allow-policy ports (union), fall back to the
    # profile's own resource port, then the type default.
    ports = sorted(
        {p.port for p in profile.policies if p.action == "allow" and p.port}
    )
    if not ports and profile.port:
        ports = [profile.port]
    if not ports:
        ports = [ptype_defaults.get("default_port") or "443"]

    if len(ports) == 1:
        return [{"type": proto_type, "port": ports[0]}]
    return [{"type": proto_type, "ports": ",".join(ports)}]


# Confirmed Netskope private-app host rule (operator-supplied, from
# Netskope's own app-definition guidance): "Do not use 0/0. Do not use any
# CIDR less than /8 (10/8 is allowed, but 1/7 is not allowed)." A prefix
# length below this is an enormous address block, not a scoped resource --
# skipped and warned about rather than sent.
MIN_CIDR_PREFIX_LEN = 8

# UNCONFIRMED against any live tenant: Netskope's private-app protocols
# schema takes a "port" or "ports" value, but no example with an
# open-ended/wildcard port has been confirmed. A full valid TCP/UDP port
# range is used as the literal stand-in for ICS's "*" (any port) --
# flagged with a warning each time it's used so it can be corrected if a
# real tenant rejects it or expects something else (e.g. omitting the
# port field entirely).
_WILDCARD_PORT_RANGE = "1-65535"


def _cidr_prefix_len(host: str) -> int | None:
    """Returns the prefix length of a CIDR host ("10.6.0.0/16" -> 16), or
    None if `host` isn't in CIDR form."""
    if "/" not in host:
        return None
    try:
        return int(host.rsplit("/", 1)[1])
    except ValueError:
        return None


def _normalize_cidr_host(host: str) -> tuple[str | None, bool]:
    """
    CONFIRMED against a real tenant: Netskope's private-app host
    validation rejects a CIDR block whose host bits aren't zeroed for its
    prefix length -- e.g. the exact error hit in production:
        POST /api/v2/steering/apps/private -> HTTP 200,
        {"status": "error", "message": "Enter a valid domain, wildcard,
         PQDN, IP address or CIDR. 10.51.150.1/24 is not a valid host."}
    "10.51.150.1/24" is a host address with a /24 mask attached, not a
    valid /24 NETWORK address (which must end in ".0" for that prefix
    length) -- a mistake that's easy to make by hand in an ICS export and
    that ICS itself apparently doesn't validate. Rather than send it
    as-is and fail loudly at create time, it's normalized to the correct
    network address here (e.g. "10.51.150.0/24") before ever building a
    payload -- this is what was clearly intended (the whole subnet), and
    a deterministic, lossless correction, not a guess.

    Returns (canonical_host, changed). canonical_host is None if `host`
    isn't parseable as a network at all (defensive; not expected to
    happen with real ICS data).
    """
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return None, False
    canonical = str(net)
    return canonical, canonical != host


def _protocols_for_resource(resource: NetworkConnectResource) -> list[dict]:
    """
    Builds a private-app `protocols` entry from one parsed Network Connect
    ACL resource. `resource.ports` is the RAW spec string -- a single port,
    a comma-separated list, or a dash range -- and is passed straight
    through: Netskope's protocols[].ports field already accepts a
    comma-separated list (used elsewhere in this tool -- see
    _protocols_for_profile()), and a dash range is passed through
    unmodified since no live-tenant example was available to confirm
    whether it needs its own field/format.
    """
    ports = resource.ports
    if not ports or ports == "*":
        ports = _WILDCARD_PORT_RANGE
    if "," in ports or "-" in ports:
        return [{"type": resource.protocol, "ports": ports}]
    return [{"type": resource.protocol, "port": ports}]


def build_migration_plan(
    ivanti_config: IvantiConfig,
    default_publishers: list[PublisherRef],
    tag_name: str = "ivanti-import",
    publisher_overrides: dict[str, PublisherRef] | None = None,
    imported_at: datetime | None = None,
) -> MigrationPlan:
    """
    `default_publishers` is applied to every private app unless a
    resource-profile-specific override is present in `publisher_overrides`.
    Netskope Private Apps accept multiple Publishers per app (for
    redundancy), so this is a list — 1 to 4 in practice, matching what the
    CLI's --select-publishers/--publisher-ids allow.

    `imported_at` is baked into every generated policy's `description` as a
    long-format UTC timestamp (e.g. "Monday, August 31, 2026 at 03:45 PM
    UTC"), recording when this plan was built. Defaults to the current time
    if not given -- callers that build a plan once and reuse it for both
    plan.json (the preview) and the actual --apply create calls will get
    the same timestamp in both, since it's computed once and stored on each
    NpaPolicyPlan's description at construction time here, not
    re-computed later at create time.
    """
    imported_at_str = _format_imported_at(imported_at or datetime.now(timezone.utc))
    publisher_overrides = publisher_overrides or {}
    plan = MigrationPlan(warnings=list(ivanti_config.warnings))

    for profile in ivanti_config.resource_profiles:
        if not profile.supported:
            plan.skipped_profiles.append(profile.name)
            continue

        app_name = _sanitize_app_name(profile.name)

        deny_policies = [p for p in profile.policies if p.action == "deny"]
        if deny_policies:
            # ICS's deny is scoped to specific resources (host/port/path)
            # WITHIN this profile, not to a role -- NPA private-app policies
            # don't support that sub-app granularity, so the generated block
            # policy covers the whole app instead, scoped to the SAME
            # role(s) already attached to this profile (mirrors Ivanti's own
            # scoping: the deny rule lives inside the same profile as those
            # roles' access).
            denied = ", ".join(
                f"{p.host}" + (f":{p.port}" if p.port else "") + (p.path or "")
                for p in deny_policies
            )
            if profile.roles:
                plan.policies.append(
                    NpaPolicyPlan(
                        rule_name=f"ivanti-import-{app_name}-block",
                        private_app_names=[app_name],
                        user_groups=list(profile.roles),
                        action="block",
                        description=(
                            f"Auto-generated BLOCK policy from {len(deny_policies)} ICS deny "
                            f"rule(s) in resource profile '{profile.name}' (denied: {denied}). "
                            "ICS's deny is scoped to specific host(s)/port(s)/path(s) within "
                            "this profile; NPA private-app policies don't support that "
                            "sub-app granularity, so this blocks the WHOLE app for the same "
                            "role(s) that have access to it -- review whether that's too broad "
                            f"for your case. Imported {imported_at_str}."
                        ),
                    )
                )
                plan.warnings.append(
                    f"Resource profile '{profile.name}' had {len(deny_policies)} ICS deny "
                    f"rule(s) (denied: {denied}); generated a companion BLOCK policy "
                    f"'ivanti-import-{app_name}-block' for the whole app instead, scoped to "
                    f"the same role(s) ({', '.join(profile.roles)}) since NPA can't block "
                    "just the specific sub-resource ICS did. Review its scope/ordering "
                    "manually, and confirm the block-policy notification template "
                    f"('{_DEFAULT_BLOCK_TEMPLATE}') actually exists in your tenant."
                )
            else:
                # No roles attached to this profile at all -- nothing to
                # scope a block policy to, so fall back to the old
                # warning-only behavior (nothing is silently over-blocked).
                plan.warnings.append(
                    f"Resource profile '{profile.name}' has {len(deny_policies)} deny "
                    f"rule(s) in Ivanti (denied: {denied}) but no roles attached to scope "
                    "a block policy to -- no block policy was generated. Review manually."
                )

        publishers_for_app = (
            [publisher_overrides[profile.name]]
            if profile.name in publisher_overrides
            else list(default_publishers)
        )

        # This tool only creates Client-based Private Apps -- Browser
        # Access (clientless) is not supported, regardless of what the
        # Ivanti profile type would normally suggest (e.g. "web" profiles
        # default to clientless=True in PROFILE_TYPE_DEFAULTS, used only
        # for cosmetic/report purposes below, never for the actual app
        # payload). Every created app requires the Netskope Client.
        would_be_clientless = PROFILE_TYPE_DEFAULTS.get(profile.profile_type, {}).get(
            "clientless", False
        )
        if would_be_clientless:
            plan.warnings.append(
                f"Resource profile '{profile.name}' (type '{profile.profile_type}') would "
                "normally map to Browser Access (clientless) in Netskope, but this tool only "
                "creates Client-based Private Apps -- Browser Access is not supported here. "
                "Users will need the Netskope Client to reach this app; configure Browser "
                "Access manually afterward in the UI if you need it."
            )

        app_plan = PrivateAppPlan(
            source_profile=profile.name,
            app_name=app_name,
            host=profile.host,
            protocols=_protocols_for_profile(profile),
            clientless_access=False,
            publishers=publishers_for_app,
            tags=[tag_name],
        )
        plan.private_apps.append(app_plan)

        # One ALLOW policy per app/server group (this profile), not per
        # role -- see module docstring point 2. Every role attached to
        # this profile lands in the SAME policy's userGroups list.
        if profile.roles:
            plan.policies.append(
                NpaPolicyPlan(
                    rule_name=f"ivanti-import-{app_name}",
                    private_app_names=[app_name],
                    user_groups=list(profile.roles),
                    description=(
                        f"Auto-generated from Ivanti Connect Secure resource profile "
                        f"'{profile.name}', granting role(s) {', '.join(profile.roles)}. "
                        "Verify 'userGroups' matches real IdP group(s) before relying on "
                        f"this policy. Imported {imported_at_str}."
                    ),
                )
            )
            plan.warnings.append(
                f"Policy 'ivanti-import-{app_name}' uses userGroups={list(profile.roles)!r} "
                f"taken directly from Ivanti role name(s) on resource profile '{profile.name}'. "
                "Confirm these match actual group name(s) synced into Netskope from your IdP "
                "— otherwise the policy will match nobody."
            )
        else:
            plan.warnings.append(
                f"Resource profile '{profile.name}' has no roles attached -- its private "
                "app was created but no policy grants access to it yet. Review manually."
            )

    # --- Network Connect ACLs -------------------------------------------
    # See module docstring point 3 and NetworkConnectAcl's docstring. One
    # Private App per DISTINCT HOST (not per raw resource, and not per
    # ACL) -- an NPA app is one host, so a multi-host ACL becomes multiple
    # numbered apps ("<acl-name>-1", "<acl-name>-2", ...), all granted by
    # the same role-based policy (an allow-action ACL just feeds
    # role_to_apps like a resource profile does; a deny-action ACL gets
    # its own BLOCK policy, mirroring the resource-profile deny handling
    # above). Two kinds of consolidation happen before any app is created:
    # multiple resources on the SAME host WITHIN one ACL merge into a
    # single app with a multi-entry `protocols` list (nothing about NPA's
    # schema limits an app to one protocols[] entry -- confirmed real: 52
    # of 979 resources across 11 ACLs in a real 433-ACL export were the
    # same host listed twice for two different protocol/port specs, e.g.
    # once for TCP ports and once for a UDP port), and an exact duplicate
    # host+protocol-signature ACROSS ACLs reuses that same app instead of
    # creating another one (see Pass 2's docstring below).
    nc_apps_created = 0
    nc_acls_converted = 0
    nc_resources_skipped_cidr = 0
    nc_resources_skipped_invalid_cidr = 0
    nc_resources_skipped_icmp = 0
    nc_resources_normalized_cidr = 0
    nc_wildcard_port_count = 0
    nc_acls_with_no_convertible_resources = 0
    nc_resources_deduplicated = 0
    nc_resources_intra_acl_merged = 0

    # --- Pass 1: per-ACL convertibility scan + intra-ACL host grouping ---
    # Skip/normalize/warning logic is unchanged from before. What's new:
    # resources are then grouped by effective_host WITHIN each ACL
    # (preserving first-appearance order), so a host listed more than once
    # in the SAME ACL (different protocol/ports each time) becomes one
    # group instead of staying as separate resources. `key_counts` uses a
    # SIGNATURE of the whole group's (protocol, ports) pairs, not a single
    # triple, so cross-ACL exact-duplicate detection (Pass 2) still only
    # matches a truly identical set of protocol/port specs on that host.
    acl_data: list[tuple] = []  # [(acl, [(host, [resource, ...]), ...]), ...]
    key_counts: Counter = Counter()  # (host, signature) -> how many ACLs reference it (allow-action only)

    for acl in ivanti_config.network_connect_acls:
        convertible: list[tuple[NetworkConnectResource, str]] = []
        for resource in acl.resources:
            if resource.protocol == "icmp":
                # UNCONFIRMED against any live tenant whether/how Netskope's
                # private-app `protocols` schema represents ICMP (no ports,
                # unlike tcp/udp) -- skipped rather than guessed. Only 4 of
                # 979 resources in the tested real export were icmp://.
                nc_resources_skipped_icmp += 1
                plan.warnings.append(
                    f"Network Connect ACL '{acl.name}': resource '{resource.raw}' uses ICMP, "
                    "which has no confirmed mapping to Netskope's private-app protocols "
                    "schema (no live tenant example available) -- skipped, not converted. "
                    "Review manually."
                )
                continue

            effective_host = resource.host
            if resource.is_cidr:
                canonical_host, changed = _normalize_cidr_host(resource.host)
                if canonical_host is None:
                    nc_resources_skipped_invalid_cidr += 1
                    plan.warnings.append(
                        f"Network Connect ACL '{acl.name}': resource '{resource.raw}' has an "
                        "unparseable CIDR host -- skipped, not converted. Review manually."
                    )
                    continue
                if changed:
                    nc_resources_normalized_cidr += 1
                    plan.warnings.append(
                        f"Network Connect ACL '{acl.name}': resource host '{resource.host}' "
                        f"normalized to '{canonical_host}' -- Netskope requires the network "
                        "address, not a host address, for a CIDR block (confirmed real error: "
                        f"\"{resource.host} is not a valid host\"). Verify '{canonical_host}' "
                        "still covers the intended range."
                    )
                effective_host = canonical_host
                prefix_len = _cidr_prefix_len(effective_host)
                if prefix_len is None or prefix_len < MIN_CIDR_PREFIX_LEN:
                    nc_resources_skipped_cidr += 1
                    plan.warnings.append(
                        f"Network Connect ACL '{acl.name}': resource '{resource.raw}' is a "
                        f"CIDR block broader than Netskope's documented /{MIN_CIDR_PREFIX_LEN} "
                        "floor for a private-app host (or malformed) -- skipped, not "
                        "converted. Review manually; consider a narrower range or a "
                        "Publisher-side network policy instead."
                    )
                    continue

            if resource.ports in ("*", None):
                nc_wildcard_port_count += 1
            convertible.append((resource, effective_host))

        # Group by host, preserving first-appearance order within this ACL.
        groups: dict[str, list[NetworkConnectResource]] = {}
        for resource, effective_host in convertible:
            groups.setdefault(effective_host, []).append(resource)
        host_groups = list(groups.items())

        acl_data.append((acl, host_groups))
        if host_groups and acl.action != "deny":
            for host, resources in host_groups:
                sig = tuple(sorted((r.protocol, r.ports) for r in resources))
                key_counts[(host, sig)] += 1

    # --- Pass 2: build apps + wire policies -------------------------------
    # `key_to_app` maps an exact (host, signature-of-protocol/port-pairs)
    # combination to the PrivateAppPlan already created for it, so a later
    # ACL specifying an IDENTICAL set of resources on that host reuses
    # that same app instead of creating a redundant duplicate. CONFIRMED
    # against a real 433-ACL export: 80 of 979 resources (179 of 706
    # distinct hosts) were exact duplicates of another ACL's resource,
    # each previously becoming its own separate app. Deny-action ACLs are
    # deliberately excluded from this CROSS-ACL sharing pool -- a shared
    # app doubling as the target of both an allow policy (for one role)
    # and a block policy (for another) is more risk than the dedup is
    # worth, and no ACL in the tested export was deny anyway (all 433 were
    # action=allow). Intra-ACL host merging (Pass 1, above) applies to
    # every ACL regardless of action, since it never shares an app across
    # ACLs -- it only affects how one ACL's OWN resources become apps.
    key_to_app: dict[tuple, PrivateAppPlan] = {}
    host_key_count: dict[str, int] = {}  # host -> how many DISTINCT shared keys seen for it so far (naming disambiguation)
    nc_shared_keys: set = set()  # keys that were actually reused by >= 1 later ACL (distinct from key_to_app, which holds every created key)
    _nc_apps_before = len(plan.private_apps)

    for acl, host_groups in acl_data:
        if not host_groups:
            if acl.resources:
                nc_acls_with_no_convertible_resources += 1
            continue

        acl_app_name = _sanitize_app_name(acl.name)
        publishers_for_acl = (
            [publisher_overrides[acl.name]]
            if acl.name in publisher_overrides
            else list(default_publishers)
        )
        multi_in_acl = len(host_groups) > 1
        acl_app_names = []

        if acl.action == "deny":
            for idx, (host, resources) in enumerate(host_groups, start=1):
                app_name = f"{acl_app_name}-{idx}" if multi_in_acl else acl_app_name
                if len(resources) > 1:
                    nc_resources_intra_acl_merged += len(resources) - 1
                protocols = [p for r in resources for p in _protocols_for_resource(r)]
                plan.private_apps.append(
                    PrivateAppPlan(
                        source_profile=acl.name,
                        source_type="network_connect_acl",
                        app_name=app_name,
                        host=host,
                        protocols=protocols,
                        clientless_access=False,
                        publishers=publishers_for_acl,
                        tags=[tag_name],
                    )
                )
                acl_app_names.append(app_name)
                nc_apps_created += len(resources)
        else:
            for idx, (host, resources) in enumerate(host_groups, start=1):
                sig = tuple(sorted((r.protocol, r.ports) for r in resources))
                key = (host, sig)
                existing = key_to_app.get(key)
                if existing is not None:
                    nc_resources_deduplicated += len(resources)
                    nc_shared_keys.add(key)
                    if acl.name not in existing.source_profiles:
                        existing.source_profiles.append(acl.name)
                    if publishers_for_acl != existing.publishers:
                        plan.warnings.append(
                            f"Network Connect ACL '{acl.name}' shares a resource on host "
                            f"'{host}' (private app '{existing.app_name}') with "
                            f"{', '.join(n for n in existing.source_profiles if n != acl.name)} "
                            "but specifies a different publisher override for it -- "
                            "keeping the publisher from whichever ACL created the app "
                            "first. Review manually if these should really use "
                            "different publishers."
                        )
                    acl_app_names.append(existing.app_name)
                    nc_apps_created += len(resources)
                    continue

                if len(resources) > 1:
                    nc_resources_intra_acl_merged += len(resources) - 1

                shared = key_counts[key] > 1
                if shared:
                    # See _host_derived_app_name()'s docstring for why a
                    # shared app is named from its host, not this ACL.
                    base = _host_derived_app_name(host)
                    n = host_key_count.get(host, 0)
                    app_name = base if n == 0 else f"{base}-{n + 1}"
                    host_key_count[host] = n + 1
                else:
                    app_name = f"{acl_app_name}-{idx}" if multi_in_acl else acl_app_name

                protocols = [p for r in resources for p in _protocols_for_resource(r)]
                app_plan = PrivateAppPlan(
                    source_profile=acl.name,
                    source_type="network_connect_acl",
                    app_name=app_name,
                    host=host,
                    protocols=protocols,
                    clientless_access=False,
                    publishers=publishers_for_acl,
                    tags=[tag_name],
                )
                plan.private_apps.append(app_plan)
                key_to_app[key] = app_plan
                acl_app_names.append(app_name)
                nc_apps_created += len(resources)

            acl_app_names = list(dict.fromkeys(acl_app_names))  # defensive: a single ACL's groups resolving to the same app name

        nc_acls_converted += 1

        if acl.action == "deny":
            if acl.roles:
                plan.policies.append(
                    NpaPolicyPlan(
                        rule_name=f"ivanti-import-{acl_app_name}-block",
                        private_app_names=acl_app_names,
                        user_groups=list(acl.roles),
                        action="block",
                        description=(
                            f"Auto-generated BLOCK policy from ICS Network Connect ACL "
                            f"'{acl.name}' (action=deny). Imported {imported_at_str}."
                        ),
                    )
                )
                plan.warnings.append(
                    f"Network Connect ACL '{acl.name}' has action=deny; generated a "
                    f"companion BLOCK policy for its {len(acl_app_names)} app(s) instead, "
                    f"scoped to role(s) ({', '.join(acl.roles)}). Confirm the block-policy "
                    f"notification template ('{_DEFAULT_BLOCK_TEMPLATE}') exists in your "
                    "tenant."
                )
            else:
                plan.warnings.append(
                    f"Network Connect ACL '{acl.name}' has action=deny but no roles "
                    "attached to scope a block policy to -- no block policy was "
                    "generated. Review manually."
                )
        else:
            # One ALLOW policy per ACL (an app/server group), not per role
            # -- see module docstring point 2. Every role attached to this
            # ACL lands in the SAME policy's userGroups list, and it grants
            # ALL of this ACL's private app(s) (including any it shares
            # with other ACLs via cross-ACL dedup, above).
            if acl.roles:
                plan.policies.append(
                    NpaPolicyPlan(
                        rule_name=f"ivanti-import-{acl_app_name}",
                        private_app_names=acl_app_names,
                        user_groups=list(acl.roles),
                        description=(
                            f"Auto-generated from Ivanti Connect Secure Network Connect ACL "
                            f"'{acl.name}', granting role(s) {', '.join(acl.roles)}. Verify "
                            "'userGroups' matches real IdP group(s) before relying on this "
                            f"policy. Imported {imported_at_str}."
                        ),
                    )
                )
                plan.warnings.append(
                    f"Policy 'ivanti-import-{acl_app_name}' uses userGroups="
                    f"{list(acl.roles)!r} taken directly from Ivanti role name(s) on Network "
                    f"Connect ACL '{acl.name}'. Confirm these match actual group name(s) "
                    "synced into Netskope from your IdP — otherwise the policy will match "
                    "nobody."
                )
            else:
                plan.warnings.append(
                    f"Network Connect ACL '{acl.name}' has no roles attached -- its "
                    f"{len(acl_app_names)} private app(s) were created but no policy "
                    "grants access to them yet. Review manually."
                )

    if ivanti_config.network_connect_acls:
        nc_total_apps_created = len(plan.private_apps) - _nc_apps_before
        summary = (
            f"Network Connect ACLs: converted {nc_apps_created} resource(s) across "
            f"{nc_acls_converted} of {len(ivanti_config.network_connect_acls)} ACL(s) into "
            f"{nc_total_apps_created} private app(s)."
        )
        if nc_resources_intra_acl_merged:
            summary += (
                f" {nc_resources_intra_acl_merged} resource(s) shared a host with another "
                "resource in the SAME ACL (e.g. one TCP spec and one UDP spec for the same "
                "box) and were merged into that one app's protocols list instead of "
                "becoming a separate numbered app."
            )
        if nc_resources_deduplicated:
            summary += (
                f" {nc_resources_deduplicated} resource(s) were an EXACT duplicate (same "
                "host and the same set of protocol/port specs) of a resource already "
                "converted from another ACL, and reuse that same private app instead of "
                f"creating a redundant one -- {len(nc_shared_keys)} distinct app(s) are "
                "shared this way, named from their host rather than any one ACL (see the "
                "'Network Connect ACLs' table below for exactly which ACLs share which app)."
            )
        if nc_resources_normalized_cidr:
            summary += (
                f" {nc_resources_normalized_cidr} CIDR resource(s) had their host normalized "
                "to a proper network address (Netskope rejects a CIDR host with non-zero "
                "host bits, e.g. '10.51.150.1/24' -> '10.51.150.0/24') -- verify the "
                "normalized range still covers what was intended."
            )
        if nc_resources_skipped_cidr:
            summary += (
                f" {nc_resources_skipped_cidr} resource(s) skipped as CIDR blocks broader "
                f"than /{MIN_CIDR_PREFIX_LEN} (Netskope disallows these, and disallows 0/0)."
            )
        if nc_resources_skipped_invalid_cidr:
            summary += (
                f" {nc_resources_skipped_invalid_cidr} resource(s) skipped as unparseable "
                "CIDR hosts."
            )
        if nc_resources_skipped_icmp:
            summary += (
                f" {nc_resources_skipped_icmp} ICMP resource(s) skipped (no confirmed "
                "mapping to Netskope's private-app protocols schema)."
            )
        if nc_acls_with_no_convertible_resources:
            summary += (
                f" {nc_acls_with_no_convertible_resources} ACL(s) had no convertible "
                "resources at all."
            )
        if nc_wildcard_port_count:
            summary += (
                f" {nc_wildcard_port_count} resource(s) had a wildcard/missing port spec "
                f"and got the placeholder port range '{_WILDCARD_PORT_RANGE}' -- "
                "UNCONFIRMED against a live tenant, verify before relying on it."
            )
        summary += (
            " Netskope recommends a hostname over an IP address where possible (these "
            "came from IP-based ICS resources), and keeping any IP-based host distinct "
            "from your Publishers' own IPs -- review both manually."
        )
        plan.warnings.append(summary)

    if not plan.private_apps:
        plan.warnings.append(
            "No supported resource profiles were converted into private apps. "
            "Nothing will be created."
        )

    return plan
