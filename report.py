"""
report.py

Human-readable mapping/analysis output — the "what does this migration
actually look like" view, as distinct from plan.json (the machine-readable
API payloads). Two outputs:

  * a Markdown report: summary stats, the profile-by-profile mapping
    table, the role-by-policy mapping table, skipped profiles, and every
    warning that needs a human decision before --apply.
  * a CSV of the private-app mapping table, for dropping into a
    spreadsheet or a migration tracker/ticket.

Neither of these touches the network — they're derived entirely from the
already-parsed IvantiConfig and the already-built MigrationPlan, so you
can generate them from a dry run alone (no Netskope credentials needed).
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from ivanti_parser import IvantiConfig
from mapper import MigrationPlan


def _profile_lookup(ivanti_config: IvantiConfig) -> dict:
    return {p.name: p for p in ivanti_config.resource_profiles}


def _acl_lookup(ivanti_config: IvantiConfig) -> dict:
    return {a.name: a for a in ivanti_config.network_connect_acls}


def build_app_rows(ivanti_config: IvantiConfig, plan: MigrationPlan) -> list[dict]:
    """One row per resource-profile OR Network-Connect-ACL resource that
    WAS converted to a private app -- `app.source_type` says which lookup
    to use, since the two source objects have different shapes."""
    profiles = _profile_lookup(ivanti_config)
    acls = _acl_lookup(ivanti_config)
    rows = []
    for app in plan.private_apps:
        if app.source_type == "network_connect_acl":
            # A shared app (see mapper.py's Network Connect ACL
            # consolidation -- an exact host/protocol/ports duplicate
            # across more than one ACL) has MULTIPLE contributing ACLs in
            # source_profiles, not just source_profile (the one that
            # happened to create it). Union their roles/actions rather
            # than showing only the first one.
            contributing = [acls[n] for n in app.source_profiles if n in acls]
            if contributing:
                actions = sorted({a.action for a in contributing})
                ivanti_type = f"network-connect-acl ({'/'.join(actions)})"
                roles: list[str] = []
                for a in contributing:
                    for r in a.roles:
                        if r not in roles:
                            roles.append(r)
                ivanti_roles = ", ".join(roles)
            else:
                ivanti_type = "network-connect-acl"
                ivanti_roles = ""
            ivanti_profile_display = ", ".join(app.source_profiles)
        else:
            profile = profiles.get(app.source_profile)
            ivanti_type = profile.profile_type if profile else ""
            ivanti_roles = ", ".join(profile.roles) if profile else ""
            ivanti_profile_display = app.source_profile
        proto_desc = ", ".join(
            f"{p.get('type', 'tcp').upper()}/{p.get('port') or p.get('ports')}"
            for p in app.protocols
        )
        rows.append(
            {
                "ivanti_profile": ivanti_profile_display,
                "ivanti_type": ivanti_type,
                "ivanti_roles": ivanti_roles,
                "netskope_app_name": app.app_name,
                "host": app.host,
                "protocols": proto_desc,
                "access_mode": "Clientless (browser)" if app.clientless_access else "Client-based",
                "publisher": app.publishers[0].publisher_name or app.publishers[0].publisher_id
                if app.publishers else "",
                "tags": ", ".join(app.tags),
            }
        )
    return rows


def build_skipped_rows(ivanti_config: IvantiConfig, plan: MigrationPlan) -> list[dict]:
    profiles = _profile_lookup(ivanti_config)
    rows = []
    for name in plan.skipped_profiles:
        profile = profiles.get(name)
        rows.append(
            {
                "ivanti_profile": name,
                "ivanti_type": profile.profile_type if profile else "unknown",
                "host": profile.host if profile else "",
                "reason": "No Netskope Private Access equivalent for this profile type "
                          "(e.g. full VPN tunneling / Network Connect) — needs a manual "
                          "decision, not an automated one.",
            }
        )
    return rows


def build_policy_rows(plan: MigrationPlan) -> list[dict]:
    """One row per generated policy. Policies are grouped by app/server
    (one resource profile or Network Connect ACL), not by role -- a
    policy's userGroups can list more than one role when multiple roles
    are attached to that same profile/ACL, so `ivanti_roles` here is the
    full joined list, not just the first entry."""
    rows = []
    for pol in plan.policies:
        rows.append(
            {
                "ivanti_roles": ", ".join(pol.user_groups),
                "netskope_policy": pol.rule_name,
                "apps_granted": ", ".join(pol.private_app_names),
                "app_count": len(pol.private_app_names),
                "idp_group_verified": "NO — confirm before relying on this policy",
            }
        )
    return rows


def render_markdown(
    ivanti_config: IvantiConfig,
    plan: MigrationPlan,
    source_path: str,
    app_rows: list[dict] | None = None,
) -> str:
    """
    `app_rows` can be pre-built and passed in so render_markdown() and
    render_csv() don't each redo the same build_app_rows() work (lookups +
    a full pass over plan.private_apps) on a large import. Optional and
    defaults to building it here, so existing callers are unaffected.
    """
    if app_rows is None:
        app_rows = build_app_rows(ivanti_config, plan)
    skipped_rows = build_skipped_rows(ivanti_config, plan)
    policy_rows = build_policy_rows(plan)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Ivanti Connect Secure → Netskope Private Access — Migration Analysis")
    lines.append("")
    lines.append(f"Source config: `{source_path}`  \nGenerated: {generated}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Realms parsed: **{len(ivanti_config.realms)}**")
    lines.append(f"- Resource profiles parsed: **{len(ivanti_config.resource_profiles)}**")
    lines.append(f"- Converted to Private Apps: **{len(app_rows)}**")
    lines.append(f"- Skipped — no NPA equivalent: **{len(skipped_rows)}**")
    lines.append(f"- Network Connect ACLs found (see below for what converted): **{len(ivanti_config.network_connect_acls)}**")
    lines.append(f"- Policies generated: **{len(policy_rows)}**")
    lines.append(f"- Warnings requiring manual review: **{len(plan.warnings)}**")
    lines.append("")

    lines.append("## Private App Mapping")
    lines.append("")
    lines.append("| Ivanti Profile | Type | Ivanti Role(s) | → Netskope App | Host | Protocol/Port | Access Mode | Publisher |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in app_rows:
        lines.append(
            f"| {r['ivanti_profile']} | {r['ivanti_type']} | {r['ivanti_roles']} | "
            f"{r['netskope_app_name']} | {r['host']} | {r['protocols']} | "
            f"{r['access_mode']} | {r['publisher']} |"
        )
    if not app_rows:
        lines.append("| _(none)_ | | | | | | | |")
    lines.append("")

    lines.append("## Policy Mapping (App/Server → Netskope NPA Policy)")
    lines.append("")
    lines.append(
        "One policy per app/server group (a resource profile or a Network Connect ACL), "
        "not per role — every role attached to that profile/ACL lands in the same "
        "policy's userGroups list."
    )
    lines.append("")
    lines.append("| → Netskope Policy | Ivanti Role(s) | Apps Granted | IdP Group Confirmed? |")
    lines.append("|---|---|---|---|")
    for r in policy_rows:
        lines.append(
            f"| {r['netskope_policy']} | {r['ivanti_roles']} | {r['apps_granted']} ({r['app_count']}) | "
            f"{r['idp_group_verified']} |"
        )
    if not policy_rows:
        lines.append("| | _(none)_ | | |")
    lines.append("")
    lines.append(
        "> Netskope Private Access policies scope users by **IdP group name**, not by "
        "Ivanti role. Every row above uses the raw Ivanti role name(s) as placeholder "
        "group name(s) — check each one against your actual SSO/SCIM groups before "
        "trusting these policies."
    )
    lines.append("")

    lines.append("## Skipped Profiles — No Direct NPA Equivalent")
    lines.append("")
    if skipped_rows:
        lines.append("| Ivanti Profile | Type | Host | Reason |")
        lines.append("|---|---|---|---|")
        for r in skipped_rows:
            lines.append(f"| {r['ivanti_profile']} | {r['ivanti_type']} | {r['host']} | {r['reason']} |")
    else:
        lines.append("None — every parsed resource profile had a Private Access equivalent.")
    lines.append("")

    lines.append("## Network Connect ACLs (Full-Tunnel Subnet/CIDR Rules)")
    lines.append("")
    if ivanti_config.network_connect_acls:
        lines.append(
            "These come from Users > Resource Policies > Network Connect: full-tunnel, "
            "subnet/CIDR-based access rules, not per-app Resource Profiles. Converted "
            "one Private App **per resource** where possible (an NPA app is one host, "
            "so a multi-resource ACL becomes multiple numbered apps) — see the "
            "'→ Private App(s)' column below for exactly what each ACL produced, or why "
            "it didn't."
        )
        lines.append("")
        lines.append("| Name | Action | Resource(s) | Role(s) | → Private App(s) |")
        lines.append("|---|---|---|---|---|")
        # A shared app (an exact host/protocol/ports duplicate across more
        # than one ACL -- see mapper.py) is attributed to EVERY
        # contributing ACL's row here, via source_profiles, not just the
        # one that happened to create it (source_profile).
        acl_apps: dict[str, list[str]] = {}
        shared_app_names = {
            app.app_name for app in plan.private_apps
            if app.source_type == "network_connect_acl" and len(app.source_profiles) > 1
        }
        for app in plan.private_apps:
            if app.source_type == "network_connect_acl":
                for name in app.source_profiles:
                    acl_apps.setdefault(name, []).append(app.app_name)
        for acl in ivanti_config.network_connect_acls:
            resource_descs = [
                f"{r.host}:{r.ports}" if r.ports else r.host for r in acl.resources
            ]
            resources_desc = ", ".join(resource_descs[:5]) + (f" (+{len(resource_descs) - 5} more)" if len(resource_descs) > 5 else "")
            roles_desc = ", ".join(acl.roles[:5]) + (f" (+{len(acl.roles) - 5} more)" if len(acl.roles) > 5 else "")
            produced = acl_apps.get(acl.name)
            if produced:
                labeled = [f"{n} (shared)" if n in shared_app_names else n for n in produced[:5]]
                produced_desc = ", ".join(labeled) + (f" (+{len(produced) - 5} more)" if len(produced) > 5 else "")
            elif not acl.resources:
                produced_desc = "_(no resources)_"
            else:
                produced_desc = "_(skipped — see warnings)_"
            lines.append(f"| {acl.name} | {acl.action} | {resources_desc or '_(none)_'} | {roles_desc or '_(none)_'} | {produced_desc} |")
    else:
        lines.append("None found.")
    lines.append("")

    lines.append("## Warnings — Review Before `--apply`")
    lines.append("")
    if plan.warnings:
        for w in plan.warnings:
            lines.append(f"- {w}")
    else:
        lines.append("None.")
    lines.append("")

    lines.append("## Realms & Role-Mapping Reference")
    lines.append("")
    lines.append("| Realm | Roles |")
    lines.append("|---|---|")
    for realm in ivanti_config.realms:
        lines.append(f"| {realm.name} | {', '.join(realm.roles) or '_(none)_'} |")
    lines.append("")

    return "\n".join(lines)


def render_csv(
    ivanti_config: IvantiConfig,
    plan: MigrationPlan,
    app_rows: list[dict] | None = None,
) -> str:
    rows = app_rows if app_rows is not None else build_app_rows(ivanti_config, plan)
    buf = io.StringIO()
    fieldnames = [
        "ivanti_profile", "ivanti_type", "ivanti_roles", "netskope_app_name",
        "host", "protocols", "access_mode", "publisher", "tags",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()
