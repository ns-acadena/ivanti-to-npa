"""
validation.py

The tool must never silently replace/overwrite something that already
exists in the Netskope tenant. This module is the single place that
enforces that: it pulls the tenant's CURRENT Private Access configuration
and cross-checks the migration plan against it before any create call is
made.

`check_for_conflicts()` is the error-checking function referenced
everywhere else in the codebase — nothing in main.py is allowed to call
create_private_app / create_npa_policy for a name this function flags,
unless the operator has explicitly opted in with --skip-conflicts (which
skips *only* the conflicting items, it never updates/overwrites them).

This module also provides the other half of that same discipline —
`verify_creation()` — which re-pulls the tenant AFTER a create loop
finishes and confirms each object the tool believes it created is
actually there. A 2xx response from a create call is not, by itself,
proof the change stuck (propagation delay, an API quirk, a proxy eating
the request after accepting it, etc.); this closes that gap by checking
independently rather than trusting the create response alone.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

from mapper import MigrationPlan


class _HasIdTypeName(Protocol):
    type: str
    id: str
    name: str


@dataclass
class ConflictReport:
    conflicting_app_names: list[str] = field(default_factory=list)
    conflicting_policy_names: list[str] = field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicting_app_names or self.conflicting_policy_names)

    def describe(self) -> list[str]:
        lines = []
        for name in self.conflicting_app_names:
            lines.append(
                f"Private app '{name}' already exists in the tenant. "
                "This tool will NOT modify or replace it."
            )
        for name in self.conflicting_policy_names:
            lines.append(
                f"NPA policy '{name}' already exists in the tenant. "
                "This tool will NOT modify or replace it."
            )
        return lines


def check_for_conflicts(
    plan: MigrationPlan,
    existing_private_apps: list[dict],
    existing_npa_policies: list[dict],
) -> ConflictReport:
    """
    Pure function: given the plan and a snapshot of what's already in the
    tenant (from NetskopeClient.list_private_apps() /
    list_npa_policies() — pulled fresh, immediately before this check),
    return every name collision. No network calls happen in here; the
    caller is responsible for pulling a current snapshot right before
    calling this, so the check reflects the tenant's real state at
    apply-time rather than a stale cache.
    """
    existing_app_names = {a.get("app_name") for a in existing_private_apps if a.get("app_name")}
    existing_policy_names = {p.get("rule_name") for p in existing_npa_policies if p.get("rule_name")}

    report = ConflictReport()
    for app in plan.private_apps:
        if app.app_name in existing_app_names:
            report.conflicting_app_names.append(app.app_name)
    for pol in plan.policies:
        if pol.rule_name in existing_policy_names:
            report.conflicting_policy_names.append(pol.rule_name)
    return report


def filter_out_conflicts(plan: MigrationPlan, report: ConflictReport) -> None:
    """Mutates `plan` in place, dropping anything flagged in `report`."""
    if report.conflicting_app_names:
        plan.private_apps = [
            a for a in plan.private_apps if a.app_name not in report.conflicting_app_names
        ]
    if report.conflicting_policy_names:
        plan.policies = [
            p for p in plan.policies if p.rule_name not in report.conflicting_policy_names
        ]


@dataclass
class VerificationReport:
    verified: list = field(default_factory=list)
    missing: list = field(default_factory=list)

    @property
    def all_verified(self) -> bool:
        return not self.missing

    def describe_missing(self) -> list[str]:
        return [
            f"{e.type} '{e.name}' (id={e.id}) was reported created, but a fresh pull of the "
            "tenant did not find it. Check the Netskope UI directly before assuming this "
            "object exists."
            for e in self.missing
        ]


def verify_creation(
    client,
    created_entries: list[_HasIdTypeName],
    retries: int = 3,
    delay_seconds: float = 2.0,
) -> VerificationReport:
    """
    Post-apply confirmation: re-list Private Apps and NPA Policies from the
    tenant and check that every object this run believes it created (by
    id, falling back to name) is actually present. Retries a few times
    with a short delay in case of listing-endpoint propagation lag — a
    fresh 2xx from create is optimistic, this is the check that it
    actually stuck. Tags aren't tracked as separate objects (see
    runlog.py), so there's nothing tag-related to verify here.

    `client` only needs list_private_apps() / list_npa_policies() /
    list_npa_policy_groups() — passing the real NetskopeClient or any
    stand-in with those methods both work (kept duck-typed so this doesn't
    import netskope_client and create a cycle).
    """
    if not created_entries:
        return VerificationReport()

    needs_groups = any(e.type == "npa_policy_group" for e in created_entries)

    report = VerificationReport()
    for attempt in range(1, retries + 1):
        existing_apps = client.list_private_apps()
        existing_policies = client.list_npa_policies()
        existing_groups = client.list_npa_policy_groups() if needs_groups else []

        app_ids = {str(a.get("id")) for a in existing_apps if a.get("id") is not None}
        app_names = {a.get("app_name") for a in existing_apps if a.get("app_name")}
        policy_ids = {str(p.get("id")) for p in existing_policies if p.get("id") is not None}
        policy_names = {p.get("rule_name") for p in existing_policies if p.get("rule_name")}
        group_ids = {str(g.get("id")) for g in existing_groups if g.get("id") is not None}
        group_names = {g.get("name") for g in existing_groups if g.get("name")}

        verified, missing = [], []
        for entry in created_entries:
            if entry.type == "private_app":
                found = str(entry.id) in app_ids or entry.name in app_names
            elif entry.type == "npa_policy":
                found = str(entry.id) in policy_ids or entry.name in policy_names
            elif entry.type == "npa_policy_group":
                found = str(entry.id) in group_ids or entry.name in group_names
            else:
                found = False
            (verified if found else missing).append(entry)

        report = VerificationReport(verified=verified, missing=missing)
        if report.all_verified or attempt == retries:
            return report
        time.sleep(delay_seconds)

    return report
