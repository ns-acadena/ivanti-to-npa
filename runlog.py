"""
runlog.py

Every object this tool creates in a live --apply run is recorded here,
one entry at a time, flushed to disk immediately after each successful
create — not batched at the end. That's deliberate: if the process dies
(API error, network drop, Ctrl-C, the machine losing power) partway
through, the on-disk log still reflects exactly what was actually created
in the tenant, so a rollback started from that file removes precisely
those objects and nothing else.

Usage from main.py:

    run = RunLog.start(tenant_url, config_path, path="run_logs/run_XYZ.json")
    ...
    run.record_created("private_app", app_id, app_name)   # flushes to disk
    ...
    run.mark_status("completed")   # or "failed"

Rollback (either right after a failed run, or later by hand):

    run = RunLog.load("run_logs/run_XYZ.json")
    results = run.rollback(client)
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from netskope_client import NetskopeApiError, NetskopeClient

# Delete in this order: things that REFERENCE other objects must go first.
# NPA policies reference private apps AND (optionally) a policy group, so
# policies are rolled back before either of those. A policy group is only
# ever recorded here if THIS run created it (an existing, reused group
# never gets deleted), matching the "never touch what we didn't create"
# rule everywhere else in this tool. Tags aren't tracked as separate
# objects at all -- they're applied inline on the private app's own create
# payload (see PrivateAppPlan.to_payload() in mapper.py), so there's
# nothing tag-related to roll back independently of the app itself.
_ROLLBACK_ORDER = ["npa_policy", "npa_policy_group", "private_app"]

_DELETE_METHOD = {
    "private_app": "delete_private_app",
    "npa_policy": "delete_npa_policy",
    "npa_policy_group": "delete_npa_policy_group",
}


@dataclass
class RunLogEntry:
    type: str          # "private_app" | "npa_policy" | "npa_policy_group"
    id: str
    name: str
    created_at: str


@dataclass
class RunLog:
    run_id: str
    tenant_url: str
    config_path: str
    started_at: str
    path: str
    status: str = "in_progress"
    created: list[RunLogEntry] = field(default_factory=list)

    @classmethod
    def start(cls, tenant_url: str, config_path: str, log_dir: str = "run_logs") -> "RunLog":
        os.makedirs(log_dir, exist_ok=True)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(log_dir, f"run_{run_id}.json")
        run = cls(
            run_id=run_id,
            tenant_url=tenant_url,
            config_path=config_path,
            started_at=datetime.now(timezone.utc).isoformat(),
            path=path,
        )
        run._save()
        return run

    @classmethod
    def load(cls, path: str) -> "RunLog":
        with open(path) as f:
            data = json.load(f)
        data["created"] = [RunLogEntry(**e) for e in data.get("created", [])]
        data["path"] = path  # trust the actual file location over whatever was serialized
        return cls(**data)

    def _save(self) -> None:
        data = asdict(self)
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def record_created(self, obj_type: str, obj_id: str, name: str) -> None:
        self.created.append(
            RunLogEntry(
                type=obj_type,
                id=str(obj_id),
                name=name,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        )
        self._save()  # flush immediately — see module docstring

    def mark_status(self, status: str) -> None:
        self.status = status
        self._save()

    def rollback(self, client: NetskopeClient) -> list[tuple[RunLogEntry, bool, str]]:
        """
        Deletes everything in `created`, in reverse-dependency order.
        Returns a list of (entry, success, error_message) so the caller
        can report exactly what did/didn't roll back cleanly (a failure
        here should never be swallowed silently — the operator needs to
        know if manual cleanup is still required).
        """
        results: list[tuple[RunLogEntry, bool, str]] = []
        order = {t: i for i, t in enumerate(_ROLLBACK_ORDER)}
        entries_sorted = sorted(self.created, key=lambda e: order.get(e.type, 99))

        for entry in entries_sorted:
            method_name = _DELETE_METHOD.get(entry.type)
            if not method_name:
                results.append((entry, False, f"unknown entry type '{entry.type}'"))
                continue
            try:
                getattr(client, method_name)(entry.id)
                results.append((entry, True, ""))
            except NetskopeApiError as e:
                results.append((entry, False, str(e)))

        self.mark_status("rolled_back")
        return results
