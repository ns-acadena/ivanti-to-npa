#!/usr/bin/env python3
"""
main.py — CLI entry point for ivanti-to-npa.

DISCLAIMER: this is a COMMUNITY-CREATED, UNOFFICIAL tool. It is not built,
reviewed, endorsed, or supported by Netskope or Ivanti, and Netskope
Customer Support cannot help with issues it causes. Use against your own
tenant is entirely at your own risk. This disclaimer is also printed every
time the tool runs.

Reads an Ivanti Connect Secure XML config export, maps its resource
profiles/roles onto Netskope Private Access objects (Private Apps, NPA
Real-Time Policies), and either:

  * writes a JSON plan + Markdown/CSV analysis report you can review
    (default — no API calls at all), or
  * applies that plan against a real Netskope tenant with --apply.

SAFETY MODEL
------------
1. Before --apply creates anything, it PULLS the tenant's current Private
   Apps and NPA Policies and checks every name in the plan against that
   live snapshot (validation.check_for_conflicts). If anything in the
   plan would collide with something that already exists, the run is
   refused by default — this tool creates new objects, it never updates
   or replaces an existing one. Pass --skip-conflicts to skip just the
   colliding items and proceed with the rest.
2. Every object actually created is recorded to a run log
   (run_logs/run_<timestamp>.json), flushed to disk after each individual
   create — not batched at the end — so if the process fails partway
   through, the log on disk still reflects exactly what exists so far.
3. On any failure during creation, the run stops immediately (no further
   creates), and you're offered an immediate rollback of everything that
   run created. You can also roll back later, separately, with:
       python main.py --rollback run_logs/run_<timestamp>.json
4. After every apply, post-apply verification re-pulls the created objects
   from the tenant to confirm they're really there (validation.verify_
   creation) -- whether that verification comes back clean or finds a gap,
   you are ALWAYS then offered the same rollback-or-keep choice (unless
   --yes was passed, which always keeps and never prompts). The exit code
   always reflects the real verification outcome regardless of that
   choice: keeping after a failed verification still exits 1; keeping
   after a clean verification exits 0; choosing to roll back exits 0 only
   if every deletion in the rollback itself succeeds.

Examples
--------
# 1. Mapping/analysis report only, no credentials needed:
python main.py --config my_export.xml --analysis-only

# 2. Parse + map, write plan.json for review (no network calls):
python main.py --config my_export.xml \\
    --default-publisher-id 123 --default-publisher-name aws-publisher-1

# 3. Check the plan against your tenant's CURRENT config for name
#    collisions, without creating or changing anything:
python main.py --config my_export.xml \\
    --default-publisher-id 123 --default-publisher-name aws-publisher-1 \\
    --tenant-url https://yourtenant.goskope.com --api-token "$NETSKOPE_API_TOKEN" \\
    --check-conflicts

# 4. Actually create the objects in Netskope:
python main.py --config my_export.xml \\
    --default-publisher-id 123 --default-publisher-name aws-publisher-1 \\
    --tenant-url https://yourtenant.goskope.com --api-token "$NETSKOPE_API_TOKEN" \\
    --apply --yes

# 5. Undo everything a specific run created:
python main.py --rollback run_logs/run_20260831T120000Z.json \\
    --tenant-url https://yourtenant.goskope.com --api-token "$NETSKOPE_API_TOKEN"
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from datetime import datetime, timezone

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
from netskope_client import NetskopeApiError, NetskopeClient, OAuthTokenProvider, _first
from policy_group_ui import select_policy_group_interactive
from publisher_ui import MAX_SELECTABLE_PUBLISHERS, select_publishers_interactive
from report import build_app_rows, render_csv, render_markdown
from runlog import RunLog
from validation import check_for_conflicts, filter_out_conflicts, verify_creation

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("ivanti_to_npa")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", help="Path to the Ivanti Connect Secure XML export. Required unless --rollback is given.")

    pub = p.add_argument_group(
        "Publishers",
        f"Which Publisher(s) new Private Apps are attached to. Netskope Private Apps accept "
        f"up to {MAX_SELECTABLE_PUBLISHERS} Publishers per app (for redundancy), so more than "
        "one can be selected. If neither flag below is given, an interactive picker showing "
        "the tenant's Publishers runs automatically (prompting for --tenant-url/--api-token "
        "first if needed) — no separate flag required to enable it.",
    )
    pub.add_argument("--publisher-ids", help=f"Comma-separated Publisher ID(s) to use, e.g. '12,34' — up to {MAX_SELECTABLE_PUBLISHERS}. Non-interactive; skips the picker entirely.")
    pub.add_argument("--default-publisher-id", help="Single Publisher ID (legacy/simple form — prefer --publisher-ids for multiple, or just leave both unset for the interactive picker).")
    pub.add_argument("--default-publisher-name", help="Publisher name to pair with --default-publisher-id (cosmetic only, not required).")
    pub.add_argument("--publisher-map", help="Optional JSON file overriding the publisher(s) above for specific resource profiles: {\"<resource-profile-name>\": {\"publisher_id\": ..., \"publisher_name\": ...}}")
    p.add_argument("--tag", default=None, help="Private App tag applied to every imported app. If omitted, you'll be prompted for a custom name interactively (default: ivanti-import, just press Enter to accept it) when running in a real terminal; falls back to ivanti-import automatically otherwise (scripted/CI runs, or no terminal to prompt on).")
    p.add_argument("--tenant-url", default=os.environ.get("NETSKOPE_TENANT_URL"), help="e.g. https://yourtenant.goskope.com (or just yourtenant.goskope.com). Falls back to $NETSKOPE_TENANT_URL. If omitted entirely, you'll be prompted for it interactively the first time it's needed (only when running in a real terminal).")
    p.add_argument("--apply", action="store_true", help="Actually send requests to Netskope. Without this flag, nothing touches the tenant.")
    p.add_argument("--skip-policies", action="store_true", help="Import Private Apps only — never call the NPA Policy create API, even though the plan/report still show what policies WOULD have been generated (for reference, e.g. if you'd rather build access policies yourself in the UI). Also excludes policies from the pre-flight conflict check, since none will be touched.")
    p.add_argument("--policy-group-name", default=None, help="Name of an EXISTING NPA Policy Group every generated policy is placed into. This tool does not create new Policy Groups -- the name must already exist in the tenant, or the run fails with a clear error. Required whenever policies are being created — if omitted, you'll see an interactive menu of the tenant's existing groups to pick from. Use --no-policy-group instead if you want the policies left ungrouped.")
    p.add_argument("--no-policy-group", action="store_true", help="Leave generated policies ungrouped instead of requiring an NPA Policy Group name. Ignored (moot) if --skip-policies is set.")

    groupcheck = p.add_argument_group(
        "User group validation (Ivanti role -> IdP group)",
        "Every generated policy's userGroups starts as the raw Ivanti role name, which may not "
        "match a real IdP group synced into your tenant. Before creating policies, the tool "
        "pulls your tenant's known user groups and checks each one. A role name that isn't "
        "found is NOT treated as a failure: that policy is still created, just without a "
        "userGroups restriction (open to any authenticated user) instead of a group that would "
        "silently match nobody. Every such policy is flagged loudly so you can lock it down "
        "manually afterward.",
    )
    groupcheck.add_argument("--skip-group-check", action="store_true", help="Don't query the tenant's user groups at all — every policy keeps the raw Ivanti role name as its userGroups value, unverified, exactly like earlier versions of this tool.")
    p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt before creating anything.")
    p.add_argument("--output-plan", default="plan.json", help="Where to write the JSON migration plan (default: plan.json).")
    p.add_argument("--limit", type=int, help="Only process the first N resource profiles (useful for a test run).")
    p.add_argument("--analysis-only", action="store_true", help="Just parse the config and write the Markdown/CSV mapping report — skip plan.json and don't require a publisher or tenant.")
    p.add_argument("--report-md", default="analysis_report.md", help="Where to write the human-readable Markdown mapping/analysis report (default: analysis_report.md).")
    p.add_argument("--report-csv", default="analysis_report.csv", help="Where to write the private-app mapping table as CSV (default: analysis_report.csv).")
    p.add_argument("--no-report", action="store_true", help="Skip generating the Markdown/CSV analysis report (only plan.json).")
    p.add_argument("--debug", action="store_true", help="Verbose logging, including the full raw JSON body of every API response. Use this if a list (publishers, apps, policies) comes back with missing/blank fields — the response shape can vary by tenant/release, and this shows you exactly what came back so the field mapping can be corrected.")
    p.add_argument("--write-pacing-ms", type=float, default=100, help="Fixed delay, in milliseconds, after every real create/delete API call, to avoid tripping the tenant's rate limit on a large --apply/--rollback run (default: 100). A 429 is also retried automatically regardless of this setting — honoring the response's Retry-After header when present, exponential backoff otherwise. Set to 0 to disable pacing entirely.")

    auth = p.add_argument_group(
        "Authentication",
        "Netskope's Private Access REST API v2 (the endpoints this tool calls — Publishers, "
        "Private Apps, NPA Policies) documents the static API-token method as its supported "
        "auth mechanism. The bearer-token / OAuth2 options below are provided for tenants "
        "fronted by their own OAuth-issuing gateway, or in case your tenant's release supports "
        "it — verify against your own Swagger UI before relying on it. If you omit --api-token "
        "entirely (and aren't using OAuth), you'll be prompted for it with input hidden "
        "(like a password prompt) the first time it's needed, rather than it ever appearing in "
        "your shell history or process list.",
    )
    auth.add_argument("--api-token", default=os.environ.get("NETSKOPE_API_TOKEN"), help="Netskope Service Account API token, OR a pre-obtained bearer token if --auth-mode bearer. Falls back to $NETSKOPE_API_TOKEN. Best practice: leave this unset and let the tool prompt for it (hidden input) instead of putting it on the command line or in an env var that lingers in your shell.")
    auth.add_argument("--auth-mode", choices=["api-token", "bearer"], default="api-token", help="How --api-token is sent: 'api-token' (Netskope-Api-Token header, default/documented) or 'bearer' (Authorization: Bearer <token>). Ignored if --oauth-client-id/--oauth-client-secret are given.")
    auth.add_argument("--oauth-token-url", default=os.environ.get("NETSKOPE_OAUTH_TOKEN_URL"), help="OAuth2 token endpoint. When given along with --oauth-client-id/--oauth-client-secret, the tool performs a client-credentials grant and uses the resulting bearer token instead of --api-token, refreshing it automatically (falls back to $NETSKOPE_OAUTH_TOKEN_URL).")
    auth.add_argument("--oauth-client-id", default=os.environ.get("NETSKOPE_OAUTH_CLIENT_ID"), help="OAuth2 client ID (falls back to $NETSKOPE_OAUTH_CLIENT_ID).")
    auth.add_argument("--oauth-client-secret", default=os.environ.get("NETSKOPE_OAUTH_CLIENT_SECRET"), help="OAuth2 client secret (falls back to $NETSKOPE_OAUTH_CLIENT_SECRET). Prefer the env var over the command line.")
    auth.add_argument("--oauth-scope", default=os.environ.get("NETSKOPE_OAUTH_SCOPE"), help="Optional OAuth2 scope to request (falls back to $NETSKOPE_OAUTH_SCOPE).")

    conflicts = p.add_argument_group("Conflict checking (never overwrite an existing entry)")
    conflicts.add_argument("--check-conflicts", action="store_true", help="Pull the tenant's current Private Apps/Policies and report name collisions with the plan. Requires --tenant-url/--api-token. Makes no changes.")
    conflicts.add_argument("--skip-conflicts", action="store_true", help="If the pre-flight check finds names that already exist in the tenant, skip just those items and proceed with the rest, instead of aborting the whole run.")
    conflicts.add_argument("--snapshot-dir", default="netskope_snapshots", help="Where the pre-apply snapshot of the tenant's existing config is saved (default: netskope_snapshots/).")

    verify = p.add_argument_group("Post-apply verification (confirm changes actually took effect)")
    verify.add_argument("--skip-verification", action="store_true", help="Don't re-check the tenant after creating everything. Off by default — a 2xx from create isn't proof the object stuck, so the tool re-pulls and confirms each one by default.")
    verify.add_argument("--verify-retries", type=int, default=3, help="How many times to re-pull the tenant looking for a not-yet-visible object before giving up (default: 3).")
    verify.add_argument("--verify-delay", type=float, default=2.0, help="Seconds to wait between verification re-pulls (default: 2.0).")

    rollback = p.add_argument_group("Rollback")
    rollback.add_argument("--rollback", metavar="RUN_LOG_PATH", help="Delete every object recorded in the given run log, then exit. Requires --tenant-url/--api-token.")
    rollback.add_argument("--run-log-dir", default="run_logs", help="Directory new run logs are written to (default: run_logs/).")
    rollback.add_argument("--auto-rollback-on-failure", action="store_true", help="If a create fails mid-run, roll back everything that run already created automatically, with no prompt.")
    rollback.add_argument("--no-rollback-prompt", action="store_true", help="If a create fails mid-run, don't ask interactively whether to roll back — just print the manual rollback command and exit.")

    return p.parse_args(argv)


def load_publisher_map(path: str | None) -> dict[str, PublisherRef]:
    if not path:
        return {}
    with open(path) as f:
        raw = json.load(f)
    return {
        name: PublisherRef(
            publisher_id=str(v.get("publisher_id")) if v.get("publisher_id") is not None else None,
            publisher_name=v.get("publisher_name"),
        )
        for name, v in raw.items()
    }


def _using_oauth(args: argparse.Namespace) -> bool:
    return bool(args.oauth_token_url and args.oauth_client_id and args.oauth_client_secret)


def _prompt_visible(prompt: str) -> str | None:
    """Plain, echoed prompt — only for non-secret values. Returns None
    (never raises) if there's no real terminal to prompt on, or the user
    hits Ctrl-C/Ctrl-D."""
    if not sys.stdin.isatty():
        return None
    try:
        value = input(prompt).strip()
        return value or None
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _prompt_hidden(prompt: str) -> str | None:
    """Password-style prompt (input not echoed to the terminal) for
    tokens/secrets — never printed, logged, or saved to shell history.
    Same None-on-no-tty/interrupt contract as _prompt_visible."""
    if not sys.stdin.isatty():
        return None
    try:
        value = getpass.getpass(prompt)
        return value or None
    except (EOFError, KeyboardInterrupt):
        print()
        return None


_DEFAULT_TAG = "ivanti-import"


def resolve_tag(args: argparse.Namespace) -> str:
    """
    --tag is explicit: use it as given. Otherwise, in a real terminal,
    prompt for a custom tag name (pressing Enter accepts the default) —
    same pattern as the Policy Group name prompt. No terminal to prompt on
    (scripted/CI, piped input, --analysis-only with input redirected, etc.)
    falls back to the default silently, exactly like before this existed —
    this never blocks a non-interactive run.
    """
    if args.tag:
        return args.tag
    entered = _prompt_visible(f"Private App tag to apply to every imported app [{_DEFAULT_TAG}]: ")
    return entered or _DEFAULT_TAG


def _normalize_tenant_url(raw: str) -> str:
    raw = raw.strip().rstrip("/")
    if raw and not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"https://{raw}"
    return raw


def _require_tenant_creds(args: argparse.Namespace) -> bool:
    if not args.tenant_url:
        entered = _prompt_visible("Netskope tenant (e.g. yourtenant.goskope.com): ")
        if entered:
            args.tenant_url = _normalize_tenant_url(entered)
    if not args.tenant_url:
        logger.error("This action requires --tenant-url (or $NETSKOPE_TENANT_URL).")
        return False

    if args.oauth_token_url and args.oauth_client_id and not args.oauth_client_secret:
        secret = _prompt_hidden(f"OAuth client secret for client_id={args.oauth_client_id} (input hidden): ")
        if secret:
            args.oauth_client_secret = secret

    if _using_oauth(args):
        return True

    if not args.api_token:
        token = _prompt_hidden(f"Netskope API token for {args.tenant_url} (input hidden, not stored or logged): ")
        if token:
            args.api_token = token

    if not args.api_token:
        logger.error(
            "This action requires credentials: either --api-token (or $NETSKOPE_API_TOKEN), "
            "or all three of --oauth-token-url/--oauth-client-id/--oauth-client-secret. "
            "(No terminal available to prompt interactively — running non-interactively? "
            "set the env var instead.)"
        )
        return False
    return True


def build_netskope_client(args: argparse.Namespace) -> NetskopeClient:
    """Single place that decides which auth mode to use, based on which
    credentials were actually supplied. Call _require_tenant_creds(args)
    first to fail with a clear message before this is reached."""
    if _using_oauth(args):
        provider = OAuthTokenProvider(
            token_url=args.oauth_token_url,
            client_id=args.oauth_client_id,
            client_secret=args.oauth_client_secret,
            scope=args.oauth_scope,
        )
        logger.info("Using OAuth2 client-credentials auth (token endpoint: %s).", args.oauth_token_url)
        return NetskopeClient(
            tenant_url=args.tenant_url,
            oauth_provider=provider,
            dry_run=False,
            write_pacing_seconds=getattr(args, "write_pacing_ms", 100) / 1000.0,
        )

    auth_mode = "bearer" if args.auth_mode == "bearer" else "api_token"
    if auth_mode == "bearer":
        logger.info("Using a pre-obtained bearer token (Authorization: Bearer ...).")
    return NetskopeClient(
        tenant_url=args.tenant_url,
        api_token=args.api_token,
        auth_mode=auth_mode,
        dry_run=False,
        # getattr, not args.write_pacing_ms: several _smoketest_*.py files
        # build their own argparse.Namespace by hand without this field,
        # and shouldn't have to know about a flag unrelated to what they're
        # testing just to keep working.
        write_pacing_seconds=getattr(args, "write_pacing_ms", 100) / 1000.0,
    )


_PLACEHOLDER_PUBLISHER_ID = "TBD"


def _placeholder_publishers() -> list[PublisherRef]:
    return [PublisherRef(publisher_id=_PLACEHOLDER_PUBLISHER_ID, publisher_name="TBD-PUBLISHER")]


def resolve_default_publishers(args: argparse.Namespace) -> tuple[list[PublisherRef], bool]:
    """
    Figures out which Publisher(s) to attach to every imported private app.

    Priority: explicit --publisher-ids, then legacy
    --default-publisher-id/--default-publisher-name. If neither is given,
    the interactive picker runs AUTOMATICALLY (no flag needed) — it pulls
    the tenant's Publisher list and prompts you to choose, prompting for
    --tenant-url/--api-token first if those weren't supplied either.

    That only happens when it can: --analysis-only never touches the
    network (always a placeholder), and if there's no real terminal to
    prompt on (or credentials really aren't available), this falls back
    to a placeholder + warning instead of hard-failing — so a plain dry
    run without any publisher flags still produces a report/plan.json.
    --apply is what actually refuses to proceed on a placeholder.

    Returns (publishers, had_error). On had_error=True, an explanatory
    message has already been logged.
    """
    if args.publisher_ids:
        ids = [x.strip() for x in args.publisher_ids.split(",") if x.strip()]
        if not ids:
            logger.error("--publisher-ids was given but empty.")
            return [], True
        if len(ids) > MAX_SELECTABLE_PUBLISHERS:
            logger.error("--publisher-ids: %d given, maximum is %d.", len(ids), MAX_SELECTABLE_PUBLISHERS)
            return [], True
        return [PublisherRef(publisher_id=i) for i in ids], False

    if args.default_publisher_id or args.default_publisher_name:
        return [PublisherRef(publisher_id=args.default_publisher_id, publisher_name=args.default_publisher_name)], False

    if args.analysis_only:
        return _placeholder_publishers(), False

    if _require_tenant_creds(args):
        client = build_netskope_client(args)
        refs = select_publishers_interactive(client, max_select=MAX_SELECTABLE_PUBLISHERS)
        if refs is not None:
            return refs, False
        logger.warning(
            "No publisher selected. The analysis report/plan.json will use a placeholder "
            "publisher; --apply will refuse to run until you supply real one(s) "
            "(--publisher-ids/--default-publisher-id, or re-run interactively)."
        )
        return _placeholder_publishers(), False

    logger.warning(
        "No publisher selected and no tenant credentials available to look them up "
        "interactively (use --publisher-ids/--default-publisher-id, or supply "
        "--tenant-url/--api-token to be prompted). The analysis report and plan.json "
        "will use a placeholder publisher; --apply will refuse to run until you supply "
        "real one(s)."
    )
    return _placeholder_publishers(), False


def _plan_uses_placeholder_publisher(plan) -> bool:
    return any(
        any(ref.publisher_id == _PLACEHOLDER_PUBLISHER_ID for ref in app.publishers)
        for app in plan.private_apps
    )


def _save_snapshot(snapshot_dir: str, existing_apps: list[dict], existing_policies: list[dict], existing_publishers: list[dict]) -> str:
    os.makedirs(snapshot_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(snapshot_dir, f"existing_config_{ts}.json")
    with open(path, "w") as f:
        json.dump(
            {
                "pulled_at": datetime.now(timezone.utc).isoformat(),
                "private_apps": existing_apps,
                "npa_policies": existing_policies,
                "publishers": existing_publishers,
            },
            f,
            indent=2,
        )
    return path


def _log_rollback_results(results: list[tuple]) -> int:
    """
    Logs each (entry, success, error) tuple from RunLog.rollback() the same
    way everywhere a rollback happens (--rollback, a mid-run creation
    failure, or the post-verification rollback-or-exit prompt below).
    Returns the number of real failures (deletions that neither succeeded
    nor were intentionally skipped).
    """
    failures = 0
    for entry, success, error in results:
        if success:
            logger.info("Rolled back %s '%s' (id=%s).", entry.type, entry.name, entry.id)
        elif error.startswith("skipped"):
            logger.info("%s '%s': %s", entry.type, entry.name, error)
        else:
            failures += 1
            logger.error("Rollback FAILED for %s '%s' (id=%s): %s", entry.type, entry.name, entry.id, error)
    return failures


def do_rollback(args: argparse.Namespace) -> int:
    if not _require_tenant_creds(args):
        return 1
    run = RunLog.load(args.rollback)
    if not run.created:
        logger.info("Run log %s recorded nothing created; nothing to roll back.", args.rollback)
        return 0

    logger.info(
        "Rolling back run %s (%d object(s) recorded, status=%s)...",
        run.run_id, len(run.created), run.status,
    )
    client = build_netskope_client(args)
    failures = _log_rollback_results(run.rollback(client))

    if failures:
        logger.error(
            "%d object(s) could not be rolled back automatically. Remove them "
            "manually in the Netskope UI, or re-run --rollback %s after fixing "
            "the underlying issue.",
            failures, args.rollback,
        )
        return 1

    logger.info("Rollback complete.")
    return 0


def _apply_skip_policies_option(args: argparse.Namespace, plan) -> None:
    """--skip-policies means this run never touches NPA Policies at all —
    not created, and not even checked for name conflicts, since nothing
    will be done with them. The full policy mapping stays intact in
    analysis_report.md/plan.json (both written earlier in main(), before
    this runs) purely for reference."""
    if args.skip_policies and plan.policies:
        logger.info(
            "--skip-policies given: %d polic(y/ies) from the plan will NOT be created "
            "or checked for conflicts this run (still shown in analysis_report.md/"
            "plan.json for reference).",
            len(plan.policies),
        )
        plan.policies = []


def resolve_policy_group(client, group_name: str, run: RunLog) -> str | None:
    """
    Looks up `group_name` among the tenant's existing NPA Policy Groups and
    returns its ID if found. This tool does NOT create new Policy Groups —
    only an existing one can be selected/reused, whether the name came from
    --policy-group-name or the interactive menu (select_policy_group_interactive()
    no longer offers a "type a new name" option either). Reusing an existing
    group is additive (more policies land in it), not a replacement, so it's
    never treated as a conflict the way a colliding app/policy NAME would be.
    `run` is accepted for signature compatibility with the rest of the
    apply-time flow but nothing is ever recorded here now, since nothing is
    ever created.
    """
    try:
        existing = client.list_npa_policy_groups()
    except NetskopeApiError as e:
        logger.error("Failed to list existing NPA policy groups: %s", e)
        return None

    for g in existing:
        if g.get("name") == group_name:
            gid = g.get("id")
            logger.info("Reusing existing NPA policy group '%s' (id=%s).", group_name, gid)
            return gid

    logger.error(
        "NPA Policy Group '%s' does not exist in this tenant. This tool only "
        "reuses an existing group -- it does not create new ones. Create the "
        "group in the Netskope UI first, choose a different --policy-group-name, "
        "or pass --no-policy-group to leave the imported policies ungrouped.",
        group_name,
    )
    return None


def _offer_rollback_or_exit(args: argparse.Namespace, run: RunLog, client: NetskopeClient, verified: bool) -> int:
    """
    Always called right after post-apply verification runs -- whether it
    fully confirmed everything or found gaps -- so the operator gets an
    explicit final choice: roll back everything this run created, or keep
    it and exit. This is IN ADDITION TO the mid-run rollback prompt in
    apply_plan()'s handle_failure(), which only fires when a create call
    itself raises. Verification can find a problem even when every create
    call reported success (a 2xx isn't proof the object stuck -- see
    validation.py's module docstring), and until this existed that case
    had no rollback offer at all, just a logged error.

    --yes skips this prompt (same as the pre-apply confirmation prompt)
    so a scripted/CI run never blocks waiting for input -- the exit code
    then reflects verification alone (0 if verified, 1 if not), same as
    before this prompt existed.
    """
    if args.yes:
        return 0 if verified else 1

    resp = input(
        "Roll back everything this run created now, or keep it and exit? "
        "[y = roll back / Enter = keep and exit] "
    )
    if resp.strip().lower() == "y":
        failures = _log_rollback_results(run.rollback(client))
        run.mark_status("rolled_back")
        if failures:
            logger.error(
                "%d object(s) could not be rolled back automatically. Remove them "
                "manually in the Netskope UI, or re-run --rollback %s later.",
                failures, run.path,
            )
            return 1
        logger.info("Rollback complete.")
        return 0

    logger.info("Keeping everything this run created. Exiting.")
    return 0 if verified else 1


def do_check_conflicts(args: argparse.Namespace, plan) -> int:
    if not _require_tenant_creds(args):
        return 1
    _apply_skip_policies_option(args, plan)
    client = build_netskope_client(args)
    logger.info("Pulling current Private Apps and NPA Policies from %s...", args.tenant_url)
    existing_apps = client.list_private_apps()
    existing_policies = client.list_npa_policies()
    report = check_for_conflicts(plan, existing_apps, existing_policies)
    if not report.has_conflicts:
        logger.info("No conflicts. Every planned private app / policy name is free in this tenant.")
        return 0
    logger.warning("%d conflict(s) found:", len(report.describe()))
    for line in report.describe():
        logger.warning("  - %s", line)
    return 1


def apply_plan(args: argparse.Namespace, plan) -> int:
    if not _require_tenant_creds(args):
        return 1
    if _plan_uses_placeholder_publisher(plan):
        logger.error(
            "--apply requires real Publisher(s): use --publisher-ids, "
            "--default-publisher-id/--default-publisher-name, or re-run interactively "
            "to use the Publisher picker."
        )
        return 1

    _apply_skip_policies_option(args, plan)

    client = build_netskope_client(args)

    # --- Mandatory pre-flight: pull the tenant's CURRENT config and check
    #     for name collisions before creating anything. This is the error
    #     check that stops the tool from ever replacing an existing entry. ---
    logger.info("Pulling existing Netskope Private Access configuration (required safety check before any change)...")
    existing_apps = client.list_private_apps()
    existing_policies = client.list_npa_policies()
    existing_publishers = client.list_publishers()
    snapshot_path = _save_snapshot(args.snapshot_dir, existing_apps, existing_policies, existing_publishers)
    logger.info(
        "Pulled %d existing private app(s), %d existing polic(y/ies). Snapshot saved to %s",
        len(existing_apps), len(existing_policies), snapshot_path,
    )

    report = check_for_conflicts(plan, existing_apps, existing_policies)
    if report.has_conflicts:
        for line in report.describe():
            logger.warning(line)
        if not args.skip_conflicts:
            logger.error(
                "Refusing to proceed: %d name collision(s) with entries that already "
                "exist in the tenant (see above). This tool will not update or replace "
                "an existing private app or policy. Rename the conflicting item(s) in "
                "your plan, or re-run with --skip-conflicts to create everything else "
                "and leave the colliding names untouched.",
                len(report.describe()),
            )
            return 1
        logger.warning("--skip-conflicts given: the %d colliding item(s) above will be left untouched; everything else proceeds.", len(report.describe()))
        filter_out_conflicts(plan, report)

    if not plan.private_apps and not plan.policies:
        logger.info("Nothing left to create after conflict filtering. Exiting.")
        return 0

    if not args.yes:
        resp = input(
            f"About to create {len(plan.private_apps)} private app(s) and "
            f"{len(plan.policies)} polic(y/ies) in {args.tenant_url}, using this "
            "UNOFFICIAL, community-created tool (not supported by Netskope). "
            "Continue? [y/N] "
        )
        if resp.strip().lower() != "y":
            logger.info("Aborted by user. No changes made.")
            return 1

    run = RunLog.start(args.tenant_url, args.config, log_dir=args.run_log_dir)
    logger.info("Run log: %s", run.path)

    def handle_failure(obj_type: str, name: str, error: Exception) -> int:
        run.mark_status("failed")
        logger.error("Failed to create %s '%s': %s", obj_type, name, error)
        logger.error(
            "Stopping immediately — %d object(s) already created this run are "
            "recorded in %s.",
            len(run.created), run.path,
        )
        do_it = args.auto_rollback_on_failure
        if not do_it and not args.no_rollback_prompt:
            resp = input("Roll back everything this run created now? [y/N] ")
            do_it = resp.strip().lower() == "y"
        if do_it:
            _log_rollback_results(run.rollback(client))
        else:
            logger.error("Not rolled back. To undo this run later, use:\n  python main.py --rollback %s --tenant-url %s --api-token <token>", run.path, args.tenant_url)
        return 1

    created_apps = 0
    for app in plan.private_apps:
        try:
            result = client.create_private_app(app.to_payload())
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            # Confirmed real create response has both "id" and "app_id" with
            # the same value, but check both aliases defensively (the list
            # endpoint for this same resource turned out to have ONLY
            # "app_id", no "id" at all -- see list_private_apps()).
            app_id = _first(data, "id", "app_id", "appId") or _first(result, "id", "app_id", "appId")
            logger.info("Created private app '%s' (id=%s).", app.app_name, app_id)
            run.record_created("private_app", app_id, app.app_name)
            created_apps += 1
        except NetskopeApiError as e:
            return handle_failure("private_app", app.app_name, e)

    policy_group_id, policy_group_name = None, None
    if plan.policies and not args.no_policy_group:
        policy_group_name = args.policy_group_name or select_policy_group_interactive(client)
        if not policy_group_name:
            run.mark_status("failed")
            logger.error(
                "A Policy Group name is required whenever policies are being created. "
                "Pass --policy-group-name, or --no-policy-group to leave them ungrouped "
                "instead. Stopping before creating any policies — %d private app(s) from "
                "this run already exist (recorded in %s).",
                len(run.created), run.path,
            )
            return 1
        policy_group_id = resolve_policy_group(client, policy_group_name, run)
        if policy_group_id is None:
            run.mark_status("failed")
            logger.error(
                "Could not resolve the NPA policy group '%s'; stopping before creating any "
                "policies. %d private app(s) from this run already exist (recorded in %s).",
                policy_group_name, len(run.created), run.path,
            )
            return 1

    # Maps lowercased group name -> the tenant's real {"id", "name"} for that
    # group. Confirmed from a live tenant's rule_data: a real grouped/scoped
    # rule carries BOTH "userGroups" (plain name strings) AND
    # "userGroupObjects" (id+name objects) side by side, so both are sent
    # when a match is found rather than guessing which one the API actually
    # consumes for the restriction.
    existing_groups_by_name = None
    if plan.policies and not args.skip_group_check:
        try:
            tenant_groups = client.list_user_groups()
            existing_groups_by_name = {
                g["name"].strip().lower(): g for g in tenant_groups if g.get("name")
            }
            logger.info(
                "Pulled %d user/IdP group(s) from the tenant to validate policy "
                "userGroups against.", len(existing_groups_by_name),
            )
        except NetskopeApiError as e:
            logger.warning(
                "Could not pull user groups from the tenant (%s) — skipping the "
                "pre-flight group-existence check for this run (same as if "
                "--skip-group-check had been passed). This is NOT the only "
                "safety net: if the tenant's own policy-create validation later "
                "rejects a role name as an invalid group, that policy is retried "
                "automatically without a userGroups restriction instead of "
                "failing the run — see the per-policy log lines below.", e,
            )
            existing_groups_by_name = None

    created_policies = 0
    for pol in plan.policies:
        omit_user_groups = False
        user_group_objects = None
        if existing_groups_by_name is not None:
            missing = [g for g in pol.user_groups if g.strip().lower() not in existing_groups_by_name]
            if missing:
                omit_user_groups = True
                logger.warning(
                    "Policy '%s': user group(s) %s not found among the tenant's known "
                    "IdP groups. Creating it WITHOUT a userGroups restriction (open to "
                    "any authenticated user) instead of blocking the run or scoping it "
                    "to a group that would match nobody — lock this down manually once "
                    "the correct group name is confirmed.", pol.rule_name, missing,
                )
            else:
                user_group_objects = [
                    {"id": existing_groups_by_name[g.strip().lower()].get("id"), "name": existing_groups_by_name[g.strip().lower()].get("name")}
                    for g in pol.user_groups
                ]
        try:
            try:
                result = client.create_npa_policy(
                    pol.to_payload(
                        group_id=policy_group_id,
                        group_name=policy_group_name,
                        omit_user_groups=omit_user_groups,
                        user_group_objects=user_group_objects,
                    )
                )
            except NetskopeApiError as e:
                # The pre-flight group-existence check (above) depends on
                # list_user_groups() hitting the right endpoint -- confirmed
                # WRONG on at least one real tenant (/api/v2/scim/groups
                # 404'd, "no Route matched with those values"), so
                # existing_groups_by_name can end up None (unverified) even
                # when a role name genuinely isn't a real group. When that
                # happens, the tenant's own create-time validation catches
                # it instead, with this exact message shape:
                #   {"message": "Invalid values from users, userGroups or
                #    organization_units:{'Employees-Full'}", "status": "error"}
                # Rather than aborting the whole run over this, treat it the
                # same as a pre-flight miss: retry once with no userGroups
                # restriction. This makes the tenant's own validation the
                # authoritative fallback trigger, independent of whether
                # list_user_groups() ever finds the right endpoint.
                if not omit_user_groups and "Invalid values from users, userGroups or organization_units" in str(e):
                    omit_user_groups = True
                    logger.warning(
                        "Policy '%s': the tenant rejected user group(s) %s as invalid "
                        "(%s). Retrying WITHOUT a userGroups restriction (open to any "
                        "authenticated user) instead of aborting the run — lock this "
                        "down manually once the correct group name is confirmed.",
                        pol.rule_name, pol.user_groups, e,
                    )
                    result = client.create_npa_policy(
                        pol.to_payload(
                            group_id=policy_group_id,
                            group_name=policy_group_name,
                            omit_user_groups=True,
                            user_group_objects=None,
                        )
                    )
                else:
                    raise
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            # rule_id, not id, is the real field name on a rule object
            # (confirmed via a live tenant's GET response) -- the create
            # response's exact shape is unconfirmed, so this checks every
            # alias in both the nested "data" object and the top level.
            rule_id = _first(data, "id", "rule_id", "ruleId") or _first(result, "id", "rule_id", "ruleId")
            logger.info(
                "Created policy '%s' (id=%s)%s%s.", pol.rule_name, rule_id,
                f" in group '{policy_group_name}'" if policy_group_name else "",
                " [NO userGroups restriction — role not found/invalid in tenant]" if omit_user_groups else "",
            )
            run.record_created("npa_policy", rule_id, pol.rule_name)
            created_policies += 1
        except NetskopeApiError as e:
            return handle_failure("npa_policy", pol.rule_name, e)

    if args.skip_verification:
        run.mark_status("completed")
        logger.info(
            "Done. Created %d private app(s) and %d polic(y/ies). Run log: %s "
            "(--skip-verification given: not independently confirmed).",
            created_apps, created_policies, run.path,
        )
        return 0

    logger.info(
        "Verifying that everything created actually exists in the tenant "
        "(re-pulling, not just trusting the create response)..."
    )
    vreport = verify_creation(client, run.created, retries=args.verify_retries, delay_seconds=args.verify_delay)

    if vreport.all_verified:
        run.mark_status("completed")
        logger.info(
            "Verified: all %d created object(s) confirmed present in the tenant. Run log: %s",
            len(run.created), run.path,
        )
    else:
        run.mark_status("completed_with_verification_failures")
        logger.error(
            "%d of %d created object(s) could NOT be confirmed present after re-checking the tenant:",
            len(vreport.missing), len(run.created),
        )
        for line in vreport.describe_missing():
            logger.error("  - %s", line)
        logger.error(
            "The create call(s) returned success, but a follow-up check didn't find these objects. "
            "Check the Netskope UI directly before assuming they exist. Run log (marked "
            "completed_with_verification_failures): %s",
            run.path,
        )

    # Always offer a rollback-or-keep decision here, whether or not
    # verification found a problem -- see _offer_rollback_or_exit()'s
    # docstring for why this exists alongside the mid-run failure prompt.
    return _offer_rollback_or_exit(args, run, client, vreport.all_verified)


DISCLAIMER = """\
================================================================================
  ivanti-to-npa is a COMMUNITY-CREATED, UNOFFICIAL tool.
  It is not built, reviewed, endorsed, or supported by Netskope or Ivanti.
  Netskope Customer Support cannot assist with issues caused by this tool.
  You are running it against your own tenant entirely AT YOUR OWN RISK.

  Before --apply: review analysis_report.md and plan.json, and prefer
  --check-conflicts / a dry run first.
================================================================================
"""


def _print_disclaimer() -> None:
    # flush=True so this reliably appears before any logging output (which
    # goes to stderr) even when both streams are redirected into one pipe.
    print(DISCLAIMER, flush=True)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.debug:
        logging.getLogger("ivanti_to_npa").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled — raw API response bodies will be printed.")
    _print_disclaimer()

    if args.rollback:
        return do_rollback(args)

    if not args.config:
        logger.error("--config is required (unless using --rollback).")
        return 1

    ivanti_config = parse_ivanti_config(args.config)
    logger.info(
        "Parsed %d realm(s) and %d resource profile(s) from %s",
        len(ivanti_config.realms), len(ivanti_config.resource_profiles), args.config,
    )
    if ivanti_config.network_connect_acls:
        logger.info(
            "Also found %d Network Connect ACL(s) in %s -- converted where possible "
            "(one private app per resource; see the analysis report's 'Network Connect "
            "ACLs' section for exactly what converted vs. was skipped, and why).",
            len(ivanti_config.network_connect_acls), args.config,
        )

    if args.limit:
        ivanti_config.resource_profiles = ivanti_config.resource_profiles[: args.limit]

    default_publishers, publisher_error = resolve_default_publishers(args)
    if publisher_error:
        return 1
    publisher_overrides = load_publisher_map(args.publisher_map)

    tag_name = resolve_tag(args)

    plan = build_migration_plan(
        ivanti_config,
        default_publishers=default_publishers,
        tag_name=tag_name,
        publisher_overrides=publisher_overrides,
    )

    if not args.no_report:
        # Built once and reused for both renderers -- render_markdown() and
        # render_csv() used to each independently redo the same
        # build_app_rows() work (lookups + a full pass over
        # plan.private_apps), which is pure duplicated effort on a large
        # import (hundreds to ~1000 private apps).
        app_rows = build_app_rows(ivanti_config, plan)
        md = render_markdown(ivanti_config, plan, source_path=args.config, app_rows=app_rows)
        with open(args.report_md, "w") as f:
            f.write(md)
        csv_text = render_csv(ivanti_config, plan, app_rows=app_rows)
        with open(args.report_csv, "w") as f:
            f.write(csv_text)
        logger.info("Analysis report written to %s and %s", args.report_md, args.report_csv)

    if args.analysis_only:
        logger.info(
            "--analysis-only: skipping plan.json. %d realm(s), %d profile(s) parsed, "
            "%d converted, %d skipped, %d warning(s). Review %s.",
            len(ivanti_config.realms), len(ivanti_config.resource_profiles),
            len(plan.private_apps), len(plan.skipped_profiles), len(plan.warnings),
            args.report_md,
        )
        return 0

    plan_json = {
        "private_apps": [pa.to_payload() for pa in plan.private_apps],
        "policies": [pol.to_payload() for pol in plan.policies],
        "skipped_profiles": plan.skipped_profiles,
        "warnings": plan.warnings,
    }
    with open(args.output_plan, "w") as f:
        json.dump(plan_json, f, indent=2)

    logger.info(
        "Plan: %d private app(s), %d polic(y/ies), %d skipped profile(s), %d warning(s). "
        "Written to %s",
        len(plan.private_apps), len(plan.policies), len(plan.skipped_profiles),
        len(plan.warnings), args.output_plan,
    )
    for w in plan.warnings:
        logger.warning(w)

    if args.check_conflicts:
        return do_check_conflicts(args, plan)

    if not args.apply:
        logger.info("Dry run only (no --apply given). Review %s, then re-run with --apply.", args.output_plan)
        return 0

    return apply_plan(args, plan)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
