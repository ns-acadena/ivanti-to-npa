# ivanti-to-npa

> **Unofficial, community-created tool** — not built, reviewed, or supported
> by Netskope or Ivanti. Netskope Support cannot help with issues it causes.
> Run it against your own tenant at your own risk. Always review
> `analysis_report.md` and `plan.json` before `--apply`, and prefer
> `--check-conflicts` or a dry run first.

Imports an Ivanti Connect Secure (ICS) configuration export into a Netskope
tenant with Private Access (NPA/ZTNA) enabled — converting ICS resource
profiles and Network Connect ACLs into Netskope Private Apps, and ICS roles
into NPA Real-Time Policies.

## What it does

1. Parses the ICS XML export: realms/roles, resource profiles (web / SAM /
   PSAM / terminal services / file browsing) with their allow/deny
   autopolicies, and Network Connect ACLs (full-tunnel, subnet/CIDR rules).
2. Maps each supported resource into a Netskope **Private App**
   (host + protocol/port), always **Client-based** — Browser Access isn't
   supported by this tool.
3. Maps each ICS role to an NPA **Real-Time Policy** scoping the apps that
   role can reach.
4. Writes a human-readable analysis report (`analysis_report.md`/`.csv`)
   and a machine-readable `plan.json` — generated on every run, including
   `--analysis-only` (no credentials needed).
5. Only touches your tenant with `--apply`, and even then checks for
   existing objects by name first so re-runs don't create duplicates.

## Safety model

- **Never overwrites.** `--apply` refuses to create anything whose name
  collides with an existing Private App or NPA Policy (`--skip-conflicts`
  to skip just those and proceed with the rest). Every pre-flight pull is
  snapshotted to `netskope_snapshots/`.
- **Every create is logged immediately** to `run_logs/run_<timestamp>.json`
  — not batched — so a mid-run failure still leaves an accurate record of
  what exists.
- **A failure offers an immediate rollback**, and any run can be rolled
  back later: `python main.py --rollback run_logs/run_....json`.
- **Creates are re-verified**, not just trusted from the API response —
  the tool re-pulls the tenant afterward and confirms each object is
  really there, retrying briefly for propagation lag.
- **You're always asked what to do next** once verification finishes,
  clean or not: roll back everything, or keep it. The exit code always
  reflects the real verification result regardless of that choice.
  `--yes` skips the prompt and keeps.
- **Rate-limit aware**: a small pacing delay follows every real
  create/delete (`--write-pacing-ms`, default 100ms), and a 429 honors the
  server's `Retry-After` header before falling back to exponential backoff.

## What it deliberately does NOT do

| Ivanti concept | Why it's not auto-converted |
|---|---|
| **Publishers** | ICS has no equivalent — give an existing Publisher's ID/name via `--publisher-ids` or `--default-publisher-id`. This tool won't provision infrastructure. |
| **Realms/roles → users** | NPA policies scope access by **IdP group name**. The Ivanti role name is used as a starting-point `userGroups` value and checked against the tenant's real groups where possible; no match still creates the policy, just without that restriction, logged loudly. |
| **Full VPN tunneling / `network-connect` profiles** | A whole-subnet L3 tunnel, not an app — listed as skipped, never converted. |
| **Deny autopolicies** | ICS denies a specific host/port *within* a profile; NPA can't block just that sub-resource, so a companion **block policy for the whole app** is generated instead (broader than the original rule — review it). |
| **MFA / cert auth / sign-in policies** | Lives in your IdP + Netskope's own auth policies, out of scope here. |

## Network Connect ACLs

ICS's Network Connect ACLs (Users > Resource Policies > Network Connect)
convert to Private Apps one host at a time, with three consolidation passes
to avoid redundant objects:

- Multiple resources on the **same host within one ACL** (e.g. one TCP
  spec, one UDP spec) merge into a single app with a combined `protocols`
  list, instead of separate numbered apps.
- An **exact duplicate host + protocol/port set across ACLs** shares one
  app (named from the host, not any one ACL) instead of creating another.
  A partial match never merges — that would silently drop access.
- `action=deny` ACLs get their own block policy and are never shared with
  an allow ACL's app.

A few edges are worth knowing: a CIDR resource narrower than Netskope's
documented `/8` floor is skipped (broader ones aren't allowed at all); a
misaligned CIDR host (e.g. `10.51.150.1/24`) is normalized to the correct
network address; `icmp://` resources are recognized but skipped (no
confirmed Netskope schema for ICMP); a missing/wildcard port becomes the
placeholder range `1-65535`, unconfirmed against a live tenant — verify
before relying on it.

## Setup

```bash
cd ivanti-to-npa
pip install -r requirements.txt --break-system-packages   # or use a venv
```

Create a Netskope **Service Account API token** (Settings > Administration
> Administrators & Roles > Administrators > Service Account) scoped to
Private Access. Supply it via `$NETSKOPE_API_TOKEN`/`--api-token`, or leave
it unset to be prompted (hidden input) the first time it's needed. Same
pattern for `$NETSKOPE_TENANT_URL`/`--tenant-url`. Bearer-token and OAuth2
client-credentials auth are also supported — see `--help`.

## Usage

```bash
# Analysis only — mapping report, no credentials needed
python main.py --config your_export.xml --analysis-only

# Dry run — writes plan.json, no network calls
python main.py --config your_export.xml \
  --default-publisher-id 123 --default-publisher-name aws-publisher-1

# Apply — actually create the apps and policies
python main.py --config your_export.xml \
  --default-publisher-id 123 --default-publisher-name aws-publisher-1 \
  --apply
```

If you omit publisher flags entirely, you'll get an interactive picker
(pulls your tenant's real Publisher list, select 1-4). Same for
`--policy-group-name` — every generated policy needs to land in an
**existing** NPA Policy Group (this tool never creates one); leave it off
for an interactive menu, or pass `--no-policy-group` to leave policies
ungrouped.

Other flags worth knowing: `--skip-policies` (apps only), `--publisher-map`
(a JSON file overriding the Publisher per resource), `--tag` (applied to
every created app, default `ivanti-import`), `--limit N` (only process the
first N profiles, good for a smoke test), `--skip-group-check`,
`--auto-rollback-on-failure`, `--debug`. Run `python main.py --help` for
the full list.

## Adapting to your real export

Ivanti doesn't publish a formal schema, and tag names can shift slightly by
ICS version. Everything the parser looks for goes through one `XPATHS`
dictionary in `ivanti_parser.py`. Namespace handling and Network Connect
ACL parsing are already confirmed against real exports and need no changes.
If your export's realm/resource-profile structure differs:

1. Get a real export: ICS admin console → Maintenance > Import/Export.
2. `grep -i` the file for `realm`, `resource-profile`, `role-mapping`,
   `autopolic` to find the real tag names.
3. Edit `XPATHS` in `ivanti_parser.py` to match — nothing else needs to
   change.
4. Re-run with `--limit 5` first and eyeball `plan.json` before processing
   the whole file.

## Files

| File | Purpose |
|---|---|
| `main.py` | CLI entry point |
| `ivanti_parser.py` | ICS XML → `IvantiConfig` object model (edit `XPATHS` here for your real export) |
| `mapper.py` | `IvantiConfig` → Netskope Private App / NPA Policy payloads |
| `report.py` | Mapping/analysis report generator (Markdown + CSV) |
| `validation.py` | Pre-flight conflict check + post-apply verification |
| `runlog.py` | Incrementally-flushed record of what a run created, and rollback |
| `publisher_ui.py` | Interactive Publisher picker |
| `policy_group_ui.py` | Interactive NPA Policy Group picker (existing groups only) |
| `netskope_client.py` | Netskope REST API v2 wrapper (auth, retries, rate-limit pacing, dry-run) |
| `sample_ivanti_config.xml` | Representative test fixture — **not** a real export |
| `run_tests.sh` | Runs every `_smoketest_*.py` file — the regression suite |
