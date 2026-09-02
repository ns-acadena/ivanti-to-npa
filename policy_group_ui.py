"""
policy_group_ui.py

Interactive NPA Policy Group picker: shows the tenant's existing Policy
Groups (id + name) in a numbered menu so the operator can select one to
reuse — instead of typing a name blind and hoping it matches.

This tool does not create new Policy Groups. Only an EXISTING group can be
selected here; there is no "type a new name" option. This only decides the
NAME the caller should use — main.py's resolve_policy_group() is still what
actually looks the name up (and fails cleanly if it doesn't exist).
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("ivanti_to_npa.policy_group_ui")


def _format_table(groups: list[dict]) -> str:
    id_w = max([len(str(g.get("id", ""))) for g in groups] + [2])
    name_w = max([len(str(g.get("name", ""))) for g in groups] + [4])
    header = f"  {'#':>3}  {'ID':<{id_w}}  Name"
    lines = [header, "  " + "-" * (len(header) - 2)]
    for i, g in enumerate(groups, start=1):
        lines.append(f"  {i:>3}  {str(g.get('id', '')):<{id_w}}  {str(g.get('name', '')):<{name_w}}")
    return "\n".join(lines)


def select_policy_group_interactive(client, input_func=input) -> str | None:
    """
    Returns the name of an EXISTING Policy Group the operator picked from
    the tenant's list, or None if there's nothing to work with: no
    terminal to prompt on, no groups exist in the tenant at all, or the
    operator gave up / entered something invalid. Never returns an empty
    string, and never returns a name that isn't already a real group in
    the tenant -- this tool does not create new Policy Groups.
    """
    if not sys.stdin.isatty():
        return None

    groups = client.list_npa_policy_groups()

    if not groups:
        logger.error(
            "No existing NPA Policy Groups found in this tenant. This tool only "
            "reuses an existing group -- it does not create new ones. Create one "
            "in the Netskope UI first, or pass --no-policy-group to leave the "
            "imported policies ungrouped."
        )
        return None

    print(f"\nExisting NPA Policy Groups ({len(groups)}):\n")
    print(_format_table(groups))
    raw = input_func("\nSelect an existing group by number: ").strip()

    if not raw:
        return None

    if not raw.isdigit():
        logger.error("'%s' is not a valid choice -- enter the number of an existing group.", raw)
        return None

    idx = int(raw)
    if idx < 1 or idx > len(groups):
        logger.error("'%d' is not a valid choice (must be 1-%d).", idx, len(groups))
        return None

    chosen = groups[idx - 1]
    name = chosen.get("name")
    logger.info("Selected existing policy group '%s' (id=%s).", name, chosen.get("id"))
    return name
