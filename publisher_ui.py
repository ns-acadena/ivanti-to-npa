"""
publisher_ui.py

Interactive Publisher picker: pulls the real Publisher list (id + name)
from the tenant via GET /api/v2/infrastructure/publishers and lets the
operator choose up to MAX_SELECTABLE_PUBLISHERS of them, instead of
having to already know a Publisher ID to pass on the command line.

Netskope Private Apps accept a *list* of Publishers (the "publishers"
field in the create-app payload is an array) so an app can be served by
more than one Publisher for redundancy — selecting more than one here is
meaningful, not just a batch-select convenience. That's why this supports
up to four, not just one.
"""

from __future__ import annotations

import logging

from mapper import PublisherRef

logger = logging.getLogger("ivanti_to_npa.publisher_ui")

MAX_SELECTABLE_PUBLISHERS = 4


def _format_table(publishers: list[dict]) -> str:
    id_w = max([len(str(p.get("id", ""))) for p in publishers] + [2])
    name_w = max([len(str(p.get("name", ""))) for p in publishers] + [4])
    header = f"  {'#':>3}  {'ID':<{id_w}}  {'Name':<{name_w}}  Apps  Local Broker"
    lines = [header, "  " + "-" * (len(header) - 2)]
    for i, p in enumerate(publishers, start=1):
        lines.append(
            f"  {i:>3}  {str(p.get('id', '')):<{id_w}}  {str(p.get('name', '')):<{name_w}}  "
            f"{str(p.get('apps_count', '?')):>4}  {'yes' if p.get('lbrokerconnect') else 'no'}"
        )
    return "\n".join(lines)


def select_publishers_interactive(
    client, max_select: int = MAX_SELECTABLE_PUBLISHERS, input_func=input
) -> list[PublisherRef] | None:
    """
    Pulls the Publisher list from `client` (anything with
    list_publishers()) and prompts for a comma-separated selection.
    Returns the selected PublisherRefs, or None on any error/abort (the
    error has already been logged — callers should treat None as "stop,
    exit 1").
    """
    publishers = client.list_publishers()
    if not publishers:
        logger.error(
            "No Publishers found in this tenant. Deploy at least one Publisher "
            "(Settings > Private Access > Publishers) before importing private apps."
        )
        return None

    print(f"\nPublishers in this tenant ({len(publishers)}):\n")
    print(_format_table(publishers))
    print(
        f"\nSelect 1-{max_select} publisher(s) by number, comma-separated "
        f"(e.g. 1,3): ",
        end="",
    )
    raw = input_func("").strip()

    try:
        indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
    except ValueError:
        logger.error("Could not parse '%s' as a comma-separated list of numbers.", raw)
        return None

    if not indices:
        logger.error("No selection made.")
        return None
    if len(indices) > max_select:
        logger.error("Selected %d publisher(s); the maximum is %d.", len(indices), max_select)
        return None
    if len(set(indices)) != len(indices):
        logger.error("Duplicate selection in '%s'.", raw)
        return None

    refs: list[PublisherRef] = []
    for idx in indices:
        if idx < 1 or idx > len(publishers):
            logger.error("'%d' is not a valid choice (must be 1-%d).", idx, len(publishers))
            return None
        p = publishers[idx - 1]
        refs.append(PublisherRef(publisher_id=str(p.get("id")), publisher_name=p.get("name")))

    logger.info(
        "Selected %d publisher(s): %s",
        len(refs),
        ", ".join(f"{r.publisher_name} (id={r.publisher_id})" for r in refs),
    )
    return refs
