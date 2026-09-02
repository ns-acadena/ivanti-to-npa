"""
netskope_client.py

Thin wrapper around the Netskope Private Access REST API v2
(Publishers / Private Apps / Tags / NPA Real-Time Policies).

Reference: https://docs.netskope.com/en/private-access-rest-apis
The exact JSON body accepted by your tenant can vary slightly by release —
before running with --apply, open Settings > Tools > REST API v2 >
API Documentation in your own tenant and confirm field names against the
Swagger UI. This client's dry_run mode (the default) prints/saves every
request it *would* make without sending it, specifically so you can diff
that against Swagger before trusting it.

Auth — two supported modes:

1. **Static API token** (the only method Netskope documents for this
   specific API surface today): a Service Account token created under
   Settings > Administration > Administrators & Roles > Administrators >
   Service Account, sent in the `Netskope-Api-Token` header. This is the
   default and what most tenants should use.

2. **Bearer token / OAuth2 client-credentials**: some environments front
   Netskope's API with their own OAuth-issuing gateway, or a future
   Netskope release may accept a standard `Authorization: Bearer <token>`
   header on these endpoints. This client supports both a pre-obtained
   bearer token (`--auth-mode bearer`) and a full OAuth2 client-credentials
   grant that fetches (and refreshes) its own token from a token endpoint
   you provide (`OAuthTokenProvider`). Verify against your own tenant's
   Swagger UI / gateway docs before relying on this — as of this writing
   Netskope's public documentation for the Private Access REST API v2
   (Publishers/Private Apps/NPA Policies) only describes the static
   token method above.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

import requests

logger = logging.getLogger("ivanti_to_npa.netskope_client")


class NetskopeApiError(RuntimeError):
    pass


def _first(d: dict, *keys: str, default=None):
    """Return the first present, non-empty value among `keys` in `d`.
    Netskope's field names for the "same" concept aren't always
    consistent across endpoints/releases (id vs publisher_id vs pub_id,
    etc.) — this tolerates the variants instead of hardcoding one."""
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def _strip_brackets(name: str) -> str:
    """
    Confirmed against a real tenant: Netskope wraps a Private App's
    app_name/name in a single pair of square brackets when storing/
    returning it -- create with "Corp-Intranet", get back "[Corp-Intranet]"
    on BOTH the create response and the list endpoint. This is the same
    bracket convention already relied on when referencing an app inside an
    NPA policy's privateApps field (see mapper.py), just seen here from the
    other direction. Comparing a plan's plain name against the tenant's
    bracketed one without stripping this made both the pre-flight conflict
    check and post-apply verification silently fail to match a real,
    successfully-created app -- verification reported "not found" for
    every app in a run that Netskope's own create responses confirmed had
    succeeded. Only strips one matching pair of brackets, so a name that
    didn't have this wrapping is returned unchanged.
    """
    if name.startswith("[") and name.endswith("]") and len(name) >= 2:
        return name[1:-1]
    return name


# Standard HTTP, not Netskope-specific -- unlike other unconfirmed schema
# details in this file, honoring Retry-After doesn't require guessing at
# Netskope's own API shape: RFC 7231 defines it as either an integer
# seconds count or an HTTP-date. Only the integer-seconds form is handled
# here (by far the more common one for rate-limit responses); an HTTP-date
# value, or a missing/malformed header, falls back to the existing
# exponential backoff via the `or` in the caller. Capped at 60s so a
# malformed or unexpectedly large header value can't stall a run
# indefinitely.
def _retry_after_seconds(resp) -> float | None:
    raw = resp.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return min(float(raw), 60.0)
    except ValueError:
        return None


def _extract_list(response: dict, wrapped_key: str) -> list[dict]:
    """
    List endpoints across Netskope's REST API v2 aren't all shaped the
    same: some wrap their array under response["data"][wrapped_key]
    (e.g. {"data": {"private_apps": [...]}}), others return
    response["data"] as the array directly (e.g. {"data": [...]}) —
    confirmed against a real tenant, where /api/v2/policy/npa/rules
    does the latter while other endpoints do the former. This helper
    tolerates both shapes instead of assuming one.
    """
    inner = response.get("data", [])
    if isinstance(inner, dict):
        return inner.get(wrapped_key, [])
    if isinstance(inner, list):
        return inner
    return []


@dataclass
class OAuthTokenProvider:
    """
    Fetches and caches a bearer token via the OAuth2 client-credentials
    grant (RFC 6749 §4.4): POSTs client_id/client_secret/grant_type to
    `token_url`, expects an `access_token` (+ optional `expires_in`) back,
    and refreshes automatically shortly before expiry or on demand.
    """

    token_url: str
    client_id: str
    client_secret: str
    scope: str | None = None
    verify_ssl: bool = True
    timeout: int = 30
    _token: str | None = field(default=None, init=False, repr=False)
    _expires_at: float = field(default=0.0, init=False, repr=False)

    def get_token(self, force_refresh: bool = False) -> str:
        if not force_refresh and self._token and time.time() < self._expires_at - 30:
            return self._token

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope

        resp = requests.post(self.token_url, data=data, timeout=self.timeout, verify=self.verify_ssl)
        if resp.status_code >= 400:
            raise NetskopeApiError(
                f"OAuth token request to {self.token_url} failed [{resp.status_code}]: {resp.text[:1000]}"
            )
        try:
            payload = resp.json()
        except ValueError as e:
            raise NetskopeApiError(f"Non-JSON OAuth token response from {self.token_url}: {e}") from e

        token = payload.get("access_token")
        if not token:
            raise NetskopeApiError(
                f"OAuth token response from {self.token_url} had no 'access_token' field: {payload}"
            )
        self._token = token
        self._expires_at = time.time() + float(payload.get("expires_in", 3600))
        return token


@dataclass
class NetskopeClient:
    tenant_url: str
    api_token: str | None = None
    oauth_provider: OAuthTokenProvider | None = None
    # "api_token" (Netskope-Api-Token header, default/documented) or
    # "bearer" (Authorization: Bearer <api_token>, for a pre-obtained
    # token). Ignored — always treated as bearer — when oauth_provider is set.
    auth_mode: str = "api_token"
    dry_run: bool = True
    timeout: int = 30
    max_retries: int = 3
    # Fixed delay after every real (non-dry-run) POST/DELETE, regardless of
    # whether a 429 was ever hit -- see the pacing comment in _request().
    write_pacing_seconds: float = 0.1

    def __post_init__(self):
        if not self.dry_run and not self.api_token and not self.oauth_provider:
            raise ValueError("NetskopeClient requires either api_token or oauth_provider (unless dry_run=True).")
        self.tenant_url = self.tenant_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
        # Dry run makes ZERO network calls, including fetching an OAuth
        # token — defer auth entirely until the first real request.
        if not self.dry_run:
            self._apply_auth_header()

    def _apply_auth_header(self, force_oauth_refresh: bool = False) -> None:
        self._session.headers.pop("Netskope-Api-Token", None)
        self._session.headers.pop("Authorization", None)
        if self.oauth_provider:
            token = self.oauth_provider.get_token(force_refresh=force_oauth_refresh)
            self._session.headers["Authorization"] = f"Bearer {token}"
        elif self.auth_mode == "bearer":
            self._session.headers["Authorization"] = f"Bearer {self.api_token}"
        elif self.api_token:
            self._session.headers["Netskope-Api-Token"] = self.api_token
        # else: dry_run with no credentials at all — fine, no header needed.

    # -- low level -----------------------------------------------------
    def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        url = f"{self.tenant_url}{path}"

        if self.dry_run:
            logger.info(
                "[DRY RUN] %s %s\n%s",
                method,
                url,
                json.dumps(json_body, indent=2) if json_body else "(no body)",
            )
            # Return a synthetic response so callers can proceed through the
            # rest of the plan without crashing on a missing "id".
            return {"dry_run": True, "would_send": {"method": method, "url": url, "body": json_body}}

        attempt = 0
        refreshed_once = False
        while True:
            attempt += 1
            resp = self._session.request(method, url, json=json_body, timeout=self.timeout)

            if resp.status_code == 401 and self.oauth_provider and not refreshed_once:
                logger.info("Got 401; refreshing OAuth token and retrying once.")
                self._apply_auth_header(force_oauth_refresh=True)
                refreshed_once = True
                continue

            if resp.status_code == 429 and attempt <= self.max_retries:
                wait = _retry_after_seconds(resp) or (2 ** attempt)
                logger.warning("Rate limited (429). Retrying in %ss...", wait)
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                raise NetskopeApiError(
                    f"{method} {path} failed [{resp.status_code}]: {resp.text[:2000]}"
                )

            # Proactive pacing, not just reactive backoff: a bulk --apply run
            # can fire off hundreds to low-thousands of sequential
            # create/delete calls (one per private app / policy) with
            # nothing throttling them, which is exactly the pattern most
            # likely to trip a tenant's rate limit in the first place.
            # GET calls aren't paced -- they're not done in a tight
            # per-object loop anywhere in this tool.
            if method in ("POST", "DELETE") and self.write_pacing_seconds:
                time.sleep(self.write_pacing_seconds)

            if not resp.content:
                return {}
            try:
                parsed = resp.json()
            except ValueError as e:
                raise NetskopeApiError(f"Non-JSON response from {method} {path}: {e}") from e

            # Only visible with --debug. If a list-endpoint's field names
            # ever turn out not to be what this client expects (it's
            # happened before — see _extract_list's docstring), this is
            # the fastest way to get the real shape without guessing again.
            logger.debug("Response body for %s %s:\n%s", method, path, json.dumps(parsed, indent=2)[:4000])

            # Netskope has been observed returning a 2xx HTTP status with an
            # error-shaped BODY instead of a 4xx/5xx -- e.g. creating an NPA
            # policy without the required "rule_data" wrapper returned HTTP
            # 200 with {"status": "error", "message": "Missing rule_data
            # when creating a policy"}. Trusting the HTTP status alone made
            # that look like a success ("Created policy ... (id=None)")
            # right up until someone checked the tenant and found nothing
            # there. Treat this body shape as a failure regardless of status
            # code so a bad payload fails loudly here instead of silently.
            if isinstance(parsed, dict) and parsed.get("status") == "error":
                raise NetskopeApiError(
                    f"{method} {path} returned HTTP {resp.status_code} but an error body: "
                    f"{parsed.get('message') or json.dumps(parsed)[:1000]}"
                )
            return parsed

    # -- publishers ------------------------------------------------------
    def list_publishers(self) -> list[dict]:
        data = self._request("GET", "/api/v2/infrastructure/publishers")
        raw = _extract_list(data, "publishers")

        normalized = []
        for p in raw:
            item = dict(p)  # keep every original field for debugging
            item["id"] = _first(p, "id", "publisher_id", "pub_id", "publisherId", "publisherID")
            item["name"] = _first(p, "name", "publisher_name", "pub_name", "publisherName", "common_name")
            normalized.append(item)

        if raw and not any(item.get("id") and item.get("name") for item in normalized):
            logger.warning(
                "GET /api/v2/infrastructure/publishers returned %d item(s), but none had "
                "a recognizable id/name field (checked id/publisher_id/pub_id and "
                "name/publisher_name/pub_name/common_name). Raw first item: %s\n"
                "Re-run with --debug to see the full raw response, and share it so the "
                "field mapping in netskope_client.py can be corrected.",
                len(raw), json.dumps(raw[0])[:800] if raw else "{}",
            )
        return normalized

    # -- private apps ------------------------------------------------------
    def list_private_apps(self) -> list[dict]:
        """
        Confirmed against a real tenant: the LIST endpoint's items only
        have `app_id` (no plain `id` at all, unlike the CREATE response
        which conveniently includes both) -- normalized onto `id` the same
        way rules/publishers/groups are. Also confirmed: `app_name`/`name`
        come back wrapped in brackets ("[Corp-Intranet]"), so `app_name` is
        overwritten here with the stripped version (see _strip_brackets)
        so every caller -- conflict checking, verification, name lookups --
        compares against a plan's plain name correctly. Before this fix,
        BOTH id-based and name-based matching against this endpoint's
        results silently failed for every app: a real, successfully
        created app was reported "not found" by post-apply verification,
        and (more seriously) a real pre-existing app with a colliding name
        could have been missed entirely by the pre-flight conflict check.
        """
        data = self._request("GET", "/api/v2/steering/apps/private")
        raw = _extract_list(data, "private_apps")

        normalized = []
        for a in raw:
            item = dict(a)
            item["id"] = _first(a, "id", "app_id", "appId")
            raw_name = _first(a, "app_name", "name")
            if raw_name:
                item["app_name"] = _strip_brackets(raw_name)
            normalized.append(item)
        return normalized

    def find_private_app_by_name(self, app_name: str) -> dict | None:
        if self.dry_run:
            return None
        for app in self.list_private_apps():
            if app.get("app_name") == app_name:
                return app
        return None

    def create_private_app(self, payload: dict) -> dict:
        return self._request("POST", "/api/v2/steering/apps/private", payload)

    def delete_private_app(self, private_app_id: str) -> dict:
        return self._request("DELETE", f"/api/v2/steering/apps/private/{private_app_id}")

    # -- NPA real-time policies ---------------------------------------------
    def list_npa_policies(self) -> list[dict]:
        data = self._request("GET", "/api/v2/policy/npa/rules")
        raw = _extract_list(data, "rules")
        # Confirmed against a real tenant: the id field on a rule object is
        # "rule_id" (a string, e.g. "67"), not "id". Normalizing it the same
        # tolerant way as publishers/policy groups so id-based matching in
        # validation.py/runlog.py works instead of silently finding nothing.
        normalized = []
        for r in raw:
            item = dict(r)
            item["id"] = _first(r, "id", "rule_id", "ruleId")
            normalized.append(item)
        return normalized

    def create_npa_policy(self, payload: dict) -> dict:
        return self._request("POST", "/api/v2/policy/npa/rules", payload)

    def delete_npa_policy(self, rule_id: str) -> dict:
        return self._request("DELETE", f"/api/v2/policy/npa/rules/{rule_id}")

    # -- NPA policy groups ----------------------------------------------------
    def list_npa_policy_groups(self) -> list[dict]:
        data = self._request("GET", "/api/v2/policy/npa/policygroups")
        raw = _extract_list(data, "groups")

        normalized = []
        for g in raw:
            item = dict(g)
            item["id"] = _first(g, "id", "group_id", "groupId")
            item["name"] = _first(g, "name", "group_name", "groupName")
            normalized.append(item)

        if raw and not any(item.get("id") and item.get("name") for item in normalized):
            logger.warning(
                "GET /api/v2/policy/npa/policygroups returned %d item(s), but none had a "
                "recognizable id/name field. Raw first item: %s\nRe-run with --debug to see "
                "the full raw response.",
                len(raw), json.dumps(raw[0])[:800] if raw else "{}",
            )
        return normalized

    def create_npa_policy_group(self, payload: dict) -> dict:
        """
        NOT CALLED ANYWHERE in this tool by design. resolve_policy_group()
        in main.py only ever looks up an EXISTING NPA Policy Group by name
        and fails cleanly if it isn't found -- it never creates one. This
        method is kept only as a documented, ready-to-use building block in
        case that restriction is ever lifted; it is not part of any current
        code path and has no test coverage exercising it as "live" behavior.

        Confirmed schema for this endpoint (from the tenant's own Swagger
        "Example Value" for POST /api/v2/policy/npa/policygroups), for
        reference if this is ever wired back up:

            {
              "group_name": "string",
              "group_order": {
                "group_order": {"group_id": "1", "order": "before"}
              },
              "modify_by": "string",
              "modify_type": "string"
            }

        `modify_by`/`modify_type` are audit/echo fields (mirroring the ones
        on rule objects, clearly server-set from the authenticated token
        and action taken, never something a client supplies on create).
        `group_order` positions a group before/after another by id --
        optional positioning info, not required just to create a group.
        """
        return self._request("POST", "/api/v2/policy/npa/policygroups", payload)

    def delete_npa_policy_group(self, group_id: str) -> dict:
        return self._request("DELETE", f"/api/v2/policy/npa/policygroups/{group_id}")

    # -- User / IdP groups -----------------------------------------------------
    def list_user_groups(self) -> list[dict]:
        """
        Pulls the tenant's known user/IdP groups (synced in via SSO/SCIM), used
        to check whether an Ivanti role name matches a real group before an NPA
        policy is scoped to it.

        NOTE: this endpoint has been CONFIRMED WRONG against a real tenant --
        GET /api/v2/scim/groups returns HTTP 404, {"message": "no Route
        matched with those values"}. It's kept as a best-effort pre-flight
        check (Netskope's public v2 REST API doesn't clearly document a real
        "list groups" endpoint the way it does for Publishers/Private
        Apps/Policies), but don't expect it to work. The caller (main.py's
        group-existence check) already treats any failure here as "can't
        verify" rather than "doesn't exist" and does NOT strip userGroups
        from every policy just because this lookup failed.

        This is NOT the only safety net, and on the tenant this was tested
        against, it's not even the one that actually catches an invalid
        group: the tenant's own policy-create validation rejects an unknown
        userGroups value with a 200 + {"status": "error", "message":
        "Invalid values from users, userGroups or organization_units:{...}"}
        body. main.py's policy-creation loop catches that specific message
        and retries the create without a userGroups restriction instead of
        failing the run -- so an unmatched Ivanti role name still degrades
        gracefully even when this pre-flight lookup can't run at all. Pass
        --skip-group-check to skip this pre-flight attempt entirely (saves
        one guaranteed-to-404 request on a tenant like the one this was
        tested against) without losing that reactive fallback.
        """
        data = self._request("GET", "/api/v2/scim/groups")
        raw = _extract_list(data, "groups")

        normalized = []
        for g in raw:
            item = dict(g)
            item["id"] = _first(g, "id", "group_id", "groupId")
            item["name"] = _first(g, "name", "group_name", "groupName", "displayName")
            normalized.append(item)

        if raw and not any(item.get("name") for item in normalized):
            logger.warning(
                "GET /api/v2/scim/groups returned %d item(s), but none had a "
                "recognizable name field. Raw first item: %s\nRe-run with --debug "
                "to see the full raw response — this endpoint's shape is unverified.",
                len(raw), json.dumps(raw[0])[:800] if raw else "{}",
            )
        return normalized
