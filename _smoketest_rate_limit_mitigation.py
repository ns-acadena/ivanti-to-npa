"""
Verify the two rate-limit mitigations added to netskope_client.py:

1. A 429 response honors the server's own Retry-After header (an
   integer-seconds value, per RFC 7231) instead of always guessing with
   exponential backoff -- more accurate when the tenant tells you exactly
   how long to wait. Falls back to the old 2**attempt behavior when the
   header is absent or unparseable (e.g. an HTTP-date, which isn't
   handled).
2. Every real (non-dry-run) POST/DELETE is followed by a small fixed
   delay (write_pacing_seconds) -- proactive pacing, not just reactive
   backoff, since a bulk --apply/--rollback run fires hundreds to
   low-thousands of sequential create/delete calls with nothing else
   throttling them. GET calls are NOT paced.

Not part of the shipped tool.
"""
from unittest.mock import MagicMock, patch

from netskope_client import NetskopeClient, _retry_after_seconds


def _client(**overrides):
    kwargs = dict(tenant_url="https://x.goskope.com", api_token="tok123", dry_run=False)
    kwargs.update(overrides)
    return NetskopeClient(**kwargs)


def test_retry_after_seconds_parses_integer_header():
    resp = MagicMock(headers={"Retry-After": "7"})
    assert _retry_after_seconds(resp) == 7.0
    print("PASS: _retry_after_seconds parses a plain integer-seconds header")


def test_retry_after_seconds_missing_header_returns_none():
    resp = MagicMock(headers={})
    assert _retry_after_seconds(resp) is None
    print("PASS: no Retry-After header -> None (caller falls back to backoff)")


def test_retry_after_seconds_unparseable_value_returns_none():
    # An HTTP-date form (e.g. "Wed, 21 Oct 2026 07:28:00 GMT") is valid per
    # RFC 7231 but deliberately not handled -- falls back to backoff rather
    # than guessing at date parsing edge cases.
    resp = MagicMock(headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
    assert _retry_after_seconds(resp) is None
    print("PASS: an HTTP-date Retry-After value safely falls back to None, not a crash")


def test_retry_after_seconds_is_capped_at_60():
    resp = MagicMock(headers={"Retry-After": "3600"})
    assert _retry_after_seconds(resp) == 60.0
    print("PASS: an oversized Retry-After value is capped at 60s, not trusted blindly")


def test_429_honors_retry_after_over_exponential_backoff():
    c = _client()
    rate_limited = MagicMock(status_code=429, headers={"Retry-After": "5"})
    ok = MagicMock(status_code=200, content=b'{"ok": true}', text="{}", headers={})
    ok.json.return_value = {"ok": True}
    with patch.object(c._session, "request", side_effect=[rate_limited, ok]):
        with patch("netskope_client.time.sleep") as mock_sleep:
            result = c._request("GET", "/api/v2/steering/apps/private")
    assert result == {"ok": True}
    # First sleep call is the 429 wait; must be the header's 5s, not 2**1=2.
    assert mock_sleep.call_args_list[0].args[0] == 5.0
    print("PASS: a 429 with Retry-After sleeps for the header's value, not 2**attempt")


def test_429_falls_back_to_exponential_backoff_without_header():
    c = _client()
    rate_limited = MagicMock(status_code=429, headers={})
    ok = MagicMock(status_code=200, content=b'{"ok": true}', text="{}", headers={})
    ok.json.return_value = {"ok": True}
    with patch.object(c._session, "request", side_effect=[rate_limited, ok]):
        with patch("netskope_client.time.sleep") as mock_sleep:
            c._request("GET", "/api/v2/steering/apps/private")
    assert mock_sleep.call_args_list[0].args[0] == 2  # 2**1, unchanged existing behavior
    print("PASS: no Retry-After header -> unchanged 2**attempt exponential backoff")


def test_post_is_paced_after_success():
    c = _client(write_pacing_seconds=0.25)
    ok = MagicMock(status_code=200, content=b'{"ok": true}', text="{}", headers={})
    ok.json.return_value = {"ok": True}
    with patch.object(c._session, "request", return_value=ok):
        with patch("netskope_client.time.sleep") as mock_sleep:
            c._request("POST", "/api/v2/steering/apps/private", {"app_name": "x"})
    mock_sleep.assert_called_once_with(0.25)
    print("PASS: a successful POST sleeps for write_pacing_seconds afterward")


def test_delete_is_paced_after_success():
    c = _client(write_pacing_seconds=0.25)
    ok = MagicMock(status_code=200, content=b"", text="", headers={})
    with patch.object(c._session, "request", return_value=ok):
        with patch("netskope_client.time.sleep") as mock_sleep:
            c._request("DELETE", "/api/v2/steering/apps/private/123")
    mock_sleep.assert_called_once_with(0.25)
    print("PASS: a successful DELETE sleeps for write_pacing_seconds afterward too")


def test_get_is_not_paced():
    c = _client(write_pacing_seconds=0.25)
    ok = MagicMock(status_code=200, content=b'{"ok": true}', text="{}", headers={})
    ok.json.return_value = {"ok": True}
    with patch.object(c._session, "request", return_value=ok):
        with patch("netskope_client.time.sleep") as mock_sleep:
            c._request("GET", "/api/v2/steering/apps/private")
    mock_sleep.assert_not_called()
    print("PASS: a GET is never paced (only done in bulk per-object loops for POST/DELETE)")


def test_pacing_disabled_when_zero():
    c = _client(write_pacing_seconds=0)
    ok = MagicMock(status_code=200, content=b'{"ok": true}', text="{}", headers={})
    ok.json.return_value = {"ok": True}
    with patch.object(c._session, "request", return_value=ok):
        with patch("netskope_client.time.sleep") as mock_sleep:
            c._request("POST", "/api/v2/steering/apps/private", {"app_name": "x"})
    mock_sleep.assert_not_called()
    print("PASS: write_pacing_seconds=0 (--write-pacing-ms 0) disables pacing entirely")


def test_write_pacing_defaults_to_point_one_seconds():
    c = _client()
    assert c.write_pacing_seconds == 0.1
    print("PASS: default write_pacing_seconds is 0.1s (100ms), matching --write-pacing-ms's default")


if __name__ == "__main__":
    test_retry_after_seconds_parses_integer_header()
    test_retry_after_seconds_missing_header_returns_none()
    test_retry_after_seconds_unparseable_value_returns_none()
    test_retry_after_seconds_is_capped_at_60()
    test_429_honors_retry_after_over_exponential_backoff()
    test_429_falls_back_to_exponential_backoff_without_header()
    test_post_is_paced_after_success()
    test_delete_is_paced_after_success()
    test_get_is_not_paced()
    test_pacing_disabled_when_zero()
    test_write_pacing_defaults_to_point_one_seconds()
    print("\nALL RATE-LIMIT MITIGATION CHECKS PASSED")
