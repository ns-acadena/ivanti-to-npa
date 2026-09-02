"""Ad-hoc verification of the auth modes. Not part of the shipped tool."""
from unittest.mock import patch, MagicMock

from netskope_client import NetskopeClient, OAuthTokenProvider


def test_default_api_token_header():
    c = NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok123", dry_run=False)
    assert c._session.headers.get("Netskope-Api-Token") == "tok123"
    assert "Authorization" not in c._session.headers
    print("PASS: default mode sets Netskope-Api-Token header")


def test_bearer_mode_header():
    c = NetskopeClient(tenant_url="https://x.goskope.com", api_token="tok123", auth_mode="bearer", dry_run=False)
    assert c._session.headers.get("Authorization") == "Bearer tok123"
    assert "Netskope-Api-Token" not in c._session.headers
    print("PASS: --auth-mode bearer sends Authorization: Bearer <token>")


def test_dry_run_touches_no_network_even_with_oauth():
    provider = OAuthTokenProvider(token_url="https://auth.example.com/token", client_id="id", client_secret="secret")
    with patch("netskope_client.requests.post") as mock_post:
        c = NetskopeClient(tenant_url="https://x.goskope.com", oauth_provider=provider, dry_run=True)
        mock_post.assert_not_called()
    assert "Authorization" not in c._session.headers
    print("PASS: dry_run never fetches an OAuth token at construction time")


def test_oauth_token_fetched_and_cached():
    provider = OAuthTokenProvider(token_url="https://auth.example.com/token", client_id="id", client_secret="secret")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"access_token": "abc.def.ghi", "expires_in": 3600}
    with patch("netskope_client.requests.post", return_value=fake_resp) as mock_post:
        token1 = provider.get_token()
        token2 = provider.get_token()  # should be cached, no second call
        assert mock_post.call_count == 1
    assert token1 == token2 == "abc.def.ghi"
    print("PASS: OAuth token is fetched once and cached for subsequent calls")


def test_oauth_force_refresh():
    provider = OAuthTokenProvider(token_url="https://auth.example.com/token", client_id="id", client_secret="secret")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"access_token": "tok-1", "expires_in": 3600}
    with patch("netskope_client.requests.post", return_value=fake_resp) as mock_post:
        provider.get_token()
        provider.get_token(force_refresh=True)
        assert mock_post.call_count == 2
    print("PASS: force_refresh always re-fetches")


def test_client_construction_with_oauth_sets_bearer_header_on_real_use():
    provider = OAuthTokenProvider(token_url="https://auth.example.com/token", client_id="id", client_secret="secret")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"access_token": "tok-xyz", "expires_in": 3600}
    with patch("netskope_client.requests.post", return_value=fake_resp):
        c = NetskopeClient(tenant_url="https://x.goskope.com", oauth_provider=provider, dry_run=False)
    assert c._session.headers.get("Authorization") == "Bearer tok-xyz"
    print("PASS: constructing a non-dry-run client with an oauth_provider fetches a token and sets the bearer header")


def test_401_triggers_one_oauth_refresh_and_retry():
    provider = OAuthTokenProvider(token_url="https://auth.example.com/token", client_id="id", client_secret="secret")
    token_resp = MagicMock(status_code=200)
    token_resp.json.side_effect = [
        {"access_token": "tok-old", "expires_in": 3600},
        {"access_token": "tok-new", "expires_in": 3600},
    ]
    with patch("netskope_client.requests.post", return_value=token_resp):
        c = NetskopeClient(tenant_url="https://x.goskope.com", oauth_provider=provider, dry_run=False)

    unauthorized = MagicMock(status_code=401, content=b"{}", text="unauthorized")
    ok = MagicMock(status_code=200, content=b'{"ok": true}', text="{}")
    ok.json.return_value = {"ok": True}

    with patch("netskope_client.requests.post", return_value=token_resp):
        with patch.object(c._session, "request", side_effect=[unauthorized, ok]) as mock_req:
            result = c._request("GET", "/api/v2/steering/apps/private")
    assert result == {"ok": True}
    assert mock_req.call_count == 2
    assert c._session.headers.get("Authorization") == "Bearer tok-new"
    print("PASS: a 401 triggers exactly one token refresh + retry, and succeeds")


if __name__ == "__main__":
    test_default_api_token_header()
    test_bearer_mode_header()
    test_dry_run_touches_no_network_even_with_oauth()
    test_oauth_token_fetched_and_cached()
    test_oauth_force_refresh()
    test_client_construction_with_oauth_sets_bearer_header_on_real_use()
    test_401_triggers_one_oauth_refresh_and_retry()
    print("\nALL AUTH CHECKS PASSED")
