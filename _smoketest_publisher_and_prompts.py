"""Verify the publisher picker and the interactive credential prompts.
Not part of the shipped tool."""
from unittest.mock import patch

from publisher_ui import select_publishers_interactive
import main as main_mod


class FakeClient:
    def __init__(self, publishers):
        self._publishers = publishers

    def list_publishers(self):
        return self._publishers


PUBLISHERS = [
    {"id": 1, "name": "aws-publisher-1", "apps_count": 3, "lbrokerconnect": False},
    {"id": 2, "name": "aws-publisher-2", "apps_count": 0, "lbrokerconnect": False},
    {"id": 3, "name": "onprem-publisher-1", "apps_count": 5, "lbrokerconnect": True},
    {"id": 4, "name": "onprem-publisher-2", "apps_count": 1, "lbrokerconnect": False},
    {"id": 5, "name": "onprem-publisher-3", "apps_count": 1, "lbrokerconnect": False},
]


def test_select_single_publisher():
    client = FakeClient(PUBLISHERS)
    refs = select_publishers_interactive(client, max_select=4, input_func=lambda _: "1")
    assert len(refs) == 1
    assert refs[0].publisher_id == "1" and refs[0].publisher_name == "aws-publisher-1"
    print("PASS: single selection works")


def test_select_four_publishers():
    client = FakeClient(PUBLISHERS)
    refs = select_publishers_interactive(client, max_select=4, input_func=lambda _: "1,2,3,4")
    assert [r.publisher_id for r in refs] == ["1", "2", "3", "4"]
    print("PASS: selecting exactly the max (4) works")


def test_reject_more_than_max():
    client = FakeClient(PUBLISHERS)
    refs = select_publishers_interactive(client, max_select=4, input_func=lambda _: "1,2,3,4,5")
    assert refs is None
    print("PASS: selecting more than the max is rejected")


def test_reject_out_of_range():
    client = FakeClient(PUBLISHERS)
    refs = select_publishers_interactive(client, max_select=4, input_func=lambda _: "99")
    assert refs is None
    print("PASS: an out-of-range choice is rejected")


def test_reject_duplicates():
    client = FakeClient(PUBLISHERS)
    refs = select_publishers_interactive(client, max_select=4, input_func=lambda _: "1,1")
    assert refs is None
    print("PASS: duplicate selection is rejected")


def test_no_publishers_in_tenant():
    client = FakeClient([])
    refs = select_publishers_interactive(client, max_select=4, input_func=lambda _: "1")
    assert refs is None
    print("PASS: an empty publisher list is handled cleanly")


def test_tenant_url_and_token_prompted_when_missing():
    import argparse
    args = argparse.Namespace(
        tenant_url=None, api_token=None, oauth_token_url=None, oauth_client_id=None,
        oauth_client_secret=None,
    )
    with patch("main.sys.stdin.isatty", return_value=True), \
         patch("main._prompt_visible", return_value="washington.goskope.com") as mock_visible, \
         patch("main._prompt_hidden", return_value="secret-token-123") as mock_hidden:
        ok = main_mod._require_tenant_creds(args)
    assert ok
    assert args.tenant_url == "https://washington.goskope.com", args.tenant_url
    assert args.api_token == "secret-token-123"
    mock_visible.assert_called_once()
    mock_hidden.assert_called_once()
    print("PASS: missing tenant-url and api-token are both prompted for and normalized/stored")


def test_no_prompt_when_not_a_tty():
    import argparse
    args = argparse.Namespace(
        tenant_url=None, api_token=None, oauth_token_url=None, oauth_client_id=None,
        oauth_client_secret=None,
    )
    with patch("main.sys.stdin.isatty", return_value=False):
        ok = main_mod._require_tenant_creds(args)
    assert ok is False
    assert args.tenant_url is None and args.api_token is None
    print("PASS: non-interactive (no tty) contexts get a clear error instead of hanging on input()")


def test_already_supplied_values_are_not_prompted():
    import argparse
    args = argparse.Namespace(
        tenant_url="https://already-set.goskope.com", api_token="already-set-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None,
    )
    with patch("main._prompt_visible") as mock_visible, patch("main._prompt_hidden") as mock_hidden:
        ok = main_mod._require_tenant_creds(args)
    assert ok
    mock_visible.assert_not_called()
    mock_hidden.assert_not_called()
    print("PASS: already-supplied tenant-url/api-token are never overwritten or re-prompted")


def _pub_args(**overrides):
    import argparse
    base = dict(
        publisher_ids=None, default_publisher_id=None, default_publisher_name=None,
        analysis_only=False, tenant_url=None, api_token=None,
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_resolve_default_publishers_runs_picker_automatically_no_flag_needed():
    args = _pub_args(tenant_url="https://fake.goskope.com", api_token="tok")
    fake = FakeClient(PUBLISHERS)
    with patch("main._require_tenant_creds", return_value=True), \
         patch("main.build_netskope_client", return_value=fake), \
         patch("main.select_publishers_interactive", return_value=[
             __import__("mapper").PublisherRef(publisher_id="1", publisher_name="aws-publisher-1")
         ]) as mock_picker:
        refs, had_error = main_mod.resolve_default_publishers(args)
    assert not had_error
    assert refs[0].publisher_id == "1"
    mock_picker.assert_called_once()
    print("PASS: with no --publisher-ids/--default-publisher-id, the picker runs with no extra flag required")


def test_resolve_default_publishers_explicit_ids_skip_picker():
    args = _pub_args(publisher_ids="10,20")
    with patch("main.select_publishers_interactive") as mock_picker:
        refs, had_error = main_mod.resolve_default_publishers(args)
    assert not had_error
    assert [r.publisher_id for r in refs] == ["10", "20"]
    mock_picker.assert_not_called()
    print("PASS: --publisher-ids bypasses the picker entirely")


def test_resolve_default_publishers_analysis_only_never_touches_network():
    args = _pub_args(analysis_only=True)
    with patch("main._require_tenant_creds") as mock_creds, patch("main.select_publishers_interactive") as mock_picker:
        refs, had_error = main_mod.resolve_default_publishers(args)
    assert not had_error
    assert refs[0].publisher_id == "TBD"
    mock_creds.assert_not_called()
    mock_picker.assert_not_called()
    print("PASS: --analysis-only never attempts the picker or tenant creds, always placeholder")


def test_resolve_default_publishers_falls_back_gracefully_when_not_interactive():
    args = _pub_args()  # nothing supplied at all
    with patch("main._require_tenant_creds", return_value=False):
        refs, had_error = main_mod.resolve_default_publishers(args)
    assert not had_error, "a plain dry run with no publisher flags should degrade gracefully, not hard-fail"
    assert refs[0].publisher_id == "TBD"
    print("PASS: no flags + no interactive/creds available -> placeholder + warning, no crash (dry run still works)")


def test_resolve_default_publishers_falls_back_when_picker_returns_none():
    args = _pub_args(tenant_url="https://fake.goskope.com", api_token="tok")
    with patch("main._require_tenant_creds", return_value=True), \
         patch("main.build_netskope_client", return_value=FakeClient(PUBLISHERS)), \
         patch("main.select_publishers_interactive", return_value=None):
        refs, had_error = main_mod.resolve_default_publishers(args)
    assert not had_error
    assert refs[0].publisher_id == "TBD"
    print("PASS: if the picker itself is aborted/empty, falls back to placeholder rather than erroring the whole run")


if __name__ == "__main__":
    test_select_single_publisher()
    test_select_four_publishers()
    test_reject_more_than_max()
    test_reject_out_of_range()
    test_reject_duplicates()
    test_no_publishers_in_tenant()
    test_tenant_url_and_token_prompted_when_missing()
    test_no_prompt_when_not_a_tty()
    test_already_supplied_values_are_not_prompted()
    test_resolve_default_publishers_runs_picker_automatically_no_flag_needed()
    test_resolve_default_publishers_explicit_ids_skip_picker()
    test_resolve_default_publishers_analysis_only_never_touches_network()
    test_resolve_default_publishers_falls_back_gracefully_when_not_interactive()
    test_resolve_default_publishers_falls_back_when_picker_returns_none()
    print("\nALL PUBLISHER-PICKER + PROMPT CHECKS PASSED")
