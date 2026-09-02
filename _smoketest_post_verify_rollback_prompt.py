"""
Verify that apply_plan() ALWAYS offers a rollback-or-keep choice right
after post-apply verification runs -- whether verification fully confirmed
everything or found gaps -- not just when a create call itself fails.
Before this, a verification FAILURE (create reported success, but a
follow-up pull didn't find the object) logged an error and exited with no
way to roll back interactively in that same run; only a create-time
exception (handle_failure()) offered rollback. Not part of the shipped
tool.
"""
import argparse
from unittest.mock import patch

from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan
import main as main_mod


class FakeClient:
    def __init__(self, hide_from_list=None):
        self._apps = {}
        self._policies = {}
        self._groups = {"ivanti-import": {"id": "700", "name": "ivanti-import"}}
        self._next_id = 9000
        self.deleted_apps = []
        self.deleted_policies = []
        # Names that exist (were "created") but are deliberately left out of
        # list_private_apps()/list_npa_policies() results, simulating a real
        # create-succeeded-but-verification-can't-find-it gap.
        self._hide_from_list = set(hide_from_list or [])

    def list_private_apps(self):
        return [v for k, v in self._apps.items() if k not in self._hide_from_list]

    def list_npa_policies(self):
        return [v for k, v in self._policies.items() if k not in self._hide_from_list]

    def list_private_app_tags(self):
        return []

    def list_publishers(self):
        return []

    def list_npa_policy_groups(self):
        return list(self._groups.values())

    def list_user_groups(self):
        return []

    def create_private_app(self, payload):
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._apps[payload["app_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def create_npa_policy(self, payload):
        self._next_id += 1
        rec = dict(payload, id=str(self._next_id))
        self._policies[payload["rule_name"]] = rec
        return {"data": {"id": str(self._next_id)}}

    def delete_private_app(self, app_id):
        self.deleted_apps.append(app_id)
        for name, rec in list(self._apps.items()):
            if rec["id"] == app_id:
                del self._apps[name]

    def delete_npa_policy(self, rule_id):
        self.deleted_policies.append(rule_id)
        for name, rec in list(self._policies.items()):
            if rec["id"] == rule_id:
                del self._policies[name]

    # Deliberately NO create_npa_policy_group() -- this tool never creates one.


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")


def _base_args(**overrides):
    base = dict(
        tenant_url="https://fake.goskope.com", api_token="tok", auth_mode="api-token",
        oauth_token_url=None, oauth_client_id=None, oauth_client_secret=None, oauth_scope=None,
        skip_policies=False, skip_conflicts=False, snapshot_dir="/tmp/_postverify_snap",
        run_log_dir="/tmp/_postverify_runlogs", yes=False, auto_rollback_on_failure=False,
        no_rollback_prompt=True, skip_verification=False,
        verify_retries=1, verify_delay=0, config="sample_ivanti_config.xml",
        policy_group_name="ivanti-import", no_policy_group=False, tag="ivanti-import",
        skip_group_check=True,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _run(args, fake):
    orig = main_mod.build_netskope_client
    main_mod.build_netskope_client = lambda a: fake
    try:
        return main_mod.apply_plan(args, build_plan())
    finally:
        main_mod.build_netskope_client = orig


def test_yes_flag_skips_prompt_when_verification_succeeds():
    # input() is never patched here -- if the code path reached it anyway,
    # this test would hang/error, proving --yes truly skips the prompt.
    fake = FakeClient()
    rc = _run(_base_args(yes=True), fake)
    assert rc == 0
    assert fake.deleted_apps == [] and fake.deleted_policies == [], "nothing should be rolled back with --yes and clean verification"
    print("PASS: --yes skips the prompt entirely when verification succeeds, exits 0, nothing rolled back")


def test_yes_flag_skips_prompt_when_verification_fails():
    fake = FakeClient(hide_from_list={"Corp-Intranet"})
    rc = _run(_base_args(yes=True), fake)
    assert rc == 1, "verification genuinely failed -- --yes should still report that via exit code"
    assert fake.deleted_apps == [] and fake.deleted_policies == [], "--yes means keep, not silently roll back"
    print("PASS: --yes skips the prompt when verification fails too, exits 1, nothing rolled back")


def test_interactive_choice_to_roll_back_after_clean_verification():
    fake = FakeClient()
    with patch("builtins.input", return_value="y"):
        rc = _run(_base_args(), fake)
    assert rc == 0, "a deliberate, successful rollback is not a failure"
    assert fake._apps == {} and fake._policies == {}, "everything created this run should now be gone"
    assert len(fake.deleted_apps) == 9, "all 9 apps (5 resource-profile + 4 network-connect-acl derived) should be deleted"
    print("PASS: choosing 'y' after a CLEAN verification still offers and performs a full rollback")


def test_interactive_choice_to_keep_after_clean_verification():
    # side_effect, not return_value: the FIRST input() call is the
    # pre-create "About to create N app(s)... Continue? [y/N]" confirmation
    # (must be "y" to proceed at all); the SECOND is the new post-
    # verification rollback-or-keep prompt this test is actually about.
    fake = FakeClient()
    with patch("builtins.input", side_effect=["y", ""]):
        rc = _run(_base_args(), fake)
    assert rc == 0
    assert fake.deleted_apps == [] and fake.deleted_policies == []
    assert len(fake._apps) == 9, "everything created should remain since the operator chose to keep it"
    print("PASS: choosing Enter (keep) after a clean verification exits 0 with everything left in place")


def test_interactive_choice_to_keep_after_failed_verification():
    fake = FakeClient(hide_from_list={"Corp-Intranet"})
    with patch("builtins.input", side_effect=["y", ""]) as mock_input:
        rc = _run(_base_args(), fake)
    assert mock_input.called, "the prompt must still appear even though verification failed"
    assert rc == 1, "verification genuinely failed -- keeping doesn't launder that into a success exit code"
    assert fake.deleted_apps == [] and fake.deleted_policies == []
    print("PASS: the prompt appears after a FAILED verification too; choosing to keep still reports failure via exit code")


def test_interactive_choice_to_roll_back_after_failed_verification():
    fake = FakeClient(hide_from_list={"Corp-Intranet"})
    with patch("builtins.input", return_value="y"):
        rc = _run(_base_args(), fake)
    assert rc == 0, "the rollback itself succeeded, even though the run that preceded it had a verification gap"
    assert fake._apps == {} and fake._policies == {}, "rolling back after a failed verification should still remove everything recorded"
    print("PASS: choosing 'y' after a FAILED verification rolls back everything the run log recorded")


if __name__ == "__main__":
    test_yes_flag_skips_prompt_when_verification_succeeds()
    test_yes_flag_skips_prompt_when_verification_fails()
    test_interactive_choice_to_roll_back_after_clean_verification()
    test_interactive_choice_to_keep_after_clean_verification()
    test_interactive_choice_to_keep_after_failed_verification()
    test_interactive_choice_to_roll_back_after_failed_verification()
    print("\nALL POST-VERIFICATION ROLLBACK-OR-EXIT PROMPT CHECKS PASSED")
