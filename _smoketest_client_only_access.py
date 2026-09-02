"""Verify every created Private App is Client-based (clientless_access is
always False) -- Browser Access is not supported by this tool, even for
Ivanti "web" profiles that would normally map to it. Not part of the
shipped tool."""
from ivanti_parser import parse_ivanti_config
from mapper import PublisherRef, build_migration_plan


def build_plan():
    cfg = parse_ivanti_config("sample_ivanti_config.xml")
    pub = PublisherRef(publisher_id="123", publisher_name="aws-publisher-1")
    return build_migration_plan(cfg, default_publishers=[pub], tag_name="ivanti-import")


def test_every_app_is_client_based():
    plan = build_plan()
    assert plan.private_apps, "no apps to check"
    for app in plan.private_apps:
        assert app.clientless_access is False, f"{app.app_name} should be Client-based, got clientless_access={app.clientless_access}"
        assert app.to_payload()["clientless_access"] is False
    print(f"PASS: all {len(plan.private_apps)} created app(s) are Client-based (clientless_access=False)")


def test_web_profile_gets_a_warning_about_forced_client_access():
    # sample_ivanti_config.xml's "Corp-Intranet" profile is type "web",
    # which PROFILE_TYPE_DEFAULTS classifies as clientless=True -- that
    # classification should now only produce a warning, never an actual
    # clientless app.
    plan = build_plan()
    corp_intranet = next(a for a in plan.private_apps if a.app_name == "Corp-Intranet")
    assert corp_intranet.clientless_access is False

    matching_warnings = [
        w for w in plan.warnings
        if "Corp-Intranet" in w and "Browser Access" in w and "Client-based" in w
    ]
    assert matching_warnings, f"expected a Browser-Access-forced-to-Client warning for Corp-Intranet, got warnings: {plan.warnings}"
    print("PASS: a 'web' profile that would normally be Browser Access gets a clear warning instead of silently becoming clientless")


def test_non_web_profiles_get_no_such_warning():
    plan = build_plan()
    ssh_bastion_warnings = [w for w in plan.warnings if "SSH-Bastion" in w and "Browser Access" in w]
    assert not ssh_bastion_warnings, "a profile that was never clientless shouldn't get the Browser-Access warning"
    print("PASS: profiles that were already Client-only don't get a spurious Browser Access warning")


if __name__ == "__main__":
    test_every_app_is_client_based()
    test_web_profile_gets_a_warning_about_forced_client_access()
    test_non_web_profiles_get_no_such_warning()
    print("\nALL CLIENT-ONLY ACCESS CHECKS PASSED")
