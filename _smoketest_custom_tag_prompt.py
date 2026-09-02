"""Verify resolve_tag(): --tag is used as-is when given; otherwise prompts
interactively for a custom tag (Enter accepts the default), and falls back
to the default silently when there's no terminal to prompt on. Not part of
the shipped tool."""
import argparse
from unittest.mock import patch

import main as main_mod


def _args(tag=None):
    return argparse.Namespace(tag=tag)


def test_explicit_tag_is_used_as_is_no_prompt():
    with patch("main._prompt_visible") as mock_prompt:
        result = main_mod.resolve_tag(_args(tag="my-custom-tag"))
    assert result == "my-custom-tag"
    mock_prompt.assert_not_called()
    print("PASS: an explicit --tag is used as-is and never prompts")


def test_omitted_tag_prompts_and_uses_typed_value():
    with patch("main._prompt_visible", return_value="custom-from-prompt") as mock_prompt:
        result = main_mod.resolve_tag(_args(tag=None))
    assert result == "custom-from-prompt"
    mock_prompt.assert_called_once()
    print("PASS: an omitted --tag prompts interactively and uses the typed value")


def test_empty_enter_at_prompt_falls_back_to_default():
    with patch("main._prompt_visible", return_value=None):  # Enter pressed / empty input
        result = main_mod.resolve_tag(_args(tag=None))
    assert result == "ivanti-import"
    print("PASS: pressing Enter (empty input) at the prompt accepts the default 'ivanti-import'")


def test_no_terminal_falls_back_to_default_without_hanging():
    # _prompt_visible itself returns None immediately when stdin isn't a
    # tty (see its own no-tty test coverage) -- resolve_tag must treat that
    # the same as "Enter was pressed", not as an error.
    with patch("main._prompt_visible", return_value=None) as mock_prompt:
        result = main_mod.resolve_tag(_args(tag=None))
    assert result == "ivanti-import"
    mock_prompt.assert_called_once()
    print("PASS: no terminal to prompt on falls back to the default instead of hanging or erroring")


if __name__ == "__main__":
    test_explicit_tag_is_used_as_is_no_prompt()
    test_omitted_tag_prompts_and_uses_typed_value()
    test_empty_enter_at_prompt_falls_back_to_default()
    test_no_terminal_falls_back_to_default_without_hanging()
    print("\nALL CUSTOM TAG PROMPT CHECKS PASSED")
