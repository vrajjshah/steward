"""Shared pytest fixtures for Steward's test suite."""

from __future__ import annotations

import re

import pytest

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_BOX_DRAWING = re.compile(r"[│╭╮╰╯─┃┏┓┗┛━┌┐└┘|]")


def normalize_cli_output(output: object) -> str:
    """Return CLI output with styling and Rich panel borders removed.

    Under ``GITHUB_ACTIONS`` (and only there), Rich renders Typer/Click errors
    in a colored, box-drawn panel and word-wraps long messages — including tmp
    paths — to the terminal width. A wrapped phrase can then straddle the box
    border, so a substring assertion that passes locally fails in CI. Stripping
    the ANSI codes and the panel borders and collapsing whitespace makes a
    wrapped message read as one line, so substring assertions hold everywhere.

    Accepts a ``CliRunner`` result or a raw string.
    """

    text = getattr(output, "output", output)
    if not isinstance(text, str):
        text = str(text)
    text = _ANSI_ESCAPE.sub("", text)
    text = _BOX_DRAWING.sub(" ", text)
    return re.sub(r"\s+", " ", text)


@pytest.fixture
def cli_text():
    """Fixture form of :func:`normalize_cli_output` for CLI substring assertions."""

    return normalize_cli_output
