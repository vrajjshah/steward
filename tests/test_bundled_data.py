"""The bundled fleet/tools/demo files must be reachable from an installed wheel.

Regression guard for a first-run defect: `steward analyze` and
`steward serve --demo` resolved their defaults relative to the repository root,
so after `pip install steward-agent-governance` (no clone) the CLI crashed with
a missing `data/fleet.json` and the dashboard rendered with no findings. The
wheel now carries a copy at `steward/_bundled_data/`, and resolution falls back
to it when the checkout layout is absent.
"""

from __future__ import annotations

import json
import pathlib

from steward.loaders import bundled_data_dir, load_inventory


def test_checkout_resolves_to_the_repository_data_directory() -> None:
    resolved = bundled_data_dir()
    assert resolved.is_dir()
    assert resolved.name == "data"
    assert (resolved / "fleet.json").exists()
    assert (resolved / "tools.json").exists()
    assert (resolved / "demo_results.json").exists()


def test_defaults_are_loadable_through_the_helper() -> None:
    fleet, tools = load_inventory(
        bundled_data_dir() / "fleet.json", bundled_data_dir() / "tools.json"
    )
    assert len(fleet.agents) == 30
    assert len(tools.tools) == 34


def test_cli_and_web_service_share_one_resolution_path() -> None:
    """Both entry points must agree, or one of them breaks after pip install."""

    from steward import cli
    from steward import web_service as ws

    assert cli.DEFAULT_FLEET == bundled_data_dir() / "fleet.json"
    assert cli.DEFAULT_TOOLS == bundled_data_dir() / "tools.json"
    assert ws._default_fleet_path() == bundled_data_dir() / "fleet.json"
    assert ws._default_demo_path() == bundled_data_dir() / "demo_results.json"


def test_wheel_declares_the_bundled_copies() -> None:
    """The packaging config is what makes the fallback reachable in a wheel.

    Asserting on pyproject keeps the force-include mapping from being dropped
    in a future packaging edit, which would silently reintroduce the crash for
    every `pip install` user while the source checkout stayed green.
    """

    import tomllib

    root = pathlib.Path(__file__).resolve().parent.parent
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    include = config["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert include["data/fleet.json"] == "steward/_bundled_data/fleet.json"
    assert include["data/tools.json"] == "steward/_bundled_data/tools.json"
    assert include["data/demo_results.json"] == "steward/_bundled_data/demo_results.json"


def test_cli_version_matches_pyproject() -> None:
    """`steward version` must not drift from the packaged version.

    Regression guard: the version string was hardcoded in cli.py, so 0.2.1
    shipped to PyPI reporting "Steward 0.2.0" — a bump applied to
    pyproject.toml but not to the CLI. It now reads installed metadata.
    """

    import tomllib

    from typer.testing import CliRunner

    from steward.cli import app

    root = pathlib.Path(__file__).resolve().parent.parent
    declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert declared in result.output, f"CLI reported {result.output!r}, pyproject says {declared}"


def test_bundled_demo_cache_is_the_committed_one() -> None:
    """A stale packaged copy would ship different findings than the repo."""

    demo = json.loads((bundled_data_dir() / "demo_results.json").read_text(encoding="utf-8"))
    assert len(demo["findings"]) == 10
    assert any(f["source"] == "llm_generalized" for f in demo["findings"])
