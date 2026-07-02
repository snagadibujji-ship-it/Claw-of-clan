"""GHIA Scout basic integration tests: verify imports and version."""

import pytest


def test_import_ghia_scout():
    """Test that the main package can be imported."""
    from pathlib import Path

    import toml

    import ghia_scout

    # Read version from pyproject.toml to avoid hardcoding
    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    pyproject = toml.load(pyproject_path)
    expected_version = pyproject["project"]["version"]

    assert ghia_scout.__version__ == expected_version


def test_all_submodules_importable():
    """Test that all major submodules can be imported."""


def test_no_import_errors():
    """Verify no module raises on import."""
    import importlib

    modules = [
        "ghia_scout",
        "ghia_scout.config.schema",
        "ghia_scout.config.settings",
        "ghia_scout.agent.context",
        "ghia_scout.agent.memory",
        "ghia_scout.agent.prompts",
        "ghia_scout.agent.core",
        "ghia_scout.mcp.registry",
        "ghia_scout.mcp.router",
        "ghia_scout.mcp.lifecycle",
        "ghia_scout.skills.loader",
        "ghia_scout.skills.dispatcher",
        "ghia_scout.kb.store",
        "ghia_scout.kb.retriever",
        "ghia_scout.kb.updater",
        "ghia_scout.report.generator",
        "ghia_scout.report.poc_builder",
        "ghia_scout.cli.main",
    ]
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
        except ImportError as e:
            pytest.fail(f"Failed to import {mod_name}: {e}")
