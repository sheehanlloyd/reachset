"""Config loading and SARIF shaping for policy-as-code invariants — the pure
parts of src/reachset/analysis/invariants.py. Evaluation against real reach
data is covered in tests/integration/test_invariants.py."""

import uuid
from pathlib import Path

import pytest

from reachset.analysis.invariants import (
    InvariantConfigError,
    MaxAppsPerPrincipalRule,
    VendorCapabilitySensitivityRule,
    Violation,
    load_rules,
    to_sarif,
)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.toml"
    path.write_text(text)
    return path


def test_loads_both_rule_kinds(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [[rule]]
        id = "no-ai-read"
        description = "no AI vendor reads sensitive data"
        kind = "vendor_capability_sensitivity"
        principal_patterns = ["*openai*"]
        capability = "read"
        min_sensitivity = 2

        [[rule]]
        id = "app-sprawl"
        description = "NHIs stay within 2 apps"
        kind = "max_apps_per_principal"
        principal_kinds = ["service", "agent"]
        max_apps = 2
        severity = "warning"
        """,
    )
    rules = load_rules(path)
    assert len(rules) == 2
    assert isinstance(rules[0], VendorCapabilitySensitivityRule)
    assert rules[0].severity == "error"  # default
    assert isinstance(rules[1], MaxAppsPerPrincipalRule)
    assert rules[1].severity == "warning"


def test_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InvariantConfigError, match="cannot read config"):
        load_rules(tmp_path / "nonexistent.toml")


def test_rejects_invalid_toml(tmp_path: Path) -> None:
    path = _write(tmp_path, "not [valid toml")
    with pytest.raises(InvariantConfigError, match="invalid TOML"):
        load_rules(path)


def test_rejects_empty_rule_list(tmp_path: Path) -> None:
    path = _write(tmp_path, "rule = []\n")
    with pytest.raises(InvariantConfigError, match="non-empty"):
        load_rules(path)


def test_rejects_missing_rule_key(tmp_path: Path) -> None:
    path = _write(tmp_path, "other = 1\n")
    with pytest.raises(InvariantConfigError, match="non-empty"):
        load_rules(path)


def test_rejects_unknown_kind(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [[rule]]
        id = "x"
        description = "y"
        kind = "made_up_kind"
        """,
    )
    with pytest.raises(InvariantConfigError, match="unknown kind"):
        load_rules(path)


def test_rejects_missing_required_field(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [[rule]]
        id = "x"
        description = "y"
        kind = "vendor_capability_sensitivity"
        principal_patterns = ["*foo*"]
        capability = "read"
        """,
    )
    with pytest.raises(InvariantConfigError, match="min_sensitivity"):
        load_rules(path)


def test_rejects_unknown_capability(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [[rule]]
        id = "x"
        description = "y"
        kind = "vendor_capability_sensitivity"
        principal_patterns = ["*foo*"]
        capability = "transmute"
        min_sensitivity = 1
        """,
    )
    with pytest.raises(InvariantConfigError, match="unknown capability"):
        load_rules(path)


def test_rejects_unknown_principal_kind(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [[rule]]
        id = "x"
        description = "y"
        kind = "max_apps_per_principal"
        principal_kinds = ["robot"]
        max_apps = 1
        """,
    )
    with pytest.raises(InvariantConfigError, match="unknown principal_kinds"):
        load_rules(path)


def test_rejects_bad_severity(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [[rule]]
        id = "x"
        description = "y"
        kind = "max_apps_per_principal"
        principal_kinds = ["service"]
        max_apps = 1
        severity = "critical"
        """,
    )
    with pytest.raises(InvariantConfigError, match="severity"):
        load_rules(path)


def test_rejects_non_table_rule_entries(tmp_path: Path) -> None:
    path = _write(tmp_path, "rule = [1, 2]\n")
    with pytest.raises(InvariantConfigError, match="must be tables"):
        load_rules(path)


def test_to_sarif_shape() -> None:
    rule = MaxAppsPerPrincipalRule(
        id="app-sprawl",
        description="NHIs stay within 2 apps",
        principal_kinds=("service",),
        max_apps=2,
        severity="warning",
    )
    violation = Violation(
        rule_id="app-sprawl",
        description=rule.description,
        severity="warning",
        principal_id=uuid.uuid4(),
        external_id="svc-1",
        display_name=None,
        detail="svc-1 (service) reaches 3 apps, over the limit of 2",
    )
    report = to_sarif([violation], [rule], "examples/invariants.toml")
    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "reachset"
    assert run["tool"]["driver"]["rules"][0]["id"] == "app-sprawl"
    result = run["results"][0]
    assert result["ruleId"] == "app-sprawl"
    assert result["level"] == "warning"
    assert "svc-1" in result["message"]["text"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "examples/invariants.toml"
    )


def test_to_sarif_with_no_violations_still_lists_rules() -> None:
    rule = VendorCapabilitySensitivityRule(
        id="x",
        description="y",
        principal_patterns=("*ai*",),
        capability="read",
        min_sensitivity=1,
    )
    report = to_sarif([], [rule], "examples/invariants.toml")
    assert report["runs"][0]["results"] == []
    assert report["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "x"
