"""Tests for validating Falco custom rule syntax and required schema fields."""

from pathlib import Path
import pytest
import yaml

RULES_DIR = Path(__file__).parent.parent / "falco" / "rules"

VALID_PRIORITIES = {
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFORMATIONAL",
    "DEBUG",
}

REQUIRED_RULE_FIELDS = {"rule", "desc", "condition", "output", "priority", "tags"}


def get_rule_files():
    """Returns all YAML rule files in falco/rules directory."""
    files = list(RULES_DIR.glob("*.yaml")) + list(RULES_DIR.glob("*.yml"))
    return files


def test_rule_directory_exists_and_not_empty():
    """Verify rules directory exists and contains rule files."""
    rule_files = get_rule_files()
    assert len(rule_files) >= 4, f"Expected at least 4 rule files, found {len(rule_files)}"


@pytest.mark.parametrize("rule_file", get_rule_files(), ids=lambda p: p.name)
def test_falco_rule_syntax_and_schema(rule_file: Path):
    """Validates YAML structure, required fields, and valid priority for each Falco rule file."""
    with open(rule_file, "r", encoding="utf-8") as f:
        content = yaml.safe_load(f)

    assert content is not None, f"Rule file {rule_file.name} is empty"
    assert isinstance(content, list), f"Top level structure in {rule_file.name} must be a list of rules"
    assert len(content) > 0, f"No rules found in {rule_file.name}"

    for item in content:
        assert isinstance(item, dict), f"Rule item must be a dictionary in {rule_file.name}"

        # Check for required fields
        for field in REQUIRED_RULE_FIELDS:
            assert (
                field in item
            ), f"Missing required field '{field}' in rule '{item.get('rule', 'UNKNOWN')}' ({rule_file.name})"
            assert item[field], f"Field '{field}' cannot be empty in {rule_file.name}"

        # Validate priority
        priority = str(item["priority"]).upper()
        assert (
            priority in VALID_PRIORITIES
        ), f"Invalid priority '{priority}' in rule '{item['rule']}'. Must be one of {VALID_PRIORITIES}"

        # Validate tags
        tags = item["tags"]
        assert isinstance(tags, list), f"Tags must be a list in {rule_file.name}"
        assert len(tags) >= 1, f"Tags list cannot be empty in {rule_file.name}"

        # Validate string types
        assert isinstance(item["rule"], str), "Rule name must be string"
        assert isinstance(item["desc"], str), "Description must be string"
        assert isinstance(item["condition"], str), "Condition must be string"
        assert isinstance(item["output"], str), "Output must be string"
