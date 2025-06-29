"""Unit tests for config parser module."""

import os
import sys
import tempfile

import pytest
import yaml

from src.core.config_parser import export_env_vars, load_config, validate_config

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))


class TestConfigParser:
    """Test class for configuration parser functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.sample_config = {
            "tools": {
                "bandit": {"enabled": True, "confidence": "high", "severity": "medium"},
                "semgrep": {
                    "enabled": True,
                    "rulesets": ["auto", "security", "owasp-top-ten"],
                },
                "checkov": {"enabled": False},
            },
            "filters": {
                "severity_threshold": "high",
                "exclude_paths": ["*/node_modules/*", "*/test/*"],
            },
            "github": {
                "pr_comments": {"enabled": True, "mode": "review", "format": "sarif"},
                "sarif_upload": {"enabled": True, "category": "comprehensive-scan"},
            },
        }

    def test_load_config_valid_yaml(self):
        """Test loading valid YAML configuration."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(self.sample_config, f)
            config_file = f.name

        try:
            config = load_config(config_file)
            assert config == self.sample_config
        finally:
            os.unlink(config_file)

    def test_load_config_nonexistent_file(self):
        """Test loading non-existent configuration file."""
        config = load_config("/nonexistent/file.yml")
        assert config == {}

    def test_load_config_invalid_yaml(self):
        """Test loading invalid YAML configuration."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            config_file = f.name

        try:
            config = load_config(config_file)
            assert config == {}
        finally:
            os.unlink(config_file)

    def test_validate_config_valid(self):
        """Test validating valid configuration."""
        is_valid, errors = validate_config(self.sample_config)
        assert is_valid
        assert len(errors) == 0

    def test_validate_config_invalid_structure(self):
        """Test validating configuration with invalid structure."""
        invalid_config = {
            "tools": "not_a_dict",
            "filters": {"severity_threshold": "invalid_severity"},
        }

        is_valid, errors = validate_config(invalid_config)
        assert not is_valid
        assert len(errors) > 0
        assert any("Tools section" in error for error in errors)
        assert any("severity_threshold" in error for error in errors)

    def test_validate_config_missing_required_fields(self):
        """Test validating configuration with missing fields."""
        minimal_config = {
            "tools": {
                "bandit": {
                    "enabled": True
                    # Missing other expected fields
                }
            }
        }

        is_valid, errors = validate_config(minimal_config)
        # Should still be valid as most fields are optional
        assert is_valid

    def test_validate_config_invalid_severity_threshold(self):
        """Test validating configuration with invalid severity threshold."""
        invalid_config = {"filters": {"severity_threshold": "invalid"}}

        is_valid, errors = validate_config(invalid_config)
        assert not is_valid
        assert any("severity_threshold" in error for error in errors)

    def test_validate_config_invalid_pr_comment_mode(self):
        """Test validating configuration with invalid PR comment mode."""
        invalid_config = {"github": {"pr_comments": {"mode": "invalid_mode"}}}

        is_valid, errors = validate_config(invalid_config)
        assert not is_valid
        assert any("mode" in error for error in errors)

    def test_export_env_vars_complete(self):
        """Test exporting environment variables from complete config."""
        env_vars = export_env_vars(self.sample_config)

        # Check that environment variables are properly set
        expected_vars = {
            "ASH_CONFIG_SEVERITY_THRESHOLD": "high",
            "ASH_CONFIG_PR_COMMENTS_MODE": "review",
            "ASH_CONFIG_PR_COMMENTS_FORMAT": "sarif",
            "ASH_CONFIG_SARIF_CATEGORY": "comprehensive-scan",
            "ASH_CONFIG_BANDIT_ENABLED": "true",
            "ASH_CONFIG_BANDIT_CONFIDENCE": "high",
            "ASH_CONFIG_BANDIT_SEVERITY": "medium",
            "ASH_CONFIG_SEMGREP_ENABLED": "true",
            "ASH_CONFIG_CHECKOV_ENABLED": "false",
        }

        for var, value in expected_vars.items():
            assert var in env_vars
            assert env_vars[var] == value

    def test_export_env_vars_empty_config(self):
        """Test exporting environment variables from empty config."""
        env_vars = export_env_vars({})
        assert env_vars == {}

    def test_export_env_vars_partial_config(self):
        """Test exporting environment variables from partial config."""
        partial_config = {"filters": {"severity_threshold": "medium"}}

        env_vars = export_env_vars(partial_config)

        assert "ASH_CONFIG_SEVERITY_THRESHOLD" in env_vars
        assert env_vars["ASH_CONFIG_SEVERITY_THRESHOLD"] == "medium"
        assert len(env_vars) == 1

    def test_export_env_vars_list_handling(self):
        """Test that list values are properly handled in env vars."""
        config_with_lists = {
            "tools": {"semgrep": {"rulesets": ["auto", "security", "owasp-top-ten"]}},
            "filters": {"exclude_paths": ["*/node_modules/*", "*/test/*"]},
        }

        env_vars = export_env_vars(config_with_lists)

        # Lists should be converted to comma-separated strings
        assert "ASH_CONFIG_SEMGREP_RULESETS" in env_vars
        assert env_vars["ASH_CONFIG_SEMGREP_RULESETS"] == "auto,security,owasp-top-ten"

        assert "ASH_CONFIG_EXCLUDE_PATHS" in env_vars
        assert env_vars["ASH_CONFIG_EXCLUDE_PATHS"] == "*/node_modules/*,*/test/*"

    def test_config_override_precedence(self):
        """Test that configuration values override action inputs properly."""
        # This would be tested in integration tests or through environment variable checks

    @pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
    def test_valid_severity_thresholds(self, severity):
        """Test that all valid severity thresholds are accepted."""
        config = {"filters": {"severity_threshold": severity}}

        is_valid, errors = validate_config(config)
        assert is_valid
        assert len(errors) == 0

    @pytest.mark.parametrize("mode", ["review", "individual"])
    def test_valid_pr_comment_modes(self, mode):
        """Test that all valid PR comment modes are accepted."""
        config = {"github": {"pr_comments": {"mode": mode}}}

        is_valid, errors = validate_config(config)
        assert is_valid
        assert len(errors) == 0

    @pytest.mark.parametrize("format_type", ["sarif", "legacy"])
    def test_valid_pr_comment_formats(self, format_type):
        """Test that all valid PR comment formats are accepted."""
        config = {"github": {"pr_comments": {"format": format_type}}}

        is_valid, errors = validate_config(config)
        assert is_valid
        assert len(errors) == 0
