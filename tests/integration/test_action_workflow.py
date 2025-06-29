"""Simplified integration tests for the action workflow."""

import os
import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))


class TestActionWorkflow:
    """Simplified integration tests for action workflow."""

    def test_severity_filtering_integration(self):
        """Test severity filtering integration."""
        from src.core.severity_filter import filter_findings_by_severity, count_findings_by_severity

        # Sample test data
        sample_data = {
            "results": {
                "bandit": {
                    "findings": [
                        {"severity": "HIGH", "filename": "test1.py"},
                        {"severity": "MEDIUM", "filename": "test2.py"}
                    ]
                },
                "semgrep": {
                    "findings": [
                        {"severity": "CRITICAL", "filename": "test3.js"}
                    ]
                }
            }
        }

        # Test filtering
        high_filtered = filter_findings_by_severity(sample_data, "high")
        counts = count_findings_by_severity(high_filtered)

        # Verify results
        assert counts["total"] == 2  # CRITICAL + HIGH
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 0

    def test_config_parser_integration(self):
        """Test configuration parser integration."""
        from src.core.config_parser import validate_config, export_env_vars

        # Sample configuration
        config = {
            "filters": {"severity_threshold": "high"},
            "github": {
                "pr_comments": {"mode": "review", "format": "sarif"}
            },
            "tools": {
                "bandit": {"enabled": True}
            }
        }

        # Test validation
        is_valid, errors = validate_config(config)
        assert is_valid
        assert len(errors) == 0

        # Test environment variable export
        env_vars = export_env_vars(config)
        assert env_vars["ASH_CONFIG_SEVERITY_THRESHOLD"] == "high"
        assert env_vars["ASH_CONFIG_PR_COMMENTS_MODE"] == "review"
        assert env_vars["ASH_CONFIG_BANDIT_ENABLED"] == "true"

    def test_action_yml_structure(self):
        """Test that action.yml has required structure."""
        action_root = Path(__file__).parent.parent.parent
        action_yml_path = action_root / "action.yml"

        if not action_yml_path.exists():
            pytest.fail("action.yml not found")

        import yaml
        with open(action_yml_path, 'r') as f:
            action_config = yaml.safe_load(f)

        # Verify required fields
        assert "name" in action_config
        assert "description" in action_config
        assert "inputs" in action_config
        assert "outputs" in action_config
        assert "runs" in action_config

        # Verify key inputs
        inputs = action_config["inputs"]
        assert "source-directory" in inputs
        assert "upload-sarif" in inputs
        assert "pr-comment" in inputs

        # Verify outputs
        outputs = action_config["outputs"]
        assert "findings-count" in outputs
        assert "sarif-path" in outputs

        # Verify runs configuration
        runs = action_config["runs"]
        assert runs["using"] == "composite"

    def test_python_imports(self):
        """Test that Python modules can be imported correctly."""
        # Test core module imports
        try:
            from src.core import severity_filter
            from src.core import config_parser
        except ImportError as e:
            pytest.fail(f"Failed to import modules: {e}")

        # Test that modules have expected functions
        assert hasattr(severity_filter, 'filter_findings_by_severity')
        assert hasattr(severity_filter, 'count_findings_by_severity')
        assert hasattr(config_parser, 'load_config')
        assert hasattr(config_parser, 'validate_config')

    def test_entrypoint_script_exists(self):
        """Test that entrypoint script exists and is readable."""
        action_root = Path(__file__).parent.parent.parent
        script_path = action_root / "scripts" / "entrypoint.sh"

        assert script_path.exists(), "entrypoint.sh not found"

        # Verify script is readable
        with open(script_path, 'r') as f:
            content = f.read()
            assert len(content) > 0
            assert "#!/bin/bash" in content
            assert "ash" in content  # Should contain ASH command

    @pytest.mark.slow
    def test_dockerfile_syntax(self):
        """Test that Dockerfile has valid syntax."""
        action_root = Path(__file__).parent.parent.parent
        dockerfile_path = action_root / "Dockerfile"

        if not dockerfile_path.exists():
            pytest.skip("Dockerfile not found")

        # Read Dockerfile and check for key elements
        with open(dockerfile_path, 'r') as f:
            content = f.read()

        # Verify key elements for the new multi-stage build
        assert "FROM" in content
        assert "python:3.12-bullseye" in content
        assert "COPY src/" in content
        assert "COPY scripts/" in content
        assert "ENTRYPOINT" in content
        assert "github-actions" in content  # Multi-stage target
