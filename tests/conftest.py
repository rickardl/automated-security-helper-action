"""Pytest configuration and shared fixtures."""

import pytest
import json
import tempfile
import os


@pytest.fixture
def sample_ash_results():
    """Sample ASH results for testing."""
    return {
        "results": {
            "bandit": {
                "findings": [
                    {
                        "filename": "src/test.py",
                        "line_number": 10,
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "issue_type": "hardcoded_password_string",
                        "issue_text": "Possible hardcoded password",
                        "line_range": [10, 10],
                        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html"
                    },
                    {
                        "filename": "src/test2.py",
                        "line_number": 15,
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "issue_type": "sql_injection",
                        "issue_text": "Possible SQL injection",
                        "line_range": [15, 15]
                    }
                ],
                "summary": {
                    "total": 2,
                    "high": 1,
                    "medium": 1,
                    "low": 0
                }
            },
            "semgrep": {
                "findings": [
                    {
                        "filename": "src/app.js",
                        "line_number": 25,
                        "severity": "CRITICAL",
                        "rule_id": "javascript.lang.security.audit.dangerous-innerHTML",
                        "message": "Detected innerHTML usage",
                        "line_range": [25, 27]
                    }
                ],
                "summary": {
                    "total": 1,
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }
        },
        "summary": {
            "total_findings": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "tools_executed": ["bandit", "semgrep"]
        }
    }


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        "tools": {
            "bandit": {
                "enabled": True,
                "confidence": "high",
                "severity": "medium"
            },
            "semgrep": {
                "enabled": True,
                "rulesets": ["auto", "security"]
            }
        },
        "filters": {
            "severity_threshold": "high",
            "exclude_paths": ["*/test/*", "*/node_modules/*"]
        },
        "github": {
            "pr_comments": {
                "enabled": True,
                "mode": "review",
                "format": "sarif"
            },
            "sarif_upload": {
                "enabled": True,
                "category": "test-scan"
            }
        }
    }


@pytest.fixture
def temp_json_file():
    """Create a temporary JSON file for testing."""
    def _create_temp_file(data):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            return f.name
    return _create_temp_file


@pytest.fixture
def temp_yaml_file():
    """Create a temporary YAML file for testing."""
    def _create_temp_file(data):
        import yaml
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(data, f)
            return f.name
    return _create_temp_file


@pytest.fixture
def cleanup_files():
    """Cleanup temporary files after tests."""
    files_to_cleanup = []

    def _add_file(filepath):
        files_to_cleanup.append(filepath)
        return filepath

    yield _add_file

    # Cleanup
    for filepath in files_to_cleanup:
        try:
            os.unlink(filepath)
        except (OSError, FileNotFoundError):
            pass


@pytest.fixture
def mock_github_env(monkeypatch):
    """Mock GitHub Actions environment variables."""
    env_vars = {
        "GITHUB_WORKSPACE": "/github/workspace",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_TOKEN": "ghp_test_token",
        "GITHUB_REF": "refs/pull/123/merge",
        "GITHUB_SHA": "abc123def456",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_OUTPUT": "/tmp/github_output"
    }

    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    return env_vars


@pytest.fixture
def sample_sarif():
    """Sample SARIF data for testing."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AWS Automated Security Helper",
                        "version": "1.0.0"
                    }
                },
                "results": [
                    {
                        "ruleId": "bandit.hardcoded_password_string",
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {
                            "text": "Possible hardcoded password"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/test.py"
                                    },
                                    "region": {
                                        "startLine": 10,
                                        "endLine": 10
                                    }
                                }
                            }
                        ]
                    }
                ],
                "rules": [
                    {
                        "id": "bandit.hardcoded_password_string",
                        "name": "hardcoded_password_string",
                        "shortDescription": {
                            "text": "Possible hardcoded password"
                        }
                    }
                ]
            }
        ]
    }
