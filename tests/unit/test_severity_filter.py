"""Unit tests for severity filter module."""

import os
import sys

import pytest

from src.core.severity_filter import (
    count_findings_by_severity,
    filter_findings_by_severity,
)

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))


class TestSeverityFilter:
    """Test class for severity filter functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.sample_results = {
            "results": {
                "bandit": {
                    "findings": [
                        {"severity": "HIGH", "filename": "test1.py"},
                        {"severity": "MEDIUM", "filename": "test2.py"},
                        {"severity": "LOW", "filename": "test3.py"},
                    ]
                },
                "semgrep": {
                    "findings": [
                        {"severity": "CRITICAL", "filename": "test4.js"},
                        {"severity": "HIGH", "filename": "test5.js"},
                    ]
                },
            }
        }

    def test_filter_findings_by_severity_high(self):
        """Test filtering findings by high severity threshold."""
        filtered = filter_findings_by_severity(self.sample_results, "high")

        # Should include critical and high findings
        assert len(filtered["results"]["bandit"]["findings"]) == 1  # HIGH
        assert len(filtered["results"]["semgrep"]["findings"]) == 2  # CRITICAL + HIGH

        # Check specific findings
        bandit_findings = filtered["results"]["bandit"]["findings"]
        assert bandit_findings[0]["severity"] == "HIGH"

        semgrep_findings = filtered["results"]["semgrep"]["findings"]
        severities = [f["severity"] for f in semgrep_findings]
        assert "CRITICAL" in severities
        assert "HIGH" in severities

    def test_filter_findings_by_severity_medium(self):
        """Test filtering findings by medium severity threshold."""
        filtered = filter_findings_by_severity(self.sample_results, "medium")

        # Should include critical, high, and medium findings
        assert len(filtered["results"]["bandit"]["findings"]) == 2  # HIGH + MEDIUM
        assert len(filtered["results"]["semgrep"]["findings"]) == 2  # CRITICAL + HIGH

    def test_filter_findings_by_severity_low(self):
        """Test filtering findings by low severity threshold."""
        filtered = filter_findings_by_severity(self.sample_results, "low")

        # Should include all findings
        assert len(filtered["results"]["bandit"]["findings"]) == 3
        assert len(filtered["results"]["semgrep"]["findings"]) == 2

    def test_filter_findings_by_severity_critical(self):
        """Test filtering findings by critical severity threshold."""
        filtered = filter_findings_by_severity(self.sample_results, "critical")

        # Should only include critical findings
        assert len(filtered["results"]["bandit"]["findings"]) == 0
        assert len(filtered["results"]["semgrep"]["findings"]) == 1

        semgrep_findings = filtered["results"]["semgrep"]["findings"]
        assert semgrep_findings[0]["severity"] == "CRITICAL"

    def test_count_findings_by_severity(self):
        """Test counting findings by severity levels."""
        counts = count_findings_by_severity(self.sample_results)

        expected = {
            "total": 5,
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 1,
            "tools": ["bandit", "semgrep"],
        }

        assert counts == expected

    def test_count_findings_empty_results(self):
        """Test counting findings with empty results."""
        empty_results = {"results": {}}
        counts = count_findings_by_severity(empty_results)

        expected = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "tools": [],
        }

        assert counts == expected

    def test_filter_invalid_severity_threshold(self):
        """Test filtering with invalid severity threshold."""
        # Should default to medium
        filtered = filter_findings_by_severity(self.sample_results, "invalid")

        # Should behave like medium threshold
        assert len(filtered["results"]["bandit"]["findings"]) == 2
        assert len(filtered["results"]["semgrep"]["findings"]) == 2

    def test_filter_missing_results_key(self):
        """Test filtering with missing results key."""
        invalid_data = {"invalid": "data"}
        filtered = filter_findings_by_severity(invalid_data, "high")

        # Should return empty structure
        assert "results" in filtered
        assert len(filtered["results"]) == 0

    @pytest.mark.parametrize(
        "severity,expected_count",
        [
            ("critical", 1),
            ("high", 3),
            ("medium", 4),
            ("low", 5),
        ],
    )
    def test_severity_threshold_counts(self, severity, expected_count):
        """Test that severity thresholds return correct counts."""
        filtered = filter_findings_by_severity(self.sample_results, severity)

        total_findings = 0
        for tool_results in filtered["results"].values():
            if "findings" in tool_results:
                total_findings += len(tool_results["findings"])

        assert total_findings == expected_count
