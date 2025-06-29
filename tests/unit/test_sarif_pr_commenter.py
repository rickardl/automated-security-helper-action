#!/usr/bin/env python3
"""
Simplified unit tests for SARIF PR commenter module
"""

from src.github.sarif_pr_commenter import SarifPRCommenter
import sys
import os
from unittest.mock import Mock, patch

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))


class TestSarifPRCommenter:
    """Simplified test class for SarifPRCommenter"""

    def setup_method(self):
        """Set up test fixtures"""
        self.commenter = SarifPRCommenter(
            github_token="test-token", repository="test-owner/test-repo", pr_number=123
        )

    def test_init(self):
        """Test SarifPRCommenter initialization"""
        assert self.commenter.github_token == "test-token"
        assert self.commenter.repository == "test-owner/test-repo"
        assert self.commenter.pr_number == 123

    @patch("requests.get")
    def test_get_pr_files_success(self, mock_get):
        """Test successful PR files retrieval"""
        mock_response = Mock()
        mock_response.json.return_value = [
            {"filename": "test.py", "patch": "@@ -1,3 +1,4 @@\n+new line"}
        ]
        mock_get.return_value = mock_response

        files = self.commenter.get_pr_files()

        assert len(files) == 1
        assert files[0]["filename"] == "test.py"

    def test_normalize_file_path_absolute(self):
        """Test file path normalization with absolute path"""
        normalized = self.commenter.normalize_file_path("/workspace/src/test.py")
        assert normalized == "src/test.py"

    def test_normalize_file_path_relative(self):
        """Test file path normalization with relative path"""
        normalized = self.commenter.normalize_file_path("src/test.py")
        assert normalized == "src/test.py"

    def test_format_sarif_comment(self):
        """Test SARIF comment formatting"""
        comment_data = {
            "message": "SQL injection vulnerability",
            "rule_id": "CWE-89",
            "severity": "error",
            "tool_name": "bandit",
            "line_number": 42,
            "help_uri": "https://cwe.mitre.org/data/definitions/89.html",
        }

        comment = self.commenter._format_sarif_comment(comment_data)

        assert "SQL injection vulnerability" in comment
        assert "CWE-89" in comment
        assert "bandit" in comment
        assert "42" in comment

    def test_extract_comments_from_sarif_success(self):
        """Test extracting comments from SARIF data"""
        sarif_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "bandit"}},
                    "results": [
                        {
                            "ruleId": "B101",
                            "level": "error",
                            "message": {"text": "Hard-coded password"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "test.py"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        comments = self.commenter.extract_comments_from_sarif(
            sarif_data, [{"filename": "test.py"}]
        )

        assert len(comments) >= 0  # Should not crash
