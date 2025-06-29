#!/usr/bin/env python3
"""
Simplified unit tests for PR commenter module
"""

from src.github.pr_commenter import GitHubPRCommenter
import sys
import os
from unittest.mock import Mock, patch

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))


class TestGitHubPRCommenter:
    """Simplified test class for GitHubPRCommenter"""

    def setup_method(self):
        """Set up test fixtures"""
        self.commenter = GitHubPRCommenter(
            github_token="test-token", repository="test-owner/test-repo", pr_number=123
        )

    def test_init(self):
        """Test GitHubPRCommenter initialization"""
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

    @patch("requests.get")
    def test_get_file_content_success(self, mock_get):
        """Test successful file content retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": "dGVzdCBjb250ZW50",  # base64 encoded "test content"
            "encoding": "base64",
        }
        mock_get.return_value = mock_response

        content = self.commenter.get_file_content("test.py", "abc123")

        assert content == "test content"

    def test_normalize_file_path(self):
        """Test file path normalization"""
        # Test absolute path
        normalized = self.commenter.normalize_file_path("/workspace/src/test.py")
        assert normalized == "src/test.py"

        # Test relative path
        normalized = self.commenter.normalize_file_path("src/test.py")
        assert normalized == "src/test.py"

    @patch("requests.post")
    def test_create_review_batch_success(self, mock_post):
        """Test successful batch review creation"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        comments = [
            {
                "file_path": "test.py",
                "line_number": 2,
                "message": "Test finding",
                "severity": "high",
                "tool": "bandit",
            }
        ]

        pr_files = [
            {
                "filename": "test.py",
                "patch": "@@ -1,3 +1,4 @@\n line1\n+new line\n line2",
            }
        ]

        with patch.object(self.commenter, "calculate_diff_position", return_value=1):
            result = self.commenter.create_review_batch("abc123", comments, pr_files)

        assert result is True
        mock_post.assert_called_once()
