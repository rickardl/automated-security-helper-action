#!/usr/bin/env python3
"""
PR Commenter for ASH GitHub Action
Creates inline comments on pull requests for security findings
"""

import json
import os
import re
import sys
from typing import Dict, List, Optional

import requests


class GitHubPRCommenter:
    def __init__(self, github_token: str, repository: str, pr_number: int):
        self.github_token = github_token
        self.repository = repository
        self.pr_number = pr_number
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AWS-ASH-Action/1.0",
        }

    def normalize_file_path(self, file_path: str) -> str:
        """Normalize file path by removing workspace prefix"""
        # Remove leading slash and common workspace prefixes
        path = file_path.lstrip("/")

        # Remove common workspace prefixes
        workspace_prefixes = ["workspace/", "github/workspace/", "home/runner/work/"]
        for prefix in workspace_prefixes:
            if path.startswith(prefix):
                path = path[len(prefix) :]
                break

        return path.lstrip("/")

    def get_pr_files(self) -> List[Dict]:
        """Get list of files changed in the PR"""
        url = f"{self.api_base}/repos/{self.repository}/pulls/{self.pr_number}/files"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def get_file_content(self, file_path: str, commit_sha: str) -> Optional[str]:
        """Get content of a file at specific commit"""
        url = f"{self.api_base}/repos/{self.repository}/contents/{file_path}"
        params = {"ref": commit_sha}
        response = requests.get(url, headers=self.headers, params=params)

        if response.status_code == 404:
            return None
        response.raise_for_status()

        content_data = response.json()
        if content_data.get("encoding") == "base64":
            import base64

            return base64.b64decode(content_data["content"]).decode(
                "utf-8", errors="ignore"
            )
        return content_data.get("content", "")

    def calculate_diff_position(
        self, file_path: str, line_number: int, pr_files: List[Dict]
    ) -> Optional[int]:
        """Calculate the position in the diff for a given line number"""
        pr_file = next((f for f in pr_files if f["filename"] == file_path), None)
        if not pr_file or not pr_file.get("patch"):
            return None

        # Parse the patch to find the position
        patch_lines = pr_file["patch"].split("\n")
        position = 0
        current_line = 0

        for patch_line in patch_lines:
            if patch_line.startswith("@@"):
                # Parse hunk header like "@@ -1,4 +1,6 @@"
                match = re.search(r"@@ -\d+,?\d* \+(\d+),?\d* @@", patch_line)
                if match:
                    current_line = int(match.group(1)) - 1
            elif patch_line.startswith("+"):
                current_line += 1
                if current_line == line_number:
                    return position
            elif patch_line.startswith("-"):
                pass  # Deleted lines don't affect new line numbers
            elif not patch_line.startswith("\\"):
                current_line += 1
                if current_line == line_number:
                    return position

            position += 1

        return None

    def create_review_comment(
        self,
        commit_sha: str,
        file_path: str,
        line_number: int,
        message: str,
        severity: str,
        tool: str,
        pr_files: List[Dict],
    ) -> bool:
        """Create a single review comment"""
        position = self.calculate_diff_position(file_path, line_number, pr_files)
        if position is None:
            print(f"⚠️  Could not determine diff position for {file_path}:{line_number}")
            return False

        # Format the comment with security context
        comment_body = self._format_security_comment(
            message, severity, tool, line_number
        )

        url = f"{self.api_base}/repos/{self.repository}/pulls/{self.pr_number}/comments"
        data = {
            "body": comment_body,
            "commit_id": commit_sha,
            "path": file_path,
            "position": position,
        }

        response = requests.post(url, headers=self.headers, json=data)
        if response.status_code == 201:
            print(f"✅ Added comment to {file_path}:{line_number}")
            return True
        else:
            print(
                f"❌ Failed to add comment to {file_path}:{line_number}: {response.text}"
            )
            return False

    def create_review_batch(
        self, commit_sha: str, comments: List[Dict], pr_files: List[Dict]
    ) -> bool:
        """Create a batch review with multiple comments"""
        review_comments = []

        for comment in comments:
            position = self.calculate_diff_position(
                comment["file_path"], comment["line_number"], pr_files
            )
            if position is not None:
                review_comments.append(
                    {
                        "path": comment["file_path"],
                        "position": position,
                        "body": self._format_security_comment(
                            comment["message"],
                            comment["severity"],
                            comment["tool"],
                            comment["line_number"],
                        ),
                    }
                )

        if not review_comments:
            print("⚠️  No valid comments to add to review")
            return False

        # Create the review
        url = f"{self.api_base}/repos/{self.repository}/pulls/{self.pr_number}/reviews"
        data = {
            "commit_id": commit_sha,
            "body": self._format_review_summary(len(review_comments), comments),
            "event": "COMMENT",
            "comments": review_comments,
        }

        response = requests.post(url, headers=self.headers, json=data)
        if response.status_code == 200:
            print(f"✅ Created review with {len(review_comments)} security comments")
            return True
        else:
            print(f"❌ Failed to create review: {response.text}")
            return False

    def _format_security_comment(
        self, message: str, severity: str, tool: str, line_number: int
    ) -> str:
        """Format a security finding as a PR comment"""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }

        emoji = severity_emoji.get(severity.lower(), "⚠️")

        return f"""## {emoji} Security Finding - {severity.title()}

**Tool:** {tool}
**Line:** {line_number}

{message}

---
*This comment was generated by [AWS Automated Security Helper](https://github.com/rickardl/automated-security-helper-action)*"""

    def _format_review_summary(self, comment_count: int, comments: List[Dict]) -> str:
        """Format the main review summary"""
        severity_counts = {}
        tools = set()

        for comment in comments:
            severity = comment["severity"].lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            tools.add(comment["tool"])

        summary = "## 🛡️ Security Scan Results\n\n"
        summary += (
            f"Found **{comment_count}** security findings in this pull request:\n\n"
        )

        for severity, count in sorted(
            severity_counts.items(),
            key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]),
        ):
            emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "ℹ️",
            }.get(severity, "⚠️")
            summary += f"- {emoji} **{severity.title()}:** {count}\n"

        summary += f"\n**Tools:** {', '.join(sorted(tools))}\n\n"
        summary += "Please review the inline comments for detailed information about each finding.\n\n"
        summary += "*Generated by [AWS Automated Security Helper](https://github.com/rickardl/automated-security-helper-action)*"

        return summary


def parse_ash_findings(json_file_path: str, workspace_path: str) -> List[Dict]:
    """Parse ASH findings from JSON output"""
    try:
        with open(json_file_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading ASH results: {e}")
        return []

    findings = []

    # Handle different ASH output formats
    if isinstance(data, dict):
        for tool_name, tool_results in data.items():
            if isinstance(tool_results, list):
                findings.extend(
                    parse_tool_findings(tool_results, tool_name, workspace_path)
                )
            elif isinstance(tool_results, dict) and "findings" in tool_results:
                findings.extend(
                    parse_tool_findings(
                        tool_results["findings"], tool_name, workspace_path
                    )
                )
    elif isinstance(data, list):
        findings.extend(parse_tool_findings(data, "ash", workspace_path))

    return findings


def parse_tool_findings(
    tool_findings: List[Dict], tool_name: str, workspace_path: str
) -> List[Dict]:
    """Parse findings from a specific tool"""
    findings = []

    for finding in tool_findings:
        if not isinstance(finding, dict):
            continue

        # Extract file path and line number
        file_path = finding.get("file", finding.get("filename", ""))
        line_number = finding.get("line", finding.get("line_number", 1))

        # Make file path relative to workspace
        if file_path and file_path.startswith(workspace_path):
            file_path = os.path.relpath(file_path, workspace_path)

        # Skip if no valid file path
        if not file_path or file_path.startswith("/"):
            continue

        findings.append(
            {
                "file_path": file_path,
                "line_number": int(line_number) if line_number else 1,
                "message": finding.get(
                    "description", finding.get("message", "Security finding detected")
                ),
                "severity": finding.get("severity", "medium"),
                "tool": tool_name,
                "rule_id": finding.get("rule_id", finding.get("test_name", "")),
            }
        )

    return findings


def main():
    if len(sys.argv) != 8:
        print(
            "Usage: pr_commenter.py <json_file> <workspace_path> <github_token> <repository> <pr_number> <commit_sha> <mode>"
        )
        sys.exit(1)

    json_file = sys.argv[1]
    workspace_path = sys.argv[2]
    github_token = sys.argv[3]
    repository = sys.argv[4]
    pr_number = int(sys.argv[5])
    commit_sha = sys.argv[6]
    mode = sys.argv[7]

    # Parse findings from ASH output
    findings = parse_ash_findings(json_file, workspace_path)
    if not findings:
        print("No security findings to comment on")
        return

    print(f"Found {len(findings)} security findings to comment on")

    # Initialize commenter
    commenter = GitHubPRCommenter(github_token, repository, pr_number)

    try:
        # Get PR files to calculate diff positions
        pr_files = commenter.get_pr_files()

        # Filter findings to only files changed in the PR
        changed_files = {f["filename"] for f in pr_files}
        pr_findings = [f for f in findings if f["file_path"] in changed_files]

        if not pr_findings:
            print("No security findings in files changed by this PR")
            return

        print(f"Commenting on {len(pr_findings)} findings in changed files")

        if mode == "review":
            # Create a single review with all comments
            success = commenter.create_review_batch(commit_sha, pr_findings, pr_files)
        else:
            # Create individual comments
            success_count = 0
            for finding in pr_findings:
                if commenter.create_review_comment(
                    commit_sha,
                    finding["file_path"],
                    finding["line_number"],
                    finding["message"],
                    finding["severity"],
                    finding["tool"],
                    pr_files,
                ):
                    success_count += 1
            success = success_count > 0
            print(f"Successfully created {success_count}/{len(pr_findings)} comments")

        if success:
            print("✅ PR commenting completed successfully")
        else:
            print("❌ PR commenting failed")
            sys.exit(1)

    except Exception as e:
        print(f"Error during PR commenting: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
