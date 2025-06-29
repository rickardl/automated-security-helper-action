#!/usr/bin/env python3
"""
SARIF-based PR Commenter for ASH GitHub Action
Creates inline comments on pull requests using SARIF data for better formatting
Based on best practices from existing SARIF-to-comment tools
"""

import json
import sys
import requests
import re
from typing import Dict, List, Optional, Any


class SarifPRCommenter:
    def __init__(self, github_token: str, repository: str, pr_number: int):
        self.github_token = github_token
        self.repository = repository
        self.pr_number = pr_number
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AWS-ASH-Action-SARIF/1.0",
        }

    def get_pr_files(self) -> List[Dict[str, Any]]:
        """Get list of files changed in the PR"""
        url = f"{self.api_base}/repos/{self.repository}/pulls/{self.pr_number}/files"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

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

    def create_review_from_sarif(
        self,
        commit_sha: str,
        sarif_data: Dict[str, Any],
        pr_files: List[Dict],
        mode: str = "review",
    ) -> bool:
        """Create PR review comments from SARIF data"""

        # Extract comments from SARIF
        comments = self.extract_comments_from_sarif(sarif_data, pr_files)

        if not comments:
            print("No security findings in files changed by this PR")
            return True

        print(f"Found {len(comments)} security findings to comment on")

        if mode == "review":
            return self.create_review_batch(commit_sha, comments, pr_files)
        else:
            return self.create_individual_comments(commit_sha, comments, pr_files)

    def extract_comments_from_sarif(
        self, sarif_data: Dict[str, Any], pr_files: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Extract comment data from SARIF format"""
        comments = []
        changed_files = {f["filename"] for f in pr_files}

        for run in sarif_data.get("runs", []):
            tool_name = (
                run.get("tool", {}).get("driver", {}).get("name", "Security Tool")
            )
            rules = {
                rule["id"]: rule
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})

                # Extract location information
                for location in result.get("locations", []):
                    physical_location = location.get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    region = physical_location.get("region", {})

                    file_path = artifact_location.get("uri", "")
                    line_number = region.get("startLine", 1)

                    # Normalize file path
                    file_path = self.normalize_file_path(file_path)

                    # Only comment on changed files
                    if file_path not in changed_files:
                        continue

                    comment = {
                        "file_path": file_path,
                        "line_number": line_number,
                        "rule_id": rule_id,
                        "message": result.get("message", {}).get(
                            "text", "Security finding detected"
                        ),
                        "level": result.get("level", "warning"),
                        "tool_name": tool_name,
                        "rule": rule,
                        "security_severity": result.get("properties", {}).get(
                            "security-severity", "5.0"
                        ),
                        "help_uri": rule.get("helpUri", ""),
                        "cwe": result.get("properties", {}).get("cwe", ""),
                    }

                    comments.append(comment)

        return comments

    def normalize_file_path(self, file_path: str) -> str:
        """Normalize file path from SARIF format"""
        if not file_path:
            return ""

        # Remove URI base IDs and normalize
        normalized = file_path.replace("%SRCROOT%/", "").replace("%SRCROOT%", "")
        normalized = normalized.replace("\\", "/")

        # Remove leading slashes
        while normalized.startswith("/"):
            normalized = normalized[1:]

        # Remove common workspace prefixes (for test compatibility)
        workspace_prefixes = ["workspace/", "github/workspace/", "home/runner/work/"]
        for prefix in workspace_prefixes:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                break

        return normalized

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
                        "body": self._format_sarif_comment(comment),
                    }
                )

        if not review_comments:
            print("⚠️  No valid comments to add to review")
            return False

        # Create the review
        url = f"{self.api_base}/repos/{self.repository}/pulls/{self.pr_number}/reviews"
        data = {
            "commit_id": commit_sha,
            "body": self._format_review_summary_from_sarif(review_comments, comments),
            "event": "COMMENT",
            "comments": review_comments,
        }

        response = requests.post(url, headers=self.headers, json=data)
        if response.status_code == 200:
            print(f"✅ Created security review with {len(review_comments)} comments")
            return True
        else:
            print(f"❌ Failed to create review: {response.text}")
            return False

    def create_individual_comments(
        self, commit_sha: str, comments: List[Dict], pr_files: List[Dict]
    ) -> bool:
        """Create individual comments for each finding"""
        success_count = 0

        for comment in comments:
            position = self.calculate_diff_position(
                comment["file_path"], comment["line_number"], pr_files
            )
            if position is None:
                print(
                    f"⚠️  Could not determine diff position for {comment['file_path']}:{comment['line_number']}"
                )
                continue

            url = f"{self.api_base}/repos/{self.repository}/pulls/{self.pr_number}/comments"
            data = {
                "body": self._format_sarif_comment(comment),
                "commit_id": commit_sha,
                "path": comment["file_path"],
                "position": position,
            }

            response = requests.post(url, headers=self.headers, json=data)
            if response.status_code == 201:
                print(
                    f"✅ Added comment to {comment['file_path']}:{comment['line_number']}"
                )
                success_count += 1
            else:
                print(
                    f"❌ Failed to add comment to {comment['file_path']}:{comment['line_number']}: {response.text}"
                )

        return success_count > 0

    def _format_sarif_comment(self, comment: Dict[str, Any]) -> str:
        """Format a SARIF-based security finding as a PR comment"""

        # Get severity information - handle both 'level' and 'severity' keys
        comment.get("level", comment.get("severity", "warning"))
        security_severity = float(comment.get("security_severity", "5.0"))

        # Determine severity level and emoji
        if security_severity >= 9.0:
            severity_emoji = "🔴"
            severity_text = "Critical"
        elif security_severity >= 7.0:
            severity_emoji = "🟠"
            severity_text = "High"
        elif security_severity >= 4.0:
            severity_emoji = "🟡"
            severity_text = "Medium"
        elif security_severity >= 1.0:
            severity_emoji = "🔵"
            severity_text = "Low"
        else:
            severity_emoji = "ℹ️"
            severity_text = "Info"

        # Build the comment
        comment_parts = [
            f"## {severity_emoji} Security Finding - {severity_text}",
            "",
            f"**Rule:** `{comment['rule_id']}`",
            f"**Tool:** {comment['tool_name']}",
            f"**Line:** {comment['line_number']}",
            "",
            comment["message"],
        ]

        # Add rule description if available
        rule = comment.get("rule", {})
        rule_description = rule.get("shortDescription", {}).get("text", "")
        if rule_description and rule_description != comment["message"]:
            comment_parts.extend(["", f"**Description:** {rule_description}"])

        # Add CWE information if available
        cwe = comment.get("cwe", "")
        if cwe:
            comment_parts.append(f"**CWE:** {cwe}")

        # Add help link if available
        help_uri = comment.get("help_uri", "")
        if help_uri:
            comment_parts.extend(["", f"📖 [Learn more]({help_uri})"])

        comment_parts.extend(
            [
                "",
                "---",
                "*Generated by [AWS Automated Security Helper](https://github.com/rickardl/automated-security-helper-action)*",
            ]
        )

        return "\n".join(comment_parts)

    def _format_review_summary_from_sarif(
        self, review_comments: List[Dict], all_comments: List[Dict]
    ) -> str:
        """Format the main review summary from SARIF data"""

        # Count findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        tools = set()

        for comment in all_comments:
            security_severity = float(comment.get("security_severity", "5.0"))
            tools.add(comment["tool_name"])

            if security_severity >= 9.0:
                severity_counts["Critical"] += 1
            elif security_severity >= 7.0:
                severity_counts["High"] += 1
            elif security_severity >= 4.0:
                severity_counts["Medium"] += 1
            elif security_severity >= 1.0:
                severity_counts["Low"] += 1
            else:
                severity_counts["Info"] += 1

        summary_parts = [
            "## 🛡️ Security Scan Results",
            "",
            f"Found **{len(all_comments)}** security findings in this pull request:",
            "",
        ]

        # Add severity breakdown
        for severity, count in severity_counts.items():
            if count > 0:
                emoji = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🔵",
                    "Info": "ℹ️",
                }[severity]
                summary_parts.append(f"- {emoji} **{severity}:** {count}")

        summary_parts.extend(
            [
                "",
                f"**Tools:** {', '.join(sorted(tools))}",
                f"**Inline Comments:** {len(review_comments)}",
                "",
                "Please review the inline comments above for detailed information about each finding.",
                "",
                "*Generated by [AWS Automated Security Helper](https://github.com/rickardl/automated-security-helper-action)*",
            ]
        )

        return "\n".join(summary_parts)


def main():
    if len(sys.argv) != 8:
        print(
            "Usage: sarif_pr_commenter.py <sarif_file> <workspace_path> <github_token> <repository> <pr_number> <commit_sha> <mode>"
        )
        sys.exit(1)

    sarif_file = sys.argv[1]
    sys.argv[2]
    github_token = sys.argv[3]
    repository = sys.argv[4]
    pr_number = int(sys.argv[5])
    commit_sha = sys.argv[6]
    mode = sys.argv[7]

    # Load SARIF data
    try:
        with open(sarif_file, "r") as f:
            sarif_data = json.load(f)
    except Exception as e:
        print(f"Error reading SARIF file: {e}")
        sys.exit(1)

    # Initialize commenter
    commenter = SarifPRCommenter(github_token, repository, pr_number)

    try:
        # Get PR files to calculate diff positions
        pr_files = commenter.get_pr_files()

        # Create review from SARIF data
        success = commenter.create_review_from_sarif(
            commit_sha, sarif_data, pr_files, mode
        )

        if success:
            print("✅ SARIF PR commenting completed successfully")
        else:
            print("❌ SARIF PR commenting failed")
            sys.exit(1)

    except Exception as e:
        print(f"Error during SARIF PR commenting: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
