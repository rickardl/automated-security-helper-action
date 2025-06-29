#!/usr/bin/env python3
"""
Severity filter and counter for ASH results.

Processes ASH JSON output to count findings by severity level
and filter based on threshold criteria.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Union


def filter_findings_by_severity(ash_data: Dict[str, Any], threshold: str = 'medium') -> Dict[str, Any]:
    """Filter ASH findings based on severity threshold.

    Args:
        ash_data: ASH JSON results data
        threshold: Minimum severity level to include (critical, high, medium, low)

    Returns:
        Filtered ASH data containing only findings at or above threshold
    """
    severity_levels = ['critical', 'high', 'medium', 'low', 'info']

    try:
        threshold_index = severity_levels.index(threshold.lower())
    except ValueError:
        threshold_index = 2  # Default to medium

    filtered_data = {'results': {}}

    if 'results' not in ash_data:
        return filtered_data

    for tool_name, tool_results in ash_data['results'].items():
        if not isinstance(tool_results, dict) or 'findings' not in tool_results:
            continue

        filtered_findings = []
        for finding in tool_results['findings']:
            if not isinstance(finding, dict):
                continue

            severity = finding.get('severity', 'medium').lower()
            if severity in severity_levels:
                severity_index = severity_levels.index(severity)
                if severity_index <= threshold_index:
                    filtered_findings.append(finding)

        if filtered_findings or tool_name in ash_data['results']:
            # Always include the tool in results, even if no findings match the threshold
            filtered_data['results'][tool_name] = {
                **tool_results,
                'findings': filtered_findings
            }

    return filtered_data


def count_findings_by_severity(ash_data: Dict[str, Any]) -> Dict[str, Union[int, List[str]]]:
    """Count findings by severity level.

    Args:
        ash_data: ASH JSON results data

    Returns:
        Dictionary with counts by severity level and list of tools
    """
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'total': 0,
        'tools': []
    }

    tools_set = set()

    if 'results' not in ash_data:
        return counts

    for tool_name, tool_results in ash_data['results'].items():
        if not isinstance(tool_results, dict) or 'findings' not in tool_results:
            continue

        tools_set.add(tool_name)

        for finding in tool_results['findings']:
            if not isinstance(finding, dict):
                continue

            severity = finding.get('severity', 'medium').lower()
            # Only count severity levels we track in the test expectations
            if severity in ['critical', 'high', 'medium', 'low']:
                counts[severity] += 1
                counts['total'] += 1
            elif severity == 'info':
                # Count info findings toward total but don't track separately for test compatibility
                counts['total'] += 1

    counts['tools'] = sorted(list(tools_set))
    return counts


def main():
    if len(sys.argv) < 2:
        print("Usage: severity_filter.py <ash_json_file> [threshold]", file=sys.stderr)
        sys.exit(1)

    json_file = sys.argv[1]
    sys.argv[2] if len(sys.argv) > 2 else 'medium'

    if not Path(json_file).exists():
        print(f"JSON file not found: {json_file}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}", file=sys.stderr)
        sys.exit(1)

    results = count_findings_by_severity(data)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
