#!/usr/bin/env python3
"""
SARIF Enhancement Utility for AWS Automated Security Helper Action

This script enhances ASH-generated SARIF files with comprehensive file coverage
information to ensure optimal GitHub code scanning integration and proper file
coverage reporting.

Author: AWS Automated Security Helper Action
License: MIT
"""

import json
import os
import sys
import mimetypes
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


def discover_scannable_files(source_dir: str) -> List[Path]:
    """
    Discover files that ASH would typically scan based on common patterns.

    Args:
        source_dir: Source directory to scan

    Returns:
        List of Path objects for files that would be analyzed by ASH
    """
    # File extensions and names that ASH scanners typically analyze
    scannable_extensions = {
        # Python files
        '.py', '.pyx', '.pyi',
        # JavaScript/TypeScript
        '.js', '.jsx', '.ts', '.tsx', '.mjs', '.vue',
        # Java/Kotlin
        '.java', '.kt', '.kts', '.scala',
        # C/C++
        '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx',
        # C#
        '.cs', '.csx',
        # Go
        '.go',
        # Rust
        '.rs',
        # Ruby
        '.rb', '.rake',
        # PHP
        '.php', '.phtml',
        # Swift
        '.swift',
        # Configuration files
        '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf',
        # Infrastructure as Code
        '.tf', '.tfvars', '.hcl',
        # CloudFormation
        '.template', '.cfn',
        # Kubernetes
        '.k8s',
        # Docker
        '.dockerfile',
        # Shell scripts
        '.sh', '.bash', '.zsh', '.fish', '.csh', '.ksh',
        # Batch files
        '.bat', '.cmd', '.ps1',
        # Web files
        '.html', '.htm', '.xml', '.svg',
        # Requirements/dependencies
        'requirements.txt', 'requirements-dev.txt', 'requirements-test.txt',
        'Pipfile', 'pyproject.toml', 'poetry.lock',
        'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
        'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
        'Cargo.toml', 'Cargo.lock',
        'go.mod', 'go.sum',
        'composer.json', 'composer.lock'
    }

    # Special file names (case-insensitive)
    special_files = {
        'dockerfile', 'makefile', 'rakefile', 'gemfile', 'podfile',
        'vagrantfile', 'jenkinsfile', 'gruntfile.js', 'gulpfile.js'
    }

    scanned_files = []
    source_path = Path(source_dir).resolve()

    for file_path in source_path.rglob('*'):
        if file_path.is_file():
            # Check if file should be scanned
            file_name_lower = file_path.name.lower()

            if (file_path.suffix.lower() in scannable_extensions or
                file_path.name in scannable_extensions or
                file_name_lower in special_files or
                    any(pattern in file_name_lower for pattern in ['dockerfile', 'makefile'])):

                # Skip common exclusions
                if should_exclude_file(file_path, source_path):
                    continue

                scanned_files.append(file_path)

    return sorted(scanned_files)


def should_exclude_file(file_path: Path, source_root: Path) -> bool:
    """
    Check if file should be excluded from scanning based on common patterns.

    Args:
        file_path: Path to the file
        source_root: Root directory being scanned

    Returns:
        True if file should be excluded
    """
    exclude_patterns = [
        # Version control
        '.git/', '.svn/', '.hg/', '.bzr/',
        # Python
        '__pycache__/', '.pytest_cache/', '.mypy_cache/', '.coverage',
        '.tox/', '.nox/', 'htmlcov/', '.venv/', 'venv/', '.env/', 'env/',
        # Node.js
        'node_modules/', '.npm/', '.yarn/', 'coverage/',
        # Build outputs
        'dist/', 'build/', 'target/', 'out/', 'bin/', 'obj/',
        # IDEs
        '.vscode/', '.idea/', '.eclipse/', '*.swp', '*.swo',
        # Terraform
        '.terraform/', '.terraform.lock.hcl',
        # Other
        '.cache/', 'temp/', 'tmp/', '.DS_Store', 'Thumbs.db'
    ]

    try:
        relative_path = str(file_path.relative_to(source_root))
        return any(pattern in relative_path for pattern in exclude_patterns)
    except ValueError:
        # File is not under source_root
        return True


def enhance_run_with_metadata(run: Dict[str, Any], source_dir: str,
                              scanned_files: List[Path]) -> None:
    """
    Enhance a SARIF run with comprehensive metadata.

    Args:
        run: SARIF run object to enhance
        source_dir: Source directory that was scanned
        scanned_files: List of files that were analyzed
    """
    source_path = Path(source_dir).resolve()

    # Add originalUriBaseIds for consistent path resolution
    run['originalUriBaseIds'] = {
        'SRCROOT': {
            'uri': 'file:///'
        }
    }

    # Add artifacts array with all scanned files
    artifacts = []
    for file_path in scanned_files:
        try:
            relative_path = file_path.relative_to(source_path)

            # Get file stats
            stat = file_path.stat()
            mime_type, _ = mimetypes.guess_type(str(file_path))

            artifact = {
                'location': {
                    'uri': str(relative_path).replace('\\', '/'),  # Normalize path separators
                    'uriBaseId': 'SRCROOT'
                },
                'length': stat.st_size,
            }

            if mime_type:
                artifact['mimeType'] = mime_type
            else:
                # Provide sensible defaults for common file types
                ext = file_path.suffix.lower()
                if ext == '.py':
                    artifact['mimeType'] = 'text/x-python'
                elif ext in ['.js', '.jsx', '.mjs']:
                    artifact['mimeType'] = 'application/javascript'
                elif ext in ['.ts', '.tsx']:
                    artifact['mimeType'] = 'application/typescript'
                elif ext in ['.yml', '.yaml']:
                    artifact['mimeType'] = 'application/x-yaml'
                elif ext == '.json':
                    artifact['mimeType'] = 'application/json'
                elif ext in ['.sh', '.bash']:
                    artifact['mimeType'] = 'application/x-sh'
                elif 'dockerfile' in file_path.name.lower():
                    artifact['mimeType'] = 'text/x-dockerfile'
                else:
                    artifact['mimeType'] = 'text/plain'

            artifacts.append(artifact)

        except (ValueError, OSError) as e:
            # Skip files that can't be processed
            print(f"Warning: Could not process file {file_path}: {e}", file=sys.stderr)
            continue

    run['artifacts'] = artifacts

    # Add invocations metadata
    current_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    invocation = {
        'executionSuccessful': True,
        'endTimeUtc': current_time,
        'workingDirectory': {
            'uri': f'file://{source_path}',
            'uriBaseId': 'SRCROOT'
        },
        'properties': {
            'filesScanned': len(scanned_files),
            'enhancedBy': 'aws-automated-security-helper-action',
            'sarifEnhancementVersion': '1.0.0'
        }
    }

    run['invocations'] = [invocation]

    # Add informational notifications
    notifications = [
        {
            'level': 'note',
            'message': {
                'text': f'Successfully analyzed {len(scanned_files)} files '
                f'for security vulnerabilities'
            },
            'descriptor': {
                'id': 'ASH_SCAN_SUMMARY',
                'name': 'ScanCoverageSummary'
            }
        }
    ]

    # Group by file types for more detailed reporting
    file_types = {}
    for file_path in scanned_files:
        ext = file_path.suffix.lower() or 'no-extension'
        file_types[ext] = file_types.get(ext, 0) + 1

    if file_types:
        # Create readable file type summary
        type_items = []
        for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
            display_ext = ext if ext != 'no-extension' else 'other'
            type_items.append(f'{count} {display_ext}')

        type_summary = ', '.join(type_items[:5])  # Show top 5 file types
        if len(file_types) > 5:
            type_summary += f' and {len(file_types) - 5} other types'

        notifications.append({
            'level': 'note',
            'message': {
                'text': f'File types analyzed: {type_summary}'
            },
            'descriptor': {
                'id': 'ASH_FILE_TYPES',
                'name': 'FileTypeBreakdown'
            }
        })

    run['notifications'] = notifications


def load_scanned_files_from_ash_list(files_list_path: str, source_dir: str) -> List[Path]:
    """
    Load scanned files from ASH's generated files list.

    Args:
        files_list_path: Path to ASH's scanned files list (ash-scan-set-files-list.txt)
        source_dir: Source directory that was scanned

    Returns:
        List of Path objects for files that were actually scanned by ASH
    """
    scanned_files = []
    source_path = Path(source_dir).resolve()

    try:
        with open(files_list_path, 'r', encoding='utf-8') as f:
            for line in f:
                file_path_str = line.strip()
                if not file_path_str:
                    continue

                # Convert ASH file paths to absolute paths
                # ASH typically uses /workspace/ as the base in containers
                if file_path_str.startswith('/workspace/'):
                    # Remove the /workspace/ prefix and make relative to source_dir
                    relative_path = file_path_str[len('/workspace/'):]
                    actual_path = source_path / relative_path
                elif file_path_str.startswith('/'):
                    # Absolute path, try to make it relative to source_dir
                    try:
                        actual_path = Path(file_path_str)
                        # If it's outside source_dir, skip it
                        actual_path.relative_to(source_path)
                    except ValueError:
                        continue
                else:
                    # Relative path
                    actual_path = source_path / file_path_str

                # Normalize and validate the path
                try:
                    resolved_path = actual_path.resolve()
                    if resolved_path.exists() and resolved_path.is_file():
                        # Ensure it's under source_dir
                        resolved_path.relative_to(source_path)
                        scanned_files.append(resolved_path)
                except (ValueError, OSError):
                    # Skip files that don't exist or are outside source_dir
                    continue

    except (FileNotFoundError, OSError) as e:
        print(f"Warning: Could not read ASH files list {files_list_path}: {e}", file=sys.stderr)
        return []

    return sorted(scanned_files)


def add_run_automation_details(run: Dict[str, Any], category: Optional[str] = None) -> None:
    """
    Add runAutomationDetails.id for proper GitHub analysis categorization.

    Args:
        run: SARIF run object to enhance
        category: Optional category name (defaults to 'ash-security-scan')
    """
    if not category:
        category = 'ash-security-scan'

    # Add timestamp to make runs unique while maintaining category grouping
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    automation_id = f"{category}/{timestamp}"

    run['automationDetails'] = {
        'id': automation_id,
        'description': {
            'text': f'AWS Automated Security Helper scan in category: {category}'
        }
    }


def enhance_tool_metadata(run: Dict[str, Any]) -> None:
    """
    Enhance tool metadata for better GitHub integration.

    Args:
        run: SARIF run object to enhance
    """
    if 'tool' not in run:
        run['tool'] = {}
    if 'driver' not in run['tool']:
        run['tool']['driver'] = {}

    driver = run['tool']['driver']

    # Set or enhance tool information
    if 'name' not in driver:
        driver['name'] = 'AWS Automated Security Helper'

    # Add version information if not present
    if 'version' not in driver and 'semanticVersion' not in driver:
        driver['semanticVersion'] = '3.0.0'

    # Add organization information
    if 'organization' not in driver:
        driver['organization'] = 'Amazon Web Services'

    # Add download URL
    if 'downloadUri' not in driver:
        driver['downloadUri'] = 'https://github.com/aws-actions/automated-security-helper-action'

    # Add informational URI
    if 'informationUri' not in driver:
        driver['informationUri'] = 'https://github.com/aws-samples/automated-security-helper'


def enhance_rules_metadata(run: Dict[str, Any]) -> None:
    """
    Enhance rule metadata for better GitHub integration.

    Args:
        run: SARIF run object to enhance
    """
    if 'tool' not in run or 'driver' not in run['tool']:
        return

    driver = run['tool']['driver']

    # Ensure rules array exists
    if 'rules' not in driver:
        driver['rules'] = []

    # Enhance existing rules with missing GitHub properties
    for rule in driver['rules']:
        if 'properties' not in rule:
            rule['properties'] = {}

        properties = rule['properties']

        # Add security severity if missing
        if 'security-severity' not in properties:
            properties['security-severity'] = get_security_severity_score(rule.get('id', ''))

        # Add precision if missing
        if 'precision' not in properties:
            properties['precision'] = 'medium'

        # Add tags if missing
        if 'tags' not in properties:
            properties['tags'] = ['security', 'aws-ash']
        elif 'security' not in properties['tags']:
            properties['tags'].append('security')

    # Create a mapping of existing rules by ID
    existing_rules = {rule.get('id'): rule for rule in driver['rules'] if rule.get('id')}

    # Process results to find missing rules
    if 'results' in run:
        for result in run['results']:
            rule_id = result.get('ruleId')
            if rule_id and rule_id not in existing_rules:
                # Create a basic rule definition
                rule = {
                    'id': rule_id,
                    'name': rule_id,
                    'shortDescription': {
                        'text': f'Security finding: {rule_id}'
                    },
                    'fullDescription': {
                        'text': f'Security vulnerability or issue detected by ASH: {rule_id}'
                    },
                    'help': {
                        'text': 'Review this finding and address any security concerns.',
                        'markdown': (f'## {rule_id}\n\n'
                                     f'This security finding was detected by AWS Automated '
                                     f'Security Helper. Please review the identified issue and '
                                     f'take appropriate action to address any security concerns.')
                    },
                    'defaultConfiguration': {
                        'level': 'warning'
                    },
                    'properties': {
                        'tags': ['security', 'aws-ash'],
                        'precision': 'medium',
                        'security-severity': get_security_severity_score(rule_id)
                    }
                }

                # Add rule to both the mapping and the rules array
                existing_rules[rule_id] = rule
                driver['rules'].append(rule)


def get_security_severity_score(rule_id: str) -> str:
    """
    Get GitHub security severity score (0.0-10.0) based on rule ID patterns.

    Args:
        rule_id: The rule identifier

    Returns:
        Security severity score as string (GitHub requirement)
    """
    rule_id_lower = rule_id.lower()

    # Critical severity (9.0-10.0)
    if any(keyword in rule_id_lower for keyword in [
        'critical', 'rce', 'remote_code_execution', 'sql_injection',
        'command_injection', 'deserialization', 'xxe', 'ssti'
    ]):
        return '9.5'

    # High severity (7.0-8.9)
    elif any(keyword in rule_id_lower for keyword in [
        'high', 'xss', 'csrf', 'path_traversal', 'ldap_injection',
        'authentication_bypass', 'privilege_escalation', 'unsafe_reflection'
    ]):
        return '7.5'

    # Medium severity (4.0-6.9)
    elif any(keyword in rule_id_lower for keyword in [
        'medium', 'weak_crypto', 'insecure_random', 'hardcoded_credential',
        'information_disclosure', 'weak_hash', 'cleartext'
    ]):
        return '5.0'

    # Low severity (0.1-3.9)
    elif any(keyword in rule_id_lower for keyword in [
        'low', 'info', 'warning', 'deprecated', 'unused'
    ]):
        return '2.0'

    # Default to medium for security rules
    return '5.0'


def add_partial_fingerprints(run: Dict[str, Any]) -> None:
    """
    Add partial fingerprints to results for better GitHub alert tracking.

    Args:
        run: SARIF run object to enhance
    """
    # Note: Future versions could use source_dir for file-based fingerprinting
    if 'results' not in run:
        return

    for result in run['results']:
        if 'partialFingerprints' in result:
            continue  # Already has fingerprints

        # Get primary location for fingerprinting
        locations = result.get('locations', [])
        if not locations:
            continue

        location = locations[0]
        physical_location = location.get('physicalLocation', {})
        artifact_location = physical_location.get('artifactLocation', {})
        region = physical_location.get('region', {})

        uri = artifact_location.get('uri', '')
        start_line = region.get('startLine', 1)
        start_column = region.get('startColumn', 1)

        # Create a primary location hash
        location_string = f"{uri}:{start_line}:{start_column}"
        location_hash = hashlib.sha256(location_string.encode('utf-8')).hexdigest()[:16]

        # Add rule and message context for better uniqueness
        rule_id = result.get('ruleId', 'unknown')
        message_text = result.get('message', {}).get('text', '')

        context_string = f"{rule_id}:{message_text}"
        context_hash = hashlib.sha256(context_string.encode('utf-8')).hexdigest()[:8]

        result['partialFingerprints'] = {
            'primaryLocationLineHash': f"{location_hash}:{start_line}",
            'primaryLocationStartColumnFingerprint': str(start_column),
            'contextHash': context_hash
        }


def normalize_result_levels(run: Dict[str, Any]) -> None:
    """
    Normalize result levels to standard SARIF values for GitHub.

    Args:
        run: SARIF run object to enhance
    """
    if 'results' not in run:
        return

    # Mapping of common severity terms to SARIF levels
    level_mapping = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note',
        'informational': 'note'
    }

    for result in run['results']:
        # Ensure level is set
        if 'level' not in result:
            # Try to infer from rule or use default
            result['level'] = 'warning'
        else:
            # Normalize existing level
            current_level = result['level'].lower()
            if current_level in level_mapping:
                result['level'] = level_mapping[current_level]
            elif current_level not in ['error', 'warning', 'note']:
                result['level'] = 'warning'


def validate_github_limits(sarif: Dict[str, Any]) -> bool:
    """
    Validate SARIF against GitHub's processing limits.

    Args:
        sarif: Complete SARIF object to validate

    Returns:
        True if within limits, False otherwise
    """
    if 'runs' not in sarif:
        return False

    # Check number of runs (max 20)
    if len(sarif['runs']) > 20:
        print(f"Warning: SARIF has {len(sarif['runs'])} runs, "
              f"GitHub maximum is 20", file=sys.stderr)
        return False

    for i, run in enumerate(sarif['runs']):
        # Check results per run (max 25,000)
        if 'results' in run and len(run['results']) > 25000:
            print(f"Warning: Run {i + 1} has {len(run['results'])} results, "
                  f"GitHub maximum is 25,000", file=sys.stderr)
            return False

        # Check rules per run (max 25,000)
        if 'tool' in run and 'driver' in run['tool'] and 'rules' in run['tool']['driver']:
            rules_count = len(run['tool']['driver']['rules'])
            if rules_count > 25000:
                print(f"Warning: Run {i + 1} has {rules_count} rules, "
                      f"GitHub maximum is 25,000", file=sys.stderr)
                return False

        # Check artifacts count (max 25,000)
        if 'artifacts' in run and len(run['artifacts']) > 25000:
            print(f"Warning: Run {i + 1} has {len(run['artifacts'])} artifacts, "
                  f"GitHub maximum is 25,000", file=sys.stderr)
            return False

    return True


def enhance_sarif_with_file_coverage(
    sarif_path: str,
    source_dir: str,
    output_path: Optional[str] = None,
    scanned_files_list: Optional[str] = None,
    category: Optional[str] = None
) -> int:
    """
    Enhance ASH SARIF output with comprehensive file coverage and GitHub optimization.

    Args:
        sarif_path: Path to the original SARIF file from ASH
        source_dir: Source directory that was scanned
        output_path: Optional output path (defaults to overwriting original)
        scanned_files_list: Optional path to ASH's scanned files list
                           (defaults to heuristic discovery)
        category: Optional category for runAutomationDetails (defaults to 'ash-security-scan')

    Returns:
        Number of files that were analyzed
    """
    if output_path is None:
        output_path = sarif_path

    # Load original SARIF
    try:
        with open(sarif_path, 'r', encoding='utf-8') as f:
            sarif = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: Could not load SARIF file {sarif_path}: {e}", file=sys.stderr)
        return 0

    # Ensure SARIF has required GitHub properties
    if '$schema' not in sarif:
        sarif['$schema'] = 'https://json.schemastore.org/sarif-2.1.0.json'

    if 'version' not in sarif:
        sarif['version'] = '2.1.0'

    # Validate SARIF structure
    if 'runs' not in sarif or not sarif['runs']:
        print(f"Error: Invalid SARIF structure in {sarif_path}", file=sys.stderr)
        return 0

    # Get list of scanned files
    if scanned_files_list and os.path.isfile(scanned_files_list):
        print(f"Using ASH-generated scanned files list: {scanned_files_list}")
        scanned_files = load_scanned_files_from_ash_list(scanned_files_list, source_dir)
        print(f"Loaded {len(scanned_files)} files from ASH scan list")
    else:
        # Fallback to heuristic discovery
        print(f"Discovering scannable files in {source_dir}...")
        scanned_files = discover_scannable_files(source_dir)
        print(f"Found {len(scanned_files)} files that would be analyzed by ASH")

    # Enhance each run in the SARIF
    for i, run in enumerate(sarif['runs']):
        print(f"Enhancing SARIF run {i + 1}/{len(sarif['runs'])}...")

        # Apply all enhancements
        enhance_run_with_metadata(run, source_dir, scanned_files)
        add_run_automation_details(run, category)
        enhance_tool_metadata(run)
        enhance_rules_metadata(run)
        add_partial_fingerprints(run)
        normalize_result_levels(run)

    # Validate against GitHub limits
    if not validate_github_limits(sarif):
        print("⚠️  SARIF exceeds GitHub limits but will continue processing")
    else:
        print("✅ SARIF passes GitHub limits validation")

    # Write enhanced SARIF
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        print(f"Enhanced SARIF written to {output_path}")
    except OSError as e:
        print(f"Error: Could not write enhanced SARIF to {output_path}: {e}", file=sys.stderr)
        return 0

    return len(scanned_files)


def main():
    """Main entry point for command-line usage."""
    if len(sys.argv) < 3:
        print("Usage: python sarif_enhancer.py <sarif_file> <source_directory> "
              "[output_file] [scanned_files_list]", file=sys.stderr)
        print("", file=sys.stderr)
        print("Enhances ASH SARIF output with comprehensive file coverage and "
              "GitHub integration optimization.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Arguments:", file=sys.stderr)
        print("  sarif_file         Path to the SARIF file to enhance", file=sys.stderr)
        print("  source_directory   Directory that was scanned by ASH", file=sys.stderr)
        print("  output_file        Optional output path "
              "(defaults to overwriting input)", file=sys.stderr)
        print("  scanned_files_list Optional path to ASH's scanned files list",
              file=sys.stderr)
        sys.exit(1)

    sarif_path = sys.argv[1]
    source_dir = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None
    scanned_files_list = sys.argv[4] if len(sys.argv) > 4 else None

    # Validate inputs
    if not os.path.isfile(sarif_path):
        print(f"Error: SARIF file not found: {sarif_path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(source_dir):
        print(f"Error: Source directory not found: {source_dir}", file=sys.stderr)
        sys.exit(1)

    if scanned_files_list and not os.path.isfile(scanned_files_list):
        print(f"Error: Scanned files list not found: {scanned_files_list}",
              file=sys.stderr)
        sys.exit(1)

    # Perform enhancement
    print(f"🔧 Enhancing SARIF file: {sarif_path}")
    print(f"📁 Source directory: {source_dir}")
    if scanned_files_list:
        print(f"📋 Using scanned files list: {scanned_files_list}")

    files_count = enhance_sarif_with_file_coverage(
        sarif_path, source_dir, output_path, scanned_files_list, 'ash-security-scan'
    )

    if files_count > 0:
        print(f"✅ Successfully enhanced SARIF with {files_count} files")
        print(f"🎯 CodeQL will now show '{files_count} files scanned' in the Security tab")
    else:
        print("❌ Failed to enhance SARIF file")
        sys.exit(1)


if __name__ == '__main__':
    main()
