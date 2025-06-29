#!/usr/bin/env python3
"""
Configuration Parser for AWS Automated Security Helper Action.

Handles loading and parsing of .ash-config.yml configuration files
"""

try:
    import yaml
except ImportError:
    yaml = None
import os
import sys
from typing import Dict, Any, List, Optional, Tuple


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to config file, if None will search for default locations

    Returns:
        Configuration dictionary
    """
    if not config_path:
        config_path = _find_config_file()

    if not config_path or not os.path.isfile(config_path):
        return {}

    if yaml is None:
        print(
            "PyYAML not available, configuration file loading disabled", file=sys.stderr
        )
        return {}

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
        return config
    except Exception as e:
        print(f"Error loading configuration file {config_path}: {e}", file=sys.stderr)
        return {}


def _find_config_file() -> Optional[str]:
    """Find ASH configuration file in the workspace."""
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    possible_paths = [
        os.path.join(workspace, ".ash-config.yml"),
        os.path.join(workspace, ".ash-config.yaml"),
        os.path.join(workspace, "ash-config.yml"),
        os.path.join(workspace, "ash-config.yaml"),
    ]

    for path in possible_paths:
        if os.path.isfile(path):
            return path

    return None


def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate configuration structure.

    Args:
        config: Configuration dictionary to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Validate severity threshold
    if "filters" in config:
        severity_threshold = config["filters"].get("severity_threshold")
        if severity_threshold and severity_threshold not in [
            "critical",
            "high",
            "medium",
            "low",
        ]:
            errors.append(
                "Invalid severity_threshold: must be one of critical, high, medium, low"
            )

    # Validate PR comment mode
    if "github" in config and "pr_comments" in config["github"]:
        mode = config["github"]["pr_comments"].get("mode")
        if mode and mode not in ["review", "individual"]:
            errors.append("Invalid PR comment mode: must be 'review' or 'individual'")

        format_type = config["github"]["pr_comments"].get("format")
        if format_type and format_type not in ["sarif", "legacy"]:
            errors.append("Invalid PR comment format: must be 'sarif' or 'legacy'")

    # Validate tools section
    if "tools" in config and not isinstance(config["tools"], dict):
        errors.append("Tools section must be a dictionary")

    return len(errors) == 0, errors


def export_env_vars(config: Dict[str, Any]) -> Dict[str, str]:
    """Export configuration as environment variables.

    Args:
        config: Configuration dictionary

    Returns:
        Dictionary of environment variable name -> value
    """
    env_vars = {}

    # Filters configuration
    if "filters" in config:
        severity_threshold = config["filters"].get("severity_threshold")
        if severity_threshold:
            env_vars["ASH_CONFIG_SEVERITY_THRESHOLD"] = severity_threshold

        exclude_paths = config["filters"].get("exclude_paths", [])
        if exclude_paths:
            env_vars["ASH_CONFIG_EXCLUDE_PATHS"] = ",".join(exclude_paths)

    # GitHub configuration
    if "github" in config:
        if "pr_comments" in config["github"]:
            pr_config = config["github"]["pr_comments"]
            if "mode" in pr_config:
                env_vars["ASH_CONFIG_PR_COMMENTS_MODE"] = pr_config["mode"]
            if "format" in pr_config:
                env_vars["ASH_CONFIG_PR_COMMENTS_FORMAT"] = pr_config["format"]

        if "sarif_upload" in config["github"]:
            sarif_config = config["github"]["sarif_upload"]
            if "category" in sarif_config:
                env_vars["ASH_CONFIG_SARIF_CATEGORY"] = sarif_config["category"]

    # Tools configuration
    if "tools" in config:
        for tool_name, tool_config in config["tools"].items():
            if isinstance(tool_config, dict):
                enabled = tool_config.get("enabled", True)
                env_vars[f"ASH_CONFIG_{tool_name.upper()}_ENABLED"] = str(
                    enabled
                ).lower()

                # Tool-specific configurations
                for key, value in tool_config.items():
                    if key != "enabled":
                        if isinstance(value, list):
                            env_vars[
                                f"ASH_CONFIG_{tool_name.upper()}_{key.upper()}"
                            ] = ",".join(map(str, value))
                        else:
                            env_vars[
                                f"ASH_CONFIG_{tool_name.upper()}_{key.upper()}"
                            ] = str(value)

    return env_vars


def main():
    """Main function for command line usage."""
    if len(sys.argv) < 2:
        print("Usage: config_parser.py <command> [args...]")
        print("Commands:")
        print("  validate                 - Validate configuration file")
        print(
            "  export-env              - Export configuration as environment variables"
        )
        sys.exit(1)

    command = sys.argv[1]
    config_path = os.environ.get("ASH_CONFIG_FILE")
    config = load_config(config_path)

    if command == "validate":
        is_valid, errors = validate_config(config)
        if is_valid:
            print("Configuration validation completed successfully")
        else:
            print("Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)

    elif command == "export-env":
        env_vars = export_env_vars(config)
        for key, value in env_vars.items():
            print(f"export {key}={value}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
