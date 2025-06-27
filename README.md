# AWS Automated Security Helper Action

[![CI](https://github.com/rickardl/automated-security-helper-action/actions/workflows/ci.yml/badge.svg)](https://github.com/rickardl/automated-security-helper-action/actions/workflows/ci.yml)
[![Tests](https://github.com/rickardl/automated-security-helper-action/actions/workflows/test.yml/badge.svg)](https://github.com/rickardl/automated-security-helper-action/actions/workflows/test.yml)
[![Release](https://github.com/rickardl/automated-security-helper-action/actions/workflows/release.yml/badge.svg)](https://github.com/rickardl/automated-security-helper-action/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/release/rickardl/automated-security-helper-action.svg)](https://github.com/rickardl/automated-security-helper-action/releases)
[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-ASH%20Action-blue)](https://github.com/marketplace/actions/aws-automated-security-helper-action)

> **A multi-language security scanning powered by [AWS Automated Security Helper (ASH) v3](https://github.com/awslabs/automated-security-helper) and seamless GitHub Security integration.**

## 🚀 Features

**🔍 Multi-Language SAST** - Python, JavaScript/TypeScript, Java, Go, C#, Ruby, PHP, Kotlin, Swift, Bash
**🏗️ Infrastructure-as-Code** - Terraform, CloudFormation, CDK, Kubernetes, Dockerfile, ARM Templates
**🔄 Native SARIF Support** - Direct integration with GitHub Security tab
**💬 Pull Request Integration** - Inline security findings comments
**⚡ Performance Optimized** - Docker layer caching and parallel execution
**🎯 Highly Configurable** - Run specific scanners, exclude others, custom thresholds

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Security Tools](#security-tools)
- [Configuration](#configuration)
- [Integration Features](#integration-features)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## 🚀 Quick Start

### Basic Security Scan

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # Required for SARIF upload
      pull-requests: write   # Required for PR comments

    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/automated-security-helper-action@v2
        with:
          upload-sarif: true
          pr-comment: true
```

### Advanced Configuration

```yaml
name: Comprehensive Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
      - name: Security Scan
        uses: aws-actions/automated-security-helper-action@v2
        with:
          # ASH v3 Configuration
          ash-mode: 'container'
          ash-version: 'beta'

          # Scanner Selection
          scanners: 'bandit,semgrep,checkov,detect-secrets'
          exclude-scanners: 'grype'
          ignore-suppressions: false

          # Output Configuration
          output-format: 'both'
          fail-on-findings: true
          severity-threshold: 'medium'

          # GitHub Integration
          upload-sarif: true
          sarif-category: 'comprehensive-scan'
          pr-comment: true
          pr-comment-format: 'sarif'

          # Performance
          parallel-execution: true
          enable-caching: true
```

## 📖 Usage Examples

### Getting Started

Perfect for new users wanting a basic security scan:

```yaml
- name: Getting Started Security Scan
  uses: aws-actions/automated-security-helper-action@v2
  with:
    source-directory: '.'
    fail-on-findings: false  # Don't fail initially
    upload-sarif: true
```

### PR Security Review

Optimized for pull request security reviews:

```yaml
- name: PR Security Review
  uses: aws-actions/automated-security-helper-action@v2
  with:
    ash-mode: 'container'
    scanners: 'bandit,semgrep,detect-secrets'  # Fast scanners for PR feedback
    pr-comment: true
    pr-comment-mode: 'review'
    fail-on-findings: false
    severity-threshold: 'high'
```

### Local Testing Configuration

For testing the action locally or in development:

```yaml
- name: Local Testing
  uses: ./  # Local action reference
  with:
    ash-mode: 'container'
    ash-version: 'beta'
    scanners: 'bandit,semgrep'
    output-format: 'both'
    upload-artifacts: true
    artifact-retention-days: 7
    debug: true
```

### Infrastructure Scanning

Focused on Infrastructure-as-Code scanning:

```yaml
- name: Infrastructure Security Scan
  uses: aws-actions/automated-security-helper-action@v2
  with:
    source-directory: './infrastructure'
    scanners: 'checkov,cfn-nag,cdk-nag'
    file-extensions: 'tf,yml,yaml,json'
    sarif-category: 'infrastructure'
```

### Matrix Strategy for Multi-Project Scanning

```yaml
name: Multi-Project Security Scan
on: [push]

jobs:
  security:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - { path: './frontend', scanners: 'semgrep,npm-audit', category: 'frontend' }
          - { path: './backend', scanners: 'bandit,semgrep', category: 'backend' }
          - { path: './infrastructure', scanners: 'checkov,cfn-nag', category: 'infrastructure' }

    steps:
      - uses: actions/checkout@v4
      - name: Scan ${{ matrix.target.category }}
        uses: aws-actions/automated-security-helper-action@v2
        with:
          source-directory: ${{ matrix.target.path }}
          scanners: ${{ matrix.target.scanners }}
          sarif-category: ${{ matrix.target.category }}
```

## 📝 Inputs

### Core Configuration

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `source-directory` | Path to source code directory to scan | No | `'.'` | `'./src'` |
| `output-directory` | Directory where scan results will be saved | No | `'ash_output'` | `'security-results'` |
| `output-format` | Output format for scan results | No | `'text'` | `'json'`, `'both'` |

### ASH v3 Configuration

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `ash-mode` | ASH execution mode | No | `'container'` | `'local'`, `'precommit'` |
| `ash-version` | Specific version of ASH to use | No | `'beta'` | `'latest'`, `'v1.2.3'` |
| `custom-config` | Path to custom ASH configuration file | No | `''` | `'./.ash-config.yml'` |

### Scanner Configuration

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `scanners` | Comma-separated list of specific scanners to run | No | `''` (all enabled) | `'bandit,semgrep,checkov'` |
| `exclude-scanners` | Comma-separated list of scanners to exclude | No | `''` | `'grype,npm-audit'` |
| `ignore-suppressions` | Ignore suppression rules and report all findings | No | `'false'` | `'true'` |
| `offline-semgrep-rulesets` | Semgrep rulesets for offline mode | No | `'p/ci'` | `'p/security-audit,p/owasp-top-ten'` |

### Filtering & Thresholds

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `fail-on-findings` | Fail the action when security findings are detected | No | `'true'` | `'false'` |
| `severity-threshold` | Minimum severity level to report | No | `'medium'` | `'high'`, `'critical'` |
| `file-extensions` | Comma-separated list of file extensions to scan | No | `''` | `'py,js,tf'` |
| `exclude-patterns` | Comma-separated list of file patterns to exclude | No | `''` | `'*/test/*,*/node_modules/*'` |

### GitHub Integration

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `upload-sarif` | Automatically upload SARIF to GitHub Security tab | No | `'true'` | `'false'` |
| `sarif-category` | Category for SARIF upload to distinguish multiple scans | No | `'automated-security-helper'` | `'terraform-scan'` |
| `github-token` | GitHub token for uploading SARIF and PR comments | No | `''` | `${{ secrets.GITHUB_TOKEN }}` |
| `pr-comment` | Add inline comments to pull requests | No | `'true'` | `'false'` |
| `pr-comment-mode` | PR comment mode: review (batched) or individual | No | `'review'` | `'individual'` |
| `pr-comment-format` | PR comment format: sarif (enhanced) or legacy | No | `'sarif'` | `'legacy'` |
| `wait-for-processing` | Wait for SARIF processing to complete before finishing | No | `'true'` | `'false'` |

### Performance & Caching

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `parallel-execution` | Enable parallel execution of security scanners | No | `'true'` | `'false'` |
| `enable-caching` | Enable Docker layer and directory caching | No | `'true'` | `'false'` |
| `cache-ttl` | Cache refresh frequency | No | `'weekly'` | `'daily'`, `'monthly'` |
| `offline-mode` | Run in offline mode using pre-downloaded databases | No | `'false'` | `'true'` |

### Artifacts & Debugging

| Input | Description | Required | Default | Example |
|-------|-------------|----------|---------|---------|
| `upload-artifacts` | Upload scan results as GitHub Actions artifacts | No | `'true'` | `'false'` |
| `artifact-retention-days` | Number of days to retain uploaded artifacts | No | `'30'` | `'7'`, `'90'` |
| `debug` | Enable debug logging for troubleshooting | No | `'false'` | `'true'` |
| `quiet` | Suppress verbose output during scanning | No | `'false'` | `'true'` |
| `preserve-reports` | Add timestamp to report names | No | `'false'` | `'true'` |

## 📤 Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `scan-results-path` | Path to the main scan results file | `'ash_output/aggregated_results.txt'` |
| `findings-count` | Total number of security findings detected | `'15'` |
| `critical-findings` | Number of critical severity findings | `'2'` |
| `high-findings` | Number of high severity findings | `'5'` |
| `medium-findings` | Number of medium severity findings | `'6'` |
| `low-findings` | Number of low severity findings | `'2'` |
| `sarif-path` | Path to the generated SARIF file | `'ash_output/reports/ash.sarif'` |
| `sarif-id` | GitHub SARIF upload ID (if uploaded successfully) | `'12345'` |
| `scan-duration` | Duration of the security scan in seconds | `'120'` |
| `tools-executed` | Comma-separated list of security tools executed | `'bandit,semgrep,checkov'` |
| `cache-enabled` | Whether caching was enabled for this run | `'true'` |

## 🔧 Security Tools

ASH v3 integrates the following open-source security tools:

### Static Application Security Testing (SAST)

- **Bandit** - Python security linter detecting common security issues
- **Semgrep** - Multi-language static analysis with customizable rules
- **ESLint** - JavaScript/TypeScript security rules and best practices

### Infrastructure-as-Code (IaC) Scanning

- **Checkov** - Infrastructure-as-Code security scanner for Terraform, CloudFormation, Kubernetes
- **cfn-nag** - CloudFormation security scanner
- **cdk-nag** - AWS CDK security rules and compliance checks

### Software Composition Analysis (SCA)

- **npm audit** - Node.js dependency vulnerability scanner
- **Grype** - Container and filesystem vulnerability scanner
- **Syft** - Software Bill of Materials (SBOM) generator

### Secrets Detection

- **git-secrets** - Git repository secret scanner
- **detect-secrets** - Enterprise secrets scanning with baseline support

## ⚙️ Configuration

### ASH Configuration File

Create an `.ash.yaml` file in your repository root for advanced configuration:

```yaml
# .ash.yaml - ASH v3 Configuration
version: 3
mode: container

scanners:
  bandit:
    enabled: true
    config:
      confidence: high
      severity: medium

  semgrep:
    enabled: true
    config:
      rulesets:
        - "auto"
        - "p/security-audit"
        - "p/owasp-top-ten"

  checkov:
    enabled: true
    config:
      framework: terraform,cloudformation

filters:
  severity_threshold: medium
  exclude_paths:
    - "*/node_modules/*"
    - "*/test/*"
    - "*/.git/*"

  include_extensions:
    - ".py"
    - ".js"
    - ".ts"
    - ".tf"
    - ".yml"
    - ".yaml"

output:
  formats:
    - text
    - sarif
  directory: "security-results"

github:
  sarif:
    enabled: true
    category: "ash-security-scan"

  pull_requests:
    enabled: true
    mode: review
    format: sarif
```

## 🔗 Integration Features

### GitHub Security Tab Integration

When `upload-sarif: true` (default), the action automatically uploads SARIF results to GitHub's Security tab:

- Security findings appear in the Security tab
- Issues are highlighted in pull requests and code reviews
- Historical tracking of security findings over time
- Integration with GitHub's notification system
- Supports multiple scan categories for different workflows

### Pull Request Comments

When `pr-comment: true` (default) and running on pull requests:

**SARIF-Enhanced Comments** (`pr-comment-format: 'sarif'`):
- Detailed rule descriptions with CWE mappings
- Severity scores and classifications
- Links to documentation and remediation guides
- Follows SARIF 2.1.0 specification

**Comment Behavior**:
- Comments only on files changed in the PR
- Severity levels indicated with emojis (🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low)
- Batched reviews (`review` mode) or individual comments (`individual` mode)
- Automatic comment updates when issues are resolved

### Permissions Required

```yaml
permissions:
  contents: read         # For accessing repository code
  security-events: write # For automatic SARIF upload to GitHub Security tab
  pull-requests: write   # For adding inline PR comments (on pull_request events)
  actions: read         # For downloading artifacts (optional)
```

## 📁 Examples

Complete example workflows are available in the [`examples/`](examples/) directory:

### Essential Examples

- **[getting-started.yml](examples/getting-started.yml)** - Simple security scan for new users
  - Basic ASH v3 configuration with container mode
  - SARIF upload and GitHub Security integration
  - Perfect for getting started with ASH

- **[pr-security-review.yml](examples/pr-security-review.yml)** - PR-focused security review
  - Optimized for pull request feedback
  - Fast scanners with inline comments
  - Security gate recommendations

- **[local-testing.yml](examples/local-testing.yml)** - Local action testing
  - Complete ASH v3 parameter showcase
  - Development and testing configuration
  - Advanced scanner control

### Example Usage in Workflow

```yaml
# Reference the examples in your workflow
- name: Run PR Security Review
  uses: aws-actions/automated-security-helper-action@v2
  with:
    # Use the same configuration as pr-security-review.yml example
    ash-mode: 'container'
    scanners: 'bandit,semgrep,detect-secrets'
    pr-comment: true
    fail-on-findings: false
    severity-threshold: 'high'
```

## 🛠️ Troubleshooting

### Common Issues

**Large repository scan times**
```yaml
- uses: aws-actions/automated-security-helper-action@v2
  with:
    parallel-execution: true  # Enable parallel scanning
    file-extensions: 'py,js'    # Limit to specific file types
    enable-caching: true      # Enable caching for faster subsequent runs
```

**Memory issues with large codebases**
```yaml
- uses: aws-actions/automated-security-helper-action@v2
  with:
    exclude-patterns: '*/node_modules/*,*/vendor/*,*/.git/*'
    scanners: 'bandit,semgrep'  # Use fewer scanners
```

**Failing builds due to findings**
```yaml
- uses: aws-actions/automated-security-helper-action@v2
  with:
    fail-on-findings: false
    severity-threshold: 'high'  # Only report high/critical
```

**SARIF upload issues**
```yaml
- uses: aws-actions/automated-security-helper-action@v2
  with:
    upload-sarif: true
    wait-for-processing: true  # Wait for SARIF processing
```

### Debug Mode

Enable debug logging to troubleshoot issues:

```yaml
- uses: aws-actions/automated-security-helper-action@v2
  with:
    debug: true
```

### Output Analysis

Check the generated files for detailed results:
- `ash_output/aggregated_results.txt` - Human-readable summary
- `ash_output/aggregated_results.txt.json` - Machine-readable JSON
- `ash_output/reports/ash.sarif` - SARIF format for GitHub Security tab

## 🧪 Development

### Prerequisites

- Python 3.8+
- Docker
- pytest for testing

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/rickardl/automated-security-helper-action.git
cd automated-security-helper-action

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v
```

### Testing Locally

```bash
# Build Docker image
docker build -t ash-action:local .

# Test with sample project
docker run --rm -v $(pwd):/workspace ash-action:local
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Start for Contributors

1. Fork the repository and create a feature branch
2. Make your changes and add tests
3. Ensure all tests pass: `pytest tests/ -v`
4. Update documentation as needed
5. Submit a pull request with a clear description

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps and environment details
- Check existing issues before creating new ones

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [AWS Automated Security Helper](https://github.com/awslabs/automated-security-helper)
- **Issues**: [GitHub Issues](https://github.com/rickardl/automated-security-helper-action/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting security issues

---

**Made with ❤️ by the AWS team. Powered by [AWS Automated Security Helper](https://github.com/awslabs/automated-security-helper).**
