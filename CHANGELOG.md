# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-27

### Initial Release

The AWS Automated Security Helper GitHub Action provides comprehensive security scanning for your repositories using AWS's Automated Security Helper (ASH) v3.

### Features

#### 🔍 **Multi-Language Security Analysis**

- Python security scanning with Bandit
- JavaScript/TypeScript vulnerability detection
- Go, Java, and other language support via Semgrep
- Multi-language static analysis across your entire codebase

#### 🏗️ **Infrastructure-as-Code Security**

- Terraform configuration security scanning with Checkov
- AWS CloudFormation template analysis with cfn-nag
- AWS CDK security validation with cdk-nag
- Kubernetes manifest security checks

#### 📊 **Comprehensive Reporting**

- SARIF output format for GitHub Security tab integration
- JSON and text output formats for custom processing
- Pull request inline comments for immediate feedback
- Configurable severity thresholds and failure policies

#### 🐳 **Container & Dependency Security**

- Container image vulnerability scanning with Grype
- Software Bill of Materials (SBOM) generation with Syft
- npm dependency vulnerability scanning
- Git repository secret detection with git-secrets

#### ⚙️ **Flexible Configuration**

- Multiple execution modes (local, container, precommit)
- Custom scanner selection and exclusion
- Configurable output directories and formats
- Support for ASH configuration files (.ash.yaml, .ash.yml)

#### 🚀 **GitHub Integration**

- Automatic SARIF upload to GitHub Security tab
- Pull request security review comments
- Artifact management with configurable retention
- Parallel execution for improved performance

#### 🛡️ **Security Best Practices**

- Fail-fast options for CI/CD security gates
- Ignore suppressions capability for comprehensive scans
- Offline mode support for air-gapped environments
- Configurable scanner strategies for optimal performance

### Supported Security Tools

- **Bandit** - Python security linter
- **Semgrep** - Multi-language static analysis
- **npm audit** - Node.js dependency vulnerability scanner
- **Checkov** - Infrastructure-as-Code security scanner
- **cfn-nag** - CloudFormation security scanner
- **cdk-nag** - AWS CDK security rules
- **Grype** - Container and filesystem vulnerability scanner
- **Syft** - Software Bill of Materials (SBOM) generator
- **git-secrets** - Git repository secret scanner

### Getting Started

Use this action in your GitHub workflows to automatically scan your code for security vulnerabilities, misconfigurations, and other security issues. See the example workflows in the `examples/` directory for common usage patterns.

### Requirements

- GitHub repository with code to scan
- GitHub Actions enabled
- Optional: Custom ASH configuration file for advanced settings
