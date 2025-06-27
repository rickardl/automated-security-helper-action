# Security Policy

## Reporting Security Vulnerabilities

AWS takes the security of our software products and services seriously. If you believe you have found a security vulnerability in this GitHub Action, please report it to us through coordinated disclosure.

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please send information about potential security vulnerabilities to:

- **AWS Security Team**: aws-security@amazon.com
- **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature

When reporting a security vulnerability, please include as much information as possible:

- Type of vulnerability (e.g., code injection, privilege escalation, information disclosure)
- Step-by-step instructions for reproducing the vulnerability
- Proof-of-concept or exploit code (if available)
- Impact assessment and potential attack scenarios
- Any suggested fixes or mitigations

## Security Considerations for Users

### Action Security Model

This GitHub Action runs in a Docker container with the following security characteristics:

1. **Isolated Environment**: The action runs in a containerized environment isolated from the GitHub Actions runner
2. **No Network Access**: Security scans run offline using pre-downloaded vulnerability databases
3. **Read-Only Source Access**: The action only requires read access to your source code
4. **No Credential Requirements**: No AWS credentials or secrets are needed for basic operation

### Data Handling

- **Source Code**: Your source code is mounted into the container for scanning but is never transmitted outside the GitHub Actions environment
- **Scan Results**: Results are stored as GitHub Actions artifacts and optionally uploaded to GitHub's Security tab
- **No Telemetry**: The action does not send any data to external services

### Permissions Required

The minimal permissions required for this action:

```yaml
permissions:
  contents: read          # Read repository contents for scanning
  security-events: write  # Upload SARIF to GitHub Security tab (optional)
  actions: read          # Access to workflow artifacts (optional)
```

### Security Best Practices

When using this action, follow these security best practices:

#### 1. Pin Action Versions
```yaml
# Good - Pin to specific version
uses: rickardl/automated-security-helper-action@v1.2.3

# Avoid - Using latest or branch references
uses: rickardl/automated-security-helper-action@main
```

#### 2. Review Action Outputs
- Regularly review security scan results in the GitHub Security tab
- Set up notifications for critical findings
- Use `fail-on-findings` to prevent deployment of vulnerable code

#### 3. Secure Workflow Configuration
```yaml
# Limit permissions to minimum required
permissions:
  contents: read
  security-events: write

# Don't expose sensitive information in workflow logs
- name: Run security scan
  uses: rickardl/automated-security-helper-action@v1
  with:
    debug: 'false'  # Avoid debug mode in production
```

#### 4. Artifact Security
- Use appropriate retention periods for security artifacts
- Consider who has access to workflow artifacts in your repository
- Review artifact contents before sharing outside your organization

### Supported Security Tools

This action includes the following vetted open-source security tools:

- **Bandit** (Python security linter)
- **Semgrep** (Multi-language static analysis)
- **Checkov** (Infrastructure-as-Code scanner)
- **cfn-nag** (CloudFormation security scanner)
- **Grype** (Vulnerability scanner)
- **git-secrets** (Secret detection)

All tools are maintained at their latest stable versions and are regularly updated.

### Container Security

The Docker container used by this action:

- Uses minimal base images to reduce attack surface
- Runs security tools with least privilege
- Does not require root access for normal operation
- Includes only necessary dependencies

### Network Security

- The action runs in offline mode by default
- No external network connections are made during scanning
- Vulnerability databases are pre-downloaded and included in the container
- No data is transmitted to external services

## Security Updates

We regularly update this action to:

- Update security tools to their latest versions
- Apply security patches to the base container image
- Address any reported security vulnerabilities
- Improve security best practices and documentation

Subscribe to repository releases to be notified of security updates.

## Compliance and Certifications

This action is designed to help with compliance requirements including:

- **SOC 2**: Security scanning and monitoring controls
- **PCI DSS**: Secure software development practices
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Security assessment and monitoring

## Contact Information

For security-related questions or concerns:

- **General Security Questions**: Create a GitHub issue with the `security` label
- **Vulnerability Reports**: aws-security@amazon.com
- **Documentation Issues**: Submit a pull request with improvements

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities and helping us improve the security of our software.

## Security Resources

- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
- [GitHub Security Features](https://github.com/features/security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls/)