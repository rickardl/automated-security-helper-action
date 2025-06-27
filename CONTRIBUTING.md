# Contributing to AWS Automated Security Helper Action

We welcome contributions to the AWS Automated Security Helper Action! This document provides guidelines for contributing to this project.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior by creating an issue.

## How to Contribute

### Reporting Issues

If you encounter a bug or have a feature request, please create an issue in the [GitHub Issues](https://github.com/rickardl/automated-security-helper-action/issues) section. When reporting issues, please include:

- A clear description of the problem
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment details (OS, Docker version, etc.)
- Relevant logs or error messages

### Submitting Changes

1. **Fork the repository** and create a new branch from `main`
2. **Make your changes** following the coding standards below
3. **Test your changes** thoroughly
4. **Update documentation** if necessary
5. **Submit a pull request** with a clear description of your changes

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/automated-security-helper-action.git
cd automated-security-helper-action

# Create a new branch for your feature
git checkout -b feature/your-feature-name

# Make your changes and test locally
docker build -t ash-action:test .

# Test with a sample repository
docker run --rm -v /path/to/test/repo:/workspace ash-action:test /workspace /output
```

### Testing

Before submitting a pull request, please ensure:

1. **Local testing**: Test the action with various repository types
2. **Integration testing**: Test with the example workflows provided
3. **Security validation**: Ensure no sensitive information is exposed in logs
4. **Performance testing**: Verify the action performs well with large repositories

#### Manual Testing

Create a test repository and run the action:

```yaml
name: Test ASH Action
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./  # Use local action
        with:
          source-directory: '.'
          debug: 'true'
```

### Coding Standards

#### Shell Scripts
- Use `#!/bin/bash` shebang
- Enable strict mode: `set -euo pipefail`
- Quote all variable expansions: `"${VARIABLE}"`
- Use descriptive variable names in UPPERCASE
- Add comments for complex logic

#### Python Scripts
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Add docstrings for functions and classes
- Handle errors gracefully with try/catch blocks

#### Docker
- Use multi-stage builds to minimize image size
- Pin base image versions
- Clean up package caches: `rm -rf /var/lib/apt/lists/*`
- Run as non-root user when possible

#### Documentation
- Update README.md for any new features or changes
- Provide examples for new functionality
- Keep examples simple and well-commented
- Update the CHANGELOG.md with your changes

### Pull Request Guidelines

When submitting a pull request:

1. **Title**: Use a clear, descriptive title
2. **Description**: Explain what changes you made and why
3. **Testing**: Describe how you tested your changes
4. **Documentation**: Note any documentation updates needed
5. **Breaking Changes**: Clearly mark any breaking changes

#### Pull Request Template

```markdown
## Description
Brief description of changes made

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested locally with sample repositories
- [ ] Integration tests pass
- [ ] Examples work as expected

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No sensitive information exposed
```

### Release Process

This project uses semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Releases are managed by the maintainers and follow this process:

1. Update CHANGELOG.md with release notes
2. Create a release branch: `release/v1.2.3`
3. Update version numbers
4. Create pull request for review
5. After approval, create GitHub release with tag
6. Update major version tag (e.g., v1) to point to latest

### Getting Help

If you need help or have questions:

- Check the [README.md](README.md) for usage examples
- Review existing [GitHub Issues](https://github.com/rickardl/automated-security-helper-action/issues)
- Ask questions in a new issue with the "question" label

### Recognition

Contributors will be recognized in:
- Release notes for significant contributions
- GitHub contributor graphs
- Project documentation where appropriate

Thank you for contributing to make this project better! 🎉