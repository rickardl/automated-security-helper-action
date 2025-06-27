.PHONY: help install install-dev install-dev-requirements test test-unit test-integration test-slow test-watch lint format format-check security clean pre-commit docker-build docker-test docker-clean ci-test docs version check-release dev-setup quick-check

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Installation
install: ## Install the package
	pip install -e .

install-dev: ## Install development dependencies
	pip install -e ".[dev]"

install-dev-requirements: ## Install development dependencies from requirements-dev.txt (alternative)
	pip install -r requirements-dev.txt
	pip install -e .

# Testing
test: ## Run all tests
	pytest tests/ -v

test-unit: ## Run unit tests with coverage
	pytest tests/unit/ -v --cov=src --cov-report=html --cov-report=term-missing

test-integration: ## Run integration tests
	pytest tests/integration/ -v

test-slow: ## Run slow integration tests
	pytest tests/integration/ -v -m "slow"

test-watch: ## Run tests in watch mode
	@command -v pytest-watch >/dev/null 2>&1 || { echo >&2 "pytest-watch not installed. Install with: pip install pytest-watch"; exit 1; }
	pytest-watch tests/ -- -v

# Code quality
lint: ## Run all linting tools
	flake8 src/ tests/
	mypy src/
	bandit -r src/
	shellcheck scripts/*.sh

format: ## Format code with black and isort
	black src/ tests/
	isort src/ tests/

format-check: ## Check code formatting
	black --check --diff src/ tests/
	isort --check-only --diff src/ tests/

security: ## Run security checks
	bandit -r src/
	safety check

# Development
clean: ## Clean up build artifacts and cache
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

pre-commit: ## Run pre-commit hooks on all files
	pre-commit run --all-files

# Docker operations
docker-build: ## Build Docker image
	docker build -t ash-action:local .

docker-test: ## Test Docker image with sample data
	@echo "🐳 Testing Docker image..."
	mkdir -p test-output
	echo 'password = "hardcoded123"' > test-file.py
	docker run --rm \
		-v "$(PWD):/workspace" \
		ash-action:local \
		/workspace \
		test-output \
		json \
		false \
		medium
	@echo "🧹 Cleaning up test files..."
	rm -f test-file.py
	rm -rf test-output
	@echo "✅ Docker test completed"

docker-clean: ## Clean up Docker images and containers
	docker system prune -f
	docker rmi ash-action:local 2>/dev/null || true

# CI/CD simulation
ci-test: ## Run CI pipeline locally
	@echo "🔍 Validating action.yml..."
	python3 -c "import yaml; yaml.safe_load(open('action.yml'))"
	@echo "✅ action.yml is valid"

	@echo "🧪 Running tests..."
	pytest tests/unit/ -v --cov=src

	@echo "🔧 Running linting..."
	flake8 src/ tests/
	black --check src/ tests/
	isort --check-only src/ tests/

	@echo "🔒 Running security checks..."
	bandit -r src/

	@echo "🐳 Building Docker image..."
	docker build -t ash-action:ci-test .

	@echo "✅ CI pipeline simulation completed successfully!"

# Documentation
docs: ## Generate documentation (placeholder)
	@echo "Documentation generation not implemented yet"

# Release helpers
version: ## Show current version
	@python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"

check-release: ## Check if ready for release
	@echo "🔍 Checking release readiness..."
	@echo "Running full test suite..."
	pytest tests/ -v
	@echo "Running security checks..."
	bandit -r src/
	safety check
	@echo "Checking code quality..."
	flake8 src/ tests/
	black --check src/ tests/
	isort --check-only src/ tests/
	@echo "Building Docker image..."
	docker build -t ash-action:release-test .
	@echo "✅ Release checks passed!"

# Development workflow
dev-setup: install-dev ## Set up development environment
	@echo "Setting up pre-commit hooks..."
	pre-commit install || echo "Warning: pre-commit not available, skipping hooks setup"
	@echo "✅ Development environment set up"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to check code quality"
	@echo "Run 'make format' to format code"

quick-check: format lint test-unit ## Quick development check
	@echo "✅ Quick development check completed"
