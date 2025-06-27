#!/bin/bash
set -euo pipefail

# Simplified test runner for AWS Automated Security Helper Action

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Test Python syntax
test_python_syntax() {
    log "Testing Python syntax..."
    
    local python_files=(
        "src/core/severity_filter.py"
        "src/core/config_parser.py"
        "src/github/pr_commenter.py"
        "src/github/sarif_pr_commenter.py"
        "tests/unit/test_severity_filter.py"
        "tests/unit/test_config_parser.py"
        "tests/unit/test_pr_commenter.py"
        "tests/unit/test_sarif_pr_commenter.py"
        "tests/integration/test_action_workflow.py"
        "tests/conftest.py"
    )
    
    cd "${PROJECT_DIR}"
    
    for file in "${python_files[@]}"; do
        if [[ -f "${file}" ]]; then
            if python3 -m py_compile "${file}"; then
                log_success "Syntax check passed: ${file}"
            else
                log_error "Syntax check failed: ${file}"
                return 1
            fi
        else
            log_error "File not found: ${file}"
            return 1
        fi
    done
    
    log_success "All Python syntax checks passed"
}

# Test shell script syntax
test_shell_syntax() {
    log "Testing shell script syntax..."
    
    local shell_files=(
        "scripts/entrypoint.sh"
        "tests/test-runner.sh"
    )
    
    cd "${PROJECT_DIR}"
    
    for file in "${shell_files[@]}"; do
        if [[ -f "${file}" ]]; then
            if bash -n "${file}"; then
                log_success "Syntax check passed: ${file}"
            else
                log_error "Syntax check failed: ${file}"
                return 1
            fi
        else
            log_error "File not found: ${file}"
            return 1
        fi
    done
    
    log_success "All shell syntax checks passed"
}

# Test imports
test_imports() {
    log "Testing Python imports..."
    
    cd "${PROJECT_DIR}"
    
    # Test core module imports
    if python3 -c "
import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

try:
    from src.core import severity_filter
    from src.core import config_parser
    print('✅ Core modules import successfully')
except ImportError as e:
    print(f'❌ Import failed: {e}')
    sys.exit(1)
"; then
        log_success "Core module imports passed"
    else
        log_error "Core module imports failed"
        return 1
    fi
    
    log_success "All import tests passed"
}

# Test configuration files
test_config_files() {
    log "Testing configuration files..."
    
    cd "${PROJECT_DIR}"
    
    # Test action.yml - Manual validation since PyYAML may not be available
    if [[ -f "action.yml" ]]; then
        # Check for required top-level fields
        local required_fields=("name:" "description:" "inputs:" "outputs:" "runs:")
        local missing_fields=()
        
        for field in "${required_fields[@]}"; do
            if ! grep -q "^${field}" action.yml; then
                missing_fields+=("${field}")
            fi
        done
        
        if [[ ${#missing_fields[@]} -eq 0 ]]; then
            log_success "action.yml structure validation passed (manual check)"
        else
            log_error "action.yml missing required fields: ${missing_fields[*]}"
            return 1
        fi
    else
        log_error "action.yml not found"
        return 1
    fi
    
    # Test Dockerfile
    if [[ -f "Dockerfile" ]]; then
        if grep -q "FROM ghcr.io/awslabs/automated-security-helper:beta" Dockerfile; then
            log_success "Dockerfile uses correct ASH v3 beta base image"
        else
            log_error "Dockerfile does not use ASH v3 beta base image"
            return 1
        fi
    else
        log_error "Dockerfile not found"
        return 1
    fi
    
    log_success "All configuration file tests passed"
}

# Test file structure
test_file_structure() {
    log "Testing project file structure..."
    
    cd "${PROJECT_DIR}"
    
    local required_files=(
        "action.yml"
        "Dockerfile"
        "README.md"
        "scripts/entrypoint.sh"
        "src/core/severity_filter.py"
        "src/core/config_parser.py"
        "src/github/pr_commenter.py"
        "src/github/sarif_pr_commenter.py"
    )
    
    for file in "${required_files[@]}"; do
        if [[ -f "${file}" ]]; then
            log_success "Found required file: ${file}"
        else
            log_error "Missing required file: ${file}"
            return 1
        fi
    done
    
    # Check that SARIF converter is removed
    if [[ -f "src/core/sarif_converter.py" ]]; then
        log_error "Old SARIF converter still exists (should be removed for ASH v3)"
        return 1
    fi
    
    log_success "File structure test passed"
}

# Main test runner
main() {
    log "Starting simplified test suite for ASH v3 GitHub Action"
    
    local tests_passed=0
    local tests_failed=0
    
    # Run tests
    local test_functions=(
        "test_file_structure"
        "test_python_syntax"
        "test_shell_syntax"
        "test_imports"
        "test_config_files"
    )
    
    for test_func in "${test_functions[@]}"; do
        log "Running: ${test_func}"
        if ${test_func}; then
            ((tests_passed++))
        else
            ((tests_failed++))
        fi
        echo
    done
    
    # Print summary
    log "Test Summary:"
    echo "=============="
    echo "Tests Passed: ${tests_passed}"
    echo "Tests Failed: ${tests_failed}"
    echo "=============="
    
    if [[ ${tests_failed} -eq 0 ]]; then
        log_success "ALL TESTS PASSED! 🎉"
        log "The ASH v3 GitHub Action is ready for use."
        return 0
    else
        log_error "Some tests failed. Please fix the issues above."
        return 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi