#!/bin/bash
set -e

# Action input parameters
SOURCE_DIR="${1:-.}"
OUTPUT_DIR="${2:-ash_output}"
OUTPUT_FORMAT="${3:-text}"
FAIL_ON_FINDINGS="${4:-true}"
SEVERITY_THRESHOLD="${5:-medium}"
OFFLINE_MODE="${6:-false}"
FILE_EXTENSIONS="${7:-}"
EXCLUDE_PATTERNS="${8:-}"
PRESERVE_REPORTS="${9:-false}"
PARALLEL_EXECUTION="${10:-true}"
DEBUG="${11:-false}"
QUIET="${12:-false}"
SARIF_OUTPUT="${13:-true}"
UPLOAD_SARIF="${14:-true}"
SARIF_CATEGORY="${15:-automated-security-helper}"
GITHUB_TOKEN="${16:-}"
WAIT_FOR_PROCESSING="${17:-true}"
PR_COMMENT="${18:-true}"
PR_COMMENT_MODE="${19:-review}"
PR_COMMENT_FORMAT="${20:-sarif}"
ASH_VERSION="${21:-latest}"
ASH_MODE="${22:-local}"
CUSTOM_CONFIG="${23:-}"
UPLOAD_ARTIFACTS="${24:-true}"
ARTIFACT_RETENTION_DAYS="${25:-30}"
SCANNERS="${26:-}"
EXCLUDE_SCANNERS="${27:-}"
IGNORE_SUPPRESSIONS="${28:-false}"
OFFLINE_SEMGREP_RULESETS="${29:-p/ci}"

# Set GitHub Actions environment
export GITHUB_ACTIONS=true
export RUNNER_WORKSPACE="${GITHUB_WORKSPACE}"

# Load configuration file if it exists
echo "::group::Loading Configuration"
if [[ -f "${GITHUB_WORKSPACE}/.ash-config.yml" ]] || [[ -f "${GITHUB_WORKSPACE}/.ash-config.yaml" ]]; then
    echo "Configuration file found, loading settings..."

    # Validate configuration
    python3 /action/src/core/config_parser.py validate

    # Export configuration as environment variables
    eval "$(python3 /action/src/core/config_parser.py export-env)"

    # Override action inputs with configuration file values if they exist
    if [[ -n "${ASH_CONFIG_SEVERITY_THRESHOLD}" ]]; then
        SEVERITY_THRESHOLD="${ASH_CONFIG_SEVERITY_THRESHOLD}"
        echo "Using severity threshold from config: ${SEVERITY_THRESHOLD}"
    fi

    if [[ -n "${ASH_CONFIG_PR_COMMENTS_MODE}" ]]; then
        PR_COMMENT_MODE="${ASH_CONFIG_PR_COMMENTS_MODE}"
        echo "Using PR comment mode from config: ${PR_COMMENT_MODE}"
    fi

    if [[ -n "${ASH_CONFIG_PR_COMMENTS_FORMAT}" ]]; then
        PR_COMMENT_FORMAT="${ASH_CONFIG_PR_COMMENTS_FORMAT}"
        echo "Using PR comment format from config: ${PR_COMMENT_FORMAT}"
    fi

    if [[ -n "${ASH_CONFIG_SARIF_CATEGORY}" ]]; then
        SARIF_CATEGORY="${ASH_CONFIG_SARIF_CATEGORY}"
        echo "Using SARIF category from config: ${SARIF_CATEGORY}"
    fi

    echo "Configuration loaded successfully"
else
    echo "No configuration file found, using action inputs and defaults"
fi
echo "::endgroup::"

# Debug logging
if [[ "${DEBUG}" == "true" ]]; then
    set -x
    echo "::debug::ASH GitHub Action starting with parameters:"
    echo "::debug::Source Directory: ${SOURCE_DIR}"
    echo "::debug::Output Directory: ${OUTPUT_DIR}"
    echo "::debug::Output Format: ${OUTPUT_FORMAT}"
    echo "::debug::Fail on Findings: ${FAIL_ON_FINDINGS}"
    echo "::debug::Severity Threshold: ${SEVERITY_THRESHOLD}"
    echo "::debug::ASH Mode: ${ASH_MODE}"
    echo "::debug::Offline Mode: ${OFFLINE_MODE}"
    echo "::debug::Parallel Execution: ${PARALLEL_EXECUTION}"
    echo "::debug::Scanners: ${SCANNERS}"
    echo "::debug::Exclude Scanners: ${EXCLUDE_SCANNERS}"
    echo "::debug::Ignore Suppressions: ${IGNORE_SUPPRESSIONS}"
    echo "::debug::Offline Semgrep Rulesets: ${OFFLINE_SEMGREP_RULESETS}"
fi

# Convert relative paths to absolute paths
if [[ ! "${SOURCE_DIR}" =~ ^/ ]]; then
    SOURCE_DIR="${GITHUB_WORKSPACE}/${SOURCE_DIR}"
fi

if [[ ! "${OUTPUT_DIR}" =~ ^/ ]]; then
    OUTPUT_DIR="${GITHUB_WORKSPACE}/${OUTPUT_DIR}"
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Build ASH command arguments for ASH v3
ASH_ARGS=()

# ASH v3 uses --mode parameter with valid values: local, container, precommit
ASH_ARGS+=("--mode" "${ASH_MODE}")
ASH_ARGS+=("--source-dir" "${SOURCE_DIR}")
ASH_ARGS+=("--output-dir" "${OUTPUT_DIR}")

# Check for ASH v3 configuration file first, then legacy
if [[ -n "${CUSTOM_CONFIG}" ]] && [[ -f "${CUSTOM_CONFIG}" ]]; then
    echo "Using custom configuration file: ${CUSTOM_CONFIG}"
    ASH_ARGS+=("--config" "${CUSTOM_CONFIG}")
elif [[ -f "${GITHUB_WORKSPACE}/.ash.yaml" ]]; then
    echo "Using ASH v3 configuration format: .ash.yaml"
    ASH_ARGS+=("--config" "${GITHUB_WORKSPACE}/.ash.yaml")
elif [[ -f "${GITHUB_WORKSPACE}/.ash.yml" ]]; then
    echo "Using ASH v3 configuration format: .ash.yml"
    ASH_ARGS+=("--config" "${GITHUB_WORKSPACE}/.ash.yml")
elif [[ -f "${GITHUB_WORKSPACE}/ash.yaml" ]]; then
    echo "Using ASH v3 configuration format: ash.yaml"
    ASH_ARGS+=("--config" "${GITHUB_WORKSPACE}/ash.yaml")
elif [[ -f "${GITHUB_WORKSPACE}/ash.yml" ]]; then
    echo "Using ASH v3 configuration format: ash.yml"
    ASH_ARGS+=("--config" "${GITHUB_WORKSPACE}/ash.yml")
elif [[ -f "${GITHUB_WORKSPACE}/.ash-config.yml" ]]; then
    echo "Legacy configuration found. Converting to ASH v3 format."
    echo "::warning::Legacy configuration format detected. Consider migrating to .ash.yaml or ash.yaml for full ASH v3 compatibility"
    # Convert and copy legacy config for ASH v3
    cp "${GITHUB_WORKSPACE}/.ash-config.yml" "${GITHUB_WORKSPACE}/.ash.yaml"
    ASH_ARGS+=("--config" "${GITHUB_WORKSPACE}/.ash.yaml")
elif [[ -f "${GITHUB_WORKSPACE}/.ash-config.yaml" ]]; then
    echo "Legacy configuration found. Converting to ASH v3 format."
    echo "::warning::Legacy configuration format detected. Consider migrating to .ash.yaml or ash.yaml for full ASH v3 compatibility"
    # Convert and copy legacy config for ASH v3
    cp "${GITHUB_WORKSPACE}/.ash-config.yaml" "${GITHUB_WORKSPACE}/.ash.yaml"
    ASH_ARGS+=("--config" "${GITHUB_WORKSPACE}/.ash.yaml")
fi

# Handle output format - ASH v3 uses --output-formats
if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
    ASH_ARGS+=("--output-formats" "flat-json")
elif [[ "${OUTPUT_FORMAT}" == "both" ]]; then
    ASH_ARGS+=("--output-formats" "text" "--output-formats" "flat-json")
else
    # Default to text format
    ASH_ARGS+=("--output-formats" "text")
fi

# Add SARIF output format if enabled
if [[ "${SARIF_OUTPUT}" == "true" ]]; then
    ASH_ARGS+=("--output-formats" "sarif")
fi

# Handle debug mode
if [[ "${DEBUG}" == "true" ]]; then
    ASH_ARGS+=("--debug")
fi

# Handle quiet mode
if [[ "${QUIET}" == "true" ]]; then
    ASH_ARGS+=("--quiet")
fi

# Handle offline mode
if [[ "${OFFLINE_MODE}" == "true" ]]; then
    ASH_ARGS+=("--offline")
    # Add offline semgrep rulesets if specified
    if [[ -n "${OFFLINE_SEMGREP_RULESETS}" ]]; then
        ASH_ARGS+=("--offline-semgrep-rulesets" "${OFFLINE_SEMGREP_RULESETS}")
    fi
fi

# Handle parallel execution strategy
if [[ "${PARALLEL_EXECUTION}" == "false" ]]; then
    ASH_ARGS+=("--strategy" "sequential")
fi

# Handle fail-on-findings parameter
if [[ "${FAIL_ON_FINDINGS}" == "true" ]]; then
    ASH_ARGS+=("--fail-on-findings")
else
    ASH_ARGS+=("--no-fail-on-findings")
fi

# Handle ignore suppressions
if [[ "${IGNORE_SUPPRESSIONS}" == "true" ]]; then
    ASH_ARGS+=("--ignore-suppressions")
fi

# Handle specific scanners to run
if [[ -n "${SCANNERS}" ]]; then
    IFS=',' read -ra SCANNER_ARRAY <<< "${SCANNERS}"
    for scanner in "${SCANNER_ARRAY[@]}"; do
        scanner=$(echo "${scanner}" | xargs)  # trim whitespace
        if [[ -n "${scanner}" ]]; then
            ASH_ARGS+=("--scanners" "${scanner}")
        fi
    done
fi

# Handle scanners to exclude
if [[ -n "${EXCLUDE_SCANNERS}" ]]; then
    IFS=',' read -ra EXCLUDE_ARRAY <<< "${EXCLUDE_SCANNERS}"
    for scanner in "${EXCLUDE_ARRAY[@]}"; do
        scanner=$(echo "${scanner}" | xargs)  # trim whitespace
        if [[ -n "${scanner}" ]]; then
            ASH_ARGS+=("--exclude-scanners" "${scanner}")
        fi
    done
fi

# Record start time
START_TIME=$(date +%s)

echo "::group::Running AWS Automated Security Helper v3"
echo "Scanning directory: ${SOURCE_DIR}"
echo "Command: ash ${ASH_ARGS[*]}"

# Change to workspace directory for ASH v3 to work properly
cd "${GITHUB_WORKSPACE}"

# Run ASH scan - ASH v3 will output to .ash/ash_output/ by default
set +e
ash "${ASH_ARGS[@]}"
ASH_EXIT_CODE=$?
set -e

# Record end time and calculate duration
END_TIME=$(date +%s)
SCAN_DURATION=$((END_TIME - START_TIME))

echo "::endgroup::"

echo "::group::Processing ASH v3 Output"
echo "ASH output directory: ${OUTPUT_DIR}"

# ASH v3 outputs directly to the specified output directory with specific file structure:
# - ash_aggregated_results.json (main aggregated data)
# - reports/ash.summary.txt (text reporter output)
# - reports/ash.sarif (SARIF reporter output)
# - reports/ash.flat.json (flat JSON reporter output)

JSON_RESULTS_FILE="${OUTPUT_DIR}/ash_aggregated_results.json"
RESULTS_FILE="${OUTPUT_DIR}/reports/ash.summary.txt"
SARIF_RESULTS_FILE="${OUTPUT_DIR}/reports/ash.sarif"
FLAT_JSON_RESULTS_FILE="${OUTPUT_DIR}/reports/ash.flat.json"

# Check what files were actually generated and log their status
echo "Checking for ASH v3 output files:"
echo "JSON aggregated results: ${JSON_RESULTS_FILE} (exists: $([ -f "${JSON_RESULTS_FILE}" ] && echo "yes" || echo "no"))"
echo "Text summary report: ${RESULTS_FILE} (exists: $([ -f "${RESULTS_FILE}" ] && echo "yes" || echo "no"))"
echo "SARIF report: ${SARIF_RESULTS_FILE} (exists: $([ -f "${SARIF_RESULTS_FILE}" ] && echo "yes" || echo "no"))"
echo "Flat JSON report: ${FLAT_JSON_RESULTS_FILE} (exists: $([ -f "${FLAT_JSON_RESULTS_FILE}" ] && echo "yes" || echo "no"))"

# Create fallback text summary if the main aggregated results exist but text summary doesn't
if [[ -f "${JSON_RESULTS_FILE}" ]] && [[ ! -f "${RESULTS_FILE}" ]]; then
    echo "Creating fallback text summary from JSON results"
    mkdir -p "${OUTPUT_DIR}/reports"
    RESULTS_FILE="${OUTPUT_DIR}/reports/ash.summary.txt"
    echo "ASH v3 Security Scan Results" > "${RESULTS_FILE}"
    echo "============================" >> "${RESULTS_FILE}"
    echo "Generated: $(date)" >> "${RESULTS_FILE}"
    echo "" >> "${RESULTS_FILE}"
    echo "See ash_aggregated_results.json for detailed results" >> "${RESULTS_FILE}"
fi

echo "::endgroup::"

# Initialize counters
TOTAL_FINDINGS=0
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0
TOOLS_EXECUTED=""

# Parse results if JSON format was requested or generated
if [[ -f "${JSON_RESULTS_FILE}" ]]; then
    echo "::debug::Processing JSON results file"

    # Extract findings counts using severity filter script
    FINDINGS_SUMMARY=$(python3 /action/src/core/severity_filter.py "${JSON_RESULTS_FILE}" "${SEVERITY_THRESHOLD}")

    # Parse findings summary
    TOTAL_FINDINGS=$(echo "${FINDINGS_SUMMARY}" | jq -r '.total // 0')
    CRITICAL_FINDINGS=$(echo "${FINDINGS_SUMMARY}" | jq -r '.critical // 0')
    HIGH_FINDINGS=$(echo "${FINDINGS_SUMMARY}" | jq -r '.high // 0')
    MEDIUM_FINDINGS=$(echo "${FINDINGS_SUMMARY}" | jq -r '.medium // 0')
    LOW_FINDINGS=$(echo "${FINDINGS_SUMMARY}" | jq -r '.low // 0')
    TOOLS_EXECUTED=$(echo "${FINDINGS_SUMMARY}" | jq -r '.tools | join(",") // ""')
elif [[ -f "${RESULTS_FILE}" ]]; then
    echo "::debug::Processing text results file"

    # Basic parsing for text format
    TOTAL_FINDINGS=$(grep -c "Finding\|Issue\|Vulnerability" "${RESULTS_FILE}" 2>/dev/null || echo "0")
    TOOLS_EXECUTED=$(grep -o "Running [a-zA-Z-]*" "${RESULTS_FILE}" 2>/dev/null | sed 's/Running //' | sort -u | tr '\n' ',' | sed 's/,$//' || echo "")
fi

# Check for native SARIF output from ASH v3
SARIF_PATH=""
SARIF_ID=""
if [[ "${SARIF_OUTPUT}" == "true" ]] && [[ -f "${SARIF_RESULTS_FILE}" ]]; then
    echo "::group::Using native SARIF output from ASH v3"
    SARIF_PATH="${SARIF_RESULTS_FILE}"
    echo "SARIF file available: ${SARIF_PATH}"
    echo "::endgroup::"

    # Note: SARIF upload is now handled by the official GitHub upload-sarif action in action.yml
    if [[ "${UPLOAD_SARIF}" == "true" ]]; then
        echo "📤 SARIF file available at ${SARIF_PATH} and will be uploaded by the official GitHub upload-sarif action"
        echo "🔍 Results will be available in the Security tab: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/security/code-scanning"
    fi
else
    echo "::debug::SARIF output not available or not requested"
    echo "::debug::Checked for SARIF at: ${SARIF_RESULTS_FILE}"
    echo "::debug::File exists: $([ -f "${SARIF_RESULTS_FILE}" ] && echo "yes" || echo "no")"
fi

# Add PR comments for security findings if this is a pull request
if [[ "${PR_COMMENT}" == "true" ]] && [[ "${GITHUB_EVENT_NAME}" == "pull_request" ]] && [[ -n "${GITHUB_TOKEN}" ]]; then
    echo "::group::Adding PR comments for security findings"

    # Extract PR number from GITHUB_REF (refs/pull/123/merge)
    PR_NUMBER=$(echo "${GITHUB_REF}" | sed 's/refs\/pull\/\([0-9]*\)\/merge/\1/')

    if [[ -n "${PR_NUMBER}" ]] && [[ "${PR_NUMBER}" =~ ^[0-9]+$ ]]; then
        echo "Adding security findings as PR comments (PR #${PR_NUMBER})"

        # Choose PR commenter based on format preference and available files
        if [[ "${PR_COMMENT_FORMAT}" == "sarif" ]] && [[ -f "${SARIF_PATH}" ]]; then
            echo "Using SARIF-based PR commenter for enhanced formatting"
            python3 /action/src/github/sarif_pr_commenter.py \
                "${SARIF_PATH}" \
                "${GITHUB_WORKSPACE}" \
                "${GITHUB_TOKEN}" \
                "${GITHUB_REPOSITORY}" \
                "${PR_NUMBER}" \
                "${GITHUB_SHA}" \
                "${PR_COMMENT_MODE}"
        elif [[ -f "${JSON_RESULTS_FILE}" ]]; then
            echo "Using JSON-based PR commenter"
            python3 /action/src/github/pr_commenter.py \
                "${JSON_RESULTS_FILE}" \
                "${GITHUB_WORKSPACE}" \
                "${GITHUB_TOKEN}" \
                "${GITHUB_REPOSITORY}" \
                "${PR_NUMBER}" \
                "${GITHUB_SHA}" \
                "${PR_COMMENT_MODE}"
        else
            echo "⚠️ No suitable results file found for PR commenting"
            exit 1
        fi

        if [[ $? -eq 0 ]]; then
            echo "✅ Successfully added PR comments for security findings"
        else
            echo "⚠️ Failed to add some PR comments, but continuing..."
        fi
    else
        echo "⚠️ Could not determine PR number from GITHUB_REF: ${GITHUB_REF}"
    fi

    echo "::endgroup::"
elif [[ "${PR_COMMENT}" == "true" ]] && [[ "${GITHUB_EVENT_NAME}" != "pull_request" ]]; then
    echo "::debug::PR commenting enabled but not running on pull request event"
elif [[ "${PR_COMMENT}" == "true" ]] && [[ -z "${GITHUB_TOKEN}" ]]; then
    echo "::warning::PR commenting requested but no GitHub token provided. Skipping PR comments."
fi

# Set GitHub Actions outputs
if [[ -n "${GITHUB_OUTPUT}" ]]; then
    # Ensure the output file directory exists
    mkdir -p "$(dirname "${GITHUB_OUTPUT}")"
    echo "scan-results-path=${RESULTS_FILE}" >> "${GITHUB_OUTPUT}"
    echo "findings-count=${TOTAL_FINDINGS}" >> "${GITHUB_OUTPUT}"
    echo "critical-findings=${CRITICAL_FINDINGS}" >> "${GITHUB_OUTPUT}"
    echo "high-findings=${HIGH_FINDINGS}" >> "${GITHUB_OUTPUT}"
    echo "medium-findings=${MEDIUM_FINDINGS}" >> "${GITHUB_OUTPUT}"
    echo "low-findings=${LOW_FINDINGS}" >> "${GITHUB_OUTPUT}"
    echo "sarif-path=${SARIF_PATH}" >> "${GITHUB_OUTPUT}"
    echo "sarif-id=${SARIF_ID}" >> "${GITHUB_OUTPUT}"
    echo "scan-duration=${SCAN_DURATION}" >> "${GITHUB_OUTPUT}"
    echo "tools-executed=${TOOLS_EXECUTED}" >> "${GITHUB_OUTPUT}"
    
    echo "::debug::GitHub outputs written to: ${GITHUB_OUTPUT}"
    echo "::debug::SARIF path output: ${SARIF_PATH}"
fi

# Create GitHub Step Summary
if [[ -n "${GITHUB_STEP_SUMMARY}" ]]; then
    {
        echo "## 🛡️ AWS Automated Security Helper Results"
        echo ""
        echo "### Summary"
        echo "- **Total Findings:** ${TOTAL_FINDINGS}"
        echo "- **Critical:** ${CRITICAL_FINDINGS}"
        echo "- **High:** ${HIGH_FINDINGS}"
        echo "- **Medium:** ${MEDIUM_FINDINGS}"
        echo "- **Low:** ${LOW_FINDINGS}"
        echo "- **Scan Duration:** ${SCAN_DURATION} seconds"
        echo "- **Tools Executed:** ${TOOLS_EXECUTED}"
        echo ""

        if [[ "${TOTAL_FINDINGS}" -gt 0 ]]; then
            echo "### 🚨 Security Findings Detected"
            echo ""
            echo "Security findings were detected in your code. Please review the detailed results in the artifacts."
            echo ""
        else
            echo "### ✅ No Security Findings"
            echo ""
            echo "No security findings detected in the scanned code."
            echo ""
        fi

        echo "### Files"
        echo "- **Results:** \`${RESULTS_FILE}\`"
        if [[ -n "${SARIF_PATH}" ]]; then
            echo "- **SARIF:** \`${SARIF_PATH}\`"
        fi
    } >> "${GITHUB_STEP_SUMMARY}"
fi

# Handle artifact upload
if [[ "${UPLOAD_ARTIFACTS}" == "true" ]]; then
    echo "::notice::Security scan results will be available as GitHub Actions artifacts"
fi

# Determine exit code based on findings and configuration
if [[ "${FAIL_ON_FINDINGS}" == "true" ]] && [[ "${TOTAL_FINDINGS}" -gt 0 ]]; then
    echo "::error::Security findings detected (${TOTAL_FINDINGS} total). Failing build as requested."
    exit 1
elif [[ "${ASH_EXIT_CODE}" -ne 0 ]]; then
    echo "::error::ASH scan failed with exit code ${ASH_EXIT_CODE}"
    exit "${ASH_EXIT_CODE}"
else
    echo "::notice::Security scan completed successfully"
    exit 0
fi
