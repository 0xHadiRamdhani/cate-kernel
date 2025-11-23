#!/bin/bash

# CATE-Kernel Security Audit Script
# Performs comprehensive security audit of the kernel

set -e

echo "Running security audit on CATE-Kernel..."

# Configuration
SRC_DIR="src"
REPORTS_DIR="reports"
SECURITY_TOOLS="bandit semgrep flawfinder rats"

# Create reports directory
mkdir -p ${REPORTS_DIR}

# Function to check if tool is available
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "Warning: $1 is not installed, skipping..."
        return 1
    fi
    return 0
}

# Function to run flawfinder
run_flawfinder() {
    echo "Running flawfinder analysis..."
    
    if ! check_tool flawfinder; then
        return
    fi
    
    flawfinder \
        --columns \
        --context \
        --html \
        --quiet \
        ${SRC_DIR} > ${REPORTS_DIR}/flawfinder-report.html 2> ${REPORTS_DIR}/flawfinder-report.txt
    
    echo "Flawfinder analysis completed"
}

# Function to run RATS (Rough Auditing Tool for Security)
run_rats() {
    echo "Running RATS analysis..."
    
    if ! check_tool rats; then
        return
    fi
    
    rats \
        --html \
        --warning 1 \
        --error 1 \
        ${SRC_DIR} > ${REPORTS_DIR}/rats-report.html 2> ${REPORTS_DIR}/rats-report.txt
    
    echo "RATS analysis completed"
}

# Function to run custom security pattern analysis
run_security_patterns() {
    echo "Running security pattern analysis..."
    
    # Define security patterns to check
    patterns=(
        "buffer_overflow:strcpy|strcat|sprintf|gets"
        "format_string:printf.*%.*[^sdfxX]"
        "integer_overflow:malloc.*\*.*sizeof"
        "command_injection:system|popen|exec"
        "path_traversal:\.\./|\.\.\\"
        "sql_injection:SELECT.*FROM.*WHERE.*\+"
        "xss:<script|javascript:"
        "directory_traversal:opendir.*\.\.|readdir.*\.\."
        "file_inclusion:include.*\$_GET|include.*\$_POST"
        "code_injection:eval|assert|preg_replace.*e"
    )
    
    > ${REPORTS_DIR}/security-patterns.txt
    
    for pattern in "${patterns[@]}"; do
        IFS=':' read -r name regex <<< "$pattern"
        echo "Checking for $name vulnerabilities..."
        
        count=$(grep -r -E "$regex" ${SRC_DIR} | wc -l)
        if [ $count -gt 0 ]; then
            echo "POTENTIAL $name: $count occurrences" >> ${REPORTS_DIR}/security-patterns.txt
            grep -r -n -E "$regex" ${SRC_DIR} >> ${REPORTS_DIR}/security-patterns.txt
            echo "---" >> ${REPORTS_DIR}/security-patterns.txt
        fi
    done
    
    echo "Security pattern analysis completed"
}

# Function to check for hardcoded secrets
run_secret_scan() {
    echo "Scanning for hardcoded secrets..."
    
    # Common secret patterns
    secret_patterns=(
        "password.*=.*['\"].*['\"]"
        "api_key.*=.*['\"].*['\"]"
        "secret.*=.*['\"].*['\"]"
        "token.*=.*['\"].*['\"]"
        "private.*key.*=.*['\"].*['\"]"
        "auth.*=.*['\"].*['\"]"
        "credential.*=.*['\"].*['\"]"
        "mysql://|postgres://|mongodb://"
        "-----BEGIN.*PRIVATE.*KEY-----"
        "-----BEGIN.*RSA.*PRIVATE.*KEY-----"
    )
    
    > ${REPORTS_DIR}/hardcoded-secrets.txt
    
    for pattern in "${secret_patterns[@]}"; do
        echo "Checking pattern: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/hardcoded-secrets.txt || true
    done
    
    echo "Secret scanning completed"
}

# Function to check for weak cryptographic practices
run_crypto_audit() {
    echo "Auditing cryptographic practices..."
    
    # Weak crypto patterns
    weak_crypto_patterns=(
        "MD5|md5"
        "SHA1|sha1"
        "DES|des"
        "RC4|rc4"
        "ECB|ecb"
        "rand\(\)"
        "srand\(\)"
        "RAND_"
        "SSLv2|SSLv3|TLSv1\.0"
    )
    
    > ${REPORTS_DIR}/weak-crypto.txt
    
    for pattern in "${weak_crypto_patterns[@]}"; do
        echo "Checking weak crypto: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/weak-crypto.txt || true
    done
    
    echo "Cryptographic audit completed"
}

# Function to check for privilege escalation risks
run_privilege_audit() {
    echo "Auditing privilege escalation risks..."
    
    # Privilege escalation patterns
    priv_patterns=(
        "setuid|setgid|seteuid|setegid"
        "getuid|getgid|geteuid|getegid"
        "sudo|su|pkexec"
        "chmod.*777|chmod.*4755|chmod.*+s"
        "chown.*root"
        "CAP_"
        "cap_set_proc|cap_get_proc"
    )
    
    > ${REPORTS_DIR}/privilege-escalation.txt
    
    for pattern in "${priv_patterns[@]}"; do
        echo "Checking privilege pattern: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/privilege-escalation.txt || true
    done
    
    echo "Privilege escalation audit completed"
}

# Function to check for memory safety issues
run_memory_safety_audit() {
    echo "Auditing memory safety..."
    
    # Memory safety patterns
    memory_patterns=(
        "malloc.*sizeof.*char"
        "free.*NULL"
        "memcpy.*sizeof"
        "strcpy.*sizeof"
        "sprintf.*sizeof"
        "gets\("
        "scanf.*%s"
        "strcat.*sizeof"
        "realloc.*sizeof"
    )
    
    > ${REPORTS_DIR}/memory-safety.txt
    
    for pattern in "${memory_patterns[@]}"; do
        echo "Checking memory pattern: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/memory-safety.txt || true
    done
    
    echo "Memory safety audit completed"
}

# Function to check for input validation issues
run_input_validation_audit() {
    echo "Auditing input validation..."
    
    # Input validation patterns
    input_patterns=(
        "scanf.*%s"
        "gets\("
        "strcpy.*argv"
        "strcat.*argv"
        "system.*argv"
        "popen.*argv"
        "exec.*argv"
        "sprintf.*argv"
        "memcpy.*argv"
    )
    
    > ${REPORTS_DIR}/input-validation.txt
    
    for pattern in "${input_patterns[@]}"; do
        echo "Checking input pattern: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/input-validation.txt || true
    done
    
    echo "Input validation audit completed"
}

# Function to check for race conditions
run_race_condition_audit() {
    echo "Auditing race conditions..."
    
    # Race condition patterns
    race_patterns=(
        "access.*fopen"
        "tmpnam"
        "mktemp"
        "fopen.*w"
        "unlink.*fopen"
        "stat.*fopen"
        "mkdir.*rmdir"
        "creat.*open"
    )
    
    > ${REPORTS_DIR}/race-conditions.txt
    
    for pattern in "${race_patterns[@]}"; do
        echo "Checking race condition: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/race-conditions.txt || true
    done
    
    echo "Race condition audit completed"
}

# Function to check for information disclosure
run_info_disclosure_audit() {
    echo "Auditing information disclosure..."
    
    # Information disclosure patterns
    info_patterns=(
        "printf.*%p"
        "fprintf.*stderr.*%p"
        "syslog.*%p"
        "error.*%p"
        "debug.*%p"
        "log.*%p"
        "print.*address"
        "print.*pointer"
    )
    
    > ${REPORTS_DIR}/info-disclosure.txt
    
    for pattern in "${info_patterns[@]}"; do
        echo "Checking info disclosure: $pattern"
        grep -r -n -i -E "$pattern" ${SRC_DIR} >> ${REPORTS_DIR}/info-disclosure.txt || true
    done
    
    echo "Information disclosure audit completed"
}

# Function to generate security summary
generate_security_summary() {
    echo "Generating security summary..."
    
    cat > ${REPORTS_DIR}/security-summary.txt << EOF
CATE-Kernel Security Audit Summary
=================================
Date: $(date)
Source Directory: ${SRC_DIR}
Reports Directory: ${REPORTS_DIR}

Security Issues Found:
EOF

    # Count issues
    local total_issues=0
    
    if [ -f "${REPORTS_DIR}/security-patterns.txt" ]; then
        SECURITY_ISSUES=$(grep -c "POTENTIAL" ${REPORTS_DIR}/security-patterns.txt || echo "0")
        echo "- Security pattern violations: ${SECURITY_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + SECURITY_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/hardcoded-secrets.txt" ]; then
        SECRET_ISSUES=$(wc -l < ${REPORTS_DIR}/hardcoded-secrets.txt || echo "0")
        echo "- Hardcoded secrets: ${SECRET_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + SECRET_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/weak-crypto.txt" ]; then
        CRYPTO_ISSUES=$(wc -l < ${REPORTS_DIR}/weak-crypto.txt || echo "0")
        echo "- Weak cryptographic practices: ${CRYPTO_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + CRYPTO_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/privilege-escalation.txt" ]; then
        PRIVILEGE_ISSUES=$(wc -l < ${REPORTS_DIR}/privilege-escalation.txt || echo "0")
        echo "- Privilege escalation risks: ${PRIVILEGE_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + PRIVILEGE_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/memory-safety.txt" ]; then
        MEMORY_ISSUES=$(wc -l < ${REPORTS_DIR}/memory-safety.txt || echo "0")
        echo "- Memory safety issues: ${MEMORY_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + MEMORY_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/input-validation.txt" ]; then
        INPUT_ISSUES=$(wc -l < ${REPORTS_DIR}/input-validation.txt || echo "0")
        echo "- Input validation issues: ${INPUT_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + INPUT_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/race-conditions.txt" ]; then
        RACE_ISSUES=$(wc -l < ${REPORTS_DIR}/race-conditions.txt || echo "0")
        echo "- Race conditions: ${RACE_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + RACE_ISSUES))
    fi
    
    if [ -f "${REPORTS_DIR}/info-disclosure.txt" ]; then
        INFO_ISSUES=$(wc -l < ${REPORTS_DIR}/info-disclosure.txt || echo "0")
        echo "- Information disclosure: ${INFO_ISSUES}" >> ${REPORTS_DIR}/security-summary.txt
        total_issues=$((total_issues + INFO_ISSUES))
    fi
    
    echo "" >> ${REPORTS_DIR}/security-summary.txt
    echo "Total security issues: ${total_issues}" >> ${REPORTS_DIR}/security-summary.txt
    echo "" >> ${REPORTS_DIR}/security-summary.txt
    echo "Risk Assessment:" >> ${REPORTS_DIR}/security-summary.txt
    
    if [ $total_issues -eq 0 ]; then
        echo "LOW RISK: No security issues found" >> ${REPORTS_DIR}/security-summary.txt
    elif [ $total_issues -lt 10 ]; then
        echo "MEDIUM RISK: Few security issues found" >> ${REPORTS_DIR}/security-summary.txt
    elif [ $total_issues -lt 50 ]; then
        echo "HIGH RISK: Moderate number of security issues found" >> ${REPORTS_DIR}/security-summary.txt
    else
        echo "CRITICAL RISK: Many security issues found" >> ${REPORTS_DIR}/security-summary.txt
    fi
    
    echo "" >> ${REPORTS_DIR}/security-summary.txt
    echo "Recommendations:" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Fix all critical security vulnerabilities first" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Replace weak cryptographic algorithms" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Remove hardcoded secrets" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Add proper input validation" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Fix memory safety issues" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Address privilege escalation risks" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Review and fix race conditions" >> ${REPORTS_DIR}/security-summary.txt
    echo "- Prevent information disclosure" >> ${REPORTS_DIR}/security-summary.txt
    
    echo "Security summary generated: ${REPORTS_DIR}/security-summary.txt"
}

# Main execution
main() {
    echo "Starting security audit..."
    
    # Run all security audits
    run_flawfinder
    run_rats
    run_security_patterns
    run_secret_scan
    run_crypto_audit
    run_privilege_audit
    run_memory_safety_audit
    run_input_validation_audit
    run_race_condition_audit
    run_info_disclosure_audit
    
    # Generate summary
    generate_security_summary
    
    echo ""
    echo "Security audit completed!"
    echo "Reports available in: ${REPORTS_DIR}/"
    echo ""
    echo "Key reports:"
    echo "- Summary: ${REPORTS_DIR}/security-summary.txt"
    echo "- Flawfinder: ${REPORTS_DIR}/flawfinder-report.html"
    echo "- RATS: ${REPORTS_DIR}/rats-report.html"
    echo "- Security patterns: ${REPORTS_DIR}/security-patterns.txt"
    echo "- Hardcoded secrets: ${REPORTS_DIR}/hardcoded-secrets.txt"
    echo "- Weak crypto: ${REPORTS_DIR}/weak-crypto.txt"
    echo "- Privilege escalation: ${REPORTS_DIR}/privilege-escalation.txt"
    echo "- Memory safety: ${REPORTS_DIR}/memory-safety.txt"
    echo "- Input validation: ${REPORTS_DIR}/input-validation.txt"
    echo "- Race conditions: ${REPORTS_DIR}/race-conditions.txt"
    echo "- Info disclosure: ${REPORTS_DIR}/info-disclosure.txt"
}

# Run main function
main "$@"