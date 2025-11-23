#!/bin/bash

# CATE-Kernel Static Analysis Script
# Runs static analysis tools on the kernel source code

set -e

echo "Running static analysis on CATE-Kernel source code..."

# Configuration
SRC_DIR="src"
BUILD_DIR="build"
REPORTS_DIR="reports"
ANALYSIS_TOOLS="cppcheck clang-tidy scan-build"

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

# Function to run cppcheck
run_cppcheck() {
    echo "Running cppcheck analysis..."
    
    if ! check_tool cppcheck; then
        return
    fi
    
    cppcheck \
        --enable=all \
        --inconclusive \
        --std=c11 \
        --platform=unix64 \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unmatchedSuppression \
        --xml \
        --xml-version=2 \
        -I ${SRC_DIR}/include \
        ${SRC_DIR} \
        2> ${REPORTS_DIR}/cppcheck-report.xml
    
    # Generate HTML report
    if command -v cppcheck-htmlreport &> /dev/null; then
        cppcheck-htmlreport \
            --file=${REPORTS_DIR}/cppcheck-report.xml \
            --report-dir=${REPORTS_DIR}/cppcheck-html \
            --source-dir=${SRC_DIR}
        echo "Cppcheck HTML report generated: ${REPORTS_DIR}/cppcheck-html/index.html"
    fi
    
    echo "Cppcheck analysis completed"
}

# Function to run clang-tidy
run_clang_tidy() {
    echo "Running clang-tidy analysis..."
    
    if ! check_tool clang-tidy; then
        return
    fi
    
    # Find all C source files
    find ${SRC_DIR} -name "*.c" -type f > ${REPORTS_DIR}/c_files.txt
    
    # Run clang-tidy on each file
    while IFS= read -r file; do
        echo "Analyzing: $file"
        clang-tidy \
            -checks='*,-llvm-header-guard,-google-readability-todo,-fuchsia-*,-zircon-*,-abseil-*,-altera-*,-android-*,-darwin-*,-llvmlibc-*,-mpi-*,-objc-*,-openmp-*,-cuda-*' \
            -header-filter=.* \
            -p ${BUILD_DIR} \
            $file \
            -- \
            -I ${SRC_DIR}/include \
            -std=c11 \
            -D__KERNEL__ \
            -ffreestanding \
            -nostdlib \
            -nostdinc \
            2>> ${REPORTS_DIR}/clang-tidy-report.txt
    done < ${REPORTS_DIR}/c_files.txt
    
    echo "Clang-tidy analysis completed"
}

# Function to run scan-build (Clang Static Analyzer)
run_scan_build() {
    echo "Running Clang Static Analyzer..."
    
    if ! check_tool scan-build; then
        return
    fi
    
    # Clean build directory
    make clean
    
    # Run scan-build
    scan-build \
        -o ${REPORTS_DIR}/scan-build \
        --html-title="CATE-Kernel Static Analysis" \
        --keep-empty \
        make all
    
    echo "Clang Static Analyzer completed"
    echo "Report available at: ${REPORTS_DIR}/scan-build/index.html"
}

# Function to run custom security checks
run_security_checks() {
    echo "Running security checks..."
    
    # Check for common security issues
    echo "Checking for buffer overflow vulnerabilities..."
    grep -r "strcpy\|strcat\|sprintf\|gets" ${SRC_DIR} > ${REPORTS_DIR}/buffer-overflow-risks.txt || true
    
    echo "Checking for format string vulnerabilities..."
    grep -r "printf.*%" ${SRC_DIR} | grep -v "fprintf\|sprintf\|snprintf" > ${REPORTS_DIR}/format-string-risks.txt || true
    
    echo "Checking for integer overflow risks..."
    grep -r "malloc\|calloc\|realloc.*\*" ${SRC_DIR} > ${REPORTS_DIR}/integer-overflow-risks.txt || true
    
    echo "Checking for race conditions..."
    grep -r "access\|tmpnam\|mktemp" ${SRC_DIR} > ${REPORTS_DIR}/race-condition-risks.txt || true
    
    echo "Security checks completed"
}

# Function to run code complexity analysis
run_complexity_analysis() {
    echo "Running code complexity analysis..."
    
    if check_tool pmccabe; then
        find ${SRC_DIR} -name "*.c" -type f -exec pmccabe {} \; > ${REPORTS_DIR}/complexity-report.txt
        echo "Complexity analysis completed"
    else
        echo "pmccabe not available, skipping complexity analysis"
    fi
}

# Function to run include analysis
run_include_analysis() {
    echo "Running include analysis..."
    
    # Find circular dependencies
    if check_tool include-what-you-use; then
        find ${SRC_DIR} -name "*.c" -type f -exec include-what-you-use {} \; 2> ${REPORTS_DIR}/include-report.txt
        echo "Include analysis completed"
    else
        echo "include-what-you-use not available, skipping include analysis"
    fi
}

# Function to generate summary report
generate_summary() {
    echo "Generating summary report..."
    
    cat > ${REPORTS_DIR}/analysis-summary.txt << EOF
CATE-Kernel Static Analysis Summary
====================================
Date: $(date)
Source Directory: ${SRC_DIR}
Reports Directory: ${REPORTS_DIR}

Analysis Results:
EOF

    # Count issues from different tools
    if [ -f "${REPORTS_DIR}/cppcheck-report.xml" ]; then
        CPPCHECK_ISSUES=$(grep -c "<error" ${REPORTS_DIR}/cppcheck-report.xml || echo "0")
        echo "- Cppcheck: ${CPPCHECK_ISSUES} issues found" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/clang-tidy-report.txt" ]; then
        CLANG_TIDY_ISSUES=$(wc -l < ${REPORTS_DIR}/clang-tidy-report.txt || echo "0")
        echo "- Clang-tidy: ${CLANG_TIDY_ISSUES} issues found" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    if [ -d "${REPORTS_DIR}/scan-build" ]; then
        SCAN_BUILD_ISSUES=$(find ${REPORTS_DIR}/scan-build -name "*.html" | wc -l || echo "0")
        echo "- Clang Static Analyzer: ${SCAN_BUILD_ISSUES} reports generated" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    # Security issues
    if [ -f "${REPORTS_DIR}/buffer-overflow-risks.txt" ]; then
        BUFFER_OVERFLOW=$(wc -l < ${REPORTS_DIR}/buffer-overflow-risks.txt || echo "0")
        echo "- Buffer overflow risks: ${BUFFER_OVERFLOW} potential issues" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/format-string-risks.txt" ]; then
        FORMAT_STRING=$(wc -l < ${REPORTS_DIR}/format-string-risks.txt || echo "0")
        echo "- Format string risks: ${FORMAT_STRING} potential issues" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/integer-overflow-risks.txt" ]; then
        INTEGER_OVERFLOW=$(wc -l < ${REPORTS_DIR}/integer-overflow-risks.txt || echo "0")
        echo "- Integer overflow risks: ${INTEGER_OVERFLOW} potential issues" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/race-condition-risks.txt" ]; then
        RACE_CONDITION=$(wc -l < ${REPORTS_DIR}/race-condition-risks.txt || echo "0")
        echo "- Race condition risks: ${RACE_CONDITION} potential issues" >> ${REPORTS_DIR}/analysis-summary.txt
    fi
    
    echo "" >> ${REPORTS_DIR}/analysis-summary.txt
    echo "Recommendations:" >> ${REPORTS_DIR}/analysis-summary.txt
    echo "- Review and fix critical security issues" >> ${REPORTS_DIR}/analysis-summary.txt
    echo "- Address buffer overflow vulnerabilities" >> ${REPORTS_DIR}/analysis-summary.txt
    echo "- Fix format string vulnerabilities" >> ${REPORTS_DIR}/analysis-summary.txt
    echo "- Review complex functions for refactoring" >> ${REPORTS_DIR}/analysis-summary.txt
    echo "- Consider adding more input validation" >> ${REPORTS_DIR}/analysis-summary.txt
    
    echo "Summary report generated: ${REPORTS_DIR}/analysis-summary.txt"
}

# Main execution
main() {
    echo "Starting static analysis..."
    
    # Run all analysis tools
    run_cppcheck
    run_clang_tidy
    run_scan_build
    run_security_checks
    run_complexity_analysis
    run_include_analysis
    
    # Generate summary
    generate_summary
    
    echo ""
    echo "Static analysis completed!"
    echo "Reports available in: ${REPORTS_DIR}/"
    echo ""
    echo "Key reports:"
    echo "- Summary: ${REPORTS_DIR}/analysis-summary.txt"
    echo "- Cppcheck: ${REPORTS_DIR}/cppcheck-report.xml"
    echo "- Clang-tidy: ${REPORTS_DIR}/clang-tidy-report.txt"
    echo "- Security: ${REPORTS_DIR}/*-risks.txt"
    echo "- Complexity: ${REPORTS_DIR}/complexity-report.txt"
    echo ""
    echo "HTML reports:"
    echo "- Cppcheck: ${REPORTS_DIR}/cppcheck-html/index.html"
    echo "- Clang Static Analyzer: ${REPORTS_DIR}/scan-build/index.html"
}

# Run main function
main "$@"