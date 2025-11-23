#!/bin/bash

# CATE-Kernel Code Coverage Analysis Script
# Runs code coverage analysis on the kernel source code

set -e

echo "Running code coverage analysis on CATE-Kernel..."

# Configuration
SRC_DIR="src"
BUILD_DIR="build"
REPORTS_DIR="reports"
COVERAGE_TOOLS="gcov lcov gcovr"

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

# Function to build with coverage flags
build_with_coverage() {
    echo "Building kernel with coverage flags..."
    
    # Clean previous build
    make clean
    
    # Build with coverage flags
    make CFLAGS="-fprofile-arcs -ftest-coverage -g -O0" \
         LDFLAGS="-fprofile-arcs -ftest-coverage" \
         BUILD_DIR=${BUILD_DIR}/coverage \
         2> ${REPORTS_DIR}/coverage-build.log || true
    
    echo "Coverage build completed"
}

# Function to run gcov
run_gcov() {
    echo "Running gcov coverage analysis..."
    
    if ! check_tool gcov; then
        return
    fi
    
    # Find all gcda files
    find ${BUILD_DIR}/coverage -name "*.gcda" -type f > ${REPORTS_DIR}/gcda-files.txt
    
    # Run gcov on each source file
    while IFS= read -r gcda_file; do
        gcov_file=$(echo $gcda_file | sed 's/\.gcda$/.gcov/')
        source_file=$(echo $gcda_file | sed 's/\.gcda$/.c/' | sed "s|${BUILD_DIR}/coverage|${SRC_DIR}|")
        
        if [ -f "$source_file" ]; then
            echo "Analyzing: $source_file"
            cd $(dirname $source_file)
            gcov -b -c $(basename $source_file) -o $(dirname $gcda_file) > /dev/null 2>&1
            cd - > /dev/null
        fi
    done < ${REPORTS_DIR}/gcda-files.txt
    
    # Collect gcov files
    find ${SRC_DIR} -name "*.gcov" -type f -exec cp {} ${REPORTS_DIR}/ \;
    
    echo "Gcov analysis completed"
}

# Function to run lcov
run_lcov() {
    echo "Running lcov coverage analysis..."
    
    if ! check_tool lcov; then
        return
    fi
    
    # Initialize lcov
    lcov --capture --initial --directory ${BUILD_DIR}/coverage --output-file ${REPORTS_DIR}/coverage-base.info
    
    # Run tests to generate coverage data
    echo "Running tests to generate coverage data..."
    make test 2> ${REPORTS_DIR}/test-run.log || true
    
    # Capture coverage data
    lcov --capture --directory ${BUILD_DIR}/coverage --output-file ${REPORTS_DIR}/coverage-test.info
    
    # Combine coverage data
    lcov --add-tracefile ${REPORTS_DIR}/coverage-base.info --add-tracefile ${REPORTS_DIR}/coverage-test.info --output-file ${REPORTS_DIR}/coverage-combined.info
    
    # Remove system files from coverage
    lcov --remove ${REPORTS_DIR}/coverage-combined.info '/usr/*' --output-file ${REPORTS_DIR}/coverage-filtered.info
    
    # Generate HTML report
    genhtml ${REPORTS_DIR}/coverage-filtered.info --output-directory ${REPORTS_DIR}/lcov-html
    
    echo "Lcov analysis completed"
    echo "HTML report: ${REPORTS_DIR}/lcov-html/index.html"
}

# Function to run gcovr
run_gcovr() {
    echo "Running gcovr coverage analysis..."
    
    if ! check_tool gcovr; then
        return
    fi
    
    # Generate XML report
    gcovr -r ${SRC_DIR} -x -o ${REPORTS_DIR}/coverage-gcovr.xml
    
    # Generate HTML report
    gcovr -r ${SRC_DIR} --html --html-details -o ${REPORTS_DIR}/coverage-gcovr.html
    
    # Generate text report
    gcovr -r ${SRC_DIR} -o ${REPORTS_DIR}/coverage-gcovr.txt
    
    # Generate JSON report
    gcovr -r ${SRC_DIR} --json -o ${REPORTS_DIR}/coverage-gcovr.json
    
    echo "Gcovr analysis completed"
}

# Function to run custom coverage analysis
run_custom_coverage() {
    echo "Running custom coverage analysis..."
    
    # Create custom coverage analyzer
    cat > ${REPORTS_DIR}/coverage-analyzer.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

typedef struct coverage_data {
    char *filename;
    int total_lines;
    int executed_lines;
    int coverage_percent;
} coverage_data_t;

// Parse gcov file
coverage_data_t parse_gcov_file(const char *filename) {
    coverage_data_t data = {0};
    FILE *fp = fopen(filename, "r");
    if (!fp) return data;
    
    data.filename = strdup(filename);
    char line[1024];
    
    while (fgets(line, sizeof(line), fp)) {
        data.total_lines++;
        
        // Check if line was executed
        if (line[0] == ' ' && line[1] == ' ' && line[2] == ' ' && line[3] == ' ') {
            // Line not executed
        } else if (line[0] == '-' && line[1] == '-') {
            // Line not executable
        } else {
            // Line was executed
            data.executed_lines++;
        }
    }
    
    fclose(fp);
    
    if (data.total_lines > 0) {
        data.coverage_percent = (data.executed_lines * 100) / data.total_lines;
    }
    
    return data;
}

// Generate coverage report
void generate_coverage_report(const char *output_file) {
    FILE *output = fopen(output_file, "w");
    if (!output) return;
    
    fprintf(output, "CATE-Kernel Custom Coverage Report\n");
    fprintf(output, "=================================\n\n");
    
    DIR *dir;
    struct dirent *ent;
    coverage_data_t *files = NULL;
    int file_count = 0;
    
    // Find all gcov files
    if ((dir = opendir(".")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (strstr(ent->d_name, ".gcov")) {
                files = realloc(files, (file_count + 1) * sizeof(coverage_data_t));
                files[file_count] = parse_gcov_file(ent->d_name);
                file_count++;
            }
        }
        closedir(dir);
    }
    
    // Calculate total coverage
    int total_lines = 0;
    int total_executed = 0;
    
    fprintf(output, "File Coverage:\n");
    fprintf(output, "=============\n");
    
    for (int i = 0; i < file_count; i++) {
        fprintf(output, "%-30s: %3d%% (%d/%d lines)\n",
                files[i].filename,
                files[i].coverage_percent,
                files[i].executed_lines,
                files[i].total_lines);
        
        total_lines += files[i].total_lines;
        total_executed += files[i].executed_lines;
    }
    
    // Overall coverage
    int overall_coverage = 0;
    if (total_lines > 0) {
        overall_coverage = (total_executed * 100) / total_lines;
    }
    
    fprintf(output, "\nOverall Coverage: %d%% (%d/%d lines)\n",
            overall_coverage, total_executed, total_lines);
    
    // Coverage recommendations
    fprintf(output, "\nCoverage Recommendations:\n");
    fprintf(output, "- Functions with < 80%% coverage should be reviewed\n");
    fprintf(output, "- Critical kernel functions should have 100%% coverage\n");
    fprintf(output, "- Error handling paths should be tested\n");
    fprintf(output, "- Edge cases should be covered\n");
    
    fclose(output);
    
    // Cleanup
    for (int i = 0; i < file_count; i++) {
        free(files[i].filename);
    }
    free(files);
}

int main() {
    generate_coverage_report("custom-coverage-report.txt");
    return 0;
}
EOF
    
    # Compile and run custom analyzer
    gcc -o ${REPORTS_DIR}/coverage-analyzer ${REPORTS_DIR}/coverage-analyzer.c
    
    # Run in directory with gcov files
    cd ${REPORTS_DIR}
    ./coverage-analyzer
    cd - > /dev/null
    
    echo "Custom coverage analysis completed"
}

# Function to analyze branch coverage
analyze_branch_coverage() {
    echo "Analyzing branch coverage..."
    
    # Find branch coverage information in gcov files
    find ${REPORTS_DIR} -name "*.gcov" -type f -exec grep -H "branch" {} \; > ${REPORTS_DIR}/branch-coverage.txt
    
    # Analyze branch coverage
    if [ -f "${REPORTS_DIR}/branch-coverage.txt" ]; then
        total_branches=$(wc -l < ${REPORTS_DIR}/branch-coverage.txt)
        taken_branches=$(grep -c "taken" ${REPORTS_DIR}/branch-coverage.txt || echo "0")
        
        branch_coverage=0
        if [ $total_branches -gt 0 ]; then
            branch_coverage=$((taken_branches * 100 / total_branches))
        fi
        
        echo "Branch Coverage Analysis:" > ${REPORTS_DIR}/branch-coverage-analysis.txt
        echo "=======================" >> ${REPORTS_DIR}/branch-coverage-analysis.txt
        echo "Total branches: $total_branches" >> ${REPORTS_DIR}/branch-coverage-analysis.txt
        echo "Taken branches: $taken_branches" >> ${REPORTS_DIR}/branch-coverage-analysis.txt
        echo "Branch coverage: ${branch_coverage}%" >> ${REPORTS_DIR}/branch-coverage-analysis.txt
    fi
    
    echo "Branch coverage analysis completed"
}

# Function to identify uncovered code
identify_uncovered_code() {
    echo "Identifying uncovered code..."
    
    # Find lines that are never executed
    find ${REPORTS_DIR} -name "*.gcov" -type f -exec grep -H "^    -" {} \; > ${REPORTS_DIR}/uncovered-lines.txt
    
    # Analyze uncovered code patterns
    if [ -f "${REPORTS_DIR}/uncovered-lines.txt" ]; then
        echo "Uncovered Code Analysis:" > ${REPORTS_DIR}/uncovered-analysis.txt
        echo "=======================" >> ${REPORTS_DIR}/uncovered-analysis.txt
        
        # Count uncovered lines per file
        awk -F: '{count[$1]++} END {for (file in count) print file ": " count[file] " uncovered lines"}' \
            ${REPORTS_DIR}/uncovered-lines.txt | sort -nr -k2 >> ${REPORTS_DIR}/uncovered-analysis.txt
        
        # Find common patterns in uncovered code
        echo "" >> ${REPORTS_DIR}/uncovered-analysis.txt
        echo "Common uncovered patterns:" >> ${REPORTS_DIR}/uncovered-analysis.txt
        
        # Error handling code
        grep -i "error\|fail\|exception" ${REPORTS_DIR}/uncovered-lines.txt | wc -l >> ${REPORTS_DIR}/uncovered-analysis.txt
        
        # Debug code
        grep -i "debug\|log\|print" ${REPORTS_DIR}/uncovered-lines.txt | wc -l >> ${REPORTS_DIR}/uncovered-analysis.txt
        
        # Edge cases
        grep -i "edge\|corner\|boundary" ${REPORTS_DIR}/uncovered-lines.txt | wc -l >> ${REPORTS_DIR}/uncovered-analysis.txt
    fi
    
    echo "Uncovered code analysis completed"
}

# Function to generate coverage summary
generate_coverage_summary() {
    echo "Generating coverage summary..."
    
    cat > ${REPORTS_DIR}/coverage-summary.txt << EOF
CATE-Kernel Code Coverage Summary
===============================
Date: $(date)
Source Directory: ${SRC_DIR}
Build Directory: ${BUILD_DIR}/coverage
Reports Directory: ${REPORTS_DIR}

Coverage Results:
EOF

    # Check for coverage results
    if [ -f "${REPORTS_DIR}/coverage-gcovr.txt" ]; then
        echo "- Gcovr coverage: Available" >> ${REPORTS_DIR}/coverage-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/coverage-filtered.info" ]; then
        echo "- Lcov coverage: Available" >> ${REPORTS_DIR}/coverage-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/custom-coverage-report.txt" ]; then
        echo "- Custom coverage: Available" >> ${REPORTS_DIR}/coverage-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/branch-coverage-analysis.txt" ]; then
        echo "- Branch coverage: Available" >> ${REPORTS_DIR}/coverage-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/uncovered-analysis.txt" ]; then
        echo "- Uncovered code analysis: Available" >> ${REPORTS_DIR}/coverage-summary.txt
    fi
    
    echo "" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "Coverage Recommendations:" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "- Aim for > 80% line coverage" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "- Aim for > 70% branch coverage" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "- Test error handling paths" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "- Test edge cases and boundary conditions" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "- Add tests for uncovered code" >> ${REPORTS_DIR}/coverage-summary.txt
    echo "- Use coverage data to guide test development" >> ${REPORTS_DIR}/coverage-summary.txt
    
    echo "Coverage summary generated: ${REPORTS_DIR}/coverage-summary.txt"
}

# Main execution
main() {
    echo "Starting code coverage analysis..."
    
    # Build with coverage
    build_with_coverage
    
    # Run coverage tools
    run_gcov
    run_lcov
    run_gcovr
    run_custom_coverage
    analyze_branch_coverage
    identify_uncovered_code
    
    # Generate summary
    generate_coverage_summary
    
    echo ""
    echo "Code coverage analysis completed!"
    echo "Reports available in: ${REPORTS_DIR}/"
    echo ""
    echo "Key reports:"
    echo "- Summary: ${REPORTS_DIR}/coverage-summary.txt"
    echo "- Gcovr: ${REPORTS_DIR}/coverage-gcovr.html"
    echo "- Lcov: ${REPORTS_DIR}/lcov-html/index.html"
    echo "- Custom: ${REPORTS_DIR}/custom-coverage-report.txt"
    echo "- Branch: ${REPORTS_DIR}/branch-coverage-analysis.txt"
    echo "- Uncovered: ${REPORTS_DIR}/uncovered-analysis.txt"
    echo ""
    echo "XML reports:"
    echo "- Gcovr: ${REPORTS_DIR}/coverage-gcovr.xml"
    echo "- Lcov: ${REPORTS_DIR}/coverage-filtered.info"
}

# Run main function
main "$@"