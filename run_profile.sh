#!/bin/bash

# CATE-Kernel Performance Profiling Script
# Runs performance profiling and analysis on the kernel

set -e

echo "Running performance profiling on CATE-Kernel..."

# Configuration
BUILD_DIR="build"
REPORTS_DIR="reports"
PROFILE_TOOLS="perf gprof valgrind callgrind"

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

# Function to profile with perf
run_perf_profile() {
    echo "Running perf profiling..."
    
    if ! check_tool perf; then
        return
    fi
    
    # Check if kernel is built with debug symbols
    if [ ! -f "${BUILD_DIR}/kernel.elf" ]; then
        echo "Error: kernel.elf not found. Please build the kernel first."
        return
    fi
    
    # Record performance data
    echo "Recording performance data..."
    perf record -g -o ${REPORTS_DIR}/perf.data \
        qemu-system-x86_64 \
        -kernel ${BUILD_DIR}/kernel.elf \
        -m 512 \
        -serial stdio \
        -nographic \
        -append "console=ttyS0" \
        2>/dev/null || true
    
    # Generate perf report
    if [ -f "${REPORTS_DIR}/perf.data" ]; then
        perf report -i ${REPORTS_DIR}/perf.data > ${REPORTS_DIR}/perf-report.txt
        perf annotate -i ${REPORTS_DIR}/perf.data > ${REPORTS_DIR}/perf-annotate.txt
        
        # Generate flame graph
        if command -v flamegraph.pl &> /dev/null; then
            perf script -i ${REPORTS_DIR}/perf.data | flamegraph.pl > ${REPORTS_DIR}/perf-flame.svg
            echo "Flame graph generated: ${REPORTS_DIR}/perf-flame.svg"
        fi
    fi
    
    echo "Perf profiling completed"
}

# Function to profile with gprof
run_gprof_profile() {
    echo "Running gprof profiling..."
    
    if ! check_tool gprof; then
        return
    fi
    
    # Check if kernel is built with profiling
    if [ ! -f "${BUILD_DIR}/kernel.gmon" ]; then
        echo "Warning: kernel.gmon not found. Kernel may not be built with profiling."
        return
    fi
    
    # Generate gprof report
    gprof ${BUILD_DIR}/kernel.elf ${BUILD_DIR}/kernel.gmon > ${REPORTS_DIR}/gprof-report.txt
    
    # Generate call graph
    if command -v gprof2dot &> /dev/null; then
        gprof ${BUILD_DIR}/kernel.elf ${BUILD_DIR}/kernel.gmon | gprof2dot | dot -Tpng -o ${REPORTS_DIR}/gprof-callgraph.png
        echo "Call graph generated: ${REPORTS_DIR}/gprof-callgraph.png"
    fi
    
    echo "Gprof profiling completed"
}

# Function to profile with Valgrind
run_valgrind_profile() {
    echo "Running Valgrind profiling..."
    
    if ! check_tool valgrind; then
        return
    fi
    
    # Memory profiling
    echo "Running memory profiling..."
    valgrind \
        --tool=memcheck \
        --leak-check=full \
        --show-leak-kinds=all \
        --track-origins=yes \
        --xml=yes \
        --xml-file=${REPORTS_DIR}/valgrind-memcheck.xml \
        qemu-system-x86_64 \
        -kernel ${BUILD_DIR}/kernel.elf \
        -m 512 \
        -serial stdio \
        -nographic \
        2> ${REPORTS_DIR}/valgrind-memcheck.txt || true
    
    # Cache profiling
    echo "Running cache profiling..."
    valgrind \
        --tool=cachegrind \
        --branch-sim=yes \
        --cache-sim=yes \
        --xml=yes \
        --xml-file=${REPORTS_DIR}/valgrind-cachegrind.xml \
        qemu-system-x86_64 \
        -kernel ${BUILD_DIR}/kernel.elf \
        -m 512 \
        -serial stdio \
        -nographic \
        2> ${REPORTS_DIR}/valgrind-cachegrind.txt || true
    
    # Callgrind profiling
    echo "Running callgrind profiling..."
    valgrind \
        --tool=callgrind \
        --collect-jumps=yes \
        --collect-systime=yes \
        --callgrind-out-file=${REPORTS_DIR}/callgrind.out \
        qemu-system-x86_64 \
        -kernel ${BUILD_DIR}/kernel.elf \
        -m 512 \
        -serial stdio \
        -nographic \
        2> ${REPORTS_DIR}/valgrind-callgrind.txt || true
    
    # Generate callgrind reports
    if [ -f "${REPORTS_DIR}/callgrind.out" ]; then
        if check_tool callgrind_annotate; then
            callgrind_annotate ${REPORTS_DIR}/callgrind.out > ${REPORTS_DIR}/callgrind-annotate.txt
        fi
        
        if check_tool kcachegrind; then
            echo "Open kcachegrind ${REPORTS_DIR}/callgrind.out for visual analysis"
        fi
    fi
    
    echo "Valgrind profiling completed"
}

# Function to analyze kernel boot time
analyze_boot_time() {
    echo "Analyzing kernel boot time..."
    
    # Run kernel and capture boot messages with timestamps
    timeout 30s qemu-system-x86_64 \
        -kernel ${BUILD_DIR}/kernel.elf \
        -m 512 \
        -serial stdio \
        -nographic \
        -append "console=ttyS0" \
        2>&1 | ts '[%Y-%m-%d %H:%M:%S]' > ${REPORTS_DIR}/boot-log.txt || true
    
    # Analyze boot sequence
    if [ -f "${REPORTS_DIR}/boot-log.txt" ]; then
        echo "Boot time analysis:" > ${REPORTS_DIR}/boot-analysis.txt
        
        # Find key boot phases
        grep -n "Initializing" ${REPORTS_DIR}/boot-log.txt >> ${REPORTS_DIR}/boot-analysis.txt
        grep -n "completed" ${REPORTS_DIR}/boot-log.txt >> ${REPORTS_DIR}/boot-analysis.txt
        grep -n "ready" ${REPORTS_DIR}/boot-log.txt >> ${REPORTS_DIR}/boot-analysis.txt
        
        # Calculate boot phases
        echo "" >> ${REPORTS_DIR}/boot-analysis.txt
        echo "Boot phase timing:" >> ${REPORTS_DIR}/boot-analysis.txt
        
        # Extract timestamps and calculate durations
        awk '
        /Initializing/ { init_time = $1 " " $2 }
        /completed/ { comp_time = $1 " " $2 }
        /ready/ { ready_time = $1 " " $2 }
        END {
            if (init_time && comp_time && ready_time) {
                print "Initialization phase: " init_time " to " comp_time
                print "Completion phase: " comp_time " to " ready_time
            }
        }
        ' ${REPORTS_DIR}/boot-log.txt >> ${REPORTS_DIR}/boot-analysis.txt
    fi
    
    echo "Boot time analysis completed"
}

# Function to analyze memory usage
analyze_memory_usage() {
    echo "Analyzing memory usage..."
    
    # Create memory usage test
    cat > ${REPORTS_DIR}/memory-test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Test memory allocation patterns
    int *arr = malloc(1000 * sizeof(int));
    if (arr) {
        memset(arr, 0, 1000 * sizeof(int));
        free(arr);
    }
    
    // Test string operations
    char *str = malloc(256);
    if (str) {
        strcpy(str, "Memory test string");
        strcat(str, " - completed");
        free(str);
    }
    
    return 0;
}
EOF
    
    # Compile and analyze
    gcc -g -o ${REPORTS_DIR}/memory-test ${REPORTS_DIR}/memory-test.c
    
    # Run with massif (Valgrind heap profiler)
    if check_tool valgrind; then
        valgrind \
            --tool=massif \
            --massif-out-file=${REPORTS_DIR}/massif.out \
            --threshold=0.1 \
            ${REPORTS_DIR}/memory-test 2> ${REPORTS_DIR}/massif.txt || true
        
        # Generate massif report
        if [ -f "${REPORTS_DIR}/massif.out" ]; then
            ms_print ${REPORTS_DIR}/massif.out > ${REPORTS_DIR}/massif-report.txt
            echo "Massif report generated: ${REPORTS_DIR}/massif-report.txt"
        fi
    fi
    
    echo "Memory usage analysis completed"
}

# Function to analyze code complexity
analyze_complexity() {
    echo "Analyzing code complexity..."
    
    # Use pmccabe for complexity analysis
    if check_tool pmccabe; then
        find ${SRC_DIR} -name "*.c" -type f -exec pmccabe {} \; > ${REPORTS_DIR}/complexity-raw.txt
        
        # Sort by complexity
        sort -nr ${REPORTS_DIR}/complexity-raw.txt > ${REPORTS_DIR}/complexity-sorted.txt
        
        # Generate complexity statistics
        echo "Complexity Statistics:" > ${REPORTS_DIR}/complexity-stats.txt
        echo "====================" >> ${REPORTS_DIR}/complexity-stats.txt
        
        # Count functions by complexity ranges
        low=$(awk '$1 <= 10' ${REPORTS_DIR}/complexity-sorted.txt | wc -l)
        medium=$(awk '$1 > 10 && $1 <= 20' ${REPORTS_DIR}/complexity-sorted.txt | wc -l)
        high=$(awk '$1 > 20 && $1 <= 50' ${REPORTS_DIR}/complexity-sorted.txt | wc -l)
        very_high=$(awk '$1 > 50' ${REPORTS_DIR}/complexity-sorted.txt | wc -l)
        
        echo "Low complexity (≤10): $low functions" >> ${REPORTS_DIR}/complexity-stats.txt
        echo "Medium complexity (11-20): $medium functions" >> ${REPORTS_DIR}/complexity-stats.txt
        echo "High complexity (21-50): $high functions" >> ${REPORTS_DIR}/complexity-stats.txt
        echo "Very high complexity (>50): $very_high functions" >> ${REPORTS_DIR}/complexity-stats.txt
        
        # Find most complex functions
        echo "" >> ${REPORTS_DIR}/complexity-stats.txt
        echo "Top 10 most complex functions:" >> ${REPORTS_DIR}/complexity-stats.txt
        head -10 ${REPORTS_DIR}/complexity-sorted.txt >> ${REPORTS_DIR}/complexity-stats.txt
    fi
    
    echo "Complexity analysis completed"
}

# Function to analyze function call graphs
analyze_call_graphs() {
    echo "Analyzing function call graphs..."
    
    # Use cflow for call graph analysis
    if check_tool cflow; then
        find ${SRC_DIR} -name "*.c" -type f | xargs cflow -d 3 > ${REPORTS_DIR}/call-graph.txt
        
        # Generate call graph statistics
        echo "Call Graph Statistics:" > ${REPORTS_DIR}/call-graph-stats.txt
        echo "=====================" >> ${REPORTS_DIR}/call-graph-stats.txt
        
        # Count function calls
        total_functions=$(grep -c "^[a-zA-Z_][a-zA-Z0-9_]*()" ${REPORTS_DIR}/call-graph.txt || echo "0")
        echo "Total functions: $total_functions" >> ${REPORTS_DIR}/call-graph-stats.txt
        
        # Find functions with most calls
        echo "" >> ${REPORTS_DIR}/call-graph-stats.txt
        echo "Functions with most calls:" >> ${REPORTS_DIR}/call-graph-stats.txt
        grep -E "^\s+[a-zA-Z_][a-zA-Z0-9_]*\(\)" ${REPORTS_DIR}/call-graph.txt | \
            sort | uniq -c | sort -nr | head -10 >> ${REPORTS_DIR}/call-graph-stats.txt
    fi
    
    echo "Call graph analysis completed"
}

# Function to generate performance summary
generate_performance_summary() {
    echo "Generating performance summary..."
    
    cat > ${REPORTS_DIR}/performance-summary.txt << EOF
CATE-Kernel Performance Profiling Summary
========================================
Date: $(date)
Build Directory: ${BUILD_DIR}
Reports Directory: ${REPORTS_DIR}

Profiling Results:
EOF

    # Check for profiling results
    if [ -f "${REPORTS_DIR}/perf-report.txt" ]; then
        echo "- Perf profiling: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/gprof-report.txt" ]; then
        echo "- Gprof profiling: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/valgrind-memcheck.xml" ]; then
        echo "- Valgrind memory profiling: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/valgrind-cachegrind.xml" ]; then
        echo "- Valgrind cache profiling: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/callgrind.out" ]; then
        echo "- Callgrind profiling: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/boot-analysis.txt" ]; then
        echo "- Boot time analysis: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/massif-report.txt" ]; then
        echo "- Memory usage analysis: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/complexity-stats.txt" ]; then
        echo "- Code complexity analysis: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    if [ -f "${REPORTS_DIR}/call-graph-stats.txt" ]; then
        echo "- Call graph analysis: Available" >> ${REPORTS_DIR}/performance-summary.txt
    fi
    
    echo "" >> ${REPORTS_DIR}/performance-summary.txt
    echo "Performance Recommendations:" >> ${REPORTS_DIR}/performance-summary.txt
    echo "- Optimize high-complexity functions" >> ${REPORTS_DIR}/performance-summary.txt
    echo "- Review memory allocation patterns" >> ${REPORTS_DIR}/performance-summary.txt
    echo "- Optimize cache usage" >> ${REPORTS_DIR}/performance-summary.txt
    echo "- Reduce function call overhead" >> ${REPORTS_DIR}/performance-summary.txt
    echo "- Profile critical code paths" >> ${REPORTS_DIR}/performance-summary.txt
    echo "- Optimize boot sequence" >> ${REPORTS_DIR}/performance-summary.txt
    
    echo "Performance summary generated: ${REPORTS_DIR}/performance-summary.txt"
}

# Main execution
main() {
    echo "Starting performance profiling..."
    
    # Run all profiling tools
    run_perf_profile
    run_gprof_profile
    run_valgrind_profile
    analyze_boot_time
    analyze_memory_usage
    analyze_complexity
    analyze_call_graphs
    
    # Generate summary
    generate_performance_summary
    
    echo ""
    echo "Performance profiling completed!"
    echo "Reports available in: ${REPORTS_DIR}/"
    echo ""
    echo "Key reports:"
    echo "- Summary: ${REPORTS_DIR}/performance-summary.txt"
    echo "- Perf: ${REPORTS_DIR}/perf-report.txt"
    echo "- Gprof: ${REPORTS_DIR}/gprof-report.txt"
    echo "- Valgrind: ${REPORTS_DIR}/valgrind-*.txt"
    echo "- Boot time: ${REPORTS_DIR}/boot-analysis.txt"
    echo "- Memory: ${REPORTS_DIR}/massif-report.txt"
    echo "- Complexity: ${REPORTS_DIR}/complexity-stats.txt"
    echo "- Call graphs: ${REPORTS_DIR}/call-graph-stats.txt"
    echo ""
    echo "Visual reports:"
    echo "- Flame graph: ${REPORTS_DIR}/perf-flame.svg"
    echo "- Call graph: ${REPORTS_DIR}/gprof-callgraph.png"
    echo "- KCachegrind: ${REPORTS_DIR}/callgrind.out"
}

# Run main function
main "$@"