#!/bin/bash

# CATE-Kernel Code Formatting Script
# Formats the kernel source code according to coding standards

set -e

echo "Formatting CATE-Kernel source code..."

# Configuration
SRC_DIR="src"
FORMATTING_TOOLS="clang-format astyle uncrustify"

# Function to check if tool is available
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "Warning: $1 is not installed, skipping..."
        return 1
    fi
    return 0
}

# Function to create clang-format configuration
create_clang_format_config() {
    echo "Creating clang-format configuration..."
    
    cat > .clang-format << 'EOF'
# CATE-Kernel clang-format configuration
# Based on Linux kernel style with modifications

Language: Cpp
BasedOnStyle: LLVM
IndentWidth: 4
TabWidth: 4
UseTab: Never
ColumnLimit: 80
MaxEmptyLinesToKeep: 2
KeepEmptyLinesAtTheStartOfBlocks: false
AllowShortFunctionsOnASingleLine: None
AllowShortIfStatementsOnASingleLine: false
AllowShortLoopsOnASingleLine: false
AlwaysBreakAfterDefinitionReturnType: None
AlwaysBreakAfterReturnType: None
AlwaysBreakBeforeMultilineStrings: false
AlwaysBreakTemplateDeclarations: false
BinPackArguments: false
BinPackParameters: false
BreakBeforeBinaryOperators: NonAssignment
BreakBeforeBraces: Linux
BreakBeforeTernaryOperators: false
BreakConstructorInitializers: BeforeColon
BreakStringLiterals: false
CompactNamespaces: false
ConstructorInitializerAllOnOneLineOrOnePerLine: false
ConstructorInitializerIndentWidth: 4
ContinuationIndentWidth: 4
Cpp11BracedListStyle: false
DerivePointerAlignment: false
DisableFormat: false
ExperimentalAutoDetectBinPacking: false
FixNamespaceComments: false
ForEachMacros: ['foreach', 'Q_FOREACH', 'BOOST_FOREACH']
IncludeCategories:
  - Regex: '^"(llvm|llvm-c|clang|clang-c)/'
    Priority: 2
  - Regex: '^(<|"(gtest|gmock|isl|json)/)'
    Priority: 3
  - Regex: '.*'
    Priority: 1
IndentCaseLabels: false
IndentPPDirectives: None
IndentWrappedFunctionNames: false
KeepEmptyLinesAtTheStartOfBlocks: true
MacroBlockBegin: ''
MacroBlockEnd: ''
NamespaceIndentation: None
ObjCBlockIndentWidth: 2
ObjCSpaceAfterProperty: false
ObjCSpaceBeforeProtocolList: true
PenaltyBreakAssignment: 2
PenaltyBreakBeforeFirstCallParameter: 19
PenaltyBreakComment: 300
PenaltyBreakFirstLessLess: 120
PenaltyBreakString: 1000
PenaltyExcessCharacter: 1000000
PenaltyReturnTypeOnItsOwnLine: 60
PointerAlignment: Right
ReflowComments: true
SortIncludes: true
SortUsingDeclarations: true
SpaceAfterCStyleCast: false
SpaceAfterLogicalNot: false
SpaceAfterTemplateKeyword: true
SpaceBeforeAssignmentOperators: true
SpaceBeforeCpp11BracedList: false
SpaceBeforeCtorInitializerColon: true
SpaceBeforeInheritanceColon: true
SpaceBeforeParens: ControlStatements
SpaceBeforeRangeBasedForLoopColon: true
SpaceInEmptyParentheses: false
SpacesBeforeTrailingComments: 1
SpacesInAngles: false
SpacesInCStyleCastParentheses: false
SpacesInContainerLiterals: true
SpacesInParentheses: false
SpacesInSquareBrackets: false
Standard: Cpp03
EOF
    
    echo "Clang-format configuration created: .clang-format"
}

# Function to create astyle configuration
create_astyle_config() {
    echo "Creating astyle configuration..."
    
    cat > .astylerc << 'EOF'
# CATE-Kernel astyle configuration
# Based on Linux kernel style

# Indentation
--indent=spaces=4
--indent-namespaces
--indent-classes
--indent-switches
--indent-cases
--indent-colon-comments

# Brackets
--style=linux
--add-brackets
--add-one-line-brackets

# Padding
--pad-oper
--pad-header
--unpad-paren
--delete-empty-lines
--fill-empty-lines

# Formatting
--align-pointer=name
--align-reference=name
--break-closing-brackets
--break-elseifs

# Other
--max-code-length=80
--min-conditional-indent=0
--suffix=none
--preserve-date
--verbose
EOF
    
    echo "Astyle configuration created: .astylerc"
}

# Function to create uncrustify configuration
create_uncrustify_config() {
    echo "Creating uncrustify configuration..."
    
    cat > .uncrustify.cfg << 'EOF'
# CATE-Kernel uncrustify configuration
# Based on Linux kernel style

# General
indent_with_tabs=0
input_tab_size=4
output_tab_size=4

# Indentation
indent_columns=4
indent_class=true
indent_namespace=true
indent_switch_case=true
indent_case_brace=3

# Newlines
nl_start_of_file=remove
nl_end_of_file=add
nl_max_blank_in_func=2
nl_after_func_proto=1
nl_after_func_proto_group=1

# Braces
mod_full_brace_if=add
mod_full_brace_for=add
mod_full_brace_while=add
mod_full_brace_do=add

# Spacing
sp_arith=add
sp_assign=add
sp_bool=add
sp_compare=add
sp_inside_paren=remove
sp_after_comma=add
sp_before_comma=remove
sp_after_semi=add
sp_before_semi=remove

# Alignment
align_var_def_span=1
align_var_def_thresh=0
align_var_def_gap=0
align_assign_span=1
align_assign_thresh=0
align_assign_gap=0

# Other
pos_bool=trail
pos_comma=trail
pos_cond=lead
pos_class_colon=lead
pos_constr_colon=lead
EOF
    
    echo "Uncrustify configuration created: .uncrustify.cfg"
}

# Function to format with clang-format
format_clang_format() {
    echo "Formatting with clang-format..."
    
    if ! check_tool clang-format; then
        return
    fi
    
    # Find all C and header files
    find ${SRC_DIR} -name "*.c" -o -name "*.h" > ${REPORTS_DIR}/format-files.txt
    
    # Format each file
    while IFS= read -r file; do
        echo "Formatting: $file"
        clang-format -i -style=file "$file"
    done < ${REPORTS_DIR}/format-files.txt
    
    echo "Clang-format formatting completed"
}

# Function to format with astyle
format_astyle() {
    echo "Formatting with astyle..."
    
    if ! check_tool astyle; then
        return
    fi
    
    # Format C files
    find ${SRC_DIR} -name "*.c" -type f -exec astyle --options=.astylerc {} \;
    
    # Format header files
    find ${SRC_DIR} -name "*.h" -type f -exec astyle --options=.astylerc {} \;
    
    echo "Astyle formatting completed"
}

# Function to format with uncrustify
format_uncrustify() {
    echo "Formatting with uncrustify..."
    
    if ! check_tool uncrustify; then
        return
    fi
    
    # Format C files
    find ${SRC_DIR} -name "*.c" -type f -exec uncrustify -c .uncrustify.cfg --no-backup {} \;
    
    # Format header files
    find ${SRC_DIR} -name "*.h" -type f -exec uncrustify -c .uncrustify.cfg --no-backup {} \;
    
    echo "Uncrustify formatting completed"
}

# Function to check code style
check_code_style() {
    echo "Checking code style..."
    
    # Create style check report
    > ${REPORTS_DIR}/style-check.txt
    
    # Check for common style issues
    echo "Checking for style issues..."
    
    # Check indentation
    echo "Checking indentation..." >> ${REPORTS_DIR}/style-check.txt
    find ${SRC_DIR} -name "*.c" -o -name "*.h" | xargs grep -n "^	" >> ${REPORTS_DIR}/style-check.txt || true
    
    # Check for trailing whitespace
    echo "Checking for trailing whitespace..." >> ${REPORTS_DIR}/style-check.txt
    find ${SRC_DIR} -name "*.c" -o -name "*.h" | xargs grep -n "[[:space:]]$" >> ${REPORTS_DIR}/style-check.txt || true
    
    # Check for long lines
    echo "Checking for long lines (>80 characters)..." >> ${REPORTS_DIR}/style-check.txt
    find ${SRC_DIR} -name "*.c" -o -name "*.h" | xargs grep -n "^.\{81,\}" >> ${REPORTS_DIR}/style-check.txt || true
    
    # Check for mixed case variable names
    echo "Checking for mixed case variable names..." >> ${REPORTS_DIR}/style-check.txt
    find ${SRC_DIR} -name "*.c" -o -name "*.h" | xargs grep -n "[a-z][A-Z]" >> ${REPORTS_DIR}/style-check.txt || true
    
    # Check for magic numbers
    echo "Checking for magic numbers..." >> ${REPORTS_DIR}/style-check.txt
    find ${SRC_DIR} -name "*.c" -o -name "*.h" | xargs grep -n "[0-9]\{3,\}" >> ${REPORTS_DIR}/style-check.txt || true
    
    echo "Style check completed: ${REPORTS_DIR}/style-check.txt"
}

# Function to generate formatting report
generate_formatting_report() {
    echo "Generating formatting report..."
    
    cat > ${REPORTS_DIR}/formatting-summary.txt << EOF
CATE-Kernel Code Formatting Summary
==================================
Date: $(date)
Source Directory: ${SRC_DIR}

Formatting Results:
EOF

    # Count files
    total_files=$(find ${SRC_DIR} -name "*.c" -o -name "*.h" | wc -l)
    echo "Total files processed: $total_files" >> ${REPORTS_DIR}/formatting-summary.txt
    
    # Check for formatting issues
    if [ -f "${REPORTS_DIR}/style-check.txt" ]; then
        style_issues=$(wc -l < ${REPORTS_DIR}/style-check.txt || echo "0")
        echo "Style issues found: $style_issues" >> ${REPORTS_DIR}/formatting-summary.txt
    fi
    
    echo "" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "Formatting Recommendations:" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Use consistent indentation (4 spaces)" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Follow Linux kernel coding style" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Keep lines under 80 characters" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Use meaningful variable names" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Add proper spacing around operators" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Use consistent brace style" >> ${REPORTS_DIR}/formatting-summary.txt
    echo "- Add comments for complex code" >> ${REPORTS_DIR}/formatting-summary.txt
    
    echo "Formatting report generated: ${REPORTS_DIR}/formatting-summary.txt"
}

# Function to validate formatting
validate_formatting() {
    echo "Validating formatting..."
    
    # Check if files were actually formatted
    echo "Checking formatting validation..."
    
    # Create a simple test
    cat > ${REPORTS_DIR}/format-test.c << 'EOF'
int main() {
    int x=1,y=2;
    if(x>y){
        printf("x is greater");
    }
    return 0;
}
EOF
    
    # Format the test file
    if check_tool clang-format; then
        clang-format -i ${REPORTS_DIR}/format-test.c
        
        # Check if formatting was applied
        if grep -q "int x = 1, y = 2;" ${REPORTS_DIR}/format-test.c; then
            echo "Formatting validation: PASSED" >> ${REPORTS_DIR}/formatting-summary.txt
        else
            echo "Formatting validation: FAILED" >> ${REPORTS_DIR}/formatting-summary.txt
        fi
    fi
    
    echo "Formatting validation completed"
}

# Function to create coding standards document
create_coding_standards() {
    echo "Creating coding standards document..."
    
    cat > ${REPORTS_DIR}/coding-standards.md << 'EOF'
# CATE-Kernel Coding Standards

## General Principles

1. **Consistency**: Follow the existing code style throughout the project
2. **Readability**: Write code that is easy to read and understand
3. **Maintainability**: Use clear variable names and proper documentation
4. **Performance**: Consider performance implications of code changes
5. **Security**: Follow secure coding practices

## Code Style

### Indentation
- Use 4 spaces for indentation (no tabs)
- Indent case labels in switch statements
- Indent preprocessor directives

### Line Length
- Maximum 80 characters per line
- Break long lines at logical points
- Align continuation lines properly

### Braces
- Use K&R style braces for functions
- Use Linux kernel style for control structures
- Always use braces for multi-line blocks

### Spacing
- Space around operators
- Space after commas and semicolons
- No space before commas and semicolons
- Space after keywords (if, for, while, etc.)

### Naming
- Use lowercase with underscores for variables and functions
- Use UPPERCASE for constants and macros
- Use descriptive names
- Avoid abbreviations

### Comments
- Use C-style comments (/* */) for multi-line comments
- Use C++-style comments (//) for single-line comments
- Comment complex code sections
- Document function parameters and return values

## File Organization

### Header Files
- Use include guards
- Include only necessary headers
- Keep headers self-contained
- Document public interfaces

### Source Files
- Group related functions together
- Order functions logically
- Keep files focused and manageable

## Error Handling

- Always check return values
- Handle errors gracefully
- Use appropriate error codes
- Log errors appropriately

## Memory Management

- Always free allocated memory
- Check allocation results
- Use appropriate allocation functions
- Avoid memory leaks

## Security Considerations

- Validate all inputs
- Use safe string functions
- Avoid buffer overflows
- Check array bounds
- Use appropriate data types

## Performance Guidelines

- Minimize function calls in hot paths
- Use appropriate data structures
- Consider cache locality
- Profile before optimizing

## Testing

- Write unit tests for new functions
- Test error conditions
- Test edge cases
- Maintain test coverage
EOF
    
    echo "Coding standards document created: ${REPORTS_DIR}/coding-standards.md"
}

# Main execution
main() {
    echo "Starting code formatting..."
    
    # Create configuration files
    create_clang_format_config
    create_astyle_config
    create_uncrustify_config
    
    # Run formatting tools
    format_clang_format
    format_astyle
    format_uncrustify
    
    # Check and validate
    check_code_style
    validate_formatting
    
    # Generate reports
    generate_formatting_report
    create_coding_standards
    
    echo ""
    echo "Code formatting completed!"
    echo "Configuration files created:"
    echo "- .clang-format"
    echo "- .astylerc"
    echo "- .uncrustify.cfg"
    echo ""
    echo "Reports available in: ${REPORTS_DIR}/"
    echo ""
    echo "Key reports:"
    echo "- Summary: ${REPORTS_DIR}/formatting-summary.txt"
    echo "- Style check: ${REPORTS_DIR}/style-check.txt"
    echo "- Coding standards: ${REPORTS_DIR}/coding-standards.md"
    echo ""
    echo "To format code automatically, use:"
    echo "clang-format -i src/**/*.c src/**/*.h"
    echo "astyle --options=.astylerc src/**/*.c src/**/*.h"
    echo "uncrustify -c .uncrustify.cfg --no-backup src/**/*.c src/**/*.h"
}

# Run main function
main "$@"