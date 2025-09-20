#!/bin/bash

# Version Update Script for CensGate Redact
# This script automates version updates across the codebase

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 <new_version> [options]"
    echo ""
    echo "Arguments:"
    echo "  new_version    The new version to set (e.g., v0.3.0, 0.3.0)"
    echo ""
    echo "Options:"
    echo "  --dry-run      Show what would be changed without making changes"
    echo "  --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 v0.3.0"
    echo "  $0 0.3.0 --dry-run"
    echo ""
    echo "This script will update version references in:"
    echo "  - cmd/redactctl/version.go"
    echo "  - cmd/redactctl/root.go"
    echo "  - README.md"
    echo "  - .github/workflows/release.yml (if applicable)"
}

# Function to validate version format
validate_version() {
    local version=$1
    
    # Remove 'v' prefix if present for validation
    local clean_version=${version#v}
    
    # Check if version matches semantic versioning pattern
    if [[ ! $clean_version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]]; then
        print_error "Invalid version format: $version"
        print_error "Version must follow semantic versioning (e.g., 1.0.0, v0.3.0, 1.0.0-beta.1)"
        exit 1
    fi
    
    print_success "Version format is valid: $version"
}

# Function to update version in version.go
update_version_go() {
    local new_version=$1
    local dry_run=$2
    local file="cmd/redactctl/version.go"
    
    print_status "Updating version in $file"
    
    if [[ $dry_run == "true" ]]; then
        echo "Would change: version = \"$new_version\""
        return
    fi
    
    # Update the version variable
    if sed -i.bak "s/version   = \"[^\"]*\"/version   = \"$new_version\"/" "$file"; then
        rm -f "$file.bak"
        print_success "Updated version in $file"
    else
        print_error "Failed to update $file"
        exit 1
    fi
}

# Function to update version in root.go
update_root_go() {
    local new_version=$1
    local dry_run=$2
    local file="cmd/redactctl/root.go"
    
    print_status "Updating version in $file"
    
    if [[ $dry_run == "true" ]]; then
        echo "Would change: Version: \"$new_version\""
        return
    fi
    
    # Update the Version field
    if sed -i.bak "s/Version: \"[^\"]*\"/Version: \"$new_version\"/" "$file"; then
        rm -f "$file.bak"
        print_success "Updated version in $file"
    else
        print_error "Failed to update $file"
        exit 1
    fi
}

# Function to update version references in README.md
update_readme() {
    local new_version=$1
    local dry_run=$2
    local file="README.md"
    
    print_status "Updating version references in $file"
    
    if [[ $dry_run == "true" ]]; then
        echo "Would update go get command to: go get github.com/censgate/redact@$new_version"
        echo "Would update changelog references to: $new_version"
        return
    fi
    
    # Update go get command
    if sed -i.bak "s|go get github.com/censgate/redact@v[0-9]\+\.[0-9]\+\.[0-9]\+|go get github.com/censgate/redact@$new_version|" "$file"; then
        print_success "Updated go get command in $file"
    else
        print_warning "Could not update go get command in $file (may not exist)"
    fi
    
    # Update changelog version references
    if sed -i.bak "s|#### ✅ \*\*Overlapping Redactions Resolution (v[0-9]\+\.[0-9]\+\.[0-9]\+)\*\*|#### ✅ **Overlapping Redactions Resolution ($new_version)**|" "$file"; then
        print_success "Updated changelog references in $file"
    else
        print_warning "Could not update changelog references in $file (may not exist)"
    fi
    
    # Clean up backup file
    rm -f "$file.bak"
}

# Function to update CHANGELOG.md
update_changelog() {
    local new_version=$1
    local dry_run=$2
    local file="CHANGELOG.md"
    
    if [[ ! -f "$file" ]]; then
        print_warning "CHANGELOG.md not found, skipping"
        return
    fi
    
    print_status "Updating CHANGELOG.md"
    
    if [[ $dry_run == "true" ]]; then
        echo "Would add new version entry to $file"
        return
    fi
    
    # Add new version entry at the top
    local today=$(date +"%Y-%m-%d")
    local temp_file=$(mktemp)
    
    # Create header
    cat > "$temp_file" << EOF
# Changelog

All notable changes to this project will be documented in this file.

## [$new_version] - $today

### Added
- 

### Fixed
- 

### Changed
- 

EOF
    
    # Append existing changelog content (preserve formatting)
    if [[ -s "$file" ]]; then
        # Skip only the header lines, preserve everything else including empty lines
        # Find the first line that starts with "## [" (version entry)
        local first_version_line=$(grep -n "^## \[" "$file" | head -1 | cut -d: -f1)
        if [[ -n "$first_version_line" ]]; then
            # Copy everything from the first version line onwards
            tail -n +"$first_version_line" "$file" >> "$temp_file"
        else
            # If no version found, skip just the header lines
            tail -n +4 "$file" >> "$temp_file"
        fi
    fi
    
    mv "$temp_file" "$file"
    print_success "Updated CHANGELOG.md with new version entry"
}

# Function to create version update summary
create_summary() {
    local new_version=$1
    local dry_run=$2
    
    echo ""
    echo "=========================================="
    if [[ $dry_run == "true" ]]; then
        echo "DRY RUN SUMMARY - No changes made"
    else
        echo "VERSION UPDATE SUMMARY"
    fi
    echo "=========================================="
    echo "New version: $new_version"
    echo "Files updated:"
    echo "  ✓ cmd/redactctl/version.go"
    echo "  ✓ cmd/redactctl/root.go"
    echo "  ✓ README.md"
    echo "  ✓ CHANGELOG.md"
    echo ""
    
    if [[ $dry_run == "true" ]]; then
        print_warning "This was a dry run. Use without --dry-run to make actual changes."
    else
        print_success "Version update completed successfully!"
        echo ""
        echo "Next steps:"
        echo "1. Review the changes: git diff"
        echo "2. Commit the changes: git commit -m \"chore: bump version to $new_version\""
        echo "3. Create a tag: git tag $new_version"
        echo "4. Push changes: git push origin main --tags"
    fi
}

# Main function
main() {
    local new_version=""
    local dry_run="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run="true"
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [[ -z "$new_version" ]]; then
                    new_version=$1
                else
                    print_error "Multiple versions specified"
                    show_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Check if version was provided
    if [[ -z "$new_version" ]]; then
        print_error "No version specified"
        show_usage
        exit 1
    fi
    
    # Validate version format
    validate_version "$new_version"
    
    # Ensure we're in the project root
    if [[ ! -f "go.mod" ]] || [[ ! -d "cmd/redactctl" ]]; then
        print_error "This script must be run from the project root directory"
        exit 1
    fi
    
    print_status "Starting version update to $new_version"
    
    # Update files
    update_version_go "$new_version" "$dry_run"
    update_root_go "$new_version" "$dry_run"
    update_readme "$new_version" "$dry_run"
    update_changelog "$new_version" "$dry_run"
    
    # Create summary
    create_summary "$new_version" "$dry_run"
}

# Run main function with all arguments
main "$@"
