#!/bin/bash

# Version Update Script for Censgate Redact (Rust)
# Updates the workspace version, every internal path dependency version, and docs.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_usage() {
    echo "Usage: $0 <new_version> [options]"
    echo ""
    echo "Arguments:"
    echo "  new_version    The new version to set (e.g., 0.2.0, 1.0.0-beta.1)"
    echo ""
    echo "Options:"
    echo "  --dry-run      Show what would be changed without making changes"
    echo "  --tag          Also create and push git tag"
    echo "  --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 0.2.0"
    echo "  $0 0.2.0 --dry-run"
    echo "  $0 1.0.0 --tag"
    echo ""
    echo "This script updates version in:"
    echo "  - Cargo.toml (workspace.package.version)"
    echo "  - every workspace-internal path dependency version"
    echo "    (scripts/ci/align-internal-versions.sh; a missed pin fails)"
    echo "  - README.md (library Cargo.toml example versions)"
    echo "  - docs/benchmarks/README.md (current release link)"
    echo "  - CHANGELOG.md (moves Unreleased notes under the new version)"
}

validate_version() {
    local version=$1
    # Remove 'v' prefix if present
    version=${version#v}
    
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
        print_error "Invalid version format: $version"
        print_error "Version must follow semantic versioning (e.g., 0.2.0, 1.0.0-beta.1)"
        exit 1
    fi
    
    echo "$version"
}

update_changelog() {
    local new_version=$1
    local dry_run=$2
    local file="CHANGELOG.md"
    local today script

    if [[ ! -f "$file" ]]; then
        print_warning "CHANGELOG.md not found, skipping"
        return
    fi

    today=$(date -u +"%Y-%m-%d")
    script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ci/version-changelog.sh"
    print_status "Updating CHANGELOG.md"

    if [[ $dry_run == "true" ]]; then
        echo "  Would move Unreleased notes to ## [$new_version] - $today"
        return
    fi

    "$script" "$new_version" "$today" "$file"
    print_success "Versioned $new_version in CHANGELOG.md"
}

update_doc_versions() {
    local new_version=$1
    local dry_run=$2

    print_status "Updating documentation version pins to $new_version"

    if [[ $dry_run == "true" ]]; then
        echo "  Would update README.md library Cargo.toml examples"
        echo "  Would update docs/benchmarks/README.md current release link"
        echo "  Would update CHANGELOG.md unsupported-version upgrade hint"
        return
    fi

    # README library usage example and published crate versions
    sed -i.bak \
        -e "s/^redact-core = \"[^\"]*\"/redact-core = \"$new_version\"/" \
        -e "s/^redact-ner = \"[^\"]*\"/redact-ner = \"$new_version\"/" \
        -e "s/\\(\\[\`redact-scan\`\\]([^)]*) \\)[0-9][0-9.]*\\./\\1${new_version}./" \
        -e "s/\\(\\[\`redact-verify\`\\]([^)]*) \\)[0-9][0-9.]*\\./\\1${new_version}./" \
        README.md
    rm -f README.md.bak

    if [[ -f docs/install.md ]]; then
        sed -i.bak -E \
            "s/(\\\[`redact-scan`\\]\\([^)]*\\) · \\[`redact-verify`\\]\\([^)]*\\) )\\([0-9]+\\.[0-9]+\\.[0-9]+\\)/\\1(${new_version})/" \
            docs/install.md
        rm -f docs/install.md.bak
    fi

    if [[ -f crates/redact-scan/README.md ]]; then
        sed -i.bak -E \
            "s/(\"scanner\"[[:space:]]*:[[:space:]]*\\{[^}]*\"version\"[[:space:]]*:[[:space:]]*\")[0-9]+\\.[0-9]+\\.[0-9]+(\")/\\1${new_version}\\2/" \
            crates/redact-scan/README.md
        rm -f crates/redact-scan/README.md.bak
    fi

    if [[ -f SECURITY.md ]]; then
        local major minor prior
        major="${new_version%%.*}"
        minor="${new_version#*.}"
        minor="${minor%%.*}"
        if [[ "$minor" =~ ^[0-9]+$ ]] && [[ "$minor" -gt 0 ]]; then
            prior=$((minor - 1))
            sed -i.bak \
                -e "s/^| 0\\.[0-9]\\+\\.x  | ✅ Yes | Current release |$/| ${major}.${minor}.x  | ✅ Yes | Current release |/" \
                -e "s/^| 0\\.[0-9]\\+\\.x  | ✅ Yes | Prior minor (security fixes) |$/| ${major}.${prior}.x  | ✅ Yes | Prior minor (security fixes) |/" \
                SECURITY.md
            rm -f SECURITY.md.bak
        fi
    fi

    # Benchmarks "current release" pointer
    sed -i.bak -E \
        "s|The \*\*current\*\* release is \*\*\[v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?\]\(https://github.com/censgate/redact/releases/tag/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?\)\*\*|The **current** release is **[v${new_version}](https://github.com/censgate/redact/releases/tag/v${new_version})**|" \
        docs/benchmarks/README.md
    rm -f docs/benchmarks/README.md.bak

    # Unsupported Go-era versions hint at bottom of CHANGELOG
    if grep -q "Please upgrade to v" CHANGELOG.md; then
        sed -i.bak -E \
            "s/Please upgrade to v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)? or later\./Please upgrade to v${new_version} or later./" \
            CHANGELOG.md
        rm -f CHANGELOG.md.bak
    fi

    print_success "Updated documentation version pins to $new_version"
}

verify_build() {
    local dry_run=$1
    
    if [[ $dry_run == "true" ]]; then
        print_status "Would verify: cargo check --workspace"
        return
    fi
    
    print_status "Verifying workspace builds..."
    if cargo check --workspace --quiet; then
        print_success "Workspace builds successfully"
    else
        print_error "Workspace build failed!"
        exit 1
    fi
}

create_tag() {
    local new_version=$1
    local dry_run=$2
    
    local tag="v$new_version"
    
    if [[ $dry_run == "true" ]]; then
        print_status "Would create tag: $tag"
        print_status "Would push tag to origin"
        return
    fi
    
    print_status "Creating git tag $tag"
    git tag -a "$tag" -m "Release $tag"
    print_success "Created tag $tag"
    
    print_status "Pushing tag to origin"
    git push origin "$tag"
    print_success "Pushed tag $tag"
}

main() {
    local new_version=""
    local dry_run="false"
    local create_git_tag="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run) dry_run="true"; shift ;;
            --tag) create_git_tag="true"; shift ;;
            --help|-h) show_usage; exit 0 ;;
            -*) print_error "Unknown option: $1"; show_usage; exit 1 ;;
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
    
    if [[ -z "$new_version" ]]; then
        print_error "No version specified"
        show_usage
        exit 1
    fi
    
    # Validate and clean version
    new_version=$(validate_version "$new_version")
    print_success "Version format valid: $new_version"
    
    # Ensure we're in project root
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crates" ]]; then
        print_error "This script must be run from the project root directory"
        exit 1
    fi
    
    echo ""
    print_status "Starting version update to $new_version"
    echo ""
    
    # One manifest walk. Do not grow a crate/dependency allowlist here.
    print_status "Aligning workspace version and internal path dependency pins"
    local align_script
    align_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ci/align-internal-versions.sh"
    if [[ $dry_run == "true" ]]; then
        "$align_script" --dry-run "$new_version"
    else
        "$align_script" "$new_version"
    fi
    update_doc_versions "$new_version" "$dry_run"
    update_changelog "$new_version" "$dry_run"
    
    echo ""
    verify_build "$dry_run"
    
    # Summary
    echo ""
    echo "=========================================="
    if [[ $dry_run == "true" ]]; then
        echo "DRY RUN COMPLETE - No changes made"
    else
        echo "VERSION UPDATE COMPLETE"
    fi
    echo "=========================================="
    echo "Version: $new_version"
    echo ""
    
    if [[ $dry_run == "true" ]]; then
        print_warning "Run without --dry-run to apply changes"
    else
        if [[ $create_git_tag == "true" ]]; then
            echo ""
            create_tag "$new_version" "$dry_run"
        else
            echo "Next steps:"
            echo "  1. Review changes: git diff"
            echo "  2. Commit: git commit -am \"chore: bump version to $new_version\""
            echo "  3. Push: git push"
            echo "  4. Tag: git tag -a v$new_version -m \"Release v$new_version\""
            echo "  5. Push tag: git push origin v$new_version"
            echo ""
            echo "Or run with --tag to auto-create and push the tag"
        fi
    fi
}

main "$@"
