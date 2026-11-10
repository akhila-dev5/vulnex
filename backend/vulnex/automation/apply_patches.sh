#!/bin/bash

# Description:
# This script applies patches listed in a spec file to a source directory.
# It handles both local patches and URL patches, applying them in numerical order.
# Features:
# - Skips .nopatch files automatically
# - Handles patches from both local files and URLs
# - Applies patches using -p1 with strict options (no fuzz, no backup)
# - Interactive handling of patch failures
# - Provides summary of successful and failed patches
#
# Usage:
#   ./apply_patches.sh <spec_file> <source_dir>
#
# Arguments:
#   spec_file: Path to the spec file containing Patch declarations
#   source_dir: Path to the source directory where patches will be applied
#
# Example:
#   ./apply_patches.sh /path/to/glibc.spec /path/to/glibc-2.38
#
# Expected output example:
# ```
# Applying patch: CVE-2023-4911.patch
# Successfully applied patch
# Applying patch: CVE-2023-5156.patch
# Error: Failed to apply patch: CVE-2023-5156.patch
# Patch 'CVE-2023-5156.patch' failed. Would you like to:
# 1) Continue with remaining patches
# 2) Exit the script
# Enter your choice (1 or 2): 1
# Continuing with next patch...
# Applying patch: CVE-2023-6246.patch
# Successfully applied patch
#
# Patch Application Summary:
# ==========================
# Successfully applied patches:
# CVE-2023-4911.patch
# CVE-2023-6246.patch
#
# Failed patches:
# CVE-2023-5156.patch
# ```

usage() {
    echo "Usage: $0 <spec_file> <source_dir>"
    echo "Example: $0 /path/to/glibc.spec /path/to/source"
    exit 1
}

# Check arguments
if [ $# -ne 2 ]; then
    usage
fi

SPEC_FILE="$1"
SOURCE_DIR="$2"
PATCH_DIR=$(dirname "$SPEC_FILE")

if [ ! -f "$SPEC_FILE" ]; then
    echo "Error: Spec file not found: $SPEC_FILE"
    exit 1
fi

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

# Arrays to track success and failure
declare -a successful_patches=()
declare -a failed_patches=()
# Arrays to track success and failure
successful_patches=()
failed_patches=()

# Store patches in an array first
mapfile -t patch_lines < <(grep -E "^Patch[0-9]+:" "$SPEC_FILE" | sort -V)

# Process each patch
for line in "${patch_lines[@]}"; do
    # Extract patch filename
    patch_file=$(echo "$line" | awk '{print $2}')

    # Skip .nopatch files
    if [[ "$patch_file" == *.nopatch ]]; then
        echo "Skipping disabled patch: $patch_file"
        continue
    fi

    # Handle both local patches and URL patches
    if [[ "$patch_file" == http* ]]; then
        patch_name=$(basename "$patch_file")
    else
        patch_name="$patch_file"
    fi

    # Check if patch exists in patch directory
    full_patch_path="$PATCH_DIR/$patch_name"
    if [ ! -f "$full_patch_path" ]; then
        echo "Warning: Patch file not found: $patch_name"
        failed_patches+=("$patch_name (not found)")
        continue
    fi

    echo "Applying patch: $patch_name"
    if patch -p1 -s --fuzz=0 --no-backup-if-mismatch -f < "$full_patch_path"; then
        successful_patches+=("$patch_name")
    else
        echo "Error: Failed to apply patch: $patch_name"
        failed_patches+=("$patch_name")
        echo "Patch '$patch_name' failed. Would you like to:"
        echo "1) Continue with remaining patches"
        echo "2) Exit the script"
        read -r -p "Enter your choice (1 or 2): " choice
        case $choice in
            2)
                echo "Exiting as requested..."
                break
                ;;
            1)
                echo "Continuing with next patch..."
                continue
                ;;
            *)
                echo "Invalid choice, exiting..."
                break
                ;;
        esac
    fi
done

# Print summary
echo -e "\nPatch Application Summary:"
echo "=========================="
echo "Successfully applied patches:"
if [ ${#successful_patches[@]} -eq 0 ]; then
    echo "None"
else
    printf '%s\n' "${successful_patches[@]}"
fi

echo -e "\nFailed patches:"
if [ ${#failed_patches[@]} -eq 0 ]; then
    echo "None"
else
    printf '%s\n' "${failed_patches[@]}"
fi