#!/bin/bash
set -euo pipefail

# FMAC Patch Script
#
# This script installs the FMAC kernel module into a Linux kernel source tree.
# It assumes that the script is run from the root of the kernel source tree.

MODULE_NAME="fmac"

# --- Configuration ---

# The current directory is assumed to be the Linux kernel source root.
KERNEL_DIR="$(pwd)"

# Determine the root directory of the FMAC project (nekosu) based on the script's location.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
NEKOSU_ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source directory for the FMAC module files.
SRC_DIR="$NEKOSU_ROOT_DIR/src"
# Directory containing kernel version-specific patches.
PATCH_DIR="$NEKOSU_ROOT_DIR/patch"

# Target directory for the FMAC module within the kernel source tree.
TARGET_DIR="$KERNEL_DIR/drivers/$MODULE_NAME"

# Kernel build system files to be patched.
KCONFIG="$KERNEL_DIR/drivers/Kconfig"
MAKEFILE="$KERNEL_DIR/drivers/Makefile"


# --- Helper Functions ---

print_info() {
    echo -e "\033[1;32m[INFO]\033[0m $*"
}

print_warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

print_err() {
    echo -e "\033[1;31m[ERROR]\033[0m $*"
    exit 1
}


# --- Core Functions ---

# Check if the current directory is a valid Linux kernel tree.
check_kernel_tree() {
    if [[ ! -f "$KERNEL_DIR/Makefile" || ! -d "$KERNEL_DIR/include" || ! -d "$KERNEL_DIR/drivers" ]]; then
        print_err "Not a valid Linux kernel tree: $KERNEL_DIR. Please run this script from the root of the kernel source tree."
    fi
    print_info "Kernel tree validation passed."
}

# Apply kernel version-specific patches.
apply_version_patches() {
    local MAJOR MINOR SUBLEVEL FULL_VER
    MAJOR=$(grep '^VERSION =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    MINOR=$(grep '^PATCHLEVEL =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    SUBLEVEL=$(grep '^SUBLEVEL =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    FULL_VER="$MAJOR.$MINOR.$SUBLEVEL"

    print_info "Detected kernel version: $FULL_VER"

    # Find all matching patch files for the detected kernel version (e.g., 5.15*.patch).
    local PATCHFILES=()
    while IFS= read -r -d $'\0' file; do
        PATCHFILES+=("$file")
    done < <(find "$PATCH_DIR" -maxdepth 1 -name "${MAJOR}.${MINOR}*.patch" -print0 | sort -z -V)

    if [[ ${#PATCHFILES[@]} -gt 0 ]]; then
        print_info "Found ${#PATCHFILES[@]} patch(es) for kernel $MAJOR.$MINOR: ${PATCHFILES[*]##*/}"
        for patchfile in "${PATCHFILES[@]}"; do
            print_info "Applying patch: $(basename "$patchfile")"
            # Apply patch from the root of the kernel tree.
            # -p1 strips the first directory level (e.g., 'a/fs/open.c' -> 'fs/open.c').
            if patch -p1 --no-backup-if-mismatch -r - < "$patchfile"; then
                print_info "Successfully applied patch: $(basename "$patchfile")"
            else
                print_warn "Patch application may have failed or had warnings: $(basename "$patchfile")"
            fi
        done
    else
        print_warn "No specific patches found for kernel version $MAJOR.$MINOR in $PATCH_DIR"
    fi
}

# Main installation function.
install_fmac() {
    check_kernel_tree
    print_info "Installing FMAC into: $KERNEL_DIR"

    # Copy FMAC source files to the kernel drivers directory.
    print_info "Copying module source from $SRC_DIR to $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    cp -a "$SRC_DIR"/* "$TARGET_DIR/"

    # Patch drivers/Kconfig to add FMAC configuration.
    if ! grep -q "source \"drivers/$MODULE_NAME/Kconfig\"" "$KCONFIG"; then
        echo -e "\nsource \"drivers/$MODULE_NAME/Kconfig\"" >> "$KCONFIG"
        print_info "Patched drivers/Kconfig"
    else
        print_warn "drivers/Kconfig already contains an entry for FMAC."
    fi

    # Patch drivers/Makefile to include FMAC in the build process.
    if ! grep -q "obj-\\\$(CONFIG_FMAC)" "$MAKEFILE"; then
        echo "obj-\\\$(CONFIG_FMAC) += $MODULE_NAME/" >> "$MAKEFILE"
        print_info "Patched drivers/Makefile"
    else
        print_warn "drivers/Makefile already contains an entry for FMAC."
    fi

    # Apply any version-specific patches.
    apply_version_patches

    print_info "FMAC installation complete."
    print_info "Run 'make menuconfig', navigate to 'Device Drivers', and enable 'FMAC' to build the module."
}

# --- Execution ---

install_fmac
