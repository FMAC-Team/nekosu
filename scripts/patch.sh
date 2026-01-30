#!/bin/bash

# FMAC Patch Script

MODULE_NAME="fmac"

# Assume current directory is Linux source root
KERNEL_DIR="$(pwd)"
SCRIPT_PATH=$(realpath "$0")
FMAC_ROOT_DIR="$KERNEL_DIR/drivers/fmac"
SRC_DIR="$FMAC_ROOT_DIR/src"
PATCH_DIR="$FMAC_ROOT_DIR/patch"
TARGET_DIR="$KERNEL_DIR/drivers/fmac"

KCONFIG="$KERNEL_DIR/drivers/Kconfig"
MAKEFILE="$KERNEL_DIR/drivers/Makefile"

print_info() {
    echo -e "\033[1;32m[INFO]\033[0m $*"
}

print_warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

print_err() {
    echo -e "\033[1;31m[ERROR]\033[0m $*"
}

check_kernel_tree() {
    [[ ! -f "$KERNEL_DIR/Makefile" || ! -d "$KERNEL_DIR/include" ]] && {
        print_err "Not a valid Linux kernel tree: $KERNEL_DIR"
        exit 1
    }
}

apply_version_patches() {
    local MAJOR MINOR PATCHFILES

    MAJOR=$(grep '^VERSION =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    MINOR=$(grep '^PATCHLEVEL =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    SUBLEVEL=$(grep '^SUBLEVEL =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    FULL_VER="$MAJOR.$MINOR.$SUBLEVEL"

    print_info "Detected kernel version: $FULL_VER"

    # Find all matching patch files
    PATCHFILES=()
    while IFS= read -r -d $'\0' file; do
        PATCHFILES+=("$file")
    done < <(find "$PATCH_DIR" -maxdepth 1 -name "${MAJOR}.${MINOR}*.patch" -print0 | sort -z -V)

    if [[ ${#PATCHFILES[@]} -gt 0 ]]; then
        print_info "Found ${#PATCHFILES[@]} patch files for kernel $MAJOR.$MINOR"
        for patchfile in "${PATCHFILES[@]}"; do
            print_info "Applying patch: $(basename "$patchfile")"
            patch -p1 --no-backup-if-mismatch -r - < "$patchfile" || {
                print_warn "Patch application had issues: $(basename "$patchfile")"
                # Continue to next patch even if this one fails
            }
        done
    else
        print_warn "No patches found for kernel $MAJOR.$MINOR in $PATCH_DIR"
    fi
}

install_patch() {
    check_kernel_tree
    print_info "Installing FMAC into: $KERNEL_DIR"

    mkdir -p "$TARGET_DIR"
    git clone https://github.com/aqnya/FMAC.git "$TARGET_DIR"
    print_info "Clone FMAC source to $TARGET_DIR"

    if ! grep -q "source \"drivers/$MODULE_NAME/Kconfig\"" "$KCONFIG"; then
        echo "source \"drivers/$MODULE_NAME/src/Kconfig\"" >> "$KCONFIG"
        print_info "Patched drivers/Kconfig"
    else
        print_warn "Kconfig already patched."
    fi

    if ! grep -q "obj-\$(CONFIG_FMAC) += $MODULE_NAME/" "$MAKEFILE"; then
        echo "obj-\$(CONFIG_FMAC) += $MODULE_NAME/src/" >> "$MAKEFILE"
        print_info "Patched drivers/Makefile"
    else
        print_warn "Makefile already patched."
    fi

    apply_version_patches

    print_info "Done. Run 'make menuconfig' and enable Device Drivers → FMAC."
}

install_patch
