#!/bin/bash

# FMAC Patch Script
# Usage: ./drivers/fmac/scripts/patch.sh install|uninstall

set -e

MODULE_NAME="fmac"

# Assume current directory is Linux source root
KERNEL_DIR="$(pwd)"
SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
FMAC_ROOT_DIR=$(realpath "$SCRIPT_DIR/..")         # drivers/FMAC
SRC_DIR="$FMAC_ROOT_DIR/src"
PATCH_DIR="$FMAC_ROOT_DIR/patch"
TARGET_DIR="$KERNEL_DIR/drivers/fmac"

KCONFIG="$KERNEL_DIR/drivers/Kconfig"
MAKEFILE="$KERNEL_DIR/drivers/Makefile"

# ---------- Print helpers ----------

print_info() {
    echo -e "\033[1;32m[INFO]\033[0m $*"
}

print_warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

print_err() {
    echo -e "\033[1;31m[ERROR]\033[0m $*"
}

# ---------- Sanity check ----------

check_kernel_tree() {
    [[ ! -f "$KERNEL_DIR/Makefile" || ! -d "$KERNEL_DIR/include" ]] && {
        echo "Not a valid Linux kernel tree: $KERNEL_DIR"
        exit 1
    }
}

# ---------- Patch functions ----------

apply_version_patch() {
    local MAJOR MINOR PATCHFILE

    MAJOR=$(grep '^VERSION =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    MINOR=$(grep '^PATCHLEVEL =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    SUBLEVEL=$(grep '^SUBLEVEL =' "$KERNEL_DIR/Makefile" | awk '{print $3}')
    FULL_VER="$MAJOR.$MINOR.$SUBLEVEL"

    print_info "Detected kernel version: $FULL_VER"

    PATCHFILE="$PATCH_DIR/${MAJOR}.${MINOR}openat.patch"
    if [[ -f "$PATCHFILE" ]]; then
        print_info "Applying patch: $(basename "$PATCHFILE")"
        patch -p1 < "$PATCHFILE" || print_warn "Failed to apply openat patch"
    else
        print_warn "No openat patch for kernel $MAJOR.$MINOR"
    fi

    if [[ -f "$PATCH_DIR/build.patch" ]]; then
        print_info "Applying build.patch..."
        patch -p1 < "$PATCH_DIR/build.patch" || print_warn "build.patch may already be applied"
    fi
}

# ---------- Install ----------

install_patch() {
    check_kernel_tree
    print_info "Installing FMAC into: $KERNEL_DIR"

    mkdir -p "$TARGET_DIR"
    git clone https://github.com/aqnya/FMAC.git "$TARGET_DIR"
    print_info "Clone FMAC source to $TARGET_DIR"

    if ! grep -q "source \"drivers/$MODULE_NAME/Kconfig\"" "$KCONFIG"; then
        echo "source \"drivers/$MODULE_NAME/Kconfig\"" >> "$KCONFIG"
        print_info "Patched drivers/Kconfig"
    else
        print_warn "Kconfig already patched."
    fi

    if ! grep -q "obj-\$(CONFIG_FMAC) += $MODULE_NAME/" "$MAKEFILE"; then
        echo "obj-\$(CONFIG_FMAC) += $MODULE_NAME/" >> "$MAKEFILE"
        print_info "Patched drivers/Makefile"
    else
        print_warn "Makefile already patched."
    fi

    apply_version_patch

    print_info "Done. Run 'make menuconfig' and enable Device Drivers → FMAC."
}

# ---------- Uninstall ----------

uninstall_patch() {
    check_kernel_tree
    print_info "Uninstalling FMAC from: $KERNEL_DIR"

    rm -rf "$TARGET_DIR"
    sed -i "/source \"drivers\/$MODULE_NAME\/Kconfig\"/d" "$KCONFIG"
    sed -i "/obj-\\\$(CONFIG_FMAC) += $MODULE_NAME\//d" "$MAKEFILE"

    print_info "FMAC removed."
}

# ---------- Entry ----------


        install_patch