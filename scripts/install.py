#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil
from pathlib import Path

# --- Configuration ---
MODULE_NAME = "fmac"
REPO_URL = "https://github.com/aqnya/FMAC.git"

# ANSI Color Codes
class Colors:
    INFO = '\033[1;32m[INFO]\033[0m'
    WARN = '\033[1;33m[WARN]\033[0m'
    ERR = '\033[1;31m[ERROR]\033[0m'

def print_info(msg): print(f"{Colors.INFO} {msg}")
def print_warn(msg): print(f"{Colors.WARN} {msg}")
def print_err(msg): print(f"{Colors.ERR} {msg}")

def check_kernel_tree(kernel_dir: Path):
    """Verify if the directory is a valid Linux kernel source tree."""
    if not (kernel_dir / "Makefile").exists() or not (kernel_dir / "include").is_dir():
        print_err(f"Not a valid Linux kernel tree: {kernel_dir}")
        sys.exit(1)

def get_kernel_version(kernel_dir: Path):
    """Parse VERSION, PATCHLEVEL, and SUBLEVEL from the kernel Makefile."""
    version_info = {}
    makefile_path = kernel_dir / "Makefile"
    try:
        with open(makefile_path, 'r') as f:
            for line in f:
                if any(line.startswith(k) for k in ['VERSION =', 'PATCHLEVEL =', 'SUBLEVEL =']):
                    key, val = line.split('=')
                    version_info[key.strip()] = val.strip()
                if len(version_info) == 3:
                    break
        return version_info.get('VERSION'), version_info.get('PATCHLEVEL'), version_info.get('SUBLEVEL')
    except Exception as e:
        print_err(f"Failed to read Makefile: {e}")
        sys.exit(1)

def install_patch():
    # Setup paths
    kernel_dir = Path(os.getcwd())
    target_dir = kernel_dir / "drivers" / MODULE_NAME
    
    check_kernel_tree(kernel_dir)
    print_info(f"Installing FMAC into: {kernel_dir}")

    # 1. Clone Source
    if target_dir.exists():
        print_warn(f"Target directory {target_dir} already exists. Skipping clone.")
    else:
        try:
            subprocess.run(["git", "clone", REPO_URL, str(target_dir)], check=True)
            print_info(f"Cloned FMAC source to {target_dir}")
        except subprocess.CalledProcessError as e:
            print_err(f"Failed to clone repository: {e}")
            sys.exit(1)

    # 2. Patch drivers/Kconfig
    drivers_kconfig = kernel_dir / "drivers" / "Kconfig"
    kconfig_entry = f'source "drivers/{MODULE_NAME}/src/Kconfig"'
    
    if drivers_kconfig.exists():
        content = drivers_kconfig.read_text()
        if kconfig_entry not in content:
            with open(drivers_kconfig, "a") as f:
                f.write(f"\n{kconfig_entry}\n")
            print_info("Patched drivers/Kconfig")
        else:
            print_warn("Kconfig already patched.")

    # 3. Patch drivers/Makefile
    drivers_makefile = kernel_dir / "drivers" / "Makefile"
    makefile_entry = f'obj-$(CONFIG_FMAC) += {MODULE_NAME}/src/'
    
    if drivers_makefile.exists():
        content = drivers_makefile.read_text()
        if makefile_entry not in content:
            with open(drivers_makefile, "a") as f:
                f.write(f"\n{makefile_entry}\n")
            print_info("Patched drivers/Makefile")
        else:
            print_warn("Makefile already patched.")
    print_info("-" * 40)
    print_info("Done. Run 'make menuconfig' and enable Device Drivers -> FMAC.")

if __name__ == "__main__":
    try:
        install_patch()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
