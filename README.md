# Nekosu

Nekosu is a project for Android that integrates a powerful kernel-level module with a user-friendly manager application. It aims to provide advanced access control and system modification capabilities.

## Components

The project consists of two main components:

### 1. FMAC (File Monitoring and Access Control)

FMAC is a Linux kernel module that provides fine-grained file access control based on file paths, user IDs (UIDs), and operation types (e.g., `mkdirat`, `openat`). It forms the core of the Nekosu project, enabling its system-level features.

**Features:**

*   **Path-based Access Control**: Restrict access to specific file paths or prefixes.
*   **UID-based Restrictions**: Apply rules to specific users.
*   **Operation Type Matching**: Control specific filesystem operations.
*   **Procfs Interface**: Manage rules and view logs via `/proc/fmac`.
*   **Root capabilities**: Provides mechanisms for privilege escalation.

The kernel module source code is located in the `src/` directory.

### 2. Nekosu (Android Application)

nksu is the official Android manager application for Nekosu. It is located in the `app/`.

The application provides:
*   An interface to manage the Nekosu environment (under development).
*   System utilities like a logcat viewer and an application list.
*   A personal activity logging feature to help you "scientifically manage your life".

## Building

### Building FMAC (Kernel Module)

To build and integrate the FMAC kernel module, you need a Linux kernel source tree for your target Android device.

1.  Place the `nekosu` project directory in your filesystem.
2.  Run the patch script from within the kernel source directory:
    ```bash
    /path/to/nekosu/scripts/patch.sh
    ```
3.  The script will copy the module source and apply the necessary patches to the kernel.
4.  Configure your kernel build (`make menuconfig`) and enable `Device Drivers -> FMAC`.
5.  Build your kernel as usual.

### Building nkus (Android App)

The NzHelper application can be built using Gradle.

1.  Navigate to the `app` directory:
    ```bash
    cd app/
    ```
2.  Initialize the submodule if you haven't:
    ```bash
    git submodule update --init
    ```
3.  Build the APK using the Gradle wrapper:
    ```bash
    ./gradlew assembleDebug
    ```
    The output APK will be in `app/build/outputs/apk/debug/`.

## License

This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit pull requests or open issues to improve the project.
