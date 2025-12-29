# Nekosu

Nekosu is a project for Android that integrates a powerful kernel-level module with a user-friendly manager application. It aims to provide advanced access control and system modification capabilities.

The project focuses on fine-grained file path access control, privilege management, and system-level monitoring through a kernel module and an Android application.

---

## Features

1. Kernel-based su and root access management  
2. FMAC: File Monitoring and Access Control  
3. Path-based access restriction and auditing  
4. Android manager application with UI and logging support  

---

## Usage

Official website:  
https://nksu.top/

---

## Project Structure

.
├── app/              Android management application  
├── src/              FMAC kernel module source code  
├── scripts/          Patch and helper scripts  
├── userspace/        User-space utilities  
├── .gitmodules  
├── LICENSE  
└── README.md  

---

## Components

The project consists of two main components:

### 1. FMAC (File Monitoring and Access Control)

FMAC is a Linux kernel module that provides fine-grained file access control based on file paths, user IDs (UIDs), and operation types (e.g., `mkdirat`, `openat`). It forms the core of the Nekosu project, enabling its system-level features.

**Features:**

- Path-based Access Control: Restrict access to specific file paths or prefixes  
- UID-based Restrictions: Apply rules to specific users  
- Operation Type Matching: Control specific filesystem operations  
- Procfs Interface: Manage rules and view logs via `/proc/fmac`  
- Root Capabilities: Provides mechanisms for privilege escalation  

The kernel module source code is located in the `src/` directory.

---

### 2. Nekosu (Android Application)

nksu is the official Android manager application for Nekosu. It is located in the `app/` directory.

The application provides:

- An interface to manage the Nekosu environment (under development)  
- System utilities such as a logcat viewer and an application list  
- A personal activity logging feature to help you scientifically manage your life  

---

## Installation & Building

### Building FMAC (Kernel Module)

To build and integrate the FMAC kernel module, you need a Linux kernel source tree for your target Android device.

#### Requirements

- Android kernel source matching your device and kernel version  
- A working kernel build environment  

#### Steps

1. Place the `nekosu` project directory somewhere on your system:
   git clone https://github.com/FMAC-Team/nekosu.git

2. Copy the project into your kernel source tree:
   cp -r nekosu /path/to/kernel_source/

3. Enter the kernel source directory:
   cd /path/to/kernel_source

4. Apply the FMAC patch:
   /path/to/nekosu/scripts/patch.sh

5. Configure the kernel:
   make menuconfig  

   Enable:
   Device Drivers  ---> FMAC  

6. Build the kernel as usual:
   make -j$(nproc)

7. Flash the compiled kernel to your device using your device-specific method.

---

### Building nksu (Android App)

The Android manager application can be built using Gradle.

1. Navigate to the `app` directory:
   cd app/

2. Initialize submodules if needed:
   git submodule update --init

3. Build the APK:
   ./gradlew assembleDebug

4. The output APK will be located at:
   app/build/outputs/apk/debug/

5. Install the APK on your device:
   adb install -r app-debug.apk

---

## Patch Instructions

Nekosu provides a helper script to integrate the FMAC kernel module into your kernel source tree.

### Usage

cd /path/to/kernel_source  
/path/to/nekosu/scripts/patch.sh

### What the Patch Does

- Copies FMAC source code into the kernel tree  
- Modifies kernel Makefile and Kconfig files  
- Applies kernel-version compatibility logic  

If the script fails due to kernel differences, manual patching may be required by editing the relevant Makefile and Kconfig entries.

---

## FMAC Usage

Once you have built and flashed the patched kernel with the FMAC module, you can interact with FMAC using the procfs interface exposed at `/proc/fmac/`. This interface lets you manage access control rules and inspect logs.

### 1. Check FMAC Status

To see if FMAC is loaded and running:

cat /proc/fmac/status

This will print basic module information such as version, enabled state, and rule count.

### 2. View Access Logs

FMAC logs file access events that match configured rules. To view the log:

cat /proc/fmac/log

The log entries show attempts to access filesystem paths, along with UID, PID, operation type, and result (allowed or denied).

Example log entry:

[Timestamp] UID:1000 PID:2345 OP:openat PATH:/data/app/example ALLOW

### 3. Add Access Control Rules

FMAC supports adding allow/deny rules dynamically. Rules are written to `/proc/fmac/rules`.

Rule format:

<allow|deny> uid=<UID> path=<path-prefix> op=<operation>

Examples:

echo "allow uid=1000 path=/data/data/com.example/* op=openat" > /proc/fmac/rules  
echo "deny uid=1001 path=/data/secret/* op=mkdirat" > /proc/fmac/rules

- `allow` / `deny` – whether to allow or block matching access  
- `uid` – target user ID  
- `path` – file path or prefix (supports wildcard semantics)  
- `op` – filesystem operation (e.g., `openat`, `mkdirat`, `unlinkat`)

### 4. Remove Rules

To clear all existing rules in FMAC:

echo "clear" > /proc/fmac/rules

To remove a specific rule by index (if supported by your FMAC version):

echo "remove 2" > /proc/fmac/rules

### 5. Real-Time Log Monitoring

To watch access attempts in real time (helpful during testing):

tail -f /proc/fmac/log

This will continuously print new log entries as they occur.

---

## Notes

- FMAC rule matching is typically done in order; the first matching rule applies.  
- Rules are reset when the device reboots unless saved and reapplied by the Android manager app (nksu).  
- Be careful creating deny rules for system UIDs (e.g., 0), as this might block essential operations.

---

## License

This project is licensed under the **GNU General Public License v3.0**.  
See the LICENSE file for details.

---

## Contributing

Contributions are welcome.  
Please submit pull requests or open issues to help improve the project.

---
## Acknowledgments

* Special thanks to the contributors of [CLI11](https://github.com/CLIUtils/CLI11) for providing an excellent command-line parsing library that simplified our CLI development.
