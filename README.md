# FMAC - File Monitoring and Access Control Kernel Module

## Overview
FMAC (File Monitoring and Access Control) is a Linux kernel module that provides fine-grained file access control based on file paths, user IDs (UIDs), and operation types (e.g., `mkdirat`, `openat`). It uses a hash table to store access rules and provides a `/proc` interface for managing rules and viewing logs. The module leverages RCU (Read-Copy-Update) for efficient rule lookups and supports logging of access violations.

## Features
- **Path-based Access Control**: Restrict access to specific file paths or prefixes.
- **UID-based Restrictions**: Apply rules to specific users or all users (UID 0).
- **Operation Type Matching**: Control specific operations (`mkdirat`, `openat`) or all operations.
- **Procfs Interface**: Manage rules via `/proc/fmac` and view logs via `/proc/fmac_log`.
- **Logging**: Log rule additions and access denials with configurable verbosity.
- **RCU and Spinlock**: Ensure thread-safe and efficient rule management.

## Requirements
- Linux kernel version 4.x or later.
- Root privileges for module installation and rule management.
- Standard kernel development tools (`gcc`, `make`, kernel headers).

## Installation
1. **Clone the Repository** (if applicable):
   ```bash
   git clone https://github.com/aqnya/FMAC.git
   cd FMAC
   ```

2. **Patch syscall**:
   You need to locate the syscall code and add the following to it
   such as
   ```diff
   diff --git a/fs/open.c b/fs/open.c
   index f2b82c462..285349ba0 100644
   --- a/fs/open.c
   +++ b/fs/open.c
   @@ -1111,10 +1111,15 @@ SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
 
 	return do_sys_open(AT_FDCWD, filename, flags, mode);
    }
   -
   +int fmac_check(const char __user *pathname, int op_type);
    SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags,
 		umode_t, mode)
    {
   +int fmac_status;
   +   fmac_status = fmac_check(filename,1);
   +    if(fmac_status){
   +     return fmac_status;
   +   }
 	if (force_o_largefile())
 		flags |= O_LARGEFILE;
 

   ```
   Don't forget replace Kconfig and Makefile.

4. **Verify Installation**:
   Check if the module is loaded:

   Confirm `/proc/fmac` and `/proc/fmac_log` exist:
   ```bash
   ls /proc/fmac /proc/fmac_log
   ```

## Usage
FMAC provides two procfs entries:
- `/proc/fmac`: View rules and add new rules.
- `/proc/fmac_log`: View access control logs.

### Adding Rules
Rules are added by writing to `/proc/fmac` in the format:
```
add <path> <uid> <deny> [op_type]
```
- `<path>`: File path or prefix (max 256 characters).
- `<uid>`: User ID (0 for all users).
- `<deny>`: 1 (deny access) or 0 (allow access).
- `<op_type>`: Operation type (-1 for all, 0 for `mkdirat`, 1 for `openat`). Optional, defaults to -1.

Examples:
```bash
# Deny UID 1000 from creating directories under /etc
echo "add /etc 1000 1 0" > /proc/fmac

# Deny all users from accessing /tmp (all operations)
echo "add /tmp 0 1 -1" > /proc/fmac
```

### Enabling/Disabling Logging
Control kernel logging verbosity:
```bash
# Enable detailed logging
echo "printk_on" > /proc/fmac

# Disable detailed logging
echo "printk_off" > /proc/fmac
```

### Viewing Rules
List all active rules:
```bash
cat /proc/fmac
```
Example output:
```
FMAC Rules (Total Buckets: 1024):
  [Bucket 123] Path: /etc, UID: 1000, Deny: 1, Op_type: 0
  [Bucket 456] Path: /tmp, UID: 0, Deny: 1, Op_type: -1
```

### Viewing Logs
Check access control logs:
```bash
cat /proc/fmac_log
```
Example output:
```
[FMAC] Procfs initialized.
[FMAC] Added rule: path=/etc, uid=1000, deny=1, op_type=0
[FMAC] Denied mkdirat: /etc/test by UID 1000 (pid 1234)
```

## Testing
1. **Add Test Rules**:
   ```bash
   echo "add /test 1000 1 0" > /proc/fmac
   ```

2. **Test Access Control**:
   - As UID 1000, try creating a directory:
     ```bash
     sudo -u user1000 mkdir /test/dir
     ```
     Expected: Permission denied (`-EACCES`).
   - Try opening a file:
     ```bash
     sudo -u user1000 cat /test/file
     ```
     Expected: Allowed (unless restricted by another rule).
   - As another user, try the same operations to verify UID-specific rules.

3. **Check Logs**:
   ```bash
   cat /proc/fmac_log
   ```
   Verify that denials are logged correctly.

## Code Structure
- **fmac.c**: Core module logic, including rule management, access checks, and initialization/exit routines.
- **fmac.h**: Header file defining structures (e.g., `struct fmac_rule`) and constants.
- **fmac_procfs.c**: Procfs interface for rule management and logging.

Key components:
- **Hash Table**: Stores rules using `DEFINE_HASHTABLE` with RCU for safe concurrent access.
- **Spinlock**: Protects rule additions and log writes.
- **Procfs**: `/proc/fmac` for rules, `/proc/fmac_log` for logs.

## Notes
- **Security**: `/proc/fmac` has `0666` permissions, allowing all users to modify rules. Consider restricting to `0600` for root-only access.
- **Operation Types**: Currently supports `mkdirat` (0), `openat` (1), and all operations (-1). Extend `op_type` to a bitmask for more operations if needed.
- **Error Handling**: Invalid inputs (e.g., `deny` not 0/1, `op_type` not -1/0/1) are logged and rejected.

## Limitations
- No rule deletion interface (can be added by extending `/proc/fmac`).
- Logs are not persistent across module reloads.
- Path matching is prefix-based; regex or glob patterns are not supported.

## License
This module is licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.txt)

## Author
[Aqnya](https://github.com/aqnya)

## Contributing
Contributions are welcome! Please submit patches or issues to improve functionality, security, or performance.

---

This `Readme.md` was generated by AI and polished by the author.