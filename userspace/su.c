// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/*
 * userspace/su.c - User-space utility to gain root via FMAC.
 *
 * This program is a simple implementation of `su` that leverages the
 * custom root escalation mechanism provided by the FMAC kernel module.
 * It uses a special `prctl` call to request root privileges.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

// Magic number for prctl to request root from the FMAC kernel module.
#define FMAC_PRCTL_GET_ROOT 0xdeadbeef

// From unistd.h, used by execve
extern char **environ;

int main(int argc, char *argv[]) {
    // Request root privileges from the FMAC kernel module.
    // We don't check the return value of prctl, as the kernel hook might not
    // return a meaningful error code. Instead, we check our UID after the call.
    prctl(FMAC_PRCTL_GET_ROOT, 0, 0, 0, 0);

    // Verify if we successfully obtained root privileges.
    if (getuid() != 0) {
        fprintf(stderr, "su: permission denied\n");
        return 1;
    }

    const char *shell = "/system/bin/sh";
    
    // If no arguments are given, execute an interactive root shell.
    if (argc < 2) {
        char *shell_argv[] = {(char *)shell, NULL};
        execve(shell, shell_argv, environ);
        // If execve returns, an error occurred.
        perror("execve (interactive shell)");
        return 127;
    }

    // If arguments are given, we support the `su -c "command"` pattern.
    if (strcmp(argv[1], "-c") == 0) {
        if (argc < 3) {
            fprintf(stderr, "su: -c option requires a command\n");
            return 126;
        }
        char *shell_argv[] = {(char *)shell, "-c", argv[2], NULL};
        execve(shell, shell_argv, environ);
        perror("execve (-c command)");
        return 127;
    }
    
    // For simplicity, other `su` arguments and patterns are not supported.
    fprintf(stderr, "su: invalid arguments. Only '-c command' is supported.\n");
    return 1;
}
