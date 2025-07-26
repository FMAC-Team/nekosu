// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC_TOKEN "123456"
#define TRIGGER_PATH "/proc/self/environ"
#define SHELL_PATH "/system/bin/sh"

/**
 * @brief Triggers the kernel module to escalate privileges.
 * @return 0 on success, -1 on failure.
 */

static int trigger_root_escalation(void) {
  int fd = open(TRIGGER_PATH, O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "[FMAC SU] Error: Failed to open trigger file '%s': %s\n",
            TRIGGER_PATH, strerror(errno));
    fprintf(stderr, "[FMAC SU] Hint: Is the FMAC kernel module loaded?\n");
    return -1;
  }

  ssize_t bytes_written = write(fd, MAGIC_TOKEN, strlen(MAGIC_TOKEN));
  close(fd);

  if (bytes_written < 0) {
    fprintf(stderr, "[FMAC SU] Error: Failed to write magic token: %s\n",
            strerror(errno));
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (trigger_root_escalation() != 0) {
    fprintf(stderr, "[FMAC SU] Kernel escalation trigger failed.\n");
    return EXIT_FAILURE;
  }

  if (getuid() != 0) {
    fprintf(stderr,
            "[FMAC SU] Escalation failed. Current UID is %d, not root.\n",
            getuid());
    return EXIT_FAILURE;
  }

  if (argc > 1 && strcmp(argv[1], "-c") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage: %s -c \"command_to_execute\"\n", argv[0]);
      return EXIT_FAILURE;
    }

    char *exec_args[] = {SHELL_PATH, "-c", argv[2], NULL};
    execv(SHELL_PATH, exec_args);
  } else {
    char *exec_args[] = {SHELL_PATH, NULL};
    execv(SHELL_PATH, exec_args);
  }

  fprintf(stderr, "[FMAC SU] Fatal: Failed to exec shell '%s': %s\n",
          SHELL_PATH, strerror(errno));
  return EXIT_FAILURE;
}
