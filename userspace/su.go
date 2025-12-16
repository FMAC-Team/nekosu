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
 * userspace/su.go - Enhanced user-space utility to gain root via FMAC.
 *
 * This is an enhanced Go implementation of `su` that leverages the
 * custom root escalation mechanism provided by the FMAC kernel module.
 * It uses a special `prctl` call to request root privileges.
 *
 * Features:
 * - Interactive shell support
 * - Command execution with -c flag
 * - User switching support
 * - Environment preservation options
 * - Login shell simulation
 * - Enhanced error handling and logging
 */

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// Magic number for prctl to request root from the FMAC kernel module
	FMAC_PRCTL_GET_ROOT = 0xdeadbeef
	
	// Exit codes
	EXIT_SUCCESS           = 0
	EXIT_PERMISSION_DENIED = 1
	EXIT_INVALID_ARGS      = 2
	EXIT_EXEC_FAILED       = 127
	EXIT_COMMAND_NOT_FOUND = 127
)

// Config holds the runtime configuration for su
type Config struct {
	TargetUser      string
	Command         string
	Shell           string
	PreserveEnv     bool
	LoginShell      bool
	Args            []string
}

// prctl makes a prctl system call
func prctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PRCTL,
		uintptr(option),
		arg2, arg3, arg4, arg5, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// requestRootPrivileges requests root privileges from FMAC kernel module
func requestRootPrivileges() error {
	// Call prctl with the magic number
	_ = prctl(FMAC_PRCTL_GET_ROOT, 0, 0, 0, 0)
	
	// Verify if we obtained root privileges
	if os.Getuid() != 0 {
		return fmt.Errorf("failed to obtain root privileges")
	}
	
	return nil
}

// setUserContext switches to the specified user's context
func setUserContext(username string) error {
	targetUser, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user %s not found: %v", username, err)
	}
	
	// Parse UID and GID
	var uid, gid int
	fmt.Sscanf(targetUser.Uid, "%d", &uid)
	fmt.Sscanf(targetUser.Gid, "%d", &gid)
	
	// Set GID first (must be done before dropping privileges)
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set GID: %v", err)
	}
	
	// Set UID
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set UID: %v", err)
	}
	
	// Change to user's home directory
	if err := os.Chdir(targetUser.HomeDir); err != nil {
		// Non-fatal, just warn
		fmt.Fprintf(os.Stderr, "warning: could not change to home directory: %v\n", err)
	}
	
	return nil
}

// getShell determines which shell to use
func getShell(config *Config, targetUser *user.User) string {
	if config.Shell != "" {
		return config.Shell
	}
	
	// Try to get user's shell from passwd
	if targetUser != nil && targetUser.Username != "" {
		// On Android/Linux, check common locations
		shells := []string{
			"/system/bin/sh",
			"/bin/bash",
			"/bin/sh",
		}
		for _, shell := range shells {
			if _, err := os.Stat(shell); err == nil {
				return shell
			}
		}
	}
	
	return "/system/bin/sh" // Default fallback
}

// setupEnvironment configures the environment for the target user
func setupEnvironment(config *Config, targetUser *user.User) []string {
	env := os.Environ()
	
	if !config.PreserveEnv && targetUser != nil {
		// Clear environment and set minimal variables
		env = []string{
			fmt.Sprintf("HOME=%s", targetUser.HomeDir),
			fmt.Sprintf("USER=%s", targetUser.Username),
			fmt.Sprintf("LOGNAME=%s", targetUser.Username),
			fmt.Sprintf("SHELL=%s", config.Shell),
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/system/bin",
		}
		
		// Preserve some important variables
		for _, key := range []string{"TERM", "DISPLAY", "LANG"} {
			if val := os.Getenv(key); val != "" {
				env = append(env, fmt.Sprintf("%s=%s", key, val))
			}
		}
	}
	
	return env
}

// executeCommand executes the command or shell
func executeCommand(config *Config, targetUser *user.User) error {
	shell := getShell(config, targetUser)
	env := setupEnvironment(config, targetUser)
	
	var args []string
	
	if config.Command != "" {
		// Execute command with -c
		args = []string{shell, "-c", config.Command}
	} else if config.LoginShell {
		// Login shell (prepend - to argv[0])
		args = []string{"-" + filepath.Base(shell)}
	} else {
		// Interactive shell
		args = []string{filepath.Base(shell)}
	}
	
	// Append any additional arguments
	args = append(args, config.Args...)
	
	// Execute using syscall.Exec for clean process replacement
	if err := syscall.Exec(shell, args, env); err != nil {
		return fmt.Errorf("failed to execute %s: %v", shell, err)
	}
	
	return nil
}

// parseArgs parses command line arguments
func parseArgs() (*Config, error) {
	config := &Config{
		TargetUser:  "root",
		PreserveEnv: false,
		LoginShell:  false,
	}
	
	args := os.Args[1:]
	
	for i := 0; i < len(args); i++ {
		arg := args[i]
		
		switch arg {
		case "-c", "--command":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-c option requires a command")
			}
			config.Command = args[i+1]
			i++
			
		case "-s", "--shell":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-s option requires a shell path")
			}
			config.Shell = args[i+1]
			i++
			
		case "-p", "--preserve-environment":
			config.PreserveEnv = true
			
		case "-l", "--login":
			config.LoginShell = true
			
		case "-h", "--help":
			printUsage()
			os.Exit(EXIT_SUCCESS)
			
		case "-v", "--version":
			printVersion()
			os.Exit(EXIT_SUCCESS)
			
		default:
			if strings.HasPrefix(arg, "-") && arg != "-" {
				return nil, fmt.Errorf("unknown option: %s", arg)
			}
			// First non-option argument is the target user
			if config.TargetUser == "root" && arg != "-" {
				config.TargetUser = arg
			} else {
				config.Args = append(config.Args, arg)
			}
		}
	}
	
	return config, nil
}

// printUsage prints usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: su [options] [user [arguments]]

Options:
  -c, --command COMMAND      Pass COMMAND to the shell
  -s, --shell SHELL          Use SHELL instead of default
  -p, --preserve-environment Preserve the environment
  -l, --login                Make the shell a login shell
  -h, --help                 Display this help and exit
  -v, --version              Display version information and exit

Examples:
  su                         # Start interactive root shell
  su -c "ls -la"            # Execute command as root
  su user                    # Switch to 'user'
  su -l user                # Login as 'user'
  su -c "id" user           # Execute command as 'user'
`)
}

// printVersion prints version information
func printVersion() {
	fmt.Println("FMAC su (Go implementation) version 1.0.0")
	fmt.Println("Copyright (C) 2025 Aqnya")
	fmt.Println("License GPLv3+: GNU GPL version 3 or later")
}

func main() {
	// Parse command line arguments
	config, err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "su: %v\n", err)
		fmt.Fprintf(os.Stderr, "Try 'su --help' for more information.\n")
		os.Exit(EXIT_INVALID_ARGS)
	}
	
	// Check if we're already root
	currentUID := os.Getuid()
	needsEscalation := currentUID != 0
	
	// If we need root and we're requesting root user
	if needsEscalation && config.TargetUser == "root" {
		
		// Request root privileges from FMAC kernel module
		if err := requestRootPrivileges(); err != nil {
			fmt.Fprintf(os.Stderr, "su: %v\n", err)
			os.Exit(EXIT_PERMISSION_DENIED)
		}
	}
	
	// If switching to a different user (not root), set user context
	var targetUser *user.User
	if config.TargetUser != "root" || os.Getuid() == 0 {
		targetUser, err = user.Lookup(config.TargetUser)
		if err != nil {
			fmt.Fprintf(os.Stderr, "su: user %s does not exist\n", config.TargetUser)
			os.Exit(EXIT_INVALID_ARGS)
		}
		
		if err := setUserContext(config.TargetUser); err != nil {
			fmt.Fprintf(os.Stderr, "su: %v\n", err)
			os.Exit(EXIT_PERMISSION_DENIED)
		}
	}
	
	// Execute the command or shell
	if err := executeCommand(config, targetUser); err != nil {
		fmt.Fprintf(os.Stderr, "su: %v\n", err)
		os.Exit(EXIT_EXEC_FAILED)
	}
	
	// Should never reach here
	os.Exit(EXIT_SUCCESS)
}