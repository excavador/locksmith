//go:build linux

package gpgsmith

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// hardenProcess applies the Linux-specific hardening defenses.
//
// PR_SET_DUMPABLE is the most important call: with dumpable=0 the kernel
// re-owns /proc/<pid>/{mem,maps,root,cwd} to root, blocking
// ptrace/process_vm_readv/proc-traversal from non-root same-user processes.
// This is the single biggest defense available without root or systemd.
//
// RLIMIT_CORE = (0,0) prevents the kernel from writing core files on crash,
// which would otherwise expose decrypted key material on disk.
//
// EPERM from setrlimit is treated as a no-op: in some sandboxes (e.g.
// systemd unit with LimitCORE already 0, or seccomp filters) the call may
// be denied even though the goal is already achieved.
func hardenProcess() error {
	if _, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		unix.PR_SET_DUMPABLE,
		0,
		0,
		0,
		0,
		0,
	); errno != 0 {
		return fmt.Errorf("harden: prctl(PR_SET_DUMPABLE, 0): %w", errno)
	}

	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		if !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("harden: setrlimit(RLIMIT_CORE, 0): %w", err)
		}
	}

	return nil
}
