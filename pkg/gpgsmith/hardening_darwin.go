//go:build darwin

package gpgsmith

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// PT_DENY_ATTACH is the macOS ptrace request that, when called by a process
// on itself, marks the process as non-attachable: subsequent attempts by
// any other process (including same-user) to attach via ptrace, task_for_pid,
// or LLDB are denied by the kernel. This is the macOS analog of Linux's
// PR_SET_DUMPABLE for debugger-attach denial.
//
// The constant is documented in Apple's <sys/ptrace.h> as 31 but does NOT
// appear in golang.org/x/sys/unix as of v0.42, so we declare it locally.
const ptDenyAttach = 31

// hardenProcess applies macOS-specific hardening defenses.
//
// PT_DENY_ATTACH blocks debugger attach for the rest of the process lifetime.
// RLIMIT_CORE = (0,0) prevents core dumps from leaking heap on crash.
//
// EPERM from setrlimit is downgraded to a no-op for the same reason as on
// Linux: some sandbox configurations may already have it set lower than the
// hard limit and refuse to "increase" it from our perspective.
func hardenProcess() error {
	// PT_DENY_ATTACH: ptrace(PT_DENY_ATTACH, 0, 0, 0)
	// On macOS this returns 0 on success or sets errno; the syscall is
	// available via unix.PtraceAttach pattern but PT_DENY_ATTACH is not
	// wrapped, so use the raw syscall.
	if _, _, errno := unix.Syscall6(
		unix.SYS_PTRACE,
		ptDenyAttach,
		0,
		0,
		0,
		0,
		0,
	); errno != 0 {
		return fmt.Errorf("harden: ptrace(PT_DENY_ATTACH): %w", errno)
	}

	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		if !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("harden: setrlimit(RLIMIT_CORE, 0): %w", err)
		}
	}

	return nil
}
