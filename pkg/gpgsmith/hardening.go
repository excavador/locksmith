package gpgsmith

// HardenProcess applies process-level defenses against same-user attackers
// trying to read the daemon's heap or files via debugger or /proc.
//
// On Linux:
//   - PR_SET_DUMPABLE = 0  blocks ptrace, process_vm_readv, /proc/<pid>/{mem,
//     maps,root,cwd} from non-root processes (the kernel
//     re-owns these to root once dumpable=0)
//   - RLIMIT_CORE   = 0,0  prevents core dumps from leaking heap on crash
//
// On macOS:
//   - PT_DENY_ATTACH       blocks ptrace attach (the macOS analog of
//     PR_SET_DUMPABLE for debugger denial)
//   - RLIMIT_CORE   = 0,0  prevents core dumps
//
// HardenProcess is intended to be called once at daemon startup, before any
// secret material is touched. It is safe to call multiple times. It returns
// an error only if the syscalls fail in a way that suggests the host kernel
// is broken; routine "operation not permitted" returns are downgraded to a
// silent no-op so test environments and unusual configurations don't break
// the daemon.
//
// HardenProcess is NOT called automatically by Session or any other kernel
// API. The daemon binary's main() is responsible for calling it explicitly,
// because:
//
//  1. Hardening is a process-wide flag — it would affect tests that import
//     the kernel package if it ran in package init.
//  2. Setting PR_SET_DUMPABLE=0 makes a process non-attachable by gdb, which
//     is friction during development. The daemon binary opts in; tests and
//     non-daemon callers do not.
//  3. The daemon may want to set other rlimits or prctls beyond the
//     defaults; surfacing this as an explicit call lets it compose with
//     future tightening.
//
// To opt out (for debugging) the daemon main() can simply not call this.
// We do not provide an environment-variable opt-out because the call site
// is in the daemon's own main() — adding env logic there is the user of
// this function's choice, not ours.
func HardenProcess() error {
	return hardenProcess()
}
