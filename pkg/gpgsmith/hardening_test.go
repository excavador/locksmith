package gpgsmith

import (
	"testing"
)

// TestHardenProcessIdempotent verifies that HardenProcess can be called
// successfully and is safe to call more than once. The actual kernel-level
// effects (PR_SET_DUMPABLE blocking ptrace, RLIMIT_CORE preventing core
// dumps) cannot be observed from inside the same process without spawning
// a child attacker, which is out of scope for a unit test. We verify the
// syscall paths return cleanly.
//
// Note: this test sets PR_SET_DUMPABLE=0 on the test binary itself. Once
// set, it stays set for the rest of the test run. Subsequent test functions
// in the same test binary will be unable to be ptrace-attached, which is
// the desired effect for a daemon but may surprise developers running
// tests under a debugger. To run tests with a debugger attached, comment
// out this test or build with a debug build tag.
func TestHardenProcessIdempotent(t *testing.T) {
	if err := HardenProcess(); err != nil {
		t.Fatalf("HardenProcess (1): %v", err)
	}
	if err := HardenProcess(); err != nil {
		t.Fatalf("HardenProcess (2): %v", err)
	}
}
