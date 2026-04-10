//go:build !linux && !darwin

package gpgsmith

// hardenProcess is a no-op on platforms where we have not implemented any
// process-level isolation primitives. The kernel package still builds and
// runs, but provides no defense against same-user attackers.
func hardenProcess() error {
	return nil
}
