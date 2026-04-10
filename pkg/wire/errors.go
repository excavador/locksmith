package wire

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/excavador/locksmith/pkg/gpgsmith"
)

// connectErr translates a kernel error into a Connect-typed error with the
// appropriate code so the client side can react to the error class without
// string-matching the message. Unknown errors fall through as
// CodeInternal.
//
// Translations:
//
//	gpgsmith.MasterKeyMismatchError → CodeFailedPrecondition
//	gpgsmith.LockContentionError    → CodeAlreadyExists
//	context-canceled               → CodeCanceled
//	everything else                 → CodeInternal
func connectErr(err error) error {
	if err == nil {
		return nil
	}

	if gpgsmith.IsMasterKeyMismatch(err) {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if gpgsmith.IsLockContention(err) {
		return connect.NewError(connect.CodeAlreadyExists, err)
	}
	if errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeCanceled, err)
	}

	return connect.NewError(connect.CodeInternal, err)
}
