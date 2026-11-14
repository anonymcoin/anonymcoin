package falcon

import "errors"

var (
	// ErrRandom indicates that system random generation failed.
	ErrRandom = errors.New("falcon: random number generation failed")
	// ErrSize indicates that an output or temporary buffer was too small.
	ErrSize = errors.New("falcon: buffer size error")
	// ErrFormat indicates malformed key, signature, or encoded object bytes.
	ErrFormat = errors.New("falcon: invalid format")
	// ErrBadSignature indicates signature verification failure.
	ErrBadSignature = errors.New("falcon: invalid signature")
	// ErrBadArgument indicates an invalid argument, such as an unsupported logn.
	ErrBadArgument = errors.New("falcon: invalid argument")
	// ErrInternal indicates an unexpected internal algorithm failure.
	ErrInternal = errors.New("falcon: internal error")
)
