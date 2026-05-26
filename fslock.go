// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package fslock provides a cross-process mutex based on file locks.
//
// It is built on top of flock for linux and darwin, and LockFileEx on Windows.
package fslock

import (
	"errors"
	"strings"
)

// ErrInvalidName indicates that the name passed to NewInRoot was not a single
// path component within the root: it was empty, ".", "..", or contained a path
// separator.
var ErrInvalidName error = errors.New("fslock: lock name must be a single path component")

// validLockName reports whether name is a single, non-special path component
// suitable for resolving against a root directory. It rejects "", ".", "..",
// and any name containing a '/' or '\' separator on every platform (so that a
// name is interpreted identically regardless of the host's separator).
func validLockName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `/\`)
}

// ErrTimeout indicates that the lock attempt timed out.
var ErrTimeout error = timeoutError("lock timeout exceeded")

type timeoutError string

func (t timeoutError) Error() string {
	return string(t)
}
func (timeoutError) Timeout() bool {
	return true
}

// ErrLocked indicates TryLock failed because the lock was already locked.
var ErrLocked error = trylockError("fslock is already locked")

type trylockError string

func (t trylockError) Error() string {
	return string(t)
}

func (trylockError) Temporary() bool {
	return true
}
