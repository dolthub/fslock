// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fslock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Lock implements cross-process locks using syscalls.
// This implementation is based on flock syscall.
type Lock struct {
	// root is a capability-scoped handle to the directory containing the
	// lock file. All access to the lock file goes through it, so operations
	// can never escape this directory via symlinks or "..".
	root *os.Root
	// name is the base name of the lock file within root.
	name string
	// file is the open lock file while the lock is held; nil otherwise.
	file *os.File
}

// New returns a new lock around the given file. It opens a handle to the
// file's parent directory and returns an error if that directory cannot be
// opened.
func New(filename string) (*Lock, error) {
	root, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	return &Lock{root: root, name: filepath.Base(filename)}, nil
}

// Close releases the directory handle held by the lock. It does not release a
// held lock; call Unlock first. The lock must not be used after Close.
func (l *Lock) Close() error {
	return l.root.Close()
}

// maxOpenRetries bounds how many times open retries the os.Root O_CREATE race
// described below. The race clears within a handful of attempts in practice;
// the cap exists only so that a genuinely missing lock directory (which also
// reports ENOENT) eventually surfaces an error instead of spinning forever.
const maxOpenRetries = 100

func (l *Lock) open() error {
	// Root.OpenFile forces O_NOFOLLOW on the final component (and O_CLOEXEC),
	// so we only request the create/access flags here. On platforms without
	// openat2 -- everything but Linux -- that O_NOFOLLOW create is not atomic
	// against concurrent creators: on macOS (observed through go1.26.2) it
	// intermittently returns a spurious ENOENT instead of opening the file.
	// The lock file is never removed while a lock is in use, so retry a bounded
	// number of times; a persistent ENOENT (e.g. the lock directory itself was
	// removed) is still returned to the caller.
	for try := 0; ; try++ {
		f, err := l.root.OpenFile(l.name, os.O_CREATE|os.O_RDWR, 0600)
		if err == nil {
			l.file = f
			return nil
		}
		if try >= maxOpenRetries || !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
}

// Lock locks the lock.  This call will block until the lock is available.
func (l *Lock) Lock() error {
	if err := l.open(); err != nil {
		return err
	}
	return syscall.Flock(int(l.file.Fd()), syscall.LOCK_EX)
}

// TryLock attempts to lock the lock.  This method will return ErrLocked
// immediately if the lock cannot be acquired.
func (l *Lock) TryLock() error {
	if err := l.open(); err != nil {
		return err
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		l.file.Close()
		l.file = nil
	}
	if err == syscall.EWOULDBLOCK {
		return ErrLocked
	}
	return err
}

// Unlock unlocks the lock.
func (l *Lock) Unlock() error {
	if l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

// Maximum interval between non-blocking lock attempts in LockWithTimeout and
// LockWithContext.
const maxLockPoll = 32 * time.Millisecond

// tryFlock makes a single non-blocking attempt to acquire the lock. It returns
// (true, nil) if the lock was acquired, (false, nil) if it is currently held by
// someone else (so the caller should wait and retry), and (false, err) on a
// real error, in which case it has already closed and cleared the file.
//
// flock cannot be canceled or given a deadline once it blocks, and closing the
// fd does not unblock an in-flight blocking flock. So rather than parking a
// goroutine in a blocking LOCK_EX (which leaks until the lock is released,
// possibly forever), the timed/contextual waiters poll with LOCK_NB.
func (l *Lock) tryFlock() (bool, error) {
	for {
		switch err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err {
		case nil:
			return true, nil
		case syscall.EINTR:
			// Interrupted before the attempt resolved; retry immediately.
			continue
		case syscall.EWOULDBLOCK:
			return false, nil
		default:
			l.file.Close()
			l.file = nil
			return false, err
		}
	}
}

// LockWithTimeout tries to lock the lock until the timeout expires.  If the
// timeout expires, this method will return ErrTimeout.
func (l *Lock) LockWithTimeout(timeout time.Duration) error {
	if err := l.open(); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	backoff := time.Millisecond
	for {
		locked, err := l.tryFlock()
		if locked || err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			l.file.Close()
			l.file = nil
			return ErrTimeout
		}
		time.Sleep(min(backoff, remaining))
		backoff = min(backoff*2, maxLockPoll)
	}
}

// LockWithContext tries to lock the lock until the context is canceled or its deadline is exceeded.
// If the context is canceled before the lock is acquired, this method returns ctx.Err().
func (l *Lock) LockWithContext(ctx context.Context) error {
	if err := l.open(); err != nil {
		return err
	}
	backoff := time.Millisecond
	for {
		locked, err := l.tryFlock()
		if locked || err != nil {
			return err
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			l.file.Close()
			l.file = nil
			return ctx.Err()
		case <-t.C:
		}
		backoff = min(backoff*2, maxLockPoll)
	}
}
