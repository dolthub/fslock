// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fslock

import (
	"context"
	"syscall"
	"time"
)

// Lock implements cross-process locks using syscalls.
// This implementation is based on flock syscall.
type Lock struct {
	filename string
	fd       int
}

// New returns a new lock around the given file.
func New(filename string) *Lock {
	return &Lock{filename: filename}
}

// Lock locks the lock.  This call will block until the lock is available.
func (l *Lock) Lock() error {
	if err := l.open(); err != nil {
		return err
	}
	return syscall.Flock(l.fd, syscall.LOCK_EX)
}

// TryLock attempts to lock the lock.  This method will return ErrLocked
// immediately if the lock cannot be acquired.
func (l *Lock) TryLock() error {
	if err := l.open(); err != nil {
		return err
	}
	err := syscall.Flock(l.fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		syscall.Close(l.fd)
	}
	if err == syscall.EWOULDBLOCK {
		return ErrLocked
	}
	return err
}

func (l *Lock) open() error {
	fd, err := syscall.Open(l.filename, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	l.fd = fd
	return nil
}

// Unlock unlocks the lock.
func (l *Lock) Unlock() error {
	if l.fd < 0 {
		return nil
	}
	_ = syscall.Flock(l.fd, syscall.LOCK_UN)
	err := syscall.Close(l.fd)
	l.fd = -1
	return err
}

// Maximum interval between non-blocking lock attempts in LockWithTimeout and
// LockWithContext.
const maxLockPoll = 32 * time.Millisecond

// tryFlock makes a single non-blocking attempt to acquire the lock. It returns
// (true, nil) if the lock was acquired, (false, nil) if it is currently held by
// someone else (so the caller should wait and retry), and (false, err) on a
// real error, in which case it has already closed and cleared the fd.
//
// flock cannot be canceled or given a deadline once it blocks, and closing the
// fd does not unblock an in-flight blocking flock. So rather than parking a
// goroutine in a blocking LOCK_EX (which leaks until the lock is released,
// possibly forever), the timed/contextual waiters poll with LOCK_NB.
func (l *Lock) tryFlock() (bool, error) {
	for {
		switch err := syscall.Flock(l.fd, syscall.LOCK_EX|syscall.LOCK_NB); err {
		case nil:
			return true, nil
		case syscall.EINTR:
			// Interrupted before the attempt resolved; retry immediately.
			continue
		case syscall.EWOULDBLOCK:
			return false, nil
		default:
			syscall.Close(l.fd)
			l.fd = -1
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
			syscall.Close(l.fd)
			l.fd = -1
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
			syscall.Close(l.fd)
			l.fd = -1
			return ctx.Err()
		case <-t.C:
		}
		backoff = min(backoff*2, maxLockPoll)
	}
}
