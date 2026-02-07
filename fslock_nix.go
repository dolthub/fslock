// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// +build darwin dragonfly freebsd linux netbsd openbsd

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
	// fdValid indicates whether fd is owned by this Lock instance and should be
	// closed by Unlock. We only set it true after the lock has been acquired.
	fdValid  bool
}

// New returns a new lock around the given file.
func New(filename string) *Lock {
	return &Lock{filename: filename, fd: -1}
}

// Lock locks the lock.  This call will block until the lock is available.
func (l *Lock) Lock() error {
	fd, err := l.open()
	if err != nil {
		return err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(fd)
		return err
	}
	l.fd = fd
	l.fdValid = true
	return nil
}

// TryLock attempts to lock the lock.  This method will return ErrLocked
// immediately if the lock cannot be acquired.
func (l *Lock) TryLock() error {
	fd, err := l.open()
	if err != nil {
		return err
	}
	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = syscall.Close(fd)
	}
	if err == syscall.EWOULDBLOCK {
		return ErrLocked
	}
	if err != nil {
		return err
	}
	l.fd = fd
	l.fdValid = true
	return nil
}

func (l *Lock) open() (int, error) {
	fd, err := syscall.Open(l.filename, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// Unlock unlocks the lock.
func (l *Lock) Unlock() error {
	if !l.fdValid {
		return nil
	}
	fd := l.fd
	l.fd = -1
	l.fdValid = false
	_ = syscall.Flock(fd, syscall.LOCK_UN)
	err := syscall.Close(fd)
	l.fd = -1
	return err
}

// LockWithTimeout tries to lock the lock until the timeout expires.  If the
// timeout expires, this method will return ErrTimeout.
func (l *Lock) LockWithTimeout(timeout time.Duration) error {
	fd, err := l.open()
	if err != nil {
		return err
	}
	result := make(chan error)
	cancel := make(chan struct{})
	go func() {
		err := syscall.Flock(fd, syscall.LOCK_EX)
		select {
		case <-cancel:
			// Timed out, cleanup if necessary.
			_ = syscall.Flock(fd, syscall.LOCK_UN)
			_ = syscall.Close(fd)
		case result <- err:
		}
	}()
	select {
	case err := <-result:
		if err != nil {
			_ = syscall.Close(fd)
			return err
		}
		l.fd = fd
		l.fdValid = true
		return nil
	case <-time.After(timeout):
		close(cancel)
		return ErrTimeout
	}
}

// LockWithContext tries to lock the lock until the context is canceled or its deadline is exceeded.
// If the context is canceled before the lock is acquired, this method returns ctx.Err().
func (l *Lock) LockWithContext(ctx context.Context) error {
	fd, err := l.open()
	if err != nil {
		return err
	}
	result := make(chan error)
	cancel := make(chan struct{})
	go func() {
		err := syscall.Flock(fd, syscall.LOCK_EX)
		select {
		case <-cancel:
			// Context canceled, cleanup if necessary.
			_ = syscall.Flock(fd, syscall.LOCK_UN)
			_ = syscall.Close(fd)
		case result <- err:
		}
	}()
	select {
	case err := <-result:
		if err != nil {
			_ = syscall.Close(fd)
			return err
		}
		l.fd = fd
		l.fdValid = true
		return nil
	case <-ctx.Done():
		close(cancel)
		return ctx.Err()
	}
}
