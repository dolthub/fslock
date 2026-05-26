// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package fslock

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Lock implements cross-process locks using syscalls.
// This implementation is based on LockFileEx syscall.
type Lock struct {
	// dir is a handle to the directory containing the lock file. It is used
	// as the RootDirectory for NtCreateFile, so the lock file is resolved
	// relative to it rather than by an absolute path and cannot escape it.
	dir *os.File
	// name is the base name of the lock file within dir.
	name string
	// handle is the open lock file while the lock is held; InvalidHandle
	// otherwise.
	handle windows.Handle
}

// New returns a new lock around the given file. It opens a handle to the
// file's parent directory and returns an error if that directory cannot be
// opened.
func New(filename string) (*Lock, error) {
	root, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	// Take an independent handle to the directory itself; it remains valid
	// after the root is closed and serves as the RootDirectory below.
	dir, err := root.Open(".")
	root.Close()
	if err != nil {
		return nil, err
	}
	return &Lock{dir: dir, name: filepath.Base(filename), handle: windows.InvalidHandle}, nil
}

// Close releases the directory handle held by the lock. It does not release a
// held lock; call Unlock first. The lock must not be used after Close.
func (l *Lock) Close() error {
	return l.dir.Close()
}

// TryLock attempts to lock the lock.  This method will return ErrLocked
// immediately if the lock cannot be acquired.
func (l *Lock) TryLock() error {
	err := l.LockWithTimeout(0)
	if err == ErrTimeout {
		// in our case, timing out immediately just means it was already locked.
		return ErrLocked
	}
	return err
}

// Lock locks the lock.  This call will block until the lock is available.
func (l *Lock) Lock() error {
	return l.LockWithTimeout(-1)
}

// Unlock unlocks the lock.
func (l *Lock) Unlock() error {
	if l.handle == windows.InvalidHandle {
		return nil
	}
	h := l.handle
	l.handle = windows.InvalidHandle
	return windows.Close(h)
}

// open creates (if necessary) and opens the lock file relative to the
// directory handle. It opens for asynchronous I/O so that LockFileEx below can
// wait with a timeout, and shared so that other processes can open the file
// (but will still need to lock it).
func (l *Lock) open() (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString(l.name)
	if err != nil {
		return 0, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(l.dir.Fd()),
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))

	var iosb windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ,
		oa,
		&iosb,
		nil, // AllocationSize
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ,
		windows.FILE_OPEN_IF, // create if absent, open if present (OPEN_ALWAYS)
		// FILE_NON_DIRECTORY_FILE without any FILE_SYNCHRONOUS_IO_* option
		// leaves the handle open for overlapped (asynchronous) I/O.
		windows.FILE_NON_DIRECTORY_FILE,
		0, // EaBuffer
		0, // EaLength
	)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// LockWithTimeout tries to lock the lock until the timeout expires.  If the
// timeout expires, this method will return ErrTimeout.
func (l *Lock) LockWithTimeout(timeout time.Duration) (oerr error) {
	handle, err := l.open()
	if err != nil {
		return err
	}
	l.handle = handle
	defer func() {
		if oerr != nil {
			// On a failed/timed-out/canceled lock we own the handle: close it
			// and forget it so a later Unlock doesn't double-close.
			windows.Close(handle)
			l.handle = windows.InvalidHandle
		}
	}()

	millis := uint32(windows.INFINITE)
	if timeout >= 0 {
		millis = uint32(timeout.Nanoseconds() / 1000000)
	}

	ol, err := newOverlapped()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ol.HEvent)
	err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
	if err == nil {
		return nil
	}

	// ERROR_IO_PENDING is expected when we're waiting on an asychronous event
	// to occur.
	if err != windows.ERROR_IO_PENDING {
		return err
	}

	// The lock acquisition is now pending in the kernel, which retains a
	// reference to ol until the operation completes. On any path that leaves it
	// pending (timeout, error) we must cancel and drain it before our deferred
	// CloseHandle(ol.HEvent) runs and before ol can be garbage collected.
	lockPending := true
	defer func() {
		if lockPending {
			drainPendingLock(handle, ol)
		}
	}()

	s, werr := windows.WaitForSingleObject(ol.HEvent, millis)
	switch s {
	case windows.WAIT_OBJECT_0:
		// success!
		lockPending = false
		return nil
	case uint32(windows.WAIT_TIMEOUT):
		return ErrTimeout
	default:
		if werr != nil {
			return werr
		}
		return windows.ERROR_INVALID_PARAMETER
	}
}

// LockWithContext tries to lock the lock until the context is canceled or its deadline is exceeded.
// If the context is canceled before the lock is acquired, this method returns ctx.Err().
func (l *Lock) LockWithContext(ctx context.Context) (oerr error) {
	handle, err := l.open()
	if err != nil {
		return err
	}
	l.handle = handle
	defer func() {
		if oerr != nil {
			// On a failed/timed-out/canceled lock we own the handle: close it
			// and forget it so a later Unlock doesn't double-close.
			windows.Close(handle)
			l.handle = windows.InvalidHandle
		}
	}()

	ol, err := newOverlapped()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ol.HEvent)

	err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
	if err == nil {
		return nil
	}
	// ERROR_IO_PENDING is expected when we're waiting on an asychronous event
	// to occur.
	if err != windows.ERROR_IO_PENDING {
		return err
	}

	// The lock acquisition is now pending in the kernel, which retains a
	// reference to ol until the operation completes. On any path that leaves it
	// pending (cancellation, error) we must cancel and drain it before our
	// deferred CloseHandle(ol.HEvent) runs and before ol can be garbage
	// collected.
	lockPending := true
	defer func() {
		if lockPending {
			drainPendingLock(handle, ol)
		}
	}()

	// Bridge context cancellation onto a waitable object: a goroutine signals
	// cancelEvent when ctx is done, so we can block on the lock and the context
	// simultaneously instead of polling.
	cancelEvent, err := windows.CreateEvent(nil, 1 /* manualReset */, 0 /* initialState */, nil)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			windows.SetEvent(cancelEvent)
		case <-stop:
		}
	}()
	// Tear the watcher down (and wait for it to exit) before closing
	// cancelEvent, so the goroutine can never SetEvent a closed -- and possibly
	// recycled -- handle.
	defer func() {
		close(stop)
		<-watcherDone
		windows.CloseHandle(cancelEvent)
	}()

	// WaitForMultipleObjects returns WAIT_OBJECT_0 + i for the lowest index i
	// that is signaled, so the lock (index 0) wins a simultaneous race.
	s, werr := windows.WaitForMultipleObjects([]windows.Handle{ol.HEvent, cancelEvent}, false, windows.INFINITE)
	switch s {
	case windows.WAIT_OBJECT_0:
		// The lock was acquired; leave the kernel's reference to ol settled.
		lockPending = false
		return nil
	case windows.WAIT_OBJECT_0 + 1:
		// Context was canceled; the deferred drain aborts the pending lock.
		return ctx.Err()
	default:
		if werr != nil {
			return werr
		}
		return windows.ERROR_INVALID_PARAMETER
	}
}

// newOverlapped creates a structure used to track asynchronous
// I/O requests that have been issued.
func newOverlapped() (*windows.Overlapped, error) {
	event, err := windows.CreateEvent(nil, 1 /* manualReset */, 0 /* initialState */, nil)
	if err != nil {
		return nil, err
	}
	return &windows.Overlapped{HEvent: event}, nil
}

// drainPendingLock cancels a still-pending asynchronous LockFileEx and blocks
// until the kernel has finished with the OVERLAPPED structure. After it
// returns, the caller may safely close ol.HEvent / the file handle and let ol
// be collected. It must be called while both handle and ol.HEvent are still
// open.
func drainPendingLock(handle windows.Handle, ol *windows.Overlapped) {
	// CancelIoEx may report ERROR_NOT_FOUND if the op already completed; in that
	// case GetOverlappedResult simply returns its result. Either way the lock is
	// released when the caller closes the file handle.
	windows.CancelIoEx(handle, ol)
	var n uint32
	windows.GetOverlappedResult(handle, ol, &n, true /* wait */)
	runtime.KeepAlive(ol)
}
