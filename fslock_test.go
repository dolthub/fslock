// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package fslock_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dolthub/fslock"
)

const shortWait = 10 * time.Millisecond

func TestLockNoContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testing")
	lock := fslock.New(path)

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		err := lock.Lock()
		close(acquired)
		assert.NoError(t, err)
	}()

	select {
	case <-started:
		// good, goroutine started.
	case <-time.After(shortWait * 2):
		t.Fatalf("timeout waiting for goroutine to start")
	}

	select {
	case <-acquired:
		// got the lock. good.
	case <-time.After(shortWait * 2):
		t.Fatalf("Timed out waiting for lock acquisition.")
	}

	err := lock.Unlock()
	require.NoError(t, err)
}

func TestLockBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testing")
	lock := fslock.New(path)

	kill := make(chan struct{})

	// this will block until the other process has the lock.
	procDone := LockFromAnotherProc(t, path, kill)

	defer func() {
		close(kill)
		err := <-procDone
		require.NoError(t, err)
	}()

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		err := lock.Lock()
		close(acquired)
		lock.Unlock()
		assert.NoError(t, err)
	}()

	select {
	case <-started:
		// good, goroutine started.
	case <-time.After(shortWait * 2):
		t.Fatalf("timeout waiting for goroutine to start")
	}

	// Waiting for something not to happen is inherently hard...
	select {
	case <-acquired:
		t.Fatalf("Unexpected lock acquisition")
	case <-time.After(shortWait * 2):
		// all good.
	}
}

func TestTryLock(t *testing.T) {
	lock := fslock.New(filepath.Join(t.TempDir(), "testing"))

	err := lock.TryLock()
	require.NoError(t, err)
	lock.Unlock()
}

func TestTryLockNoBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testing")
	lock := fslock.New(path)

	kill := make(chan struct{})

	// this will block until the other process has the lock.
	procDone := LockFromAnotherProc(t, path, kill)

	defer func() {
		close(kill)
		err := <-procDone
		require.NoError(t, err)
	}()

	started := make(chan struct{})
	result := make(chan error)
	go func() {
		close(started)
		result <- lock.TryLock()
	}()

	select {
	case <-started:
		// good, goroutine started.
	case <-time.After(shortWait):
		t.Fatalf("timeout waiting for goroutine to start")
	}

	// Wait for trylock to fail.
	select {
	case err := <-result:
		// This should be the error from trylock failing.
		require.ErrorIs(t, err, fslock.ErrLocked)
	case <-time.After(shortWait):
		t.Fatalf("took too long to fail trylock")
	}
}

func TestUnlockedWithTimeout(t *testing.T) {
	lock := fslock.New(filepath.Join(t.TempDir(), "testing"))

	err := lock.LockWithTimeout(shortWait)
	require.NoError(t, err)
	lock.Unlock()
}

func TestLockWithTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testing")
	lock := fslock.New(path)
	defer lock.Unlock()

	kill := make(chan struct{})

	// this will block until the other process has the lock.
	procDone := LockFromAnotherProc(t, path, kill)

	defer func() {
		close(kill)
		err := <-procDone
		require.NoError(t, err)
	}()

	started := make(chan struct{})
	result := make(chan error)
	go func() {
		close(started)
		result <- lock.LockWithTimeout(shortWait)
	}()

	select {
	case <-started:
		// good, goroutine started.
	case <-time.After(shortWait * 2):
		t.Fatalf("timeout waiting for goroutine to start")
	}

	// Wait for timeout.
	select {
	case err := <-result:
		// This should be the error from the lock timing out.
		require.ErrorIs(t, err, fslock.ErrTimeout)
	case <-time.After(shortWait * 2):
		t.Fatalf("lock took too long to timeout")
	}
}

func TestUnlockedWithContext(t *testing.T) {
	lock := fslock.New(filepath.Join(t.TempDir(), "testing"))

	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	err := lock.LockWithContext(ctx)
	require.NoError(t, err)
	lock.Unlock()
}

func TestLockWithContextDeadlineExceeded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testing")
	lock := fslock.New(path)

	kill := make(chan struct{})

	// this will block until the other process has the lock.
	procDone := LockFromAnotherProc(t, path, kill)

	defer func() {
		close(kill)
		err := <-procDone
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	err := lock.LockWithContext(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestStress(t *testing.T) {
	const lockAttempts = 200
	const concurrentLocks = 10

	var counter = new(int64)
	// Use atomics to update lockState to make sure the lock isn't held by
	// someone else. A value of 1 means locked, 0 means unlocked.
	var lockState = new(int32)

	var wg sync.WaitGroup

	dir := t.TempDir()

	var stress = func() {
		defer wg.Done()
		lock := fslock.New(filepath.Join(dir, "testing"))
		for range lockAttempts {
			err := lock.Lock()
			assert.NoError(t, err)
			state := atomic.AddInt32(lockState, 1)
			assert.Equal(t, int32(1), state)
			// Tell the go routine scheduler to give a slice to someone else
			// while we have this locked.
			runtime.Gosched()
			// need to decrement prior to unlock to avoid the race of someone
			// else grabbing the lock before we decrement the state.
			atomic.AddInt32(lockState, -1)
			err = lock.Unlock()
			assert.NoError(t, err)
			// increment the general counter
			atomic.AddInt64(counter, 1)
		}
	}

	for range concurrentLocks {
		wg.Add(1)
		go stress()
	}
	wg.Wait()
	require.Equal(t, int64(lockAttempts*concurrentLocks), *counter)
}

// LockFromAnotherProc launches a process that takes the lock at path and blocks
// until that process signals that it has actually acquired the lock. The child
// writes a byte to its stdout only after Lock returns, which is a reliable
// cross-process barrier; waiting for the lock file to appear on disk would not
// be, because open(2) creates the file before flock/LockFileEx grants the lock.
// If the child fails to acquire the lock, this function fails the current test.
//
// The child holds the lock until the parent closes its stdin (triggered by
// closing kill), then unlocks and writes a second byte before exiting. The
// returned channel reports the outcome of releasing the child: receive from it
// after closing kill to wait for the release and surface any error the child
// hit; a nil value means it released the lock cleanly.
func LockFromAnotherProc(t *testing.T, path string, kill chan struct{}) chan error {
	cmd := exec.Command(os.Args[0], "-test.run", "TestLockFromOtherProcess")
	cmd.Env = append(
		// We must preserve os.Environ() on Windows,
		// or the subprocess will fail in weird and
		// wonderful ways.
		os.Environ(),
		"FSLOCK_TEST_HELPER_WANTED=1",
		"FSLOCK_TEST_HELPER_PATH="+path,
	)
	// Surface the child's stderr so a failed lock/unlock in the child reports
	// why, rather than just an opaque exit code at the call site.
	cmd.Stderr = os.Stderr

	// The child will write a byte to stdout when it acquires the lock
	// and another one when it releases it.
	//
	// The child will read its stdin until we close it. That is its signal
	// to release the lock.
	release, err := cmd.StdinPipe()
	require.NoError(t, err)
	childOut, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoErrorf(t, err, "error starting other proc")

	ret := make(chan error, 1)
	done := make(chan struct{})

	acquired := make(chan error, 1)
	go func() {
		// Read the byte indicated the lock is acquired.
		var buf [1]byte
		n, err := io.ReadFull(childOut, buf[:])
		if err != nil {
			acquired <- err
		} else if n != 1 {
			acquired <- fmt.Errorf("on lock acquired read, unexpected %d byte read from stdout", n)
		} else {
			close(acquired)
		}
		// Read the byte indicating the lock is released.
		n, err = io.ReadFull(childOut, buf[:])
		if err == nil && n == 1 {
			// Happy path. Return no errors and force kill
			// the process. We do not care about the fate of
			// the child process at this point. When running
			// under -race, the child process clean exit will
			// take ~1s. We simply kill and ignore here
			// instead.
			close(ret)
			close(done)
			cmd.Process.Kill()
			io.Copy(io.Discard, childOut)
			cmd.Wait()
		} else {
			// If we see anything unexpected, take the
			// child process exit code into account.
			io.Copy(io.Discard, childOut)
			ret <- cmd.Wait()
			close(done)
		}
	}()

	go func() {
		select {
		case <-kill:
			// Closing the child's stdin tells it to release the lock and exit.
			release.Close()
		case <-done:
		}
	}()

	// Block until the child writes its "lock acquired" byte. A read error
	// (typically EOF) means the child exited without taking the lock.
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("other process failed to acquire the lock: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for other process to acquire the lock")
	}

	return ret
}

func TestLockFromOtherProcess(t *testing.T) {
	if os.Getenv("FSLOCK_TEST_HELPER_WANTED") == "" {
		return
	}
	filename := os.Getenv("FSLOCK_TEST_HELPER_PATH")
	lock := fslock.New(filename)
	err := lock.Lock()
	require.NoError(t, err)

	// Signal the parent that the lock is now held.
	_, err = os.Stdout.Write([]byte{1})
	require.NoError(t, err)

	// Hold the lock until the parent closes our stdin.
	_, err = io.Copy(io.Discard, os.Stdin)
	require.NoError(t, err)

	err = lock.Unlock()
	require.NoError(t, err)

	// Signal that the lock has been released.
	_, err = os.Stdout.Write([]byte{1})
	require.NoError(t, err)
}
