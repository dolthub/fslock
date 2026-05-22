// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package fslock_test

import (
	"context"
	"fmt"
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

const (
	shortWait = 10 * time.Millisecond
	longWait  = 10 * shortWait
)

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
		// now wait for the other process to exit so the file will be unlocked.
		select {
		case <-procDone:
		case <-time.After(time.Second):
		}
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
		// now wait for the other process to exit so the file will be unlocked.
		select {
		case <-procDone:
		case <-time.After(time.Second):
		}
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
		// now wait for the other process to exit so the file will be unlocked.
		select {
		case <-procDone:
		case <-time.After(time.Second):
		}
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
		// now wait for the other process to exit so the file will be unlocked.
		select {
		case <-procDone:
		case <-time.After(time.Second):
		}
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

// LockFromAnotherProc will launch a process and block until that process has
// created the lock file.  If we time out waiting for the other process to take
// the lock, this function will fail the current test.
func LockFromAnotherProc(t *testing.T, path string, kill chan struct{}) (done chan struct{}) {
	cmd := exec.Command(os.Args[0], "-test.run", "TestLockFromOtherProcess")
	cmd.Env = append(
		// We must preserve os.Environ() on Windows,
		// or the subprocess will fail in weird and
		// wonderful ways.
		os.Environ(),
		"FSLOCK_TEST_HELPER_WANTED=1",
		"FSLOCK_TEST_HELPER_PATH="+path,
	)

	err := cmd.Start()
	require.NoErrorf(t, err, "error starting other proc")

	done = make(chan struct{})

	go func() {
		cmd.Wait()
		close(done)
	}()

	go func() {
		select {
		case <-kill:
			// this may fail, but there's not much we can do about it
			_ = cmd.Process.Kill()
		case <-done:
		}
	}()

	for x := range 10 {
		time.Sleep(shortWait)
		if _, err := os.Stat(path); err == nil {
			// file created by other process, let's continue
			break
		}
		if x == 9 {
			t.Fatalf("timed out waiting for other process to start")
		}
	}
	return done
}

func TestLockFromOtherProcess(t *testing.T) {
	if os.Getenv("FSLOCK_TEST_HELPER_WANTED") == "" {
		return
	}
	filename := os.Getenv("FSLOCK_TEST_HELPER_PATH")
	lock := fslock.New(filename)
	err := lock.Lock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error locking %q: %v", filename, err)
		os.Exit(1)
	}
	time.Sleep(longWait)
	err = lock.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error unlocking %q: %v", filename, err)
		os.Exit(1)
	}
	os.Exit(0)
}
