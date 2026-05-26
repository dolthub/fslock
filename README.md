
# fslock [![GoDoc](https://godoc.org/github.com/juju/fslock?status.svg)](https://godoc.org/github.com/juju/fslock)
fslock provides a cross-process mutex based on file locks that works on windows and *nix platforms.


![fslock](https://cloud.githubusercontent.com/assets/3185864/15507515/f3351498-2199-11e6-9f37-bc59657a9e8c.jpg)

<sup><sub>image: [public domain](https://pixabay.com/en/encrypted-privacy-policy-445155/)
(don't ask)
</sub></sup>

fslock relies on LockFileEx on Windows and flock on \*nix systems.  The timed and
context-bounded calls (LockWithTimeout and LockWithContext) use overlapped IO on
Windows.  On \*nix systems a blocking flock cannot be interrupted once it parks,
so these calls instead poll with a non-blocking flock until the lock is acquired
or the deadline or cancellation fires.



## Variables
``` go
var ErrInvalidName error = errors.New("fslock: lock name must be a single path component")
```
ErrInvalidName indicates that the name passed to NewInRoot was not a single path
component within the root: it was empty, ".", "..", or contained a path
separator.

``` go
var ErrLocked error = trylockError("fslock is already locked")
```
ErrLocked indicates TryLock failed because the lock was already locked.

``` go
var ErrTimeout error = timeoutError("lock timeout exceeded")
```
ErrTimeout indicates that the lock attempt timed out.


## type Lock
``` go
type Lock struct {
    // contains filtered or unexported fields
}
```
Lock implements cross-process locks using syscalls.


### func New
``` go
func New(filename string) (*Lock, error)
```
New returns a new lock around the given file. It opens a handle to the file's
parent directory and returns an error if that directory cannot be opened.

### func NewInRoot
``` go
func NewInRoot(root *os.Root, name string) (*Lock, error)
```
NewInRoot returns a new lock around the file named name within root. name must
be a single path component: it may not be empty, ".", "..", or contain a path
separator, and otherwise NewInRoot returns ErrInvalidName. To lock a file in a
subdirectory, pass a sub-root obtained from root.OpenRoot. The lock file is
resolved relative to a directory handle, so it can never escape root via
symlinks or "..".

The lock borrows root only for the duration of this call: it opens its own
independent handle to root's directory, which it owns and which Close releases.
The caller retains ownership of root and may close it independently of the
returned Lock.

### func (\*Lock) Close
``` go
func (l *Lock) Close() error
```
Close releases the directory handle held by the lock. It does not release a
held lock; call Unlock first. The lock must not be used after Close.


### func (\*Lock) Lock
``` go
func (l *Lock) Lock() error
```
Lock locks the lock.  This call will block until the lock is available.

### func (\*Lock) LockWithContext
``` go
func (l *Lock) LockWithContext(ctx context.Context) error
```
LockWithContext tries to lock the lock until the context is canceled or its
deadline is exceeded.  If the context is canceled before the lock is acquired,
this method returns ctx.Err().

### func (\*Lock) LockWithTimeout
``` go
func (l *Lock) LockWithTimeout(timeout time.Duration) error
```
LockWithTimeout tries to lock the lock until the timeout expires.  If the
timeout expires, this method will return ErrTimeout.

### func (\*Lock) TryLock
``` go
func (l *Lock) TryLock() error
```
TryLock attempts to lock the lock.  This method will return ErrLocked
immediately if the lock cannot be acquired.

### func (\*Lock) Unlock
``` go
func (l *Lock) Unlock() error
```
Unlock unlocks the lock.


