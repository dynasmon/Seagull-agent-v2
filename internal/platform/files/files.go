package files

import "errors"

var ErrLocked = errors.New("another process holds the lock")
