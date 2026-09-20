// Package dumps keeps what the agent holds in memory out of everything the
// kernel would otherwise let somebody read: the private key it proves its
// identity with lives there, and a core dump or another process of the same
// account would carry it off the host as a file nothing else protects.
package dumps

// Withhold asks the kernel to write no core dump of this process and to keep
// its memory out of reach of the other processes its account runs. It reports
// errors.ErrUnsupported on a platform that offers no such control, and what
// the kernel says afterwards rather than what it was asked for.
func Withhold() error { return withhold() }
