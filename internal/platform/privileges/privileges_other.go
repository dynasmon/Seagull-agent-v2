//go:build !linux

package privileges

func capabilities() ([]string, bool, error) { return []string{}, false, nil }
