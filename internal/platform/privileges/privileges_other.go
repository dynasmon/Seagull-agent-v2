//go:build !linux

package privileges

func granted() (Privileges, error) {
	return Privileges{Capabilities: []string{}, Seccomp: "unsupported"}, nil
}
