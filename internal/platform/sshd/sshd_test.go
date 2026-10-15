package sshd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func server(t *testing.T, held map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range held {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	savedConfiguration, savedDirectory := configuration, directory
	configuration, directory = filepath.Join(root, "sshd_config"), root
	t.Cleanup(func() { configuration, directory = savedConfiguration, savedDirectory })
	return root
}

func values(settings []Setting) []string {
	var found []string
	for _, setting := range settings {
		found = append(found, setting.Value+"@"+filepath.Base(setting.File)+":"+setting.Match)
	}
	return found
}

func TestEveryLineIsReadAsSshdSplitsItInTheOrderSshdReadsIt(t *testing.T) {
	root := server(t, map[string]string{
		"sshd_config": "# the server\n" +
			"Include sshd_config.d/*.conf\n" +
			"  permitrootlogin   yes  # as shipped\n" +
			"PasswordAuthentication=no\n" +
			"Banner = \"/etc/issue net\"\n" +
			"AuthorizedKeysFile .ssh/authorized_keys 'with space'\n" +
			"Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n" +
			"Match User admin Address 10.0.0.0/8\n" +
			"    PermitRootLogin prohibit-password\n" +
			"    Include /etc/ssh/extra/admin.conf\n" +
			"Match all\n" +
			"MaxAuthTries 4\n",
		"sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\nMatch Group sftp\nPermitRootLogin no\n",
		"sshd_config.d/10-first.conf":      "PermitRootLogin no\n",
		"sshd_config.d/notes.txt":          "PermitRootLogin forced-commands-only\n",
	})
	if err := os.MkdirAll(filepath.Join(root, "extra"), 0o755); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(content), "/etc/ssh/extra/admin.conf", filepath.Join(root, "extra", "admin.conf"), 1)
	if err := os.WriteFile(configuration, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra", "admin.conf"), []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	read, err := Read()
	if err != nil {
		t.Fatalf("read the configuration: %v", err)
	}
	for keyword, want := range map[string][]string{
		"PermitRootLogin": {
			"no@10-first.conf:",
			"no@50-cloud-init.conf:Group sftp",
			"yes@sshd_config:",
			"prohibit-password@sshd_config:User admin Address 10.0.0.0/8",
		},
		"PASSWORDAUTHENTICATION": {
			"yes@50-cloud-init.conf:",
			"no@sshd_config:",
			"yes@admin.conf:User admin Address 10.0.0.0/8",
		},
		"Banner":             {"/etc/issue net@sshd_config:"},
		"AuthorizedKeysFile": {".ssh/authorized_keys with space@sshd_config:"},
		"Ciphers":            {"aes256-gcm@openssh.com,chacha20-poly1305@openssh.com@sshd_config:"},
		"MaxAuthTries":       {"4@sshd_config:"},
	} {
		if got := values(read.Settings(keyword)); !slices.Equal(got, want) {
			t.Errorf("%s reads as %q, want %q", keyword, got, want)
		}
	}
	if settings := read.Settings("PermitRootLogin"); settings[2].Line != 3 {
		t.Errorf("the line of the main file's PermitRootLogin is read as %d", settings[2].Line)
	}
}

func TestAConfigurationSshdWouldNotReadOrTheAgentCannotIsNotReadAtAll(t *testing.T) {
	server(t, map[string]string{})
	if _, err := Read(); !errors.Is(err, ErrAbsent) {
		t.Fatalf("a host without sshd_config was answered %v", err)
	}
	for name, content := range map[string]string{
		"an unclosed quote":      "Banner \"/etc/issue\n",
		"a keyword alone":        "PermitRootLogin\n",
		"an include of itself":   "Include sshd_config\n",
		"a pattern glob refuses": "Include [\n",
	} {
		server(t, map[string]string{"sshd_config": content})
		if _, err := Read(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s was answered %v", name, err)
		}
	}
	if os.Geteuid() == 0 {
		t.Skip("the superuser reads whatever the mode says")
	}
	root := server(t, map[string]string{"sshd_config": "Include sshd_config.d/*.conf\n", "sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n"})
	if err := os.Chmod(filepath.Join(root, "sshd_config.d", "50-cloud-init.conf"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("a configuration including a file the agent may not read was answered %v", err)
	}
}
