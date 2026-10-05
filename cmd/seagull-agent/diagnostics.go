package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

const packagedService = "seagull-agent.service"

var journalFields = []string{"MESSAGE", "PRIORITY", "_PID", "_UID", "_COMM", "_AUDIT_LOGINUID"}

// The latest entries of the system journal a query matches, as many as most,
// read until the journal or ctx ends: what a bundle holds of what the agent
// and the commands run as its account wrote.
var journaled = func(ctx context.Context, query journal.Query, most int) ([]journal.Entry, error) {
	held, err := journal.New(query)
	if err != nil {
		return nil, err
	}
	reader, err := held.Open(ctx, journal.Position{Last: most}, false)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var read []journal.Entry
	for len(read) < most {
		entry, err := reader.Next()
		switch {
		case errors.Is(err, io.EOF):
			return read, nil
		case errors.Is(err, journal.ErrUnreadable):
			continue
		case err != nil:
			return read, err
		}
		read = append(read, entry)
	}
	return read, nil
}

// A bundle is gathered beside the running agent and never through it: without
// the installation's lock, opening neither its keys nor its spool, and within
// diagnostics.MaxTime, so an agent that runs keeps running as it was and one
// that cannot run is described all the same.
func diagnose(ctx context.Context, path, destination string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, diagnostics.MaxTime)
	defer cancel()
	bundle := gathered(ctx, path)
	named := secrets.Bounded(destination)
	written, err := diagnostics.Write(destination, bundle)
	if err != nil {
		audit(stderr, slog.LevelWarn, "diagnostics_not_written", slog.String("config", path), slog.String("bundle", named), slog.Any("error", err))
		hint := "write the bundle into a directory where the account the agent runs as may create a file, such as /var/tmp, and read it there as root"
		if errors.Is(err, diagnostics.ErrExists) || errors.Is(err, diagnostics.ErrInstallation) {
			hint = recovery(path, "", err)
		}
		fmt.Fprintf(stderr, "seagull-agent: %v\nseagull-agent: %s\n", err, hint)
		return 1
	}
	unread := bundle.Unread()
	audit(stderr, slog.LevelInfo, "diagnostics_written", slog.String("config", path), slog.String("bundle", named), slog.Int("bytes", written), slog.Int("unread", len(unread)))
	fmt.Fprintf(stdout, "the bundle is written to %s: %d bytes, which the account the agent runs as alone reads\n", secrets.Shown(destination), written)
	for _, missed := range unread {
		fmt.Fprintf(stdout, "it says why it holds no %s\n", secrets.Bounded(missed))
	}
	return 0
}

func gathered(ctx context.Context, path string) diagnostics.Bundle {
	info, _ := debug.ReadBuildInfo()
	versions := make(map[string]int)
	for _, spoken := range wireVersions() {
		versions[spoken.name] = spoken.version
	}
	groups, _ := os.Getgroups()
	slices.Sort(groups)
	bundle := diagnostics.Bundle{
		Writer: diagnostics.Writer{User: os.Geteuid(), Group: os.Getegid(), Groups: groups},
		Build:  diagnostics.Built(buildIdentity(), versions, info),
	}
	installed(ctx, path, &bundle)
	bundle.Logs = journalOf(ctx)
	return bundle
}

func installed(ctx context.Context, path string, bundle *diagnostics.Bundle) {
	settings, err := config.Load(path)
	if err == nil {
		var effective []byte
		if effective, err = settings.Encode(); err == nil {
			bundle.Configuration = diagnostics.Took(path, json.RawMessage(effective))
		}
	}
	if err != nil {
		bundle.Configuration = diagnostics.Missed(path, err, recovery(path, "", err))
		unnamed := diagnostics.Text("the configuration names no installation the agent could read")
		bundle.Status.Unread, bundle.Installation.Unread, bundle.Credential.Unread = unnamed, unnamed, unnamed
		bundle.Authorities.Configured.Unread, bundle.Files.Unread = unnamed, unnamed
		return
	}
	state := settings.Identity.StateDirectory
	bundle.Files = diagnostics.List(ctx, state)
	kept := filepath.Join(state, statusDirectory)
	if snapshot, err := status.Read(kept); err != nil {
		bundle.Status = diagnostics.Missed(kept, err, recovery(path, state, err))
	} else {
		bundle.Status = diagnostics.Took(kept, snapshot)
	}
	recorded, found, err := identity.Recorded(state)
	switch {
	case err != nil:
		bundle.Installation = diagnostics.Missed(state, err, recovery(path, state, err))
	case !found:
		bundle.Installation = diagnostics.Missed(state, fmt.Errorf("%s holds no installation yet", state), recovery(path, state, identity.ErrNoInstallation))
	default:
		bundle.Installation = diagnostics.Took(state, recorded)
	}
	var trusted []*x509.Certificate
	bundle.Authorities, trusted = vouched(path, settings, recorded)
	bundle.Credential = chained(path, state, recorded, trusted)
}

// The authorities the configuration names and those the installation adopted,
// and which of them the agent trusts, as a running agent would decide it.
func vouched(path string, settings config.Config, recorded identity.Record) (diagnostics.Authorities, []*x509.Certificate) {
	state, bundle := settings.Identity.StateDirectory, settings.Server.TrustBundle
	var held diagnostics.Authorities
	if configured, err := settings.Server.Authorities(); err != nil {
		refused := fmt.Errorf("%w: %w", config.ErrInvalid, err)
		held.Configured = diagnostics.Set{From: diagnostics.Text(bundle), Unread: diagnostics.Text(err.Error()), Recovery: diagnostics.Text(recovery(path, state, refused))}
	} else {
		held.Configured = diagnostics.Trusting(bundle, pki.Digest(configured), configured)
	}
	adopting := func() (identity.Trust, bool, error) {
		if recorded.Trust == nil {
			return identity.Trust{}, false, nil
		}
		return *recorded.Trust, true, nil
	}
	chosen, _ := trusted(settings, adopting, func(digest string) ([]*x509.Certificate, error) { return adopted(state, digest) })
	held.Trusted = diagnostics.Text(chosen.source)
	if recorded.Trust != nil {
		directory := filepath.Join(state, trustDirectory)
		if published, err := adopted(state, recorded.Trust.Authorities); err != nil {
			held.Adopted = &diagnostics.Set{From: diagnostics.Text(directory), Digest: diagnostics.Text(recorded.Trust.Authorities), Unread: diagnostics.Text(err.Error()),
				Recovery: "nothing: the agent authenticates the platform against server.trust_bundle until a renewal adopts the authorities the platform publishes again"}
		} else {
			set := diagnostics.Trusting(directory, recorded.Trust.Authorities, published)
			held.Adopted = &set
		}
	}
	return held, chosen.authorities
}

func adopted(state, digest string) ([]*x509.Certificate, error) {
	root, err := within(state, trustDirectory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return pki.ReadAuthorities(root, digest)
}

func chained(path, state string, recorded identity.Record, trusted []*x509.Certificate) diagnostics.Credential {
	directory := filepath.Join(state, certificatesDirectory)
	if recorded.Enrollment == nil {
		return diagnostics.Credential{Unread: "the installation is not enrolled", Recovery: diagnostics.Text(recovery(path, state, renewal.ErrNotEnrolled))}
	}
	root, err := within(state, certificatesDirectory)
	if err != nil {
		return diagnostics.Credential{From: diagnostics.Text(directory), Unread: diagnostics.Text(err.Error()), Recovery: diagnostics.Text(recovery(path, state, err))}
	}
	defer root.Close()
	chain, err := pki.ReadCertificates(root, recorded.Enrollment.Certificate.FingerprintSHA256)
	if err != nil {
		return diagnostics.Credential{From: diagnostics.Text(directory), Unread: diagnostics.Text(err.Error()), Recovery: diagnostics.Text(recovery(path, state, err))}
	}
	return diagnostics.Presented(directory, chain, trusted, time.Now())
}

// A directory of the installation, opened from the installation's own so that
// a link there leads nowhere outside it.
func within(state, name string) (*os.Root, error) {
	installation, err := os.OpenRoot(state)
	if err != nil {
		return nil, err
	}
	defer installation.Close()
	return installation.OpenRoot(name)
}

func journalOf(ctx context.Context) diagnostics.Logs {
	audited := []journal.Match{{Field: "SYSLOG_IDENTIFIER", Value: syslogIdentifier}, {Field: "_TRANSPORT", Value: "journal"}, {Field: "_UID", Value: strconv.Itoa(os.Geteuid())}}
	held := diagnostics.Logs{Complete: true}
	var entries []diagnostics.Entry
	for _, query := range []journal.Query{{Unit: packagedService, Fields: journalFields}, {Matches: audited, Fields: journalFields}} {
		matched := []string{}
		if query.Unit != "" {
			matched = append(matched, "--unit="+query.Unit)
		}
		for _, match := range query.Matches {
			matched = append(matched, match.Field+"="+match.Value)
		}
		held.Sources = append(held.Sources, diagnostics.Text(strings.Join(matched, " ")))
		read, err := journaled(ctx, query, diagnostics.MaxEntries)
		for _, entry := range read {
			entries = append(entries, diagnostics.Logged(entry.Cursor, entry.Realtime, entry.Fields))
		}
		switch {
		case err != nil:
			held.Complete = false
			held.Unread = append(held.Unread, diagnostics.Text(err.Error()))
			if errors.Is(err, journal.ErrDenied) {
				held.Recovery = "make the account the agent runs as a member of systemd-journal, as the package does, and write the bundle again"
			}
		case len(read) == diagnostics.MaxEntries:
			held.Complete = false
		}
	}
	kept, complete := diagnostics.Kept(entries)
	if kept == nil {
		kept = []diagnostics.Entry{}
	}
	held.Entries, held.Complete = kept, held.Complete && complete
	return held
}
