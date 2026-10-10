# Seagull Agent v2

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-Go%201.26-00ADD8.svg)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04%20systemd-E95420.svg)](packaging/linux/seagull-agent.service)
[![Contracts](https://img.shields.io/badge/contracts-Seagull--contracts-00A6A6.svg)](https://github.com/dynasmon/Seagull-contracts)
[![Backend](https://img.shields.io/badge/backend-Seagull--backend--v2-4B32C3.svg)](https://github.com/dynasmon/Seagull-backend-v2)

Seagull Agent v2 is the endpoint component of Seagull v2: the process that runs
on a host, observes it, and delivers what it observed durably to the
[Seagull backend](https://github.com/dynasmon/Seagull-backend-v2). It is built,
tested, packaged and released from this repository alone. The only Seagull code
it consumes is the published
[contracts](https://github.com/dynasmon/Seagull-contracts) module, at the release
`go.mod` pins; the [legacy agent](https://github.com/dynasmon/seagull-agent) is a
record of behavior, not a dependency.

The agent owns its installation identity, its private key, its configuration,
its delivery backlog, its collector checkpoints and its status. The platform
owns agent registration, certificate issuance, the decision to admit each
request, ingestion, storage and analysis.

## Agent capabilities

Collectors are enabled under `modules` in the configuration, and none runs
unless it is named. Five are available: `authentication`, `inventory`,
`processes`, `files` and `network`. The settings the package installs enable
`authentication` and `inventory`.

### Authentication monitoring

`authentication` reads what sshd decides from the system journal, never from
`auth.log`, and takes only the entries sshd's monitor wrote as root, as journald
records the sender, so a line another program writes in sshd's name is ignored.
Each accepted or failed attempt becomes one `LOGON` event with its outcome,
method, user and source address. The collector records its place in the
journal only once the spool made the events before it durable, so a restart
loses nothing, and reports a journal rotated past that place as a
`collection_gap`.

### Inventory

`inventory` takes complete snapshots of the operating system, kernel, hardware,
dpkg packages, systemd services, network interfaces and local accounts, as
`seagull.inventory.v1` records, when it starts and then every
`modules.inventory.interval`. A kind is sent again only when it changed or once
the platform's copy is a day old, and a kind the agent cannot read whole is
never sent in part.

### Processes

`processes` takes snapshots of the running processes as `process` inventory:
PID, parent, name, account, start time and, where the agent may read it, the
executable. It never opens a process's arguments, environment or memory. The
service hides other accounts' processes from the agent, so the module needs the
drop-in [Privileges](#privileges) lists.

### File integrity monitoring

`files` walks the paths `modules.files.paths` names, by default `/etc`,
`/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`,
`/usr/lib/systemd/system`, `/boot` and `/var/spool/cron`. It keeps a baseline
with the SHA-256 of every regular file up to 256 MiB, follows inotify hints as
they arrive, and walks everything again every `modules.files.interval`.
Creations, deletions, modifications, renames and transient files are written
to the agent's log as `file_changed`, with what changed and the entry before
and after. Links are recorded and never followed. The contracts have no record
for a file change yet, so nothing leaves the host.

### Network listeners and flows

`network` reads the TCP and UDP socket tables of every network namespace it
can see, every `modules.network.interval`, and logs listeners as they open,
close or change, and flows, the connections of one account with one remote
address on one service port in one direction, as they start and end. It names
the process holding a socket when the agent may read it, and opens no socket,
reads no packet and resolves no name. Like `files`, it delivers nothing until
the contracts carry these records.

### Durable delivery

A record is admitted to the on-disk spool only once it is synced, in one of two
checksummed streams, `events` and `inventory`, each kept in its own order.
Delivery sends batches over mutual TLS 1.3, and only a durable acknowledgement
that counts every record drops them; anything less sends the same batch again,
with jittered backoff and the platform's `Retry-After` honoured. A record the
platform refuses for good is quarantined, while a refusal of the agent itself,
or of a version it speaks, holds the records and drops none. The spool is
bounded by `spool.max_bytes` and `spool.max_age`, keeps no event longer than the
platform admits one, pauses admission when it is full instead of evicting, and
counts every record that leaves it undelivered as lost, expired or quarantined.
Events are sent before inventory.

### Identity and renewal

Each installation draws its own ECDSA P-256 key, which never leaves the host,
and is enrolled by an operator who has the platform sign its certificate
request: the agent holds no bootstrap secret. Once enrolled, it renews its
certificate on its own, between seven and nine twelfths of its lifetime,
rotates its key once it is older than `identity.key_lifetime`, follows the
authorities the platform publishes when it rotates its own, and asks again with
the very same request when the answer to a renewal was lost.

### Status and diagnostics

The running agent writes its status every 30 seconds, and `status` prints it,
exiting with 0 only while the agent runs as it should. `diagnostics BUNDLE`
writes a JSON bundle for troubleshooting that holds no key, no certificate or
request as encoded and no record of the spool. Every command that changes the
installation, and every bundle, is recorded in the system journal, attributed
to whoever ran it: `journalctl SYSLOG_IDENTIFIER=seagull-agent _TRANSPORT=journal`.

## Supported systems

| Operating system | Architectures |
|---|---|
| Ubuntu 24.04 with systemd | `amd64` |

The agent is a static Go binary, and its Debian package depends only on systemd
and procps. The host needs neither Go, Git nor any Seagull repository.
`make package ARCH=arm64` builds an arm64 package, which is not supported until
it passes its own native gate; other distributions, Windows and macOS are not
supported.

## Verify a release

A release is a tag `vX.Y.Z`. Its workflow verifies the commit, packages it, runs
the package through the native gate, and only then attests SLSA provenance for
it through Sigstore. The package and that statement, as a `.sigstore.json`
bundle, are attached to a draft release that a maintainer publishes. Verify a
package before installing it, with a GitHub CLI that has `gh attestation`
(Ubuntu 24.04's own, 2.45, predates it):

```bash
gh attestation verify seagull-agent_0.1.0-1_amd64.deb \
  --repo dynasmon/Seagull-agent-v2 \
  --signer-workflow dynasmon/Seagull-agent-v2/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

Verification fails for a package whose bytes changed and for one another
repository, workflow or tag built; `--bundle` checks against the attached
statement instead of asking GitHub. No signing key exists to be kept or lost:
the workflow signs with a certificate that expires minutes later. The same
commit always packages into the same bytes, and tag `v0.1.0` is package version
`0.1.0-1`.

## Installing

```bash
sudo apt install ./seagull-agent_0.1.0-1_amd64.deb
```

The package creates the `seagull-agent` system account, a member of
`systemd-journal`, with `/var/lib/seagull-agent` (0700) for its installation and
`/etc/seagull-agent` for its settings. It installs the agent at
`/usr/bin/seagull-agent`, the `seagull-agent` service and a settings template at
`/usr/share/seagull-agent/agent.json`. It starts and enables nothing, and holds
no key, certificate or authority.

An operator then gives the agent its settings, enrolls it and starts it:

```bash
sudo install -m 0644 platform-ca.pem /etc/seagull-agent/platform-ca.pem
sudo install -m 0644 /usr/share/seagull-agent/agent.json /etc/seagull-agent/agent.json
sudoedit /etc/seagull-agent/agent.json     # server.ingest_url and server.renewal_url
sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json platform check
sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json enrollment request web-01 > web-01.csr
# the platform issues the certificate, off this host
sudo install -m 0644 web-01.issued /var/tmp/web-01.issued
sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json enrollment import /var/tmp/web-01.issued
sudo systemctl enable --now seagull-agent
```

- `platform-ca.pem` holds the authority that issues the platform's
  certificates, and decides which platform the agent trusts: obtain it through
  a trusted channel and compare its fingerprint,
  `openssl x509 -in platform-ca.pem -noout -fingerprint -sha256`.
- Every command runs as the service account, since the installation is private
  to it. `seagull-agent -h` lists them all.
- `enrollment request` draws the key on the host and prints a PEM certificate
  request that carries only its public half; asking again prints the same
  request. An operator has the platform issue the certificate as themselves:
  `POST /v1/agents/web-01/certificate` on the control plane, with the request
  as `csr_pem`.
- `enrollment import` activates the answer only when it certifies that
  request's key for that agent and chains to `server.trust_bundle`, and it is
  safe to repeat.
- The agent logs to the journal, `journalctl -u seagull-agent`, and
  `systemctl reload seagull-agent` has it read its settings again.

## Configuration

`-config` names one JSON file, and everything the agent runs on is in it:

```json
{
  "format": 1,
  "identity": {"state_directory": "/var/lib/seagull-agent"},
  "server": {
    "ingest_url": "https://gateway.example:8443",
    "renewal_url": "https://control.example:8446",
    "trust_bundle": "/etc/seagull-agent/platform-ca.pem"
  },
  "modules": {"authentication": {"enabled": true}, "inventory": {"enabled": true}}
}
```

The `server` settings are the deployment's and have no default; every other
setting has one, which `config print` shows. The file is read whole or refused
whole: an unknown, repeated or null setting, a size or a time without its unit
(`8MiB`, `30s`), or a file above 64 KiB is refused, and `config check` names
every problem without starting the agent. The file holds no secret, and only
root or the agent's account may write it. On SIGHUP the agent validates the
whole file before it replaces its configuration, and keeps the one it has when
it refuses the new one; the state directory, the key provider, the `server`
settings, the connect and request timeouts, the reply bound, the log format
and the shutdown timeout take a restart.

| Setting | Default | What it decides |
|---|---|---|
| `identity.key_lifetime` | `720h` | how long renewals keep a key before drawing a new one |
| `spool.max_bytes` | `512MiB` | the disk the backlog may use |
| `spool.max_age` | `72h` | how long a record waits; events never more than `168h` |
| `modules.<name>.enabled` | `false` | which collectors run |
| `modules.inventory.interval`, `modules.processes.interval` | `1h` | how often each takes stock |
| `modules.files.paths`, `modules.files.exclude`, `modules.files.interval` | as above, none, `1h` | what the files module watches, leaves out, and walks again how often |
| `modules.network.interval` | `1m` | how often the socket tables are read |
| `resources.memory_limit` | `256MiB` | the target of the garbage collector |
| `resources.max_scan_bytes_per_second` | `8MiB` | the pace of scans and hashing |
| `logging.level`, `logging.format` | `info`, `json` | what the log says, and how |

`transport.*` sets the timeouts, the batch sizes, within the platform's
ceilings, and the upload bandwidth; `resources.*` also bounds the scans and
uploads that run at once and how long the agent takes to stop.

## Privileges

The service runs the agent as `seagull-agent`, with no capability and
`NoNewPrivileges=yes`. The agent writes only its installation and a `/tmp` and
`/var/tmp` of its own, and sees the rest of the host read-only; home
directories, the processes of other accounts, shared memory and all but the
basic devices are hidden from it. It may open IPv4, IPv6 and local sockets
alone, make the `@system-service` system calls less `@privileged`, and use
512 MiB of memory with no swap, half a processor, 256 tasks and 4096
descriptors. As it starts, the agent logs what it actually holds as
`agent_privileges` and the ceilings it runs under as `agent_resources`, and
warns about anything it holds beyond what its enabled modules need.

Collectors that need more of the host are the operator's to allow, with a
drop-in under `/etc/systemd/system/seagull-agent.service.d/` followed by
`systemctl daemon-reload` and a restart:

| Module | Drop-in | What it allows |
|---|---|---|
| `processes` | `ProtectProc=default` | every process in `/proc` |
| `files` | `ProtectHome=read-only`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `AmbientCapabilities=CAP_DAC_READ_SEARCH` | `/home`, `/root` and the files only root reads |
| `network` | `ProtectProc=default` | the other network namespaces |
| `network` | also `ReadOnlyPaths=/proc`, `CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`, `AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`, `SystemCallFilter=~process_vm_readv process_vm_writev` | the process holding another account's socket |

`CAP_DAC_READ_SEARCH` lets the agent read any file on the host, keys included,
which is why the package never grants it. Modules share one process, so a
drop-in loosens the agent as a whole.

## Upgrade and removal

Install a newer package the same way. The upgrade replaces the agent and its
service and restarts the service when it is enabled or running; the
installation, its keys, its backlog and its settings stay, so it runs on as the
same agent. The agent never updates itself.

```bash
sudo apt remove seagull-agent   # keeps the installation, the settings and the account
sudo apt purge seagull-agent    # also deletes them and the service's overrides
```

`purge` deletes the installation's keys, but not the certificate the platform
issued for them, so revoke the agent on the platform first. With the agent
stopped, `seagull-agent -config FILE installation replace` sets the current
installation aside under `replaced/` and starts a new, unenrolled one, for a
host whose state was damaged or whose key may have been copied. Keys set aside
still authenticate until their certificate expires or is revoked, so revoke the
old agent when it was enrolled.

## Runtime state

| Path | Purpose |
|---|---|
| `/etc/seagull-agent/agent.json` | Configuration, root's and public |
| `/etc/seagull-agent/platform-ca.pem` | `server.trust_bundle`: the authorities trust in the platform starts from |
| `/var/lib/seagull-agent/installation.json` | Installation identifier, credential generation, pending request, adopted authorities |
| `/var/lib/seagull-agent/keys/` | Private keys, PKCS #8 |
| `/var/lib/seagull-agent/certificates/` | Issued certificates and their chains |
| `/var/lib/seagull-agent/trust/` | Authorities adopted from renewals |
| `/var/lib/seagull-agent/spool/` | Durable `events` and `inventory` streams |
| `/var/lib/seagull-agent/collection/` | Collector checkpoints and baselines |
| `/var/lib/seagull-agent/status/status.json` | What the agent last said of itself |
| `/var/lib/seagull-agent/replaced/` | Installations set aside by `installation replace` |

The state directory is private to the agent's account and locked while the
agent runs, and the agent refuses state another account can reach. Keys are
not encrypted at rest, since the secret to decrypt them would sit on the same
disk: whoever can read the directory, root and backups included, holds the
agent's identity, and a copied key is revoked with its agent.

## Compatibility

This build speaks protocol 1, event schema 1 and inventory schema 1, as
`seagull-agent -version` prints, from the contracts release `go.mod` pins. The
agent negotiates nothing before it sends; the platform's answer to a batch is
where it learns what the platform accepts. A refused version, or a refused value
its contracts declare, is an incompatibility that holds the records rather than
quarantining them, since a platform that speaks them accepts them unchanged. A
refusal of the agent itself is an exclusion that waits for an operator. Reply
fields the contracts do not declare are ignored.

Compatibility is claimed only with the backend commits recorded under
[`tests/compatibility/testdata`](tests/compatibility/testdata): 6fae345, 2829b0d
and 0656b2a, whose ingest gateway, control plane and pipeline were driven with
what this agent sends. The suite fails when `go.mod` pins contracts no recorded
platform was built with, or when a recorded answer reads differently.

## Build and test

The go command selects the toolchain `go.mod` names and fetches every
dependency from the module proxy, so a checkout is all a build needs.

```bash
make build        # dist/seagull-agent
make verify       # formatting, vet, module graph, tests, race detector and build
make vulncheck    # known vulnerabilities reachable from the agent
make package      # dist/deb/seagull-agent_<version>_amd64.deb, of the commit checked out
make native-gate  # installs that package on this host, as root: use a disposable host
```

`make verify` runs the unit, architecture and compatibility suites;
`tests/architecture` holds the package boundaries as tests. CI also packages
every commit twice and compares the bytes, and runs the native gate, which
takes the installed service through enrollment, renewal, collection, delivery,
upgrade, removal and purge on Ubuntu 24.04. While a contract change is in
progress, a `go.work` may use a sibling contracts checkout; Git ignores it, and
every `make` target runs with `GOWORK=off`.

## Security

Never attach a private key, the contents of `/var/lib/seagull-agent` or the
spool to a public issue. A diagnostics bundle is meant to be shared once an
operator has read it: it holds no key and no spool record, but it names the
host's paths, the platform's addresses and the agent, and holds its log.

## License

Seagull Agent v2 is licensed under the [GNU General Public License v3.0](LICENSE).
