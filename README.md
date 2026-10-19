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
unless it is named. Six are available: `authentication`, `inventory`,
`processes`, `files`, `network` and `assessment`. The settings the package
installs enable `authentication` and `inventory`.

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

### Security configuration assessment

`assessment` runs the checks of the signed policy in force against the host, and
nothing else: the agent's configuration names no checks, so what it assesses is
what an operator signed. A check is a typed test, never a command: the owner,
group, kind or permission bits of a path; a rule about the accounts and groups
of `/etc/passwd` and `/etc/group`; a kernel parameter in force; a kernel module
loaded, or kept out by an `install` line of the modprobe configuration; a dpkg
package installed or not; a systemd unit enabled, masked or running; a directive
as sshd applies `/etc/ssh/sshd_config` and what it includes, Match blocks too,
or as the shadow utilities apply `/etc/login.defs`. Each check is answered
`pass`, `fail`, `error` when the agent could not read what it is about, or not
within the five minutes a round is given, `unsupported` when it does not run
such a check, a newer test included, or `not_applicable` when what it is about
is not on the host, with evidence naming what was judged and where, and never
more of a file than the directive a check names. The module assesses when it
starts, every `modules.assessment.interval`, and as soon as the policy in force
changes, and admits an assessment answering every check when what it found
changed, or once the platform's copy is nearly a day old. A policy enables the
module like any other, under `modules`.

The agent judges the host through the sandbox the service runs it in: a path
the service hides from it, such as `/root`, or one its account may not reach,
such as an sshd file of mode 0600, is an `error` that names the drop-in
[Privileges](#privileges) lists, never a pass. A module built into the kernel
without parameters cannot be told from an absent one, as the service hides
`/usr/lib/modules`, and options sshd is started with outside its configuration
are not read.

### Durable delivery

A record is admitted to the on-disk spool only once it is synced, in one of
three checksummed streams, `events`, `inventory` and `assessments`, each kept in
its own order.
Delivery sends batches over mutual TLS 1.3, and only a durable acknowledgement
that counts every record drops them; anything less sends the same batch again,
with jittered backoff and the platform's `Retry-After` honoured. A record the
platform refuses for good is quarantined, while a refusal of the agent itself,
or of a version it speaks, holds the records and drops none. The spool is
bounded by `spool.max_bytes` and `spool.max_age`, keeps no event longer than the
platform admits one, pauses admission when it is full instead of evicting, and
counts every record that leaves it undelivered as lost, expired or quarantined.
Events are sent before inventory and assessments, which take at most half and a
sixteenth of the spool.

### Identity and renewal

Each installation draws its own ECDSA P-256 key, which never leaves the host,
and is enrolled by an operator who has the platform sign its certificate
request: the agent holds no bootstrap secret. Once enrolled, it renews its
certificate on its own, between seven and nine twelfths of its lifetime,
rotates its key once it is older than `identity.key_lifetime`, follows the
authorities the platform publishes when it rotates its own, and asks again with
the very same request when the answer to a renewal was lost.

### Signed policy

An agent can be told how to run by a policy an operator signs off the platform:
the platform hands it on the listener the agent renews on, and the agent applies
it only when a key `policy.signers` holds the public half of signed it, it names
the agent, it has not expired and its revision is no lower than the one the
agent holds. A policy sets the log level, which modules collect and how often,
what the files module watches, the checks the assessment module runs, and
budgets, which only ever lower the ceilings of `agent.json`; it never reaches
the platform the agent talks to, what it trusts, its identity or its timeouts.
The policy in force is kept in the installation and verified again at every
start and on SIGHUP, so retiring a key from `policy.signers` withdraws what it
signed; one that expires stays in force and is reported until a newer one
arrives. `status` says which revision the
agent runs on, and every policy applied or refused is in the journal.

### Signed updates

Once an operator enables it, the agent installs the release the platform asks
it to run when a catalog operators signed off the platform names it, and goes
back to the release before when the new one does not run as it should. The
platform decides which agents are asked, and when, agent by agent or in the
waves of a rollout, and pauses a rollout on the agents that report it went
wrong. See [Updating](#updating).

### Status and diagnostics

The running agent writes its status every 30 seconds, and `status` prints it,
exiting with 0 only while the agent runs as it should, with how the run before
it ended. Once enrolled, it also tells the platform how it runs every
`reporting.interval`, on a stream of its own beside what it delivers, and once
more as it stops: each report stands on its own, so the agent sends its newest
and keeps no backlog, and the platform judges an agent active, late, silent or
stopped by when its reports arrive. `diagnostics BUNDLE`
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
the package through the native gate and packages the commit again on a second
builder. Only when both builders wrote the same bytes does it attest, through
Sigstore, SLSA provenance for the package and the SPDX bill of materials of what
the package holds. The package, its bill of materials and both statements, as
`.sigstore.json` bundles, are attached to a draft release that a maintainer
publishes. Verify a package before installing it, with a GitHub CLI that has
`gh attestation` (Ubuntu 24.04's own, 2.45, predates it):

```bash
gh attestation verify seagull-agent_0.1.0-1_amd64.deb \
  --repo dynasmon/Seagull-agent-v2 \
  --signer-workflow dynasmon/Seagull-agent-v2/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

The same command with `--predicate-type https://spdx.dev/Document/v2.3`
verifies the bill of materials, `seagull-agent_0.1.0-1_amd64.spdx.json`: the
package and its SHA-256, the agent and the commit it was built from, the Go
toolchain and every module the agent links, with its version and `go.sum` hash.
Verification fails for a package whose bytes changed, which the workflow checks
with a changed copy before it drafts the release, for one another repository,
workflow or tag built, and, given `--source-digest` with the commit the release
notes name, for one built from another commit; `--bundle` checks against an
attached statement instead of asking GitHub. No signing key exists to be kept or lost:
the workflow signs with a certificate that expires minutes later. Tag `v0.1.0`
is package version `0.1.0-1`, and a pre-release such as `v0.1.0-rc.1` is
`0.1.0~rc.1-1`. A pre-release is a word and its numbers, such as `rc.2`: dpkg
would order another kind differently from the agent, or give two of them one
package version, so the workflow refuses to package it.

A release can be rebuilt and compared with the one published: `make package`
at its tag, with Go 1.26.9, writes the same package and bill of materials, byte
for byte. CI checks it for every commit, packaging it on the Ubuntu 24.04 runner
and again in the `golang:1.26.9-trixie` image as another account, in another
directory and under another time zone, locale and umask; one commit packaged on
Ubuntu 24.04 and 22.04 and on Debian 12 and 13 was the same bytes on all four.
The agent is built without its symbol table and debugging information, which
halves the package; a panic still names every function and line it went
through.

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
settings, the connect and request timeouts, the reply bound, the log format,
the shutdown timeout, the `policy.signers` file named and `updates.enabled` and
`updates.root` take a restart.

| Setting | Default | What it decides |
|---|---|---|
| `identity.key_lifetime` | `720h` | how long renewals keep a key before drawing a new one |
| `spool.max_bytes` | `512MiB` | the disk the backlog may use |
| `spool.max_age` | `72h` | how long a record waits; events never more than `168h` |
| `modules.<name>.enabled` | `false` | which collectors run |
| `modules.inventory.interval`, `modules.processes.interval` | `1h` | how often each takes stock |
| `modules.files.paths`, `modules.files.exclude`, `modules.files.interval` | as above, none, `1h` | what the files module watches, leaves out, and walks again how often |
| `modules.network.interval` | `1m` | how often the socket tables are read |
| `modules.assessment.interval` | `1h` | how often the checks of the policy in force run |
| `resources.memory_limit` | `256MiB` | the target of the garbage collector |
| `resources.max_scan_bytes_per_second` | `8MiB` | the pace of scans and hashing |
| `logging.level`, `logging.format` | `info`, `json` | what the log says, and how |
| `policy.signers` | none | the PEM public keys, ECDSA P-256, a signed policy is accepted under; none asks for no policy |
| `policy.interval` | `5m` | how often the agent asks for the policy that names it |
| `reporting.interval` | `1m` | how often the agent tells the platform how it runs, between `10s` and `1h` |
| `updates.enabled` | `false` | whether the agent installs the release the platform asks it to run |
| `updates.root` | none | the update root the agent is provisioned with, as its signed envelope; needed once updates are enabled |
| `updates.interval` | `15m` | how often the agent asks whether to update, between `1m` and `24h` |
| `updates.check_within` | `4m` | how long a new release has to show it runs before the installer goes back, between `1m` and `1h` |

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
| `assessment` | `ProtectHome=read-only`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `AmbientCapabilities=CAP_DAC_READ_SEARCH` | checks of `/home`, `/root` and the files only root reads |

`CAP_DAC_READ_SEARCH` lets the agent read any file on the host, keys included,
which is why the package never grants it. Modules share one process, so a
drop-in loosens the agent as a whole.

## Self-protection

The agent runs only when root alone can change what decides it: its
executable, its configuration, `server.trust_bundle`, `policy.signers`,
`updates.root` and the directory that holds its installation, with every
directory above them. When
another account could change one of them, its own included, the agent refuses
to start and says which and why, so taking over its account does not change
what it runs after it starts again; `config check` says the same without
starting it. The service starts the agent again however it ended, unless the
service manager was asked to stop it: 5 seconds after the first exit, then
further apart up to 5 minutes, which systemd keeps counting until the service
is stopped or the host starts again.

As it starts, the agent logs how the run before it ended, `stopped` as it was
asked or `interrupted` by a kill, a crash or the host losing power, and how
long it was not running, then as `agent_changed` what differs from what that
run said of itself: its build, its settings, the policy in force, the
collectors that run and what it may do on the host. A collector stopped, a
privilege gained or a policy gone is a warning. The same facts travel in every
report, with a count of the reports the installation sent and the boot of its
host: the platform tells an agent somebody stopped from one that went quiet,
and the count and the boot are what tell a copy of an installation from the
original.

None of this holds against root. Root can stop or remove the agent, change or
replace any of its files, read its key, and erase the journal these lines are
in; what the agent says of its build, its settings and its privileges is its
word, never an attestation. Accounts other than root cannot change any of it,
read the installation, signal the agent or stop the service, as the native
gate checks. An agent that stops reporting is late and then silent, never
disabled or revoked for it, and a copied key is still found at renewal, as
[Identity and renewal](#identity-and-renewal) describes.

## Upgrade and removal

Install a newer package the same way. The upgrade replaces the agent and its
service and restarts the service when it is enabled or running; the
installation, its keys, its backlog and its settings stay, so it runs on as the
same agent. The agent updates itself only as [Updating](#updating) describes.

```bash
sudo apt remove seagull-agent   # keeps the installation, the settings and the account
sudo apt purge seagull-agent    # also deletes them, what the installer kept and the service's overrides
```

`purge` deletes the installation's keys, but not the certificate the platform
issued for them, so revoke the agent on the platform first. With the agent
stopped, `seagull-agent -config FILE installation replace` sets the current
installation aside under `replaced/` and starts a new, unenrolled one, for a
host whose state was damaged or whose key may have been copied. Keys set aside
still authenticate until their certificate expires or is revoked, so revoke the
old agent when it was enrolled.

## Updating

The agent installs a release only once an operator enables updates, and only a
release operators authorized off the platform, after The Update Framework: the
root role of a root signs the next root, and its catalog role signs a catalog of
every release agents may install, with the digest and size of its package. Give
the agent the first root as root, enable updates and restart the service:

```json
"updates": {"enabled": true, "root": "/etc/seagull-agent/update-root.pb"}
```

Every `updates.interval`, the agent asks the platform, on the listener it renews
on, for the roots after the one it was provisioned with, the newest catalog and
the version the platform wants it to run, and verifies all of it from
`updates.root`. It refuses a root or a catalog older than one it verified, a
catalog that ran out, a release for another system, one older than the release
it runs unless that release `replaces` it, and one that keeps an older
generation of state than the agent's. A release is installed only over one the
same catalog names, which is the release the installer goes back to: the agent
downloads both packages, checks every byte against the catalog and stages them.

The installer, `seagull-agent-update.service`, runs as root and only when
`seagull-agent-update.path` sees a staged release or a pending installation. It
trusts nothing the agent's account wrote: it follows no link and waits on no
pipe the account put in its way, verifies what was staged again from
`updates.root` and what it verified before, counting what a message holds
before decoding it, copies each package where only root writes and checks the
copy, and has dpkg confirm the package is the release. It installs with apt, keeping the configuration, then waits
`updates.check_within` for a run of the new release, started after the
installation, to say it runs as it should for a whole status interval; unless
one does, it installs the release before again and waits for it the same way.
Each step is written down before it is taken, so an installation a crash or a
reboot interrupted is taken to its end when the host starts again, and going
back is refused once the state was moved past what the release before reads.
When dpkg itself was interrupted and the agent's package is all it left
halfway, the installer has dpkg finish it and installs again; when it left
other packages halfway too, the installation ends failed and leaves
`dpkg --configure -a` to an operator.
How the last update went is in `status`, in what the agent reports to the
platform and in `journalctl -u seagull-agent-update`.

The platform holds no key of either role: a taken platform can withhold an
update or move an agent to another release a catalog it verified allows, but not
to anything operators did not sign, nor back past what a release allows.

Which agents are asked to run a release, and when, is the platform's decision
and never signed: an operator assigns a release agent by agent, or rolls it out
to a tenant in waves, a canary first and then shares of the rest, each agent at
a place drawn from the rollout and its identifier, so renewing its certificate
or rotating its key never moves it between waves. The agent takes part only
through what it reports. Every report says which contracts release it was built
with, the protocol and schemas it speaks and reads, and whether it takes
updates, in which format, over which state and under which root and catalog, so
a rollout does not wait for an agent that cannot take its release; and where
its update stands, so the platform pauses a rollout once agents went back from
its release or could not verify or install it, and never because an agent could
not reach it. What a rollout decides changes nothing the agent verifies.

## Failures

What the agent does when what it depends on fails, and what it can lose:

| Failure | What the agent does | What it can lose |
|---|---|---|
| The agent killed at any moment: as it admits, writes a checkpoint, sends, writes an acknowledgement down or reclaims a segment | starts again on what its spool and checkpoints hold, and sends again what it could not know was delivered | nothing; the platform may receive an event again, byte for byte |
| An answer lost, a batch published in part, an acknowledgement that does not count every record | sends the same batch again | nothing; the platform stores the event once |
| The platform or its backbone out, its name not resolving, connections dropped, answers later than `transport.request_timeout` | keeps the records and tries again, one request at a time, with jittered backoff and the platform's `Retry-After` | nothing while records are younger than `spool.max_age`, which then expire, counted as expired; a full spool pauses collection as below |
| A listener the agent does not trust, an agent the platform no longer admits, a certificate that expired | keeps the records, tries again at most an hour apart and says in `status` what an operator does | as above |
| The platform rotating its authority | adopts the authorities a renewal publishes, from the renewal listener the agent already trusts | nothing |
| A filesystem with less than 64 MiB free, or with no room for a write | pauses admission; collectors keep their place in what they read and catch up once there is room | what the source drops meanwhile, reported as a gap |
| A filesystem the kernel made read-only, or a sync that failed | stops, so the service starts it again on what the spool holds, which it refuses to do while the filesystem takes no writes | nothing it admitted; what the source drops meanwhile, reported as a gap |
| A record damaged on disk | delivers the others | that record, counted as lost |
| The journal dropping entries before the agent read them | reports a gap | those entries |
| The platform refusing a record for good | delivers the others | that record, counted as quarantined |
| An update interrupted as dpkg installs it or as the installer checks it | the installer takes it to its end when it runs again | nothing |

`make chaos` proves it on Ubuntu 24.04, as root, on a disposable host: it installs
the package, keeps the installation on an ext4 filesystem of its own and has
sshd's stand-in decide thousands of outcomes while it kills the agent over and
over, has the emulated platform lose answers, publish part of batches, go away,
answer late, present a certificate the agent does not trust, stop admitting the
agent and rotate its authority, lets a certificate expire, fills the
filesystem, has the kernel find an error in it, damages a record and has the
journal drop entries, and interrupts an update twice. After every failure, the
platform holds each outcome as one event, byte for byte however often it was
delivered, and the agent counts every other one under the reason it was given.
The compatibility suite also holds what platform 331492d's own gateway,
backbone and store kept of what the installed agent delivered while it was
killed over and over and the backbone stopped for longer than the agent waits
for an answer: the backbone holds some events twice, as the agent sent again
what it was never told was durable, and the store keeps each event once.

## Footprint

What the agent spends, measured from outside its service with the package's
unit and settings on Ubuntu 24.04 amd64 and systemd 255, while sshd's outcomes
are what it collects and an emulated platform takes what it delivers. The
service counts the agent and the `journalctl` it reads the journal through, and
its memory here is anonymous memory, which no file backs. It was measured in a
container on a VMware VM with 8 processors of a Ryzen 7 5700X, and on GitHub's
runner, an Azure VM with 4 processors of an EPYC 7763:

| Workload | VMware VM | GitHub's runner | Budget |
|---|---|---|---|
| Idle | 0.01% of a processor, 8 MiB, 19 goroutines, 23 descriptors, 0.2 KiB written a second | 0.01%, 11 MiB, 19 goroutines, 23 descriptors, 0.2 KiB | 0.5%, 32 MiB, 40 goroutines, 48 descriptors, 4 KiB |
| 10 outcomes a second | 1% of a processor, 9 MiB; each event on the platform at most 304 ms after its outcome went to journald | 0.7%, 11 MiB, 344 ms | 3%, 32 MiB, 2 seconds |
| A burst of 60,000 outcomes | 730 a second: 5% of a processor, 9 MiB, caught up 0.2 seconds after the last | 920 a second: 8%, 11 MiB, 0.2 seconds | 48 MiB, 30 seconds |
| The platform out for 2 minutes | 9 MiB | 11 MiB | 32 MiB |
| The platform back | delivering again 6 seconds later; 9 MiB | 16 seconds later; 11 MiB | 48 MiB |
| 120,000 outcomes with the platform out and `spool.max_bytes` at 16 MiB | admission paused at 14 MiB of spool and 39,231 events, the rest left in the journal; 10 MiB | 39,204 events; 11 MiB | below 16 MiB of spool, 32 MiB |
| The platform back with them | delivering again 100 seconds later, then 3,400 events a second, the upload rate of 1 MiB/s; 27% of a processor over the busiest 5 seconds, held back by the unit's quota for 10 seconds in all; 11 MiB | 122 seconds later, 3,400 a second; 42%, held back for 14 seconds; 11 MiB | 1,500 events a second, 48 MiB |
| Starting and taking stock | stock taken in 0.3 seconds, 9 MiB | 0.9 seconds, 10 MiB | 64 MiB |
| The files baseline of the default paths | 1,037 entries in 6 seconds, 10 MiB | 8,155 entries, 3 GiB read at the 8 MiB/s of `resources.max_scan_bytes_per_second` in 6.5 minutes, 26 MiB | 64 MiB |
| Every module with the [Privileges](#privileges) drop-ins, 10 outcomes a second | 1% of a processor, 11 MiB, 27 goroutines, 26 descriptors | 0.8%, 27 MiB, 27 goroutines, 26 descriptors | 5%, 64 MiB, 64 goroutines, 64 descriptors |

The spool takes about 370 bytes an event. Delivery resumes at the agent's next
try, at most 7.5 minutes after the platform is back. The agent syncs every
admission and every acknowledgement, so at 10 outcomes a second its service
writes about 54 KB a second to storage, 5 KiB an event, and in a burst about
440 bytes an event. The service's control group also counts the page cache of
the files it reads: on the runner, the files baseline filled it to the unit's
512 MiB, where the kernel reclaims it.

`make footprint` measures it again on Ubuntu 24.04, as root, on a disposable
host, and fails when a workload goes over its budget; CI runs it on every push.
`make soak` runs the agent for `SOAK` with every module at its shortest
interval, certificates that last ten minutes, the platform out and every
connection dropped every quarter of an hour, and fails when its goroutines,
descriptors or memory grow once settled; CI soaks it for four hours every
week. What was measured, on which host and how, is under
[`tests/native/testdata/footprint`](tests/native/testdata/footprint).

## Runtime state

| Path | Purpose |
|---|---|
| `/etc/seagull-agent/agent.json` | Configuration, root's and public |
| `/etc/seagull-agent/platform-ca.pem` | `server.trust_bundle`: the authorities trust in the platform starts from |
| `/var/lib/seagull-agent/installation.json` | Installation identifier, credential generation, pending request, adopted authorities |
| `/var/lib/seagull-agent/keys/` | Private keys, PKCS #8 |
| `/var/lib/seagull-agent/certificates/` | Issued certificates and their chains |
| `/var/lib/seagull-agent/trust/` | Authorities adopted from renewals |
| `/var/lib/seagull-agent/spool/` | Durable `events`, `inventory` and `assessments` streams |
| `/var/lib/seagull-agent/collection/` | Collector checkpoints and baselines |
| `/var/lib/seagull-agent/status/status.json` | What the agent last said of itself |
| `/var/lib/seagull-agent/policy/policy.json` | The signed policy applied last, and the revision no later one goes below |
| `/var/lib/seagull-agent/reporting/sequence.json` | The count of the reports the installation sent, which never goes back |
| `/var/lib/seagull-agent/update/` | The newest root and catalog the agent verified, which nothing handed later goes below, and the generation of its state |
| `/var/lib/seagull-agent/staged/` | The release staged for the installer, with the one the agent runs |
| `/var/lib/seagull-agent-update/` | The installer's journal, what it verified and the packages it installs from, root's |
| `/var/lib/seagull-agent/replaced/` | Installations set aside by `installation replace` |

The state directory is private to the agent's account and locked while the
agent runs, and the agent refuses state another account can reach. Keys are
not encrypted at rest, since the secret to decrypt them would sit on the same
disk: whoever can read the directory, root and backups included, holds the
agent's identity, and a copied key is revoked with its agent.

## Compatibility

This build speaks protocol 1, event schema 1, inventory schema 1, status schema
1 and assessment schema 1, and reads signed policies of schema 1 and update
metadata of schema 1, from the contracts release `go.mod` pins, as
`seagull-agent -version` prints and every status report says. The agent
negotiates nothing before it sends; the platform's answer to a batch is where it
learns what the platform accepts. A refused version, or a refused value its
contracts declare, is an incompatibility that holds the records rather than
quarantining them, since a platform that speaks them accepts them unchanged. A
refusal of the agent itself is an exclusion that waits for an operator. Reply
fields the contracts do not declare are ignored.

Compatibility is claimed only with the backend commits recorded under
[`tests/compatibility/testdata`](tests/compatibility/testdata): 6fae345,
2829b0d, 0656b2a, fdd814d, 46ca9c7, 6b85c4b, 8d1e9e0 and 331492d, whose ingest
gateway, control plane and pipeline were driven with what this agent sends;
fdd814d, 46ca9c7, 6b85c4b, 8d1e9e0 and 331492d also handed it the signed
policies it applies; 46ca9c7, 6b85c4b, 8d1e9e0 and 331492d took and kept the
status reports this build's installed agent sent in the native gate; 6b85c4b,
8d1e9e0 and 331492d handed it the signed releases it installs and took what it
reported while it was updated; 8d1e9e0 and 331492d rolled releases out on those
reports, opening the next wave once the agent ran one and pausing the rollout
of the one it went back from; and 331492d handed it the checks it ran in the
native gate, refusing to publish the one written for a newer contract, and took
and kept what it found, the newest assessment as its posture. The suite fails
when `go.mod` pins contracts no recorded platform was built with, or when a
recorded answer reads differently.

## Build and test

The go command selects the toolchain `go.mod` names and fetches every
dependency from the module proxy, so a checkout is all a build needs.

```bash
make build        # dist/seagull-agent
make verify       # formatting, vet, module graph, tests, race detector and build
make fuzz         # every fuzz target for FUZZTIME (10s); an input that fails is kept under testdata/fuzz
make vulncheck    # known vulnerabilities reachable from the agent
make package      # dist/deb/seagull-agent_<version>_amd64.deb and .spdx.json, of the commit checked out
make native-gate  # installs that package on this host, as root: use a disposable host
make chaos        # installs it again and fails what it depends on, as root: use a disposable host
make footprint    # installs it again and holds what it spends to its budgets, as root: use a disposable host
make soak         # installs it again and runs it for SOAK (4h) with every module, as root: use a disposable host
```

`make verify` runs the unit, architecture and compatibility suites;
`tests/architecture` holds the package boundaries as tests, and refuses code
that reads a file or a stream without a bound or decodes a message without
counting what it holds. Every parser of what the agent did not write itself in
the same run, from its configuration and the platform's answers to its own
state and what the host's files and programs say, has a fuzz target that
`make test` runs over its seeds and every input kept under its `testdata/fuzz`.
CI fuzzes every target for ten seconds on each push and for two minutes every
night, from the inputs earlier nights found; an input that fails is attached to
the run, to be kept under `testdata/fuzz` once fixed. CI also packages
every commit twice on its runner and once more on a second builder and requires
the same bytes from all three, and runs the native gate, which
takes the installed service through enrollment, renewal, collection, delivery,
upgrade, removal and purge on Ubuntu 24.04, with the chaos suite and the
footprint measurement beside it, and soaks the installed agent for four hours
every week. While a contract change is in progress, a `go.work` may use a
sibling contracts checkout; Git ignores it, and every `make` target runs with
`GOWORK=off`.

## Security

Never attach a private key, the contents of `/var/lib/seagull-agent` or the
spool to a public issue. A diagnostics bundle is meant to be shared once an
operator has read it: it holds no key and no spool record, but it names the
host's paths, the platform's addresses and the agent, and holds its log.

## License

Seagull Agent v2 is licensed under the [GNU General Public License v3.0](LICENSE).
