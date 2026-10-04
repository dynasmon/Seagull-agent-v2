# Seagull Agent v2

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-Go%201.26-00ADD8.svg)](go.mod)
[![Contracts](https://img.shields.io/badge/contracts-Seagull--contracts-00A6A6.svg)](https://github.com/dynasmon/Seagull-contracts)

Seagull Agent v2 is the endpoint component of Seagull v2: the process that runs
on a host, observes it, and delivers what it observed durably to the
[Seagull backend](https://github.com/dynasmon/Seagull-backend-v2).

It is built, tested and released from this repository alone. The only Seagull
code it consumes is the published
[contracts](https://github.com/dynasmon/Seagull-contracts) module, at the release
`go.mod` pins. Nothing from the backend, the frontend or the
[legacy agent](https://github.com/dynasmon/seagull-agent) is imported, replaced
or checked out beside it; the legacy agent is a record of behavior and edge
cases, not a template.

## Build and test

The go command selects the toolchain `go.mod` names and fetches every dependency
from the module proxy, so a checkout of this repository is all a build needs.

```bash
make build      # dist/seagull-agent
make verify     # formatting, vet, module graph, tests, race detector and build
make vulncheck  # known vulnerabilities reachable from the agent
make package    # dist/deb/seagull-agent_<version>_amd64.deb, of the commit checked out
```

`seagull-agent -version` prints the build identity, which is the version Go
stamps from this repository's history, the toolchain and the platform, and then
the wire versions the build speaks. `go version -m` lists every module and build
setting that went into a binary. Both are metadata about a build, not proof of
which build is running.

## Installing

The agent is packaged for Ubuntu 24.04 on amd64, as a Debian package, and that
is the one platform it is installed on. `make package` builds the package of the
commit checked out, and CI installs the package of every commit it builds on an
Ubuntu 24.04 host and runs it there as a service, as the evidence below
describes.

A package is a commit, built the same way each time:

- its version is the one Go stamps on the agent, which `seagull-agent -version`
  prints: a tag `v0.1.0` is packaged as `0.1.0-1`, and a commit after it, the
  pseudo-version `v0.1.1-0.20260926004346-7d7db5969ad5`, as
  `0.1.1~0.20260926004346.7d7db5969ad5-1`, so dpkg orders packages as Go orders
  the builds in them;
- the builder refuses an agent built from changes no commit holds, with cgo,
  without `-trimpath`, for another system, or for more than the instruction set
  every host of its architecture runs (`GOAMD64=v1`). The agent is linked
  statically, so the package depends on no library, only on systemd, and on
  procps for the `kill` that a reload signals the agent with;
- every file is root's, has the mode the builder gives it whatever the umask,
  and is dated at the commit, so the same commit is packaged into the same
  bytes. CI packages every commit twice and compares them.

A release is a tag `vX.Y.Z`. Its workflow verifies the commit, packages it, runs
the package through the native gate below, and only then attests where it was
built: a SLSA provenance statement naming the package's SHA-256 digest, this
repository, the workflow, the tag and the commit, signed through Sigstore with
the identity GitHub gives the workflow, in a job apart from the one that built
the package. The package and that statement, as a `.sigstore.json` bundle, are
attached to a draft release that a maintainer publishes. Verify a package before
installing it, with a GitHub CLI that has `gh attestation` (Ubuntu 24.04's own,
2.45, predates it):

```bash
gh attestation verify seagull-agent_0.1.0-1_amd64.deb \
  --repo dynasmon/Seagull-agent-v2 \
  --signer-workflow dynasmon/Seagull-agent-v2/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

It fails for a package whose bytes changed, one another repository or workflow
built, and one built from another tag, and `--bundle` reads the statement from
the file attached to the release instead of asking GitHub for it. No signing
key exists to be kept or lost: the workflow signs with a certificate that
expires minutes later.

Installing it:

```bash
sudo apt install ./seagull-agent_0.1.0-1_amd64.deb
```

- creates `seagull-agent`, a system account and group of its own, with no shell,
  through `systemd-sysusers`, and makes the account a member of
  `systemd-journal`, so that the commands an operator runs as the account read
  the agent's log as the service does;
- creates `/var/lib/seagull-agent`, where the installation is kept, as the
  account's and 0700, and `/etc/seagull-agent`, where its settings go, as root's
  and 0755, through `systemd-tmpfiles`;
- installs the agent at `/usr/bin/seagull-agent`, the `seagull-agent` service,
  and the settings an installation starts from at
  `/usr/share/seagull-agent/agent.json`;
- starts nothing and enables nothing. The agent runs once it has settings, and
  it is enrolled while it is stopped. The package holds no key, no certificate
  and no authority: an installation draws its own key the first time it asks
  for a certificate.

Then an operator gives it its settings, enrolls it and starts it:

```bash
sudo install -m 0644 platform-ca.pem /etc/seagull-agent/platform-ca.pem
sudo install -m 0644 /usr/share/seagull-agent/agent.json /etc/seagull-agent/agent.json
sudoedit /etc/seagull-agent/agent.json     # server.ingest_url and server.renewal_url
sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json platform check
sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json enrollment request web-01 > web-01.csr
# the platform issues the certificate, as Enrollment describes
sudo install -m 0644 web-01.issued /var/tmp/web-01.issued
sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json enrollment import /var/tmp/web-01.issued
sudo systemctl enable --now seagull-agent
```

- the authority in `platform-ca.pem` decides which platform the agent trusts, so
  it comes from the platform's operators through a channel that is already
  trusted, and its fingerprint, `openssl x509 -in platform-ca.pem -noout
  -fingerprint -sha256`, is compared with theirs. `platform check` authenticates
  the platform against that authority, and cannot tell a genuine one from one an
  impostor handed over with a listener of its own;
- every command runs as the account the service runs as, because the
  installation is private to it and the agent refuses state another account
  owns, root's included. The platform's answer is public, and that account only
  has to be able to read it.

The service runs the agent as the account, with nothing more, and bounds it:

| What | What the service sets |
| --- | --- |
| Account | `User=seagull-agent` and `Group=seagull-agent`, and `SupplementaryGroups=systemd-journal`, the group that reads the system journal, which the [authentication collector](#authentication) reads |
| Privileges | no capability, bounding or ambient, and `NoNewPrivileges=yes`, so nothing the agent starts gains one |
| Memory | `MemoryMax=512M`, above the default `resources.memory_limit` of 256 MiB, and `MemorySwapMax=0` |
| Processor | `CPUQuota=50%` |
| Tasks and descriptors | `TasksMax=256` and `LimitNOFILE=4096` |
| Core dumps | `LimitCORE=0`, which the agent also sets itself |
| The installation | `StateDirectory=seagull-agent`, 0700, and `UMask=0077` |
| Stopping | SIGTERM, then `TimeoutStopSec=30s`, above the default `resources.shutdown_timeout` of 10s |
| Failing | `Restart=on-failure`, 5 seconds later, growing to 5 minutes over six restarts |
| Reloading | `systemctl reload seagull-agent` sends SIGHUP, and the agent reads its configuration again |

- the agent says what it was given as it starts: `agent_privileges` names the
  account, its two groups, no capability, `no_new_privs` and the `seccomp`
  filter the service gives it, and `agent_resources` the ceilings, with nothing
  unenforced. A drop-in, `systemctl edit seagull-agent`, changes a ceiling for
  the next start, and the agent reports the new one, as a warning when
  `resources.memory_limit` is not below `MemoryMax`;
- `MemorySwapMax=0` keeps the agent's memory, and its key with it, off the swap
  device, on a kernel that accounts for swap;
- the agent logs to the journal: `journalctl -u seagull-agent`.

The service also confines the agent to what it uses of the host, which
[Privileges](#privileges) lists:

| What | What the service sets | What it leaves the agent |
| --- | --- | --- |
| Files | `ProtectSystem=strict`, `ReadOnlyPaths=/run`, `BindReadOnlyPaths=/sys`, `ProtectHome=yes`, `PrivateTmp=yes` and `MemoryPressureWatch=off` | its installation, the one directory `StateDirectory=` names, and a `/tmp` and a `/var/tmp` of its own to write; every other filesystem read-only, and the home directories, `/root` and `/run/user` out of reach |
| Devices | `PrivateDevices=yes` | `null`, `zero`, `full`, `random`, `urandom`, `tty`, and `ptmx`, which opens pseudo-terminals |
| Shared memory | `PrivateIPC=yes` and `InaccessiblePaths=-/dev/shm -/dev/mqueue` | no IPC object, shared memory or message queue that another process holds |
| The kernel | `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes` and `ProtectHostname=yes` | `/proc/sys`, `/sys` and the control groups to read; no module, kernel log, clock or host name |
| Processes | `ProtectProc=invisible` | the processes of its own account, alone, in `/proc` |
| The network | `RestrictAddressFamilies=AF_INET AF_INET6` | IPv4 and IPv6 sockets alone: no local socket of its own, so no D-Bus or other local service to reach, and no netlink socket |
| System calls | `SystemCallFilter=@system-service` and `SystemCallFilter=~@privileged`, `SystemCallArchitectures=native` and `SystemCallErrorNumber=EPERM` | the calls a system service makes, less those that need the superuser; any other fails with `EPERM`, and a call through the 32-bit entry ends the process |
| Within those calls | `MemoryDenyWriteExecute=yes`, `LockPersonality=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes` and `RestrictSUIDSGID=yes` | no memory both writable and executable, no other execution domain, no namespace, no real-time scheduling, no setuid or setgid file |

- systemd 255, which Ubuntu 24.04 ships, leaves `/run` and `/sys` writable
  despite `ProtectSystem=strict` and `ProtectKernelTunables=yes`:
  `ProtectKernelTunables=`, `ProtectControlGroups=` and `ProtectProc=` have it
  mount the API filesystems, and the entries it makes for `/run` and `/sys`
  displace the read-only ones, which leaves `/run/lock` writable to every
  account. `ReadOnlyPaths=/run` and `BindReadOnlyPaths=/sys` make both
  read-only again, and the native gate checks that they are;
- several settings take away what the account may not do on Ubuntu 24.04
  anyway, such as loading a module, reading the kernel's log, setting the clock
  or the host name and scheduling in real time, so they hold on a host whose
  defaults differ;
- the confinement is the service's. The commands an operator runs as the
  account, `enrollment import` among them, run as that account runs anywhere;
- a state directory other than `/var/lib/seagull-agent` takes a drop-in that
  names it in `ReadWritePaths=`. Without one the agent refuses to start, and
  where it finds the directory read-only its recovery says what to do;
- a drop-in that loosens a setting loosens it for every module, since they share
  the process. A collector that needs more of the host than this names it under
  [Privileges](#privileges), and the unit grants that alone.

Upgrading, removing and purging:

- an upgrade replaces the agent and the service, and restarts the service when
  it is enabled or running. The installation, its keys, its spool and its
  settings stay as they were, so the agent runs on as the same installation, at
  the same credential generation, with the same backlog;
- `apt remove seagull-agent` stops the service and removes the agent and the
  service. It keeps the installation, the settings, the account and whether the
  service was enabled, so installing the package again runs the same
  installation;
- `apt purge seagull-agent` also deletes `/var/lib/seagull-agent`,
  `/etc/seagull-agent` and what enabling and overriding the service wrote under
  `/etc/systemd/system`, so the next installation is a new one. The keys go with
  it and the certificate issued for them does not, so revoke the agent on the
  platform first. The account stays: whatever it owns elsewhere would otherwise
  belong to the next account given its uid.

The evidence:

- `packaging` tests that the package installs the agent, its service, the
  account, the directories and the settings and nothing else, root's and at the
  modes given, with the checksums `dpkg --verify` reads; that dpkg orders the
  versions as Go does; that the same commit gives the same bytes; that the
  service, the account, the directories and the settings agree with one another
  and with the agent's defaults; and that the unit confines the agent with every
  setting the table names, so loosening one changes that test too;
- `tests/native` is the native gate. On a host systemd runs, as root, it
  installs the package and takes it through its life against an emulated
  platform: install, check the settings and the platform as the account,
  enroll, start, check the confinement, renew a certificate valid for 30
  seconds under the service's permissions, reload, stop, admit records to the
  spool as the account, start, kill the agent, upgrade to the next version,
  override a ceiling, remove, reinstall, deliver the backlog once the emulated
  platform takes it, collect what the host's own sshd decides, write a
  diagnostics bundle beside the running agent, purge and install again. Until it delivers the platform answers every batch as the
  recorded gateway does when its backbone does not take one. To collect, it
  installs openssh-server when the host has none, lets it take passwords, gives
  an account of its own a password and the loopback the address 203.0.113.10,
  and has the agent's configuration name the authentication collector, as the
  package's does. At each step it checks what the agent reported, the account
  and the modes and owners of what it keeps, and after the upgrade and the
  removal that the installation and its backlog are the same bytes. CI runs it
  on Ubuntu 24.04 with `make native-gate`, which installs the package on the
  host it runs on and rotates and vacuums that host's journal, so it belongs
  on a disposable one;
- to check the confinement, the gate has the service run a copy of the gate
  before the agent, through a drop-in's `ExecStartPre=`, confined as the agent
  is, and runs the same copy as the account outside the service. Each copy
  writes to `/run/lock`, `/dev/shm`, `/dev/mqueue`, `/tmp` and `/var/tmp`, lists
  `/home`, `/run/user` and the kernel's modules, looks for PID 1, opens local,
  netlink and Internet sockets, makes a user namespace, takes the 32-bit
  personality, maps memory both writable and executable, makes a setuid file,
  schedules in real time, reads the clock's discipline and the kernel's log,
  calls `pidfd_getfd` on itself and `setuid` to its own account, and runs a
  32-bit program, and it walks every filesystem that is not read-only for what
  the account may write. In the service the account may write its
  installation, its `/tmp` and its `/var/tmp` and nothing else, finds no device
  but the seven the table names, and is refused everything else it tries but
  Internet sockets. Outside the service it is allowed each of those, unless
  Ubuntu already refuses it, as it does the kernel's log and real-time
  scheduling, and what it wrote to `/tmp` and `/var/tmp` in the service is not
  in the host's. The gate then reads the agent's own process: no capability,
  `no_new_privs`, a seccomp filter, and mount, UTS and IPC namespaces apart
  from the host's. Every later step runs under that confinement, collection,
  renewal and the spool included;
- `systemd-analyze security` rates the unit 1.4, OK, on Ubuntu 24.04's systemd
  255, where it rated the unit before this confinement 6.6, medium. The gate
  does not depend on that rating.

What it does not claim:

- another distribution, an RPM, arm64, Windows or macOS. `make package
  ARCH=arm64` builds an arm64 package, and none of them is supported until its
  own native gate passes;
- more confinement than the table: the agent may connect to any address,
  since the platform's are not the package's to know; `ProcSubset=pid` is left
  out because `journalctl` reads the boot it follows from
  `/proc/sys/kernel/random/boot_id`, and `PrivateUsers=yes` because the
  journal's group would be unmapped in the agent's user namespace, and the
  agent could not say which groups it holds;
- that the confinement holds against the kernel itself: what the filter lets
  through is still the kernel's to get right. It is tested on an Ubuntu 24.04
  host and in a privileged container, not where systemd cannot make the
  namespaces it needs;
- confinement on Windows or macOS, where no service exists to confine. Service
  ACLs and account privileges there, and launchd, the hardened runtime and
  entitlements, are weighed when native development for them begins;
- that a package is reproduced anywhere else: the same commit gives the same
  bytes with the same toolchain, dpkg and tar, which is what CI compares;
- that a package installed without its attestation verified came from this
  repository. apt knows nothing of the attestation, and there is no APT
  repository to sign;
- updates: the agent installs none itself, and a release is installed as above.

## Running

`seagull-agent -config FILE run` starts the agent on the configuration held in
`FILE` and keeps it running until it receives SIGINT or SIGTERM. It logs to
stderr, and exits with 0 after a requested stop, 1 when it could not start, an
essential component failed or the stop overran its deadline, and 2 on a usage
error. The package runs it as the `seagull-agent` service, as
[Installing](#installing) describes.

`cmd/seagull-agent` is the composition root: it builds each component and hands
the enabled ones to `internal/runtime`, which owns their lifecycle.

- A component is a `Run(ctx)` call that returns once everything it started has
  stopped. Building one must start no work, so a component left out of the
  composition, such as a disabled one, never runs.
- Every component declares a failure policy. An optional component that fails
  is reported and the agent carries on without it; an essential one that fails,
  or stops before it is asked to, stops the agent.
- Stopping cancels every component and waits `resources.shutdown_timeout` for
  them. A component still running after that is named in the log, and the
  process exits rather than wait any longer.
- A panic is never recovered. It ends the process, because the goroutine that
  panicked may have left shared state inconsistent; durable state has to
  survive that just as it survives any other crash.

The components composed are the configuration the agent holds, which reads the
file again whenever the agent is asked to; the [collection](#collection),
optional, which runs the collectors `modules` names; once the installation is enrolled,
the [renewal](#renewal) that keeps its credential current and the
[delivery](#delivery) that sends the platform what the spool holds; and the
[status](#status), optional, which writes down what the agent says of itself.
The renewal is optional, so an agent whose renewal failed keeps collecting what
it will deliver once it holds a certificate again. The delivery is essential: it
never stops over what the platform answers, and one that stopped for any other
reason stops the agent, which its service starts again. The spool is not a
component, since it starts no work of its own: the agent opens it with the
installation, reads back what it holds before it starts, and closes it as it
stops. Neither is the governor, which bounds the expensive work of whoever asks
it and starts none of its own.

## Configuration

`-config` names one file, and everything the agent runs on is in it. The file
is JSON: what the agent refuses has to be what an operator wrote, and JSON has
one way to write a value, no unit or type it infers, and no dependency of its
own in a build whose whole module graph is verified.

```json
{
  "format": 1,
  "identity": {"state_directory": "/var/lib/seagull-agent"},
  "server": {
    "ingest_url": "https://gateway.example:8443",
    "renewal_url": "https://control.example:8446",
    "trust_bundle": "/etc/seagull-agent/platform-ca.pem"
  },
  "modules": {"authentication": {"enabled": true}}
}
```

That is a whole configuration: the `server` settings are the deployment, so the
agent has no default to offer for them, and every other setting has one it
documents below, `modules` included, which collects nothing unless it names a
collector. `seagull-agent -config FILE config print` prints what the agent would run
on, defaults and all, and `config check` reads the file and reports what it
refuses without starting the agent. The package installs those settings, with
example addresses, as `/usr/share/seagull-agent/agent.json`.

The agent reads the file whole, or refuses it whole:

- a setting it does not have, a setting written twice, a setting written as
  null, more than one document, or a file above 64 KiB, is refused. Nothing is
  guessed: what the file leaves out is the default below, and a file written
  for a build with settings this one does not have is refused rather than half
  understood;
- a size is bytes with a binary unit, `8MiB`, and a time carries its unit,
  `30s`. A bare number is refused, because what it counts is the reader's guess;
- every setting the file gets wrong is reported at once, each with its name, and
  the same file is always refused the same way, whether the agent is starting or
  reading it again;
- `format` is the shape of the file and not the release of the agent. This build
  reads format 1. A newer format is refused and names the release that reads it.
  A release that changes what a setting means raises the format and keeps
  reading the formats it still supports; a release that only adds a setting
  leaves the format where it is.

| Setting | Default | What the agent takes |
| --- | --- | --- |
| `identity.state_directory` | — | an absolute path to the directory that holds the installation |
| `identity.key_provider` | `filesystem` | `filesystem` |
| `identity.key_lifetime` | `720h` | `1h` to `8760h`: how long a renewal keeps a key before it draws a new one |
| `server.ingest_url` | — | an `https` URL, with no credentials and nothing to resolve |
| `server.renewal_url` | — | an `https` URL, for the platform's renewal listener |
| `server.trust_bundle` | — | an absolute path to the PEM certificates of the authorities that issue the platform's |
| `transport.connect_timeout` | `10s` | `1s` to `1m` |
| `transport.request_timeout` | `30s` | `5s` to `10m`, never shorter than the connect timeout |
| `transport.max_batch_bytes` | `4MiB` | `64KiB` to `8MiB`, the recorded platform's request ceiling |
| `transport.max_events_per_batch` | `1000` | 1 to 1000, the recorded platform's ceiling |
| `transport.max_inventory_records_per_batch` | `64` | 1 to 64, the recorded platform's ceiling |
| `transport.max_response_bytes` | `64KiB` | `4KiB` to `1MiB` |
| `transport.max_upload_bytes_per_second` | `1MiB` | `64KiB` to `1GiB`, and enough to connect and send a whole batch within `transport.request_timeout` |
| `spool.max_bytes` | `512MiB` | `16MiB` to `64GiB`, and at least four batches |
| `spool.max_age` | `72h` | `1h` to `720h`; events are kept `168h` at most |
| `modules` | `{}` | `{"authentication": {"enabled": true}}`, to collect what sshd decides; `authentication` is the one collector this build has |
| `resources.memory_limit` | `256MiB` | `64MiB` to `8GiB` |
| `resources.max_concurrent_scans` | `2` | 1 to 64 |
| `resources.max_scan_bytes_per_second` | `8MiB` | `1MiB` to `1GiB` |
| `resources.max_concurrent_uploads` | `1` | 1 to 16 |
| `resources.shutdown_timeout` | `10s` | `1s` to `5m` |
| `logging.level` | `info` | `debug`, `info`, `warn` or `error` |
| `logging.format` | `json` | `json` or `text` |
| `updates.enabled` | `false` | `false`: this build installs no update |

The defaults are what a supported deployment reaches the recorded platform with.
Its ingest listener reads at most 8 MiB per request, takes at most 1000 events
or 64 inventory records in a batch, and admits events up to seven days old and
inventory up to thirty, so the agent keeps no event longer than seven days,
whatever `spool.max_age` says. `resources.memory_limit` is the target the
garbage collector works to, not a ceiling the kernel enforces: that one belongs
to the service the agent is installed as. None of the defaults turns a check off
or leaves a budget unlimited, and there is no setting that does either.

The file is the agent's instructions, so who may write it is who decides what
the agent does:

- the file and the directory that holds it belong to the account the agent runs
  as or to root, and neither their group nor anybody else may write them. They
  may be read by anyone: the settings are public;
- `server.trust_bundle` is read under the same rule, and has to hold
  certificates the agent can parse, each of them a certificate authority.
  Whoever changes it decides which platform the agent trusts, until the
  platform publishes the authorities it is to be trusted by over the agent's
  own credential, as a [renewal](#renewal) describes: the bundle is where trust
  starts, and a change to it is the operator's newer word. A certificate of the
  platform's own is refused there, since trusting it would pin the platform to
  it and the next certificate the platform installed would not be trusted;
- no setting carries a secret. A setting names where credential material is
  kept, and the agent's own keys live in the installation, so the file can be
  read, copied into a ticket or written by configuration management without
  handing anything over.

A running agent reads the file again when it receives SIGHUP. It reads and
validates the whole candidate before anything changes:

- a file it refuses leaves the agent on the configuration it already read,
  logged as `configuration_not_reloaded` with the reason and a `recovery`;
- a file it accepts replaces that configuration whole, logged as
  `configuration_reloaded`, so nothing ever runs on half of each;
- what the agent settled as it started is refused as a change:
  `identity.state_directory`, `identity.key_provider`, `server.ingest_url`,
  `server.renewal_url`, `server.trust_bundle`, `transport.connect_timeout`,
  `transport.request_timeout`, `transport.max_response_bytes`,
  `logging.format` and `resources.shutdown_timeout` take stopping the agent and
  starting it again. The transport keeps the waits and the bound on a reply it
  was built with, and the agent reads the authorities `server.trust_bundle`
  holds as it starts, so a bundle rewritten in place takes a restart too.

What a setting does today follows what the agent has. `identity`, `logging`,
`spool`, `modules`, `resources`, `server` and `transport` are in force: they decide where
the installation is opened, what the log says, how much the spool keeps and for
how long, how large a record it takes, what the agent and its expensive work may
spend, which platform `platform check` authenticates and how long it waits for
it, which authorities a certificate the agent imports has to chain to, where,
how long and how often the agent renews its credential, which collectors run,
and where and in what batches it delivers what they collect. A reload applies
`modules` whole: a collector it no longer names is stopped and the agent waits
for it, and one it names again starts where it stopped. The governor keeps the
budget for scans before anything spends it, since no collector scans yet. A
module this build does not have is refused, and so is `updates.enabled`: an
agent that accepted either would be promising collection it cannot do or
updates it cannot install.

## Collection

`internal/modules` runs the collectors this build has. The agent's runtime owns
components and knows none of them; the collection owns the collectors inside one
component, so a collector that fails is the collection's business and never the
agent's.

A module is a name and a `Collect(ctx)` call that owns every goroutine, timer,
descriptor and checkpoint it starts, and returns once all of them have stopped.
Modules share the agent's process and its privileges: a goroutine is a unit of
lifecycle and never one of isolation.

Each enabled module collects in a goroutine of its own, and the collection says
what each of them is doing:

- `running`: it is collecting;
- `degraded`: it is enabled and not collecting, because it failed and will be
  started again, or because the agent has not started it yet;
- `failed`: it failed as often as its budget allows, so the agent leaves it
  alone rather than start it again forever;
- `disabled`: nothing asked for it.

A module that returns before the agent is asked to stop has failed, whether it
returned an error or nothing at all. The agent waits a second before starting it
again and twice as long after each failure, up to five minutes, spread by a
fifth so the endpoints of a fleet that failed together do not return together.
Five failures in a row spend a module's budget; a module that collected for five
minutes has its failures forgiven. What a module reported is kept with its
state, bounded, and is never a label. `module_restarting` and `module_started`
are written for a module's first restart and each time its count of restarts
doubles, so a module that keeps failing after five minutes of collecting does
not fill the log; the health of the collection counts every restart.

The set of modules that should be collecting is applied whole: a name this build
does not have refuses the set, so nothing is half applied; a module the set
leaves out is cancelled, and the agent waits for it to return, so disabling a
collector releases what it held; and a module that spent its budget is started
once more when it is named again, because the budget bounds what the agent
retries on its own, not what an operator asks for. Stopping cancels every
module, and the collection names the ones that did not return rather than wait
for them. A panic inside a module is not recovered, as anywhere else in the
agent.

The composition root composes the collection with the collectors this build
has, `authentication` alone, each enabled when `modules` names it, and the
collection runs as an optional component: a collector that spent its budget
leaves the agent delivering what the others admit.

## Authentication

`internal/modules/authentication` is the agent's first collector: it turns what
sshd decides as it authenticates a connection into authentication events, read
from the system journal, and runs as the module `authentication` while
`modules.authentication.enabled` is true.

It reads the journal through `journalctl`, which `internal/platform/journal`
runs with fixed arguments, no shell and an empty environment, asking for JSON
and for the fields the collector uses. It never reads `/var/log/auth.log` or
`/var/log/secure`: any account on a host can hand syslog a line in sshd's name,
and a file keeps no trace of who wrote it. journald does: it records who sent
each entry from what the kernel says of the sending process, as `_UID` and
`_COMM`, fields no sender writes. The collector takes an entry only when
`sshd`, or `sshd-session` from OpenSSH 9.8 on, wrote it as the superuser, which
is how sshd's monitor, the process that decides an authentication, writes. A
program another account runs under that name, or one root runs under another,
is not sshd to it.

Of what sshd writes, an outcome is a line its monitor writes as it decides one:
`Accepted METHOD for USER from ADDRESS port PORT ssh2`, or `Failed`, for the
methods `password`, `publickey`, `keyboard-interactive`, `hostbased`,
`gssapi-with-mic` and `none`. Every other line, PAM's included, is read past:
an attempt is one event, not one per line that mentions it.

| Field | What it holds |
| --- | --- |
| `event_id` | a UUID drawn from the installation and the entry's cursor, so an entry read again is the same event, byte for byte |
| `time.event_time` | when sshd sent the line, or, when the entry does not say, when journald wrote it down |
| `time.observed_time` | when journald wrote it down |
| `origin.host` | the host name journald recorded, `linux` and the agent's architecture; the agent and the tenant are the platform's to write |
| `collection` | collector `authentication`, source `journal:sshd` or `journal:sshd-session` |
| `authentication.activity` | `LOGON` |
| `authentication.outcome` | `SUCCESS` for `Accepted`, `FAILURE` for `Failed` |
| `authentication.outcome_reason` | `invalid user` when the account does not exist |
| `authentication.method` | the method as sshd names it, `keyboard-interactive/pam` included |
| `authentication.user.name` | the user as sshd wrote it, with sshd's escaping of what is not printable, at most 256 bytes |
| `authentication.service` | `sshd`, protocol `ssh` |
| `authentication.network` | `TCP`, and the address and port the connection came from |
| `authentication.raw_record` | the line sshd wrote |

The user of an account that does not exist is whatever the client sent, and so
is the identifier of a certificate it presents: either can hold text that looks
like ` from 10.0.0.1 port 22 ssh2`. A user and an address are read only when
exactly one place fits the line as sshd writes it: ending the line for a method
that writes nothing after `ssh2`, and followed by a key's fingerprint or a
certificate's description for `publickey`. Otherwise the event says the outcome
and the method alone, so a client can neither choose the address its failure
counts against nor hide the failure.

Where the collector stopped is `collection/authentication.json` in the
installation: the cursor of the last entry it read and when journald wrote it.
It is written, synced and renamed over the last one, only once the spool made
the events of the entries before it durable. A stop before then has the
collector read those entries again and admit their events again under the same
identifiers, which the platform keeps once.

- The first time it runs, it reads from that moment on: what sshd decided before
  is not sent.
- Started again, it reads what the journal holds from where it stopped, through
  every boot the journal kept, and then follows the boot that is running. It
  reads to the end of the journal first because `journalctl` follows the boot
  that is running alone.
- When the journal no longer holds the entry it stopped at, because journald
  rotated or vacuumed past it or the journal was reset, it reads on from the
  first entry still held, and reports `collection_gap` with when it stopped and
  when the next entry was written: what journald dropped meanwhile is lost.
- An outcome older than the platform admits, seven days, is read past, counted
  and reported as `collection_entries_too_old`, at the first and as the count
  doubles, as is an entry it cannot read, `collection_entry_unreadable`.
- A place it cannot read is reported as `collection_place_lost`, and the
  collector reads again everything the platform still admits, whose events are
  the same as before. A place written by a newer agent, or open to another
  account, stops the collector.

It admits up to 256 events, or 1 MiB, at once. When the spool has no room it
keeps its place and waits for room through the governor, while `journalctl`
waits behind it and journald keeps what sshd writes; the status says since when
it waits, and what journald drops meanwhile is a gap it reports once it reads
on. A journal it may not read, or a `journalctl` that stops, fails the module,
which the collection starts again as it starts any other.

What it does not collect:

- a logoff. sshd writes `Disconnected from user` from the session's own process,
  which runs as the user and fails the check above, and PAM's `session closed`
  says nothing of where the session came from;
- any other authentication: the console, display managers, `su` and `sudo`, and
  what PAM writes for other services. `sudo` running a command is not an
  authentication at all, and no contract carries one;
- any platform but Linux, where it needs `journalctl`. On Windows it waits for
  native development to begin, with the security event log;
- the difference between a name an attacker tries and a password a person typed
  where their name goes: both reach the platform as sshd logged them, since the
  platform needs the names that are tried.

The evidence:

- `internal/modules/authentication` tests the lines sshd writes and forged ones,
  places a client wrote, and what is not an outcome, and fuzzes them; reads a
  journal that answers as `journalctl` does from its first run, after a restart,
  past a vacuum, with a place damaged, insecure or newer, with old and
  unreadable entries and into a full spool; and kills a child collector before
  an admission, after one and before its place is written, and after that,
  checking that every event is in the spool and that an event admitted twice is
  the same bytes;
- `internal/platform/journal` tests the arguments `journalctl` is given and the
  entries it writes, binary, withheld and repeated values among them, against a
  stand-in, and reads the journal of the host it runs on with that host's
  `journalctl`;
- the [native gate](#installing) has the host's own sshd take 24 wrong passwords
  for an account that does not exist from 203.0.113.10, eight at a time, then a
  wrong and a right one for the account it created, after a line `logger` wrote
  in sshd's name as root and one a program named `sshd` wrote as `nobody`. The
  platform takes 26 events and the two forged lines are not among them. It then
  stops the agent across three more attempts, rotates the journal across two,
  and vacuums it across two more: after the restart and the rotation the agent
  delivers what sshd decided with no gap, and after the vacuum it reports the
  gap and never delivers the attempts journald dropped;
- `tests/compatibility` makes again, with the collector of the build under test,
  the events the installed agent delivered of what that sshd wrote, byte for
  byte, and holds what a [recorded platform](#compatibility-with-the-platform)
  stored and decided of them, once and sent again.

## Privileges

The agent is one process running as one account, and everything it does happens
with what that account may do. Modules run inside it, so a module may do
whatever the agent may: the process is the privilege boundary and a goroutine
is not one.

| What the agent does | What it needs |
| --- | --- |
| Keep its installation, its keys and its spool | a directory of its own, owned by the account it runs as |
| Read its configuration and its trust bundle | files that account, or root, writes and it reads |
| Reach the platform | an outgoing TLS connection, which needs no privilege |
| Collect what sshd decides | read the system journal, as a member of `systemd-journal`, which the package makes the account and the service grants again |

Nothing on that list needs the superuser, a Linux capability, or a helper of its
own. A collector that needs more names it there, and the packaging grants that
much: a group where a group is enough, as for the journal, and a capability only
where it is not. The same holds for what the service confines: a collector that
needs another kind of socket, a path to write or a group of system calls has the
unit grant that one, and the packaging test pins every setting, so loosening any
of them changes that test too.

At start the agent reports what it actually may do as `agent_privileges`: the
account, the groups it belongs to, the capabilities it holds, whether
`no_new_privs` is set, and how the kernel filters its system calls, as
`seccomp`: `filter` under its service, `disabled` when nothing filters them,
as when it runs by hand. A capability counts as held when it is permitted or
effective, since a permitted one can be raised into use. When the agent holds
anything the table above does not need, that line is a warning that names it: a
claim about privileges is about the process that is running, not about the one
the packaging intended.

The agent does not drop privileges itself. Go runs it on several threads and
Linux keeps a capability set for each of them, so a program that drops what it
holds part way through its life promises it for the thread that made the call
and no other. Bounding the process belongs to the service manager, before the
agent starts, and the service the package installs does it: it runs the agent
as an account of its own, with no capability and with `no_new_privs` set, and
confines it to the files, devices, sockets and system calls it uses, as
[Installing](#installing) lists.

It refuses to start as more than one account. A real and an effective identity
that differ mean it was started through a setuid or setgid program, and every
check it makes about its state, its keys and its settings compares against the
account it runs as, so an agent that cannot say which account that is cannot
make them.

There is no privileged helper, because nothing the agent does needs a privilege
its service account cannot be given. One would take more than a second process:
fixed typed operations rather than a way to run commands, callers authenticated
by what the kernel says about them rather than by what they claim, bounded
messages, targets confined to the files the operation is for, and a lifecycle
and failure behavior of its own. None of that exists, and nothing in the agent
reaches for it.

## The installation

An installation is one agent installed on one machine, and
`identity.state_directory` names the directory that holds it. The first start in
a new or empty directory draws its `installation_id`, 122 random bits written as
a UUID; every later start reads the same one. It is never derived from the
hostname, an address, a MAC or a machine identifier, which stay observations
about the machine.

The installation is not the agent the platform knows. The platform issues a
certificate for an `agent_id` an operator registered, and once
[enrollment](#enrollment) activates a credential generation,
`installation.json` records it: that agent, the generation number, the
`key_id` of its key, when that key was drawn, and what the certificate says.
Until the platform issued the certificate the installation asked for, it
records that request too: the agent it asked to be, the key it asked with and
when. Once a renewal adopted the authorities the platform published, it records
their digest, when they were adopted and the digest of the `server.trust_bundle`
they took over from. It holds no key, token or
other secret, and a field it does not declare, such as a key, makes the file
damaged, so copying it or the agent's public settings authenticates nothing.
Each generation follows the active one by exactly one and is issued to the same
agent; enrolling as another agent takes a new installation.

The state is the agent's alone:

- the directory and its files belong to the account the agent runs as and are
  closed to its group and to others, and the agent reads nothing that is not;
- a running agent holds the directory locked, so a second agent or a
  replacement on the same directory is refused, and the lock goes away however
  the agent ends;
- a write lands in a temporary file that is synced and renamed over
  `installation.json` before the directory is synced, and a start discards what
  an interrupted write left behind;
- whatever else the installation keeps, such as its keys, its certificates,
  the authorities it adopted and its spool, lives in a private directory of its
  own inside the state directory, which the installation holds under the same
  lock and closes when it is closed. The installation's state may be read while
  it changes, since every change replaces it whole: a renewal activates a
  generation while the transport reads the one it presents.

When the state cannot be used, the agent does not start: it logs
`agent_not_started` with the reason and a `recovery`, and never creates a new
identity in its place. A damaged `installation.json`, or a directory that holds
something but no `installation.json`, is restored from a backup of this
installation or replaced; a state written by a newer agent is read by that
release or replaced; a state others can reach is made private again.

`seagull-agent -config FILE installation replace` is that replacement, made on
purpose while the agent is stopped. It sets everything the state directory held
aside under `replaced/`, in a directory named after the moment of the
replacement: `installation.json`, the keys and anything else, even when the
state was damaged or lost. It then draws a new `installation_id` that names the
one it replaces whenever that one could be read, and leaves the new
installation unenrolled and without keys. Keys set aside still authenticate as
the agent they were certified for until its certificate expires or is revoked,
so revoke it when the replaced installation was enrolled, and delete
`replaced/` once nothing in it is needed. Records belong to the installation
that admitted them, so its spool is set aside with it rather than handed to its
replacement, and nothing it admitted is delivered as another installation.

The package follows the same line: removing it leaves the state where it is, so
installing it again is the same installation, and only purging it deletes the
directory, after which the next start is a new installation.

## Keys

The agent proves which agent it is with a private key it draws itself, and the
key stays where it was drawn. `internal/pki` holds that line: a `KeyProvider`
creates keys and opens them by identifier, and each `Key` it hands out is a
`crypto.Signer` with an identifier and nothing more. A certificate request and
a TLS client handshake need no more than that, so no caller receives a private
key, and a provider that never exports its keys fits the same boundary without
an export to fall back on.

Every key is ECDSA on P-256. At the recorded backend commit, the platform signs
requests for P-256, P-384, P-521, Ed25519 and RSA keys of at least 2048 bits,
and its ingest and renewal listeners accept only TLS 1.3, which every
implementation must support with ECDSA on P-256. P-256 is also a curve that
TPM 2.0, PKCS #11 tokens, Windows CNG and the Apple Secure Enclave hold, so
keeping keys in one of them would change nothing the platform receives.

A key's `key_id` is the SHA-256 digest, in lower-case hexadecimal, of its
DER-encoded SubjectPublicKeyInfo: the bytes a certificate request and a
certificate for the key carry, so a credential generation names exactly one
key.

The only provider keeps keys in files, under `keys/` in the state directory:

- each key is an unencrypted PKCS #8 PEM file named `<key_id>.pem`, created
  0600 in a 0700 directory, and the directory or a key in it is refused when it
  does not belong to the account the agent runs as or is open to its group or
  to others;
- a new key is written to a temporary file that is synced and then linked under
  its name, which never replaces an existing file, before the directory is
  synced; `Create` returns the key only then, and opening the directory
  discards whatever an interrupted write left behind;
- a key opens only from a regular file holding one unencrypted PKCS #8 ECDSA
  P-256 key, the one its name identifies, so a key that is truncated,
  re-encoded, swapped for another or replaced by a symbolic link is damaged,
  and it is left as it was.

At start, the agent opens `keys/` and `certificates/` and, once the
installation is enrolled, the key and the certificate of its active credential
generation, and checks that the certificate was issued for that key. When
`keys/` or a key in it is reachable by another account, or that key or
certificate is missing, damaged or not issued for that key, the agent logs
`agent_not_started` with a `recovery` and does not start, as for damaged
installation state: the installation is restored from a backup, or an operator
has the platform issue it a new certificate, as [enrollment](#enrollment)
describes. A key another account could read has to be treated as exposed:
revoke the certificate issued for it and replace the installation.
`agent_starting` names the provider in `key_provider` and says in
`key_exportable` whether a key can be read out of it; no log line carries a key.
A certificate that expired, or that the host's clock says is not valid yet, does
not stop the agent: the transport refuses to present it, and an agent that
cannot deliver still starts and keeps what it holds.

The files keep a key from other accounts, and from nothing else:

- root, the account the agent runs as, anything that can act as that account
  and whoever copies the state directory, such as a backup or a disk image, can
  read a key, so `key_exportable` is `true` and a copied key is an identity to
  revoke;
- a key is not encrypted at rest, since the secret to decrypt it would have to
  sit on the same disk, within reach of whoever can read the key;
- the agent does not claim to erase a key's copies from memory, which Go does
  not guarantee.

Protected providers were weighed against Linux, the platform the agent is built
and tested for:

- a TPM 2.0 is the one that fits: it signs with a key wrapped by its own storage
  key and never exports it. It is not implemented yet, because no supported
  deployment requires it and many hosts, virtual machines and containers have no
  TPM to use;
- PKCS #11 needs a hardware token on every endpoint and cgo in the build;
- CNG, DPAPI, the Keychain and the Secure Enclave belong to Windows and macOS,
  which the agent does not support yet.

Providers never fall back to one another: when a protected provider is added,
a host where it is unavailable will not have its keys quietly kept in files
instead.

## Enrollment

An installation becomes an agent the platform knows when an operator has the
platform issue it a certificate. At the recorded backend commit that is how
every first certificate is issued: an operator allowed to write agents asks the
control plane to sign a certificate request for an agent they registered, and
the platform signs it and binds the certificate to that agent in one act.
`internal/enrollment` is the agent's half of it, and it reaches no host: the
request and the certificate travel through the operator, and the operator's
credentials never reach the endpoint.

```bash
seagull-agent -config /etc/seagull-agent/agent.json enrollment request web-01 > web-01.csr
# the operator has the platform issue it, from anywhere but this host
seagull-agent -config /etc/seagull-agent/agent.json enrollment import web-01.issued
```

`enrollment request AGENT_ID` asks to be the agent the operator registered:

- the installation draws a key of its own with its key provider and records the
  request, the agent and the `key_id`, before it prints the request. That is a
  PKCS #10 certificate request, printed as PEM on stdout, whose common name is
  the agent, which carries the public half of the key and which the key signed
  to prove the installation holds it. It asks for nothing else, and carries no
  private key: no code outside the key provider draws, writes or reads one, and
  `tests/architecture` holds that as a test;
- asking again for the same agent prints the same request, with the same key,
  so a request lost on its way costs nothing. Asking for another agent draws
  another key, since a key is only ever asked to be one agent, and so does
  asking again once the key of the request is gone or damaged, since a key
  nothing was issued to is no identity yet;
- the identifier is the platform's: letters, digits, `.`, `_` and `-`, starting
  with a letter or a digit, at most 64 of them, the shape the platform reads an
  agent out of a certificate with. An installation enrolled as one agent asks
  only to stay that agent, and becoming another takes a replacement
  installation.

The operator then has the platform issue the certificate, as themselves and
from anywhere but the host: `POST /v1/agents/<agent_id>/certificate` on the
control plane's operator listener, with the request as the `csr_pem` of a
`seagull.agent.v1.CertificateRequest`. The platform signs only a request whose
common name is the agent the operator names, only for an agent it registered and
has not revoked or decommissioned, and answers with a
`seagull.agent.v1.IssuedCertificate`: the certificate, the chain of the
authority that signed it, the authorities it tells its agents to trust, and what
it recorded of the certificate.

`enrollment import ISSUED` reads that answer, as the platform gave it, and
activates it only when it is the certificate the pending request asked for:

- its certificate names the agent the request asked to be and carries the key
  the request was made with, authenticates a client, lets its key sign, belongs
  to no authority and is valid now;
- it chains, through the chain the answer carries, to an authority in
  `server.trust_bundle`, the authorities the agent authenticates the platform
  with. A certificate an impostor signed, or another platform issued, is refused
  however it reached the host;
- what the platform recorded of it, its subject, serial, fingerprint and
  validity, is the certificate the answer carries;
- the authorities the answer tells the agent to trust are read and never
  trusted. Trust changes only through `server.trust_bundle`, the path the
  operator already controls, and the import names each authority the platform
  publishes that the bundle does not hold, so that the operator adds it before
  the platform serves or issues certificates from it.

Anything else is refused with what is wrong and a `recovery`, and changes
nothing: the request stays pending, and the installation keeps the generation
it had. Activation survives any interruption:

- the certificate and its chain are kept under `certificates/` in the state
  directory, in a file named after the SHA-256 fingerprint of the certificate,
  0600 in a 0700 directory, written to a temporary file that is synced and
  renamed before the directory is synced;
- only then does `installation.json` record the next credential generation, and
  the same write ends the request;
- an import interrupted before that write leaves the request pending, and
  running it again completes it. Importing the certificate of the active
  generation again changes nothing but restoring its file, so an import is
  always safe to repeat.

An enrolled installation asks for its next certificate the same way, with a
new key, and the import activates it as the next generation of the same agent.
That is how an operator recovers an installation whose key or certificate was
lost or damaged, without replacing it or setting its spool aside; a key another
account could read is exposed instead, and is revoked with its agent. Both
commands hold the installation, so they run while the agent is stopped, and as
the account the agent runs as: `sudo -u seagull-agent` for the service the
package installs.

The evidence:

- `internal/enrollment` is tested against a platform that signs as the recorded
  platform's authority signs. Nothing is activated for another key, for another
  agent, from an authority the agent does not trust, for a server, for a key
  that may not sign, as an authority, outside its validity, when what the
  platform recorded is another certificate, from an answer that is not one, or
  without a request; an import interrupted before its activation completes, a
  repeated one changes nothing, and an authority only the answer names is never
  trusted. The answer's parser is fuzzed;
- the exchanges were recorded from the control plane of the recorded backend
  commit, driven by that commit's own end-to-end harness and by the agent's
  binary: the platform issued a certificate from the agent's request; it refused
  the same request for another agent, a request for an agent it never
  registered, and one for an agent it revoked; the agent imported what it
  issued; and the credential it activated authenticated to the platform's
  renewal listener, whose answer the agent imported as its next generation.
  `tests/compatibility` verifies every certificate the platform issued against
  the request it answered and the authority the agent trusted, and checks that
  the request the agent makes today is the one the platform signed;
- the command-line tests enroll an installation end to end and reach an mTLS
  listener through `internal/transport` with the credential it activated, which
  the listener authenticates as the agent it was issued to.

What it does not claim:

- enrollment without an operator. The recorded platform issues no bootstrap
  credential an agent could present, and the agent adds none: a token that
  enrolled an endpoint would have to be single-use, short-lived, scoped and
  consumed atomically by the platform, and until the platform and the contracts
  define one, only an operator has a certificate issued;
- that the platform still admits the agent. Importing checks what the platform
  issued, and an agent the platform later revokes still holds a certificate
  that verifies: it learns of it from the platform's answers, as
  [Reaching the platform](#reaching-the-platform) describes;
- that the generation before stops authenticating. The platform honours a
  certificate it replaced until that certificate expires, and its key stays in
  `keys/`, so an installation whose key was exposed is revoked with its agent,
  never merely issued a new certificate;
- that an operator is needed again while the credential is current: the agent
  renews it itself, as [Renewal](#renewal) describes, and an operator is back
  only for a credential that expired, was lost or damaged, or that the platform
  no longer renews.

## Renewal

An enrolled agent keeps its credential current without an operator. Once the
installation is enrolled, the running agent composes `internal/renewal`, which
asks the platform's renewal listener for the next certificate before the active
one expires, over the credential it is replacing: `POST /v1/agents/certificate`
under `server.renewal_url`, a `seagull.agent.v1.RenewalRequest` carrying a
certificate request made as [enrollment](#enrollment) makes one. At the recorded
backend commit, that listener takes the agent off the certificate it verified,
signs only a request naming that agent, and renews only an agent its registry
still admits.

When:

- at a point between seven and nine twelfths of the active certificate's
  lifetime, drawn from the installation and the certificate, so a fleet issued
  its certificates at once does not renew them at once, and a restart does not
  move the moment; `credential_renewal_scheduled` says when, and an agent that
  starts past that point renews at once;
- a failure the network or a busy platform explains, a lost connection, a
  request the listener never answered, a 5xx or a 429, is retried after a
  minute, doubling up to an hour; a failure somebody has to act on, a refusal, a
  certificate the listener refused, a listener the agent cannot authenticate or
  an answer that does not verify, is retried every hour. Each wait is drawn as
  every wait before the platform is tried again is, as
  [The connection to the platform](#the-connection-to-the-platform) describes.
  A failure is logged as `credential_not_renewed`, a warning or an error, with
  its class when it has one, the attempt, the next one and a `recovery`, the
  first time, each time the count of failed attempts doubles and each time an
  attempt fails otherwise than the one before; the [status](#status) counts
  every attempt. The agent never enrolls itself again whatever the platform
  answers;
- the agent waits an hour at most before it looks at the clock again, so a
  clock that moved, or a host that slept, moves the renewal with it.

With which key:

- a renewal replaces the certificate and keeps the key while the key is younger
  than `identity.key_lifetime`, 720 hours by default, and draws a new key once it
  is not: replacing a certificate and rotating a key are two operations, and
  the key lifetime decides between them. A generation records when its key was
  drawn; one enrolled before it did is rotated at its next renewal;
- the request is recorded, with its key, before it is sent, so a renewal whose
  answer was lost is asked again with the same key and never draws another;
- the answer is verified as an imported one is, against the authorities that
  very answer publishes, which is sound because it arrived over a connection
  the agent authenticated with the authorities it trusts, from the platform its
  credential authenticated to. The certificate is kept and the next generation
  activated as an import activates it, so an interrupted renewal leaves the
  generation before active and whole, and the transport presents the new one
  from its next request;
- the generation a renewal replaced keeps its key and its certificate. The
  recorded platform honours a certificate it replaced until it expires, and the
  agent assumes neither was revoked.

Whom it trusts. Every answer carries the authorities the platform tells its
agents to trust, and that is how the platform rotates its authority without
anybody visiting a host: it publishes the next authority beside the current
one, signs with the next once its agents renewed, and retires the current one.
The agent follows:

- it adopts the set an answer publishes when that set differs from the one it
  trusts and still authenticates the listener that answered, and from then on
  authenticates the platform against it, `platform check` and
  `enrollment import` included. While both authorities are published it trusts
  both, and once the current one is retired a listener still presenting one of
  its certificates is no longer authenticated;
- a set that would not authenticate the listener it came from is not adopted:
  adopting it would leave the agent unable to reach the platform to be told
  better. The agent keeps what it trusts and logs `authorities_not_adopted`,
  and adopts the set at a later renewal once the listener serves a certificate
  the set authenticates;
- the set is kept under `trust/` in the state directory, named after its digest
  like a certificate, and adopted in `installation.json` beside the digest of
  the `server.trust_bundle` it took over from. When an operator changes that
  bundle, the change is the newer word: the agent trusts the bundle, logs
  `authorities_reset`, and adopts what the platform publishes at its next
  renewal. A set the agent cannot read back falls back to the bundle the same
  way, logged as `authorities_not_read`.

When the credential cannot be renewed:

- a certificate that expired, or that the host's clock says is not valid yet,
  is no credential to renew with. The agent logs `credential_expired` or
  `credential_not_valid_yet` once, asks nothing, and waits: an operator has the
  platform issue a new certificate through `enrollment request` and
  `enrollment import`, or corrects the clock. The platform backdates what it
  issues by a minute, so a clock more than a minute behind the platform's
  refuses a renewal's answer as not valid yet;
- a platform that no longer renews the agent, because an operator disabled,
  revoked or decommissioned it, answers `illegal_move`. The agent keeps its
  credential and asks again every hour, since disabling is reversible; a
  revoked or decommissioned agent is replaced, never revived;
- a platform that renews only the certificate it last issued an agent, as
  backend commit 2829b0d does, answers a certificate a renewal replaced with
  `illegal_move` too, saying `the certificate was already replaced`. An
  installation hears it once a copy of it renewed first, or once the answer to
  its own renewal was lost, and cannot tell which:
  [Forgery, replay and copies](#forgery-replay-and-copies) says what an operator
  does. The agent keeps delivering with the certificate until it expires, and
  asks again every hour.

`seagull-agent -config FILE enrollment renew` renews at once, as the running
agent would, while the agent is stopped: it says which generation and key it
renewed to, and which authorities it trusts from then on.

Revocation and the roster. Renewal and ingestion learn that the platform stopped
admitting an agent apart. The renewal listener reads the registry as it
answers, so a revoked agent's next renewal is refused, as the recordings show.
The ingest gateway admits by a roster it follows on a compacted topic, so it
refuses the agent once the revocation reaches that roster: measured with the
recorded commit's own publisher, reader and roster against a single local
broker of the version its deployment runs, over 300 revocations, that took 6.8
ms at the median and 10.2 ms at most, a floor a deployment adds its network and
replication to. A revocation the control plane recorded while the broker could
not be reached is published again at its next sweep, every 30 seconds by
default. A roster that lags admits the revoked agent until the revocation
reaches it, which is the window measured above, and what it admits meanwhile is
the platform's to disposition. The agent keeps no admission state of its own:
each answer is the platform's word for that request, a refusal is never read as
lasting beyond it, and an answer that admits the agent again is taken as it
comes.

Recovering from a compromise is the operator's, and never the agent's: revoke
the agent, which is final on the platform and ends its renewals and its
ingestion; register a new agent; replace the installation with
`installation replace`, which sets the exposed key and certificate aside; and
enroll the new installation as the new agent. The revoked certificate still
verifies until it expires, and the roster refuses it.

The evidence:

- `internal/renewal` is tested against a renewal listener set up as the
  platform's: a renewal keeps a young key and rotates one as old as its
  lifetime, resumes an interrupted one with the same key, changes nothing when
  refused, activates no answer that is not the certificate asked for, adopts the
  authorities published during a rotation and refuses a set that would not
  authenticate its listener, leaves the replaced generation authenticating,
  renews on its own without an operator, retries within its bounds, and stops
  asking once the certificate expired;
- the command-line tests run the agent until it renews a certificate valid for
  seconds, renew from the command line, check the platform against the
  authorities it published, and reset to a `server.trust_bundle` an operator
  changed;
- the exchanges were recorded from the renewal handler of each recorded backend
  commit, served as its control plane serves it, with the agent's binary
  renewing its credential: keeping its key, rotating it, while the platform
  published its next authority, signed with it, retired the current one before
  and after moving its listener, and finally revoked the agent. The recording of
  backend commit 6fae345 also shows the platform renewing a generation two
  renewals had replaced, and that of backend commit 2829b0d refusing it.
  `tests/compatibility` verifies every answer as the agent does, checks which
  key each renewal asked with and which authorities each answer published, and
  holds which recorded commit renews a replaced certificate.

What it does not claim:

- that a renewal is a delivery: it sends no record, and does not wait for the
  governor's upload permits;
- a revocation deadline for a deployment: the measurement bounds what the
  platform's code adds on one host, not its network, its broker's replication
  or a backbone that was down;
- that a key renewal draws is better protected than the first: keys stay in
  files, as [Keys](#keys) describes.

## The spool

`internal/spool` keeps what the agent admits until the platform has it. It lives
in the installation, under `spool/` in the state directory, and holds two
streams, `events` and `inventory`, because the platform takes each on a route of
its own: each stream keeps its own order, and one the platform refuses holds
back no other. A record is an identifier and the bytes admission hands the
spool, kept with the sequence number it was admitted under and the moment it
was. The spool never looks inside a record, and reads no contract.

A record is admitted once it is durable, and not before:

- admission writes the records at the end of the stream's last segment and
  syncs it before it returns a receipt, and a new segment is synced, header and
  directory, before any record goes into it;
- a write that fails is undone, and admits none of the records it carried; one
  that cannot be undone stops the stream as a failed sync does;
- a sync that fails stops the stream admitting until the agent is started
  again, and says so as `spool_unavailable`: after a failed sync the kernel may
  have dropped what it had not written, and only reading the segment back tells
  what reached the disk. Reading and acknowledging go on;
- a sequence number a receipt named is never handed out again, not even once
  everything the stream held was delivered and its files removed.

A record is read back until it settles, and it settles once: as delivered when
its acknowledgement is durable, as lost when it cannot be read back, or as
expired or quarantined, which [Pressure](#pressure) describes. Each stream keeps
what settled, and how many records settled each way, in its `ledger`, which is
replaced whole: written
to a temporary file, synced, renamed over the ledger, and the directory synced.
The rename is what makes the replacement atomic and the syncs are what make it
durable, and neither stands in for the other. Acknowledgements may arrive in
any order, and the ledger keeps whatever settled above the oldest record still
outstanding, so a record between two delivered ones stays outstanding. A
segment is removed only once everything it holds has settled, and a removal a
crash undid is done again when the spool opens. Reading follows admission
order, skips what settled, and is bounded by a number of records and of bytes,
though it always returns the first record there is.

Opening the spool reads back what it holds before the agent starts:

- a write the agent was interrupted in leaves the end of the last segment
  missing: a record cut short, or sectors the disk never wrote, which read back
  as zeros. The spool discards it and reports `spool_write_interrupted` with the
  bytes it discarded. The write was never confirmed, so the collectors that
  made it admit its records again, and nothing is counted as lost;
- anything else that does not verify is damage. Each record carries two CRC-32C
  checksums, one over its header and one over what it holds, and a record that
  fails either is never delivered: the spool steps over it to the next record
  that verifies, settles the records between as lost, and reports
  `spool_records_lost` once, with the segment, the first record lost and how
  many. Damage costs the records it touched and never the ones after it. Damage
  at the end of the last segment that is not an interrupted write costs at least
  the record it starts in, and a segment the spool no longer finds costs the
  records it held, counted the same way;
- the last segment of each stream is read back whole as the spool opens, since
  it is the one a crash leaves unfinished. The segments before it were synced
  whole, and are verified as they are read;
- a ledger that is missing or does not verify is reported as
  `spool_acknowledgements_lost`, and every record the stream holds is delivered
  again. An acknowledgement is what lets the spool drop a record, so losing one
  costs a duplicate and never a record;
- the agent does not start on a spool another account can reach, on a spool
  written by a newer agent, or on one that holds anything it did not write: a
  file, a stream this build does not keep, a link, or a segment moved from
  another stream. The spool never resets itself, and `agent_not_started` says
  what to do instead.

`spool.max_bytes` bounds every file the spool keeps, both streams together, and
[Pressure](#pressure) says what happens when records keep arriving that the
platform does not take. Segments are a sixteenth of that budget, between 1 MiB
and 64 MiB, so freeing room never waits on more than that. What the spool holds
in memory is the list of its segments, the spans that settled out of order and
the records a read returns, never a segment: a record holds at most 8 MiB, and
everything else is read through a buffer of 64 KiB.

Only one process keeps a spool: the installation's lock already keeps a second
agent out, and the spool also locks its own directory. Its files are private to
the account the agent runs as, like everything else in the installation, and
they are not encrypted. A key to decrypt them would have to sit on the same
disk, readable by whoever could read the spool, so it would protect nothing and
be one more secret to lose. There is therefore no storage key: none to lose,
and none shared with the key the agent proves its identity with.

The spool is an append-only log of checksummed records for each stream and a
ledger replaced whole, written with the standard library alone. An embedded
database was weighed against it: bbolt keeps no checksum over the pages that
hold data and panics on some damage, which an agent that never recovers from a
panic would meet at every start, and SQLite takes cgo or a large translated
dependency and checksums no page unless it is built to. The evidence is in
`internal/spool`:

- a test kills, with SIGKILL, a process that admits and acknowledges as fast as
  its spool allows, over and over, and checks after every kill that each record
  whose receipt the process printed is read back unaltered and in order, and
  that nothing whose acknowledgement it printed comes back;
- tests cut, zero and flip the bytes a crash or a disk leaves behind, fail
  writes and syncs part way, restore segments a compaction had removed and take
  away ledgers and segments, and check what the spool reads back and reports;
- `FuzzRecover` hands recovery arbitrary segments and requires that opening the
  spool a second time finds nothing more to discard or count and reads back the
  same records, and `FuzzLedger` requires that a ledger is read back only as it
  was written;
- a test opens a spool of 24 MiB and reads one record back allocating less than
  2 MiB.

What the spool does not claim:

- a process that is killed is tested; a machine that loses power relies on its
  disk keeping what it acknowledged as synced, and a disk or a volume that
  acknowledges a sync it did not do can lose records the spool confirmed;
- damage that leaves a record with checksums that still match what it holds is
  not detected, and neither is the last segment of a stream taken away whole
  when nothing the ledger settled came after it: what is left reads as a spool
  that ended sooner;
- a record whose write was interrupted after it reached the disk, but before
  its receipt reached the collector, is read back and admitted again: the
  platform receives it twice, under the same identifier;
- records wait while the platform is unreachable for as long as the budget and
  their age allow, and no longer.

## Pressure

The agent keeps what it cannot deliver yet within limits it names, and when a
limit is reached it says what it does rather than choose in silence what to
lose.

| What | Bounded by | Spent by |
| --- | --- | --- |
| Records on disk | `spool.max_bytes`, both streams together | the spool |
| How long a record is kept | `spool.max_age`, and never longer than the platform admits it | the spool |
| Records in memory | none are queued: a record is on disk or it was refused | admission |
| One record | a batch that carries it alone: `transport.max_batch_bytes` less 1 KiB | the spool |
| One batch | `transport.max_batch_bytes`, `transport.max_events_per_batch` and `transport.max_inventory_records_per_batch` | delivery |
| Uploads at once | `resources.max_concurrent_uploads` | the governor, for delivery |
| Upload bandwidth | `transport.max_upload_bytes_per_second` | the governor, for delivery |
| Scans | `resources.max_concurrent_scans`, `resources.max_scan_bytes_per_second` and the room left in the stream a scan admits to | the governor, for collectors that scan |
| Reading a source as it is written | the room admission leaves, and 256 events or 1 MiB admitted at once | the authentication collector |

Priority is the agent's own, and never travels on the wire: events are what a
host cannot produce again, and inventory is collected again on the next scan.
It decides what the spool keeps when it cannot keep everything, and it never
reorders a stream, which keeps the order its records were admitted in:

- events may hold seven eighths of the budget and inventory half of it, so
  events always have at least half the spool, inventory at least an eighth, and
  neither waits on the other however long the platform is away;
- which stream is sent first is the governor's: events go before inventory
  when both wait to be sent, as [Resources](#resources) describes.

A spool that has no room for a record refuses it, and admission is paused:

- the refusal is `ErrFull`, and whoever admits keeps its place in what it reads
  and tries again later. `spool_admission_paused` says so once, with the limit
  that was reached, and `spool_admission_resumed` says how long the pause lasted
  and how many records were refused during it; the stream's stats say since
  when it is paused and how many records it refused;
- what a source loses while its collector waits, a journal rotated past the
  place the collector kept, is a gap in that source, and the collector reports
  it as `collection_gap`;
- before it refuses a record for room, the spool expires what outlived its age.

A record older than its stream's maximum age expires: it settles as expired, is
reported as `spool_records_expired`, and is never delivered. The maximum age is
`spool.max_age`, and never more than the recorded platform admits, `168h` for
events and `720h` for inventory: a spool kept for a fortnight still sends the
inventory it collected while the platform was away, and no event the platform
would refuse. The spool looks for expired records as it opens, before it
refuses a record for room and before a read, at most once a minute for each
stream. It judges a record by the moment it was admitted, stops at the first
record still within its age, and so keeps records longer, never shorter, when
the clock is set back.

A record the platform refuses for good is quarantined: it settles as
quarantined, is reported once as `spool_records_quarantined` with the reason the
platform gave, cut to what one message carries, and is never sent again.
[Delivery](#delivery) decides which refusals are for good.

Nothing is evicted. The spool never drops a record to make room for another: a
record leaves it undelivered only when it is counted as lost, expired or
quarantined, and each of those is reported and counted apart from what was
delivered, in the ledger, in `spool_opened` and in the spool's stats.

What the agent must still write is never refused for room: the spool keeps
64 KiB of its budget for its ledgers, and refuses a record that would leave the
filesystem it is on with less than 64 MiB free, so its acknowledgements, the
installation beside it and the place each collector keeps in its source can
still be written while records are refused. An acknowledgement
or a quarantine is never refused for room.

The evidence is in `internal/spool`: a test admits through a simulated outage of
two days, with no acknowledgement, and checks that the spool never holds more
than its budget, pauses, expires what outlives a day, admits again, keeps its
heap flat and accounts for every record it admitted; others fill each stream
first and check the room left to the other, keep a spool full for two hours and
count its reports, take away the filesystem's room, quarantine, and settle
records every way at once to check that each is counted once under one reason.

What pressure does not claim:

- the platform judges a record by the times it carries, and the spool by the
  moment it admitted it, so a record already old when it was admitted can be
  refused by the platform before it expires here;
- a record that expires while its delivery is on its way may reach the platform
  and still be counted as expired;
- the filesystem's 64 MiB protects what the agent writes, not what the rest of
  the host does: sizing `spool.max_bytes` to the disk is the deployment's to do.

## Resources

The agent bounds what it spends in two ways, and says which is which. What it
keeps to on its own is a budget: the memory its garbage collector works to, and
what `internal/governor` lets expensive work spend. A budget binds the work that
asks for it, is kept as well as the process is scheduled, and is measured by the
tests below. What the operating system holds the agent to is a ceiling: the
memory, processor time and tasks the cgroup of its service allows, and the
descriptors it may open. A ceiling holds whatever the agent does, and belongs to
the service the agent is installed as.

| What | Budget the agent keeps to | Ceiling the system enforces |
| --- | --- | --- |
| Memory | `resources.memory_limit`, the target of the garbage collector | `memory.max` of its cgroup, which `MemoryMax=` sets |
| Processor | `resources.max_concurrent_scans` and `resources.max_scan_bytes_per_second`, for expensive work | `cpu.max` of its cgroup, which `CPUQuota=` sets, and which Go follows in how many threads run goroutines at once |
| Disk | `spool.max_bytes`, and the scan budget for what scans read | the filesystem the installation is on |
| Network | `resources.max_concurrent_uploads` and `transport.max_upload_bytes_per_second` | none |
| Tasks and descriptors | none | `pids.max` of its cgroup, which `TasksMax=` sets, and `RLIMIT_NOFILE`, which `LimitNOFILE=` sets |

`agent_resources` says both as the agent starts and after every reload:
`budgets` as configured; `ceilings` as read from the cgroup the process runs in,
each the tightest limit on the way from that cgroup to the root of the hierarchy
the process sees, and from its descriptor limit; `unenforced`, what nothing
outside the agent bounds; and `processors`, how many threads Go runs goroutines
on at once. The line is a warning with a `recovery` when anything is unenforced,
or when `resources.memory_limit` is not below the memory ceiling, since the
kernel would end the agent before its garbage collector works to that target.
The agent reads ceilings on Linux, from a cgroup v2 hierarchy at
`/sys/fs/cgroup`; elsewhere, or on a host that keeps only v1 controllers, the
line is a warning that says the agent cannot tell, and never that nothing is
enforced. The service the package installs sets every ceiling, so the agent it
runs reports nothing unenforced.

The governor owns no work and starts none. A collector or delivery asks it
before something expensive, and waits on it in a goroutine of its own:

- a scan is expensive work a module does in one go, such as enumerating what is
  installed or hashing a file. At most `resources.max_concurrent_scans` run at
  once, and together they read and hash at most
  `resources.max_scan_bytes_per_second`. A scan is one unit of work, a file or
  a kind of inventory, and a module asks again for the next, so a long baseline
  never keeps another module waiting for its end;
- an upload is one batch on its way to the platform, from connecting to the
  reply. At most `resources.max_concurrent_uploads` run at once, and together
  they send at most `transport.max_upload_bytes_per_second`;
- reading a source as it is written, as the authentication log will be read,
  is not a scan: it never waits on the scan budget, and the room admission
  leaves bounds it instead.

A budget of bytes paces work rather than cutting it off: work charges what it
reads or sends as it goes, and waits once it has spent what the budget allows
so far. After a pause, work may spend an eighth of a second of its budget at
once, and at least 64 KiB, and never faster than the budget after that. A wait
lasts at least 20ms, so work kept waiting wakes at most fifty times a second:
waking a goroutine costs the processor more than a shorter wait would save.

What the governor keeps for critical work, and the order it serves the rest:

- events are critical and inventory is bulk. When both wait to be sent, events
  go first, and inventory goes after at most four event uploads in a row have
  passed it, so events delay inventory and never starve it. The same order
  holds for bandwidth when both send at once;
- when two or more uploads may run at once, inventory takes one fewer, so an
  event batch never waits for inventory to finish sending. With the default of
  one, it waits at most for the inventory batch already on its way, which
  `transport.request_timeout` bounds;
- scans are served in turn, and the module holding the fewest slots goes first,
  so a module that scans in parallel never keeps another's first scan waiting;
- events always have at least half of the spool, as [Pressure](#pressure) says.

Pressure reaches the governor as room. A scan that admits to a stream names what
it needs there, and waits for that much room before it takes a slot, so it never
holds a slot it cannot use: `scan_deferred` says so once, with the room there
was, and `scan_resumed` says how long it waited. It looks again at growing
intervals, from a quarter of a second up to five seconds, because what frees
room, a delivery or an expiry, tells nobody who waits for it. A collector that
admission refuses for room waits the same way, and keeps its place in its source
meanwhile.

Periodic work runs once an interval, at a phase drawn from the installation and
the task: the SHA-256 digest of both, reduced to the interval.

- installations draw their identifiers at random, so a fleet started at the
  same moment, after a mass reboot or an upgrade, spreads each task across its
  interval, and one installation's tasks do not all run at once;
- runs fall at the same points of the clock whenever the agent started, so
  neither a restart, a crash loop nor a reload runs a task before its turn;
- a run the work kept waiting past its successor is not made up, and a clock
  set back never brings back a run that already happened.

Whatever the governor hands out comes back however the work ends. A scan or an
upload gives its slot back when its work returns, whether it succeeded, failed
or was cancelled; a wait for a slot, for bytes or for room ends as soon as its
context does, and takes nothing with it. A module the collection disables is
cancelled and waited for, so it leaves nothing scheduled, held or waiting
behind. A reload replaces the budget whole: a lower one takes effect as the
work already running ends, since nothing running is stopped for it, and a
higher one serves what waits at once.

The evidence is in `internal/governor`, on the clock of `testing/synctest`, so
what a budget allows is checked exactly rather than waited for:

- three modules hash real files over and over at the scan budget, inventory
  sends at the upload budget, and an authentication event is admitted to a real
  spool every half second. Over three minutes, scans spend exactly their budget
  and never more over any stretch of time, at most two of them run at once,
  every event is admitted and delivered within 2.5 seconds, no event upload
  waits longer than one inventory upload, and inventory is sent throughout;
- eight senders reconnect at once after a five-minute outage: no more attempts
  run at once than the budget, one of them is kept for events, and a 64 MiB
  backlog drains at the upload budget without a burst;
- a fleet of ten thousand random installations started at the same moment
  spreads each task across every hundredth of its interval, for intervals of a
  minute, an hour and a day;
- tests take slots away with cancellations, failures and lower budgets, and
  check the order critical, bulk and parallel work is served in; a test in
  `internal/modules` disables modules while they wait for their turn, for a slot
  and for their budget, and finds the governor holding nothing;
- hashing 16 MiB through the governor allocates less than 1 MiB, and hashing
  8 MiB paced at 16 MiB/s takes about twice the processor time of the hashing
  itself, 12 ms rather than 6 ms over 0.38 seconds, on the AMD Ryzen 7 5700X,
  8 processors and Linux 7.0 the tests were developed on. The test prints both
  on whatever host runs it.

`internal/platform/ceilings` reads cgroup hierarchies written for its tests,
and a test starts a process under a transient systemd scope with `MemoryMax=`,
`CPUQuota=` and `TasksMax=` and finds the process reading back what the scope
sets. It runs wherever the account running the tests has a systemd user manager
that hands a scope those controllers, and is skipped elsewhere.

What the budgets do not claim:

- a budget binds only work that asks the governor. Nothing stops code from
  reading a file without charging for it, so every collector is reviewed for it
  as it arrives;
- the scan budget counts bytes, not the processor time or the disk operations
  they cost: a scan charges what it reads, and each collector decides what to
  charge for work that reads little, such as listing a large directory;
- the processor time above is one host's. What the agent spends on a
  deployment is measured when its collectors exist, and until then no footprint
  is claimed;
- the governor keeps no memory budget of its own: each collector bounds what it
  holds, and `resources.memory_limit` and the memory ceiling bound the process;
- the events of different collectors are not kept apart in the spool: while the
  authentication log is the only source of events, none has to be;
- the phase spreads a fleet whose installations drew their own identifiers: a
  copied installation shares its origin's phase, as it shares its identity.

## Reaching the platform

`internal/transport` is how the agent reaches the platform, and the only part
of it that opens a connection. It authenticates the listener before it sends
anything, presents the agent's credential with everything it sends, and bounds
what a request may take. It moves bytes and knows nothing of what they carry:
delivery decides what to send and what an answer means, and the credential it
presents is handed to it by whoever keeps it.

The platform is authenticated, never assumed:

- the agent speaks TLS 1.3 and nothing older. At the recorded backend commit
  the platform's agent listeners, ingest and renewal, speak 1.3 alone, so no
  supported deployment needs 1.2, and a listener that offers nothing newer is
  refused;
- the listener's certificate has to chain to an authority the agent trusts,
  `server.trust_bundle` or the authorities the platform published over the
  agent's credential and a [renewal](#renewal) adopted, be allowed to
  authenticate a server, be valid now, and
  name the host the address names, as a DNS name or an IP address. Nothing
  turns a check off: `tests/architecture` refuses any production code that
  names `InsecureSkipVerify`;
- the bundle holds authorities and never a certificate of the platform's own,
  so the platform replaces its certificates, and brings a new authority in
  beside the old one, without the agent's configuration changing;
- the agent follows no redirect and uses no proxy. Go's default client and
  transport, and the proxy variables of the environment that they follow, are
  refused in production code as the environment is: a batch goes to the address
  in the configuration file and nowhere else.

What the agent presents:

- the platform knows an agent by the certificate it verified on the connection,
  and takes the agent and its tenant from that certificate and its roster: the
  agent sends no identity of its own in a header, and nothing a batch says
  stands in for the certificate;
- a request is only ever sent as the enrolled agent. The transport takes the
  credential before it connects, and one it cannot use stops the request before
  a connection is opened: an installation that is not enrolled, a key that
  cannot be opened, a certificate that expired or that the host's clock says is
  not valid yet, one issued for another key, one that does not authenticate a
  client or whose key may not sign. Each is `ErrUnauthenticated`, with the
  reason;
- a credential is a certificate chain and a `crypto.Signer`, so the key signs
  the handshake where it is kept and the transport never holds it whole. A new
  credential generation is presented from the next request on, over new
  connections, and idle connections made with the one before are closed;
- the credential is the key and the certificate of the installation's active
  credential generation, opened where [enrollment](#enrollment) keeps them and
    checked to belong together before the transport presents them. The running
  agent presents it to renew it and to deliver records;
- the authorities the transport authenticates the platform against change while
  it runs when a renewal adopts new ones: from the next connection on, while a
  connection already made finishes what it carries.

What the agent is told, apart:

- `ErrUntrusted`: the listener could not be authenticated, for its certificate,
  its name or a TLS version the two could not agree on. Nothing is sent, and it
  is a question for whoever wrote the trust bundle and the address;
- `ErrUnauthenticated`: the agent had no credential to present;
- `ErrRefused`: the listener refused the agent's certificate during the
  handshake, as issued by an authority it does not know, expired or revoked;
- `ErrUnreachable`: the request never reached the listener: its name did not
  resolve, nothing answered the connection, or the listener never finished the
  handshake;
- `ErrUnanswered`: the listener took the request and did not answer it, because
  the request outlasted `transport.request_timeout` or the connection was cut
  before the answer ended. The platform may have acted on it;
- a reply, whatever its status: a refusal is an answer like any other, read
  whole up to `transport.max_response_bytes` or not at all, as
  `ErrReplyTooLarge`. It says when the platform answered, by its own clock, and
  how long it asked the agent to wait with `Retry-After`, in seconds or as a
  moment by that clock, read as a day at most and as nothing when it cannot be
  read.

Being authenticated is not being admitted. Once the handshake is done, the
platform decides whether it still admits the agent its certificate names, and
`internal/protocol` reads that refusal as an `Exclusion`, apart from any refusal
of a record: a certificate naming no agent the platform reads
(`unauthenticated_agent`), an agent it never registered
(`agent_not_registered`), and one it no longer admits because it was revoked,
decommissioned or disabled (`agent_not_admitted`). An exclusion refuses no record, whatever record it
points at: every record stays as valid as it was, none is quarantined for it,
and none is sent as that agent until an operator acts. [Delivery](#delivery)
keeps to that.

What a request may take:

- connecting and the TLS handshake take at most `transport.connect_timeout`, and
  a whole request, from dialing to the end of the reply, at most
  `transport.request_timeout`. Resolving the listener's name is part of
  connecting, so a name server that never answers holds a request no longer
  than the connect timeout, and a name that resolves to several addresses is
  tried address by address within it;
- at most `resources.max_concurrent_uploads` connections are open to a listener
  at once, one idles for 30 seconds at most, below the idle timeouts of the
  platform's listeners, and the headers of a reply are read up to 16 KiB;
- a request that is cancelled returns at once, its connection is closed, and
  the platform sees the request abandoned.

`seagull-agent -config FILE platform check` authenticates both listeners the
configuration names, presenting nothing and sending nothing, and closes each
connection as soon as the listener is authenticated. It says what each listener
presented, until when, and whether it asks for an agent's certificate, and exits
with 1, saying what to check, when a listener could not be authenticated or
reached. It opens no installation, so it runs before there is one and while the
agent runs.

The evidence:

- `internal/transport` is tested against listeners set up as the platform's
  agent listeners are, TLS 1.3 alone and a client certificate required and
  verified, with keys drawn by the agent's own key provider. The tests send
  nothing to a listener with an untrusted authority, another name, an expired
  certificate, a client's certificate or TLS 1.2 alone; open no connection
  without a usable credential; tell a refused certificate from a closed port, a
  listener that never answers the handshake and one that never answers the
  request; tell a request the listener dropped or never answered from one that
  never reached it; wait no longer than the connect timeout on a name server
  that answers nothing; read the wait an answer asks for in seconds and as a
  moment by the platform's clock, a day at most, and ignore one nobody can read;
  release a cancelled request and its connection, and every goroutine
  it started; stop reading an endless reply and never reuse its connection;
  keep to the connection limit; present a renewed credential from the next
  request on; and accept a platform that replaced its certificate or its
  authority;
- the refusals of the agent itself were recorded from the ingest gateway of the
  recorded backend commit, driven by that commit's own end-to-end harness: a
  certificate for an agent the roster never named, for an agent it revoked while
  the certificate stayed valid, and one naming no agent, sent to both routes.
  `tests/compatibility` reads each as an exclusion, and none as a refusal of a
  record or as an incompatibility;
- `platform check` is tested against listeners set up the same way, including
  one whose certificate an impostor authority issued and a closed port, and
  opens no installation while it checks.

What it does not claim:

- revocation is the platform's to enforce. A certificate that still verifies is
  refused by the platform's roster, and the agent learns of it from the answer
  to its next request, as soon as the roster does;
- the transport checks that a credential can be used, not that it is the
  enrolled one: which agent and which generation belong to enrollment;
- the agent pins no certificate, so any certificate an authority in the bundle
  issued for the name is the platform, and which authorities those are is the
  operator's decision;
- a deployment that reaches the platform only through a proxy is not supported.

## The connection to the platform

`internal/link` keeps the agent's connection to a listener of the platform:
whether the listener answers, since when it has not and why, and when it is
tried again. Delivery's two routes share the link to the ingest listener, since
the platform serves both on one listener, behind one certificate, one roster,
one rate limit and one capacity bound. Renewal asks its own listener on the
schedule [Renewal](#renewal) describes, and waits as the link does.

Every batch takes a turn on the link before it takes an upload:

- while the listener answers, every route has its turn at once;
- once the listener fails, one request at a time tries it again, when its wait
  is over, while the other route waits on the link, holding no upload and
  opening no connection. A batch that took its turn before the listener failed,
  and had not been sent yet, is not sent;
- the first answer, whatever it says of the batch it answers, lets every route
  through at once, and an outage several requests ran into is counted once.

What fails the listener, and what fails a batch alone:

| Failure | What happened | Holds | First wait, doubling up to |
| --- | --- | --- | --- |
| `transport` | the name did not resolve, nothing answered the connection, or the handshake never finished | both routes | a second, five minutes |
| `transport` | the listener took the request and never answered it | its route | a second, five minutes |
| `tls` | the listener could not be authenticated | both routes | a minute, an hour |
| `authorization` | the agent has no credential it can present, the listener refused it, or the platform refuses the agent itself: `unauthenticated_agent`, `agent_not_registered` or `agent_not_admitted` | both routes | a minute, an hour |
| `capacity` | a 429 or a 503 that does not name the batch: `rate_limited`, `gateway_at_capacity`, or no code at all, the gateway taking nothing from the agent then | both routes | a second, five minutes |
| `capacity` | any other 5xx, such as `backbone_unavailable` | its route | a second, five minutes |

A refusal of what a batch carries holds its route as [Delivery](#delivery)
describes, and is no failure of the connection.

Every wait is drawn anywhere between half and one and a half times its value, so
agents that failed at the same moment drift apart with every failure. A wait the
platform asks for with `Retry-After` is never cut short, up to five minutes, and
is drawn anywhere up to twice as long, so a fleet told to come back in a second
does not come back in the same second. `connection_failing` says when a listener
starts failing, and again when the class of its failure changes, as a warning,
or as an error with a `recovery` when somebody has to act; `connection_restored`
says how long it failed and after how many attempts. `delivery_failed` and
`credential_not_renewed` name the class of each failure as `failure`.

Which listeners: only those the configuration names, `server.ingest_url` and
`server.renewal_url`, authenticated as
[Reaching the platform](#reaching-the-platform) describes, with no redirect
followed and no proxy used. The platform publishes no other listener to fail
over to: a deployment serves its agents one ingest listener, and a name that
resolves to several addresses is tried address by address within
`transport.connect_timeout`, which is all the failover the agent does.

No heartbeat: the contracts carry no message for one and the platform serves no
listener that takes it; it reads when it last heard from an agent off the
telemetry that landed. The agent keeps locally what a heartbeat would say of its
connection: when the listener last answered, since when it fails, why, and when
it is tried next; when each route last delivered, and when the oldest record it
holds was admitted. The validity of its certificate, and when it renews it, are
kept by the installation and [Renewal](#renewal). Nothing outside the agent
reads any of it yet.

The evidence:

- `internal/link` is tested on a clock of its own: every request has its turn
  while the listener answers; one request at a time tries a listener that
  fails, once its wait is over; the first answer lets the rest through; an
  outage several requests ran into is counted once; a turn taken before the
  listener failed no longer stands; a request that stopped gives its turn back;
  a failure somebody has to act on waits longer and says what to do; and a wait
  the platform asked for is never cut short;
- a fleet of ten thousand agents that lose the platform at the same instant is
  modelled with the waits the agent draws. After the first ten seconds no
  second carries more than a fifth of the fleet's attempts, 13% in the model;
  after the first minute no more than a twentieth, 3.5%; after ten minutes no
  more than a hundredth, 0.6%. Once the platform returns after half an hour, no
  second brings back more than a hundredth of the fleet, and every agent is back
  within seven and a half minutes. A fleet asked to come back in a second, or
  in five, comes back over the following second, or five, with no tenth of
  that holding a fifth of it;
- `internal/delivery` is tested through a network that passes, holds or closes
  every connection. While it holds them, one connection at a time tries the
  listener, and both routes count their backlog and date its oldest record;
  once it passes, both routes deliver. A gateway that asks the agent to wait a
  second is sent nothing, on either route, for that second. A request the
  gateway took and dropped holds inventory while events are delivered. A
  listener that flaps between the three, over and over, leaves no goroutine,
  descriptor or upload behind once everything is delivered. A collector admits
  at its own pace, never waiting on a connection, while every connection hangs;
- every answer the recorded gateway gave that asked the agent to wait, a second
  or five, is one the agent sends again after, and never sooner.

What it does not claim:

- that a fleet which failed at the same instant spreads its first attempts: they
  come within the first seconds, as close together as the failures were, and
  spread from then on;
- a wait longer than five minutes because the platform asked for one;
- failover to another listener, or a heartbeat;
- that the state it keeps can be read from outside the agent.

## Delivery

`internal/delivery` sends the platform what the spool holds, and decides from
each answer what becomes of the records a batch carried. It is composed once the
installation is enrolled: an installation that is not keeps what it admits in
the spool until it is. It reads records from the spool, frames them into
batches, sends them through the transport within the governor's budget, and
settles them in the spool. It never decodes a record to send it, and never
changes one.

A record is what admission hands the spool. On the events route it is the wire
encoding of one `seagull.event.v1.Event`, whose `event_id` is the identifier it
was admitted under; on the inventory route, one `seagull.inventory.v1.Record`,
whose `record_id` is. A batch is the batch message of its route,
`seagull.ingest.v1.EventBatch` or `seagull.inventory.v1.RecordBatch`, with an
identifier drawn at random, the protocol version, and each record framed as one
element of it, byte for byte as it was admitted: `internal/protocol` builds it
from the field numbers the contracts declare. A record the agent cannot read as
one of its route, or that carries another identifier than the one it was
admitted under, is quarantined without being sent, since no batch that carried
it could be read, and `record_not_delivered` says so.

Each route delivers on its own, one batch at a time and in the order its records
were admitted, so a route whose batches the platform does not take holds nothing
back on the other, while a listener that fails holds back both, as
[The connection to the platform](#the-connection-to-the-platform) describes.
Events are critical and inventory is bulk, as the governor serves them. A
batch holds at most `transport.max_batch_bytes`, its envelope included, at most
`transport.max_events_per_batch` events or
`transport.max_inventory_records_per_batch` inventory records, and inventory
records holding 20,000 items at most between them, the recorded platform's
ceiling, and it always holds one record, even one a lower setting made larger
than the rest. A batch keeps to the settings in force when it is made, so a
reload shapes the next one.

What each answer means is read by `internal/protocol`, and what delivery does
follows from it:

| The platform answered | Outcome | What delivery does |
| --- | --- | --- |
| 200 with an acknowledgement that is `accepted`, `durable` and counts every record the batch carried | durable | writes the acknowledgement down in the spool, and only then drops the records |
| 200 with an acknowledgement short of that; 408 or any other 5xx, such as `backbone_unavailable`; 400 `unreadable_body`; a listener that never answered, or could not be reached | unconfirmed | sends the same batch again soon; a listener that could not be reached holds both routes |
| 429 or 503 that does not name the batch: `rate_limited`, `gateway_at_capacity`, or no code at all | busy | holds both routes, and sends the same batch again soon |
| 422 `invalid_event` or `invalid_record` refusing one record for what it holds | refused | quarantines the record, sends the records before it again at once, and the ones after it in smaller batches |
| 413, or 422 `batch_too_large` | too large | sends the first half again at once and the rest in batches half as large, and quarantines a record the platform refuses alone |
| 400 `malformed_payload` | undecodable | halves the batch the same way, until the record the platform cannot decode is alone, and quarantines it |
| 403 refusing the agent itself | agent refused | keeps every record, holds both routes, and sends the same batch again later |
| 426, or a record carrying a version or a value the platform does not speak | incompatible | the same |
| a record refused over a moment the platform's clock has not reached | disputed | the same |
| anything else: another status or code, a success that acknowledges nothing, a reply larger than `transport.max_response_bytes`, a listener the agent cannot authenticate or present its credential to | unexpected | the same, holding both routes when the listener could not be authenticated or took no credential |

Only a durable acknowledgement drops a record, and an HTTP success alone never
does. The acknowledgement carries no batch identifier and no record, so what it
answers is the request it is the reply to: a route sends one request at a time
and reads its reply before it sends anything else, and an acknowledgement
settles the records of that batch and no others. It has to say the batch was
accepted and made durable, and count exactly the records the batch carried,
inventory records rather than the items they hold. A reply that arrives after
the agent stopped waiting for it is never read: the transport closed its
connection, and the batch is sent again. The records are dropped only once the
acknowledgement is written down in the spool's ledger, and a ledger the spool
cannot write keeps the route waiting, as `delivery_not_settled`, until it can:
nothing is read past records that were delivered but not written down.

A batch sent again is the same batch, with its identifier and its bytes, for as
long as the agent holds it. A batch built again, a half of one the platform
found too large, the records before one it refused, or whatever the spool still
holds when the agent starts, gets an identifier of its own, and carries its
records under their identifiers and as the bytes they were admitted as.

The platform checks every record of a batch before it publishes any, but it can
publish part of a batch before its backbone fails, and an answer can be lost
after the platform published all of it. Either way the agent does not know, and
sends the batch again: the platform then holds records it already had, under the
same identifiers and with the same bytes. At the recorded commit the gateway
takes such a batch again whole, and its store keeps an event once by its
identifier and its time, which a batch sent again carries unchanged: that is
what makes sending it again safe.

A refusal of one record says the records before it passed what the platform
checks, since it checks them in order and stops at the first it refuses; those
after it were never looked at. So the records before it go again at once as a
batch of their own, and those after it in batches half as large as the one that
carried the refused record, growing again with each batch the platform takes. A
refusal that is not the record's fault is never a reason to quarantine it:

- a refusal of the agent itself is an exclusion, as
  [Reaching the platform](#reaching-the-platform) describes, and every record
  waits for an operator to act;
- a refused version, or a refused value the agent's contracts declare, is an
  incompatibility, as [Compatibility](#compatibility-with-the-platform)
  describes: the platform does not speak it yet;
- a record refused over one of its times is disputed when the platform's clock,
  which the `Date` of the answer tells, had not reached that moment although
  the agent's clock had when it admitted the record: the two clocks disagree.
  A moment the platform's clock had passed is older than the platform takes,
  and only grows older, and a moment later than the agent admitted the record
  at, by more than the five minutes the platform tolerates, is the record's
  own mistake: both are refused for good.

What is sent again waits: a second after the first unconfirmed or busy answer,
doubling up to five minutes, and a minute after the first of any other, doubling
up to an hour, each drawn between half and one and a half times that so a fleet
does not return at once, and never sooner than a `Retry-After` asked, up to five
minutes. A failure of the listener is waited out once, on the link, for both
routes; a failure of the batch, by its route alone. A durable answer ends the
wait. `delivery_failed` reports the first attempt that failed, each attempt that
doubles their count and each that fails otherwise than the one before, as a
warning when the platform did not confirm or was busy and as an error with a
`recovery` otherwise, with the batch, its records, the outcome, the class of the
failure when it has one, the attempt and the next one; the [status](#status)
counts every attempt;
`delivery_resumed` says how long the route failed once it delivers again;
`record_refused` names each record quarantined and the platform's reason, and
`batch_split` each batch sent again in halves. A stop cancels the request on its
way and settles nothing; the records are sent again after the agent starts.

The evidence:

- `internal/protocol` is tested against acknowledgements and refusals of every
  kind, checks that its batches are the bytes the contracts' own encoder writes,
  and fuzzes how it identifies a record against what the contracts decode;
- `internal/delivery` is tested against an emulated platform that speaks TLS 1.3
  alone, asks for the agent's certificate, decodes each batch with the published
  contracts, publishes records and keeps each once by its identifier: batches
  within their limits, a batch sent again unchanged through a partial
  publication, an unconfirmed acknowledgement, a miscount, a page that is no
  acknowledgement and a lost connection, refused records, batches too large or
  undecodable, refusals of the agent, of its protocol, of a schema and of a
  clock, records the agent cannot read, a route refused while the other
  delivers, a late answer, a stop, and records admitted while the route waits;
- a process delivering a spool is killed, with SIGKILL, before a batch is sent,
  while it is on its way, after the platform published it and before it
  answered, after the answer and before the acknowledgement is written down,
  and after it is written down and before the segment is removed; the spool is
  then delivered again. Every record reaches the platform's store once, as the
  bytes it was admitted as, and the only records the platform receives twice
  are those it held without the agent having written that down. Another test
  kills a process delivering over and over at random moments, while the
  platform fails some batches after publishing part of them, loses its answers
  to others and miscounts others, and checks after every kill that each record
  the spool no longer holds is in the platform's store;
- the answers were recorded from the ingest gateway of the recorded backend
  commit, driven by that commit's own end-to-end harness, and
  `tests/compatibility` checks that the agent reads every one of them, the
  earlier recordings included, as it means: a batch sent again under another
  identifier, taken again whole, and batches refused for their size, their
  encoding, their identifier, their media type, the times of a record, a
  backbone that did not take them, an agent sending too fast and a gateway
  holding all it may. It also checks that every batch the gateway read is the
  bytes the agent builds from its records;
- the batch sent again was admitted a second time by that commit's own admitter
  publishing to a real broker: both batches were acknowledged as durable, and
  the broker held every record twice, the same but for what the gateway stamps
  on it.

What delivery does not claim:

- that the platform keeps a record sent again once: at the recorded commit its
  store keeps an event once by its identifier and time, which the backend's own
  integration suite checks, and the agent's evidence stops at the broker;
- that a route moves past a record the platform does not speak yet, or whose
  time it disputes: the records after it wait until the platform takes it or it
  expires;
- that a batch holding several records the platform refuses is settled in one
  request: the platform names one refused record at a time;
- more than two uploads at once: each route sends one batch at a time, so
  `resources.max_concurrent_uploads` above two changes nothing yet. With two at
  once, an inventory batch shares the upload budget with events, which go first,
  and can take up to five times as long as alone; one that outlasts
  `transport.request_timeout` is sent again;
- that a quarantined record can be sent again: it is counted and reported, not
  set aside for an operator.

## Forgery, replay and copies

Which agent the platform takes a request for is decided by what the agent
holds, never by what it says. The connection proves possession of the key the
platform's authority certified for an agent, and the platform's registry decides
whether it admits that agent and in which tenant. Nothing the agent writes in a
record or a header stands in for either, and the agent writes nothing of the
kind:

- a request carries a batch, its media type and its length, and the `Host` and
  `User-Agent` headers Go writes, and names no agent, tenant, installation,
  release or build;
- the platform replaces the agent and the tenant of every record it admits, and
  the whole of its reception, with what the certificate and the registration
  say, and keeps the rest of the record as the agent wrote it, the host it
  observed included. A record claiming another agent is published as the agent
  that sent it;
- the agent reports no release or build to the platform, and a platform could
  not rely on one: whoever runs a changed binary with the key reports whatever
  they choose. A certificate proves who holds the key, not which code holds it
  or that the host is sound.

Forging an agent takes its key:

- a certificate is public, and one copied without its key cannot sign the
  handshake, so the platform refuses the connection before any request reaches
  it. The agent's own transport never presents a certificate its key does not
  match;
- no build of the agent carries a key, a certificate or an authority, and the
  package adds none: an installation draws its own key, is issued its
  certificate for that key, and trusts the authority its settings name. A copied
  binary or package authenticates as no agent;
- the agent signs nothing above TLS. A signature made with the key that
  authenticates the connection proves nothing the connection does not: whoever
  holds the key can sign anything, and whoever does not cannot connect. What a
  record holds once the platform has it is the platform's to protect.

Sending again is not forging:

- the agent sends a batch again whenever it cannot know that the platform made
  it durable, with the same records under the same identifiers and as the same
  bytes, as [Delivery](#delivery) describes. The platform takes it whole, since
  it cannot know it already has it, and keeps and decides it once: fed a batch
  and the same batch sent again, backend commit 2829b0d's own pipeline, on a real
  broker and store, stored the same three events, the same three detections of a
  rule that fires on each failed logon and the one detection of a rule counting
  three, as for the batch sent once;
- a record keeps its identifier and its bytes for as long as the agent holds it,
  and one whose bytes do not carry the identifier it was admitted under is
  quarantined rather than sent.

A copy is the agent:

- whoever holds a copy of an installation's key and certificate, from its state
  directory, a backup, a disk image or a snapshot of a virtual machine, is that
  agent to the platform. On the ingest path nothing tells the two apart: the
  platform answered both alike and published what both sent as the agent. A
  copied key is a compromise, recovered from as [Renewal](#renewal) describes:
  revoke the agent, which refuses every holder, register a new one and replace
  the installation;
- the one sign a platform gives comes at renewal, and not every platform gives
  it. Backend commit 2829b0d renews only the certificate it last issued an
  agent, so the first holder to renew carries on and the other is refused from
  its next renewal on, with `illegal_move` and `the certificate was already
  replaced`. A copy renews at the moment the original does, since that moment is
  drawn from the installation and the certificate a copy shares, so the refusal
  comes at the first renewal after the copy was made, and the refused holder
  keeps delivering until its certificate expires. Backend commit 6fae345 renews a
  replaced certificate, so there two holders renew side by side and nothing
  tells either of them;
- the agent reports that refusal as `credential_not_renewed`, with the
  platform's words and a `recovery`, and its [status](#status) shows the
  credential degraded. The same refusal follows a renewal whose answer was lost,
  when the platform issued the certificate and the agent never received it, and
  nothing in the refusal tells the two apart. So the operator decides: a key that
  may have been copied, from a host that was imaged, restored or cloned, or a
  backup that left its owners' hands, is revoked with its agent and the
  installation replaced; otherwise the operator has the platform issue the
  installation a new certificate, as [Enrollment](#enrollment) describes, and a
  copy, if there is one, can no longer renew;
- nothing else is read as a sign of a copy. The hostname, the addresses and the
  machine identifiers are observations and never identity, and the agent
  compares none of them. Every event carries `collection.sequence`, which the
  recorded platforms store for a search to read and decide nothing from, and the
  contracts carry no epoch, so the agent claims no gap and no copy found by
  counting.

Revocation takes effect at the agent's next request once the platform applied
it. The renewal listener reads the registry as it answers, so the next renewal
is refused. The gateway refuses the agent once its roster holds the revocation,
within the propagation [Renewal](#renewal) measured, 10.2 ms at most on one host,
and, for a revocation recorded while the broker was down, at the control plane's
next sweep once the broker is back, every 30 seconds by default. That is the
deadline the agent is held to, and it adds nothing to it: it keeps no admission
of its own, every request is answered by the roster as it stands, and a refusal
holds every record for an operator, as
[Reaching the platform](#reaching-the-platform) describes. Both holders of a
copied credential were refused once the revocation reached the roster.

The evidence:

- `tests/architecture` builds the agent for linux, windows and darwin and finds
  no PEM block, and no certificate or private key encoded as DER, anywhere in
  the bytes of each build, and recognises one hidden in any of those forms;
- `internal/transport` is tested with a client that presents an agent's
  certificate with a key of its own: the listener, set up as the platform's,
  refuses the handshake and receives no request, and the agent's own transport
  refuses to present it. A request's headers are tested to be its media type,
  its length and Go's `User-Agent`, beside the host it is sent to, and nothing
  else;
- the ingest gateway of backend commit 2829b0d was recorded, driven by its own
  end-to-end harness, taking a batch of events and one of inventory whose records
  claim another agent registered in another tenant, sent with headers claiming
  the same; refusing the certificate of a registered agent presented with
  another key; and taking a batch from each of two holders of one certificate and
  key, then refusing both once the agent was revoked. `tests/compatibility` reads
  each answer as the agent reads it and checks, record by record, that the
  platform published the certificate's agent and the registration's tenant with
  nothing else changed;
- the batch sent and the same batch sent again, recorded from backend commit
  6fae345's gateway, were admitted by backend commit 2829b0d's own admitter to a
  real broker, stored by its event writer, decided by its analysis engine and
  stored as detections by its detection writer, once alone and once with the
  batch sent again, and `tests/compatibility` checks that nothing the platform
  kept or decided grew;
- the renewal handler of backend commit 2829b0d was recorded with the agent's
  binary renewing, as for [Renewal](#renewal): an installation whose copy renewed
  first is refused, an installation whose renewal the platform granted but whose
  answer was dropped asks again with the key it asked with and is refused, and
  the agent says what each may mean. The same recording shows that commit
  refusing a generation two renewals replaced, which backend commit 6fae345
  renewed.

What it does not claim:

- that the agent or its host is sound: a key proves who holds it, and a
  compromised host holds it;
- that a copy is found on the ingest path, before its next renewal, or at all by
  a platform that renews a replaced certificate;
- that the agent tells a copy from a lost answer: both are the platform's
  `illegal_move`, and only the operator knows whether the key may have left the
  host;
- that the platform tells a record sent again from another agent's record under
  the same identifier at the same moment: its store keeps one event per tenant,
  moment and identifier, whichever agent sent it;
- a revocation deadline for a deployment's network and broker, which the
  measurement leaves out.

## Status

The running agent writes down what it says of itself where somebody on the
endpoint can read it: `status/status.json` in the installation's state
directory, private to the account the agent runs as, written as the agent
starts, every 30 seconds after, and once more as it stops. Each write replaces
the one before whole. `seagull-agent -config FILE status` prints it, run as the
account the agent runs as, as the other commands are:

    sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json status

It reads the file without the installation's lock, so it runs beside the agent,
and exits with 0 only while the agent runs as it should: with 1 when a part of
it is degraded or failed, when it stopped, when it has not written its status
for three of its intervals, and when there is no status to read, saying which.

For each part of the agent it says its state and since when, and, when the part
does not run as it should, why and what to do about it, in the words of the log:

| Part | Degraded, or failed, when |
| --- | --- |
| `configuration` | the last reload was refused, so the agent runs on a configuration the file no longer holds |
| `collection` | a module enabled in `modules` fails and is started again; failed once it spent its budget; disabled when `modules` enables none |
| `spool` | a stream holds all its budget allows and refuses what is admitted to it; failed when it can no longer make a record durable |
| `delivery` | the installation is not enrolled, the ingest listener fails, or a route's batches fail |
| `credential` | renewal fails, or the host's clock is behind the certificate; failed once the certificate expired |
| `resources` | the agent holds more memory than `resources.memory_limit` |

The agent is in the state of its worst part, and a part nothing asked for is
disabled and weighs nothing. Then, for each module this build has, its state,
since when, how often it was started again and why it does not collect, or,
for the authentication collector while it collects, since when it waits for
room in the spool and how often the journal dropped what it had not read yet.
Then, for each stream, what waits and when the
oldest record waiting was admitted, when the route last delivered and, while it
fails, since when, how often, why and when it tries next; what the spool settled
otherwise, as expired, lost or quarantined; and apart, what it refused to admit.
A record refused is one the agent never kept, a gap in what it collected; a
record waiting is one it keeps and could not deliver yet, an outage. Then, for
the ingest listener, when it last answered and, while it fails, since when and
why; the credential's generation, serial and validity, and when it renews; and
what the agent spends: the memory it holds against its target and ceiling, its
goroutines, the uploads and scans it holds and those waiting, and the scans it
deferred.

The file is JSON, `format` 1, with `written_at`, `every_seconds`, `state`, and
`reason` once the agent stopped, `agent`, `components`, `modules`, `streams`,
`listeners`, `credential` and `resources`. Every text in it is a kilobyte at most, and it holds what the log
already says: names, states, times, counts, reasons and what to do, and of the
credential, the serial and the validity the installation records. No key, no
certificate and nothing a request carries is in it.

A failure that repeats does not fill the log. `delivery_failed`,
`delivery_not_read`, `delivery_not_settled`, `credential_not_renewed`,
`module_restarting`, `module_started` and `status_not_written` are written for
the first attempt and each time the count of attempts doubles, and
`delivery_failed` and `credential_not_renewed` also whenever an attempt fails
otherwise than the one before; a failure that repeats the same way n times
writes about log2(n) lines. The status counts every attempt, and
`delivery_resumed`, `connection_restored` and `credential_renewed` say when the
failure ended. What else the agent logs happens once for each event, change or
record, bounded by whatever causes it. The journal keeps what the agent writes
for as long as the host's journald configuration says: the agent keeps no log of
its own, and its status is one file it replaces.

No remote reporting: the contracts carry no message for the agent's status and
the platform serves no listener that takes one, so the status stays on the
endpoint. `tests/architecture` keeps `internal/status` from reaching the
network, reading a contract or importing anything of the agent but
`internal/secrets` and `internal/platform/files`: it is handed the snapshot it
writes, and nothing it keeps authenticates the agent.

The evidence:

- `internal/status` is tested on a clock of its own: it writes the status as the
  agent starts, each interval after and as it stops; replaces it whole and
  keeps it private; discards an interrupted write; refuses to read a status
  that is missing, damaged, larger than it reads, written by a newer agent, or
  open to another account; writes each text as a kilobyte at most; reports a
  status it cannot write at the first failure and each doubling of their count;
  and prints what state the agent is in, what to do, what waits apart from what
  was refused, and no terminal escape it was handed;
- `cmd/seagull-agent` runs the agent and reads its status: before it ever ran,
  while an installation that is not enrolled runs, degraded with what to do,
  and once it stopped; with an enrolled agent the platform no longer admits,
  delivery degraded with the platform's reason, what to do, the records waiting
  and when the oldest was admitted, and the listener failing; the same agent
  running, with 0, once the platform takes its records; a certificate that
  expired as failed, with what to do; a refused reload; a full spool as a gap;
  and a status that holds no key or certificate material and is private;
- delivery, renewal, the collection and the status each log a failure that
  repeats at its first attempt and each doubling of their count: a delivery
  that fails forty times or more writes a line for each doubling alone, while
  its stats count every attempt, with the reason and what to do.

What it does not claim:

- that it is live: it is as fresh as its last write, 30 seconds at most while
  the agent runs;
- how old the records of an installation that is not enrolled are: it counts
  them, and their age is read by the delivery that waits on them;
- remote reporting, or a heartbeat.

## Diagnostics

`seagull-agent -config FILE diagnostics BUNDLE` writes what helps troubleshoot
the agent into a new file, a bundle an operator reads before handing it over,
and nothing that authenticates the agent. It runs as the account the agent runs
as, as the other commands do, and the account writes where it may, such as
`/var/tmp`, where root reads the bundle:

    sudo -u seagull-agent seagull-agent -config /etc/seagull-agent/agent.json diagnostics /var/tmp/seagull-diagnostics.json
    sudo cat /var/tmp/seagull-diagnostics.json > seagull-diagnostics.json

The bundle is one JSON document, `format` 1:

| Part | What it holds |
| --- | --- |
| `build` | the build identity `-version` prints, the wire versions, and what Go stamped on the binary: its module and version, the toolchain, the build settings and every dependency with its checksum |
| `writer` | the account, group and groups the command ran as |
| `configuration` | the configuration the agent would run on, defaults and all, as `config print` prints it, or why the agent refuses the file |
| `status` | what the agent last said of itself, as `status` reads it |
| `installation` | what `installation.json` records: the installation and the one it replaced, the credential generation, the request still pending and the authorities it adopted |
| `credential` | each certificate of the chain the installation presents, as it says in public: subject, issuer, serial, fingerprint, the `key_id` of the key it certifies, the key and signature algorithms, validity, usages and names; and whether the chain authenticates the agent, as a client, to whoever trusts the authorities the agent trusts, at the moment the bundle is written |
| `authorities` | the authorities `server.trust_bundle` holds and those the installation adopted, described the same way and named by their digest, and which of the two the agent trusts |
| `files` | every file and directory of the installation by its path, mode, size, owner and when it last changed |
| `logs` | the latest entries the system journal holds for the service the package installs, what the agent wrote and what systemd wrote of the service, and the records the commands run as the account wrote, as the end of this section describes |
| `limits` | the bounds below |

A part the command cannot read says why and what to do about it, the command
names it as it writes the bundle, and the rest of the bundle is written all the
same: a bundle is most useful when the agent does not start.

What a bundle never holds:

- a key. The files of the installation are listed by their names and never
  opened, and nothing asks the key provider for a key;
- a certificate, a request or the configuration file as they are encoded: the
  certificates are described by what they say in public, and the configuration
  as the agent read it, so a file the agent refuses, such as one whose address
  carries a password, is described by the refusal, which holds what every
  refusal holds;
- a record the spool keeps. The spool is listed as files and never opened, so
  nothing a collector admitted reaches a bundle, and no option includes it;
- the log of another service, or what the account writes to the journal
  through anything but the agent's commands.

What a bundle costs:

- at most 8 MiB, 1024 files of the installation listed eight levels deep, and
  2000 log entries holding 4 MiB of messages, the latest, each message cut to
  4 KiB and every other text to a kilobyte;
- a minute to gather, after which the command writes what it gathered and says
  what it could not;
- nothing of the running agent's. The command is a process of its own, outside
  the service and its bounds, that reads beside the agent without the
  installation's lock and changes nothing in the installation: it never opens
  the spool, so it neither recovers nor waits on it, never discards what an
  interrupted write left behind, and while it lists follows no link and opens
  nothing but directories, without waiting on a pipe put in a directory's
  place. The agent runs on as it was.

Where a bundle is written:

- `BUNDLE` is a new file. A file, a link or anything else already there is
  refused and left as it was, and a bundle is never written into the
  installation it describes, whatever path leads there, nor into any directory
  only the account may enter, which is where the agent keeps what is its own:
  that holds when the configuration cannot be read and nothing names the
  installation;
- it is written 0600 as the account the agent runs as, under a temporary name
  beside `BUNDLE`, synced, and linked into place only once it is whole and
  then checked to be what was written, so `BUNDLE` holds the whole bundle or
  nothing, whatever stops the command. A command killed as it writes leaves at
  most its temporary file, which only the account reads;
- text nobody chose for the agent, a name in the installation or a message in
  the journal, is written as a JSON string, so it cannot carry a terminal's own
  escape sequences.

Every command that changes the installation, and every bundle, is recorded in
the system journal, which makes the record attributable:

- `enrollment request`, `enrollment import`, `enrollment renew`,
  `installation replace` and `diagnostics` each write one entry once they are
  done, under the identifier `seagull-agent`, its message a JSON line as the
  agent's log writes one and `SEAGULL_EVENT` naming what happened:
  `enrollment_requested`, `credential_imported`, `credential_renewed`,
  `installation_replaced` or `diagnostics_written`, or what was refused, such
  as `credential_not_imported`, with the error;
- journald writes down beside each entry who sent it as the kernel tells, which
  no command chooses: the account in `_UID`, the process and its command line,
  and, on a host that keeps login sessions, the login the command was run from
  in `_AUDIT_LOGINUID`, however many accounts `sudo` went through on the way.
  `journalctl SYSLOG_IDENTIFIER=seagull-agent _TRANSPORT=journal` lists them;
- what the running agent does to the installation, a renewal, a reload or
  authorities it adopted, is in its own log, attributed to its service;
- a command whose record journald does not take still does what it was asked
  and says so, and a platform without a journal records nothing.

The account is a member of `systemd-journal`, so the commands an operator runs
as it read the agent's log as the service does. A bundle written without that
group says that its log was left out, and why.

The evidence:

- `internal/diagnostics` is tested listing an installation that holds a key no
  account may read, a pipe and a link to a directory outside it, which it
  lists without opening, waiting on or following; a directory the account may
  not list, past which it lists the rest; a directory of 1524 files, one twelve
  levels deep and a listing out of time, which stop at their bounds;
  names that hold a terminal's escape sequences, written down escaped;
  certificates described as they say in public, verified against the right
  authority, another one, none, after they expired and for a server; log
  entries cut, ordered, kept once each and bounded; and bundles refused over a
  file, a link, a pipe and a directory already there, inside the directory
  they list however the path leads there, deeper than the listing reached
  included, in a directory only the account may enter when no installation is
  named, in a directory the account may not write and when too large, each
  leaving nothing behind. A process writing
  bundles of 6 MiB is killed at random moments, over and over, and every
  bundle it leaves is whole and every temporary file private;
- `cmd/seagull-agent` writes bundles of an enrolled agent, of one running,
  whose status and installation it reads while the agent holds them and
  changes nothing of, and of agents that cannot run, for an address carrying a
  password, damaged state, a damaged key and a spool holding secrets, none of
  which reaches a bundle; refuses destinations over a file, a link to the key,
  the key itself, the installation, a directory only the account may enter, the
  installation of a configuration the agent refuses and a missing directory,
  leaving the key and the installation as they were; keeps a bundle within its bounds over an
  installation of thousands of files and a journal of oversized entries, and
  within its time when the journal never answers; and records what each
  command that changes the installation did, refusals included, and nothing for
  the commands that change nothing;
- `internal/platform/journal` sends notes to a journald that listens as journald
  does, refuses those journald would read otherwise, such as one claiming the
  account that sent it, and reads a unit and its last entries with the
  arguments journalctl takes;
- the [native gate](#installing) checks that the package makes the account a
  member of `systemd-journal`, that enrolling records the request and the
  import, attributed to the account, and, beside the running agent, has the
  account write a bundle after refusing one into the installation and one over
  its settings: the bundle is the account's and 0600, holds the running
  agent's status, its installation, its credential verified, its files, its
  start and systemd's lines from the journal, and none of the key's bytes,
  certificate material or what sshd wrote, and the service ran on as it was.

What it does not claim:

- that a bundle holds nothing about the host: it names its paths, the
  platform's addresses, the agent and the installation, and holds the agent's
  log, which names records by their identifiers. It is the operator's to read
  before it leaves the host;
- a whole log: the journal keeps what its configuration says, and a bundle the
  latest of that;
- that every entry it holds is this agent's: another service named
  `seagull-agent.service`, such as an earlier agent, is read the same way, and
  each entry says which account, process and command wrote it;
- a record of what an operator does to the installation by hand, or one beyond
  the reach of root, who controls the journal as the rest of the host;
- delivering a bundle anywhere: it stays where it was written.

## What the agent writes down

The agent holds one secret, the private key of its installation, and it reads
text it did not write: its configuration, its installation state, its trust
bundle, its key files, the certificates the platform issued it and what it finds
in its spool. `internal/secrets` is the
one place that decides what any of that may become in a log line, a refusal or a
message on the terminal. A [diagnostics bundle](#diagnostics) holds no more
than those, what the installation records and what certificates say in public.

- No message carries a key. A `Key` is a `crypto.Signer` with an identifier, so
  no caller holds a private half to print; the buffers a key file is read and
  written through are cleared as soon as it is parsed or stored; and a refusal
  about a key names the file and what is wrong with its shape, never its bytes.
- Text copied out of something the agent read — a setting's value or name, the
  type of a PEM block, what a library said about bytes it could not parse — is
  cut to 96 bytes and quoted when it is not printable. A file cannot decide how
  long a log line is, and cannot write a terminal's own escape sequences into
  one either.
- An address never carries credentials into a message. The agent refuses a
  `server.*` URL that holds a user and a password, and whatever was written
  between `//` and `@` reads as `(redacted)` in every message about that URL,
  including one about a URL the agent could not parse: the text a parser
  repeats back is its own, and the agent writes what it kept of it.
- The agent takes one argument, `-config FILE`, and reads nothing from the
  environment it was started in; `tests/architecture` holds that as a test. A
  credential on a command line or in an environment variable is readable by
  other accounts on the host, so the agent accepts neither.
- The configuration names where secrets are kept and holds none: a test refuses
  any setting whose name says otherwise, which is why `config print` prints the
  file as it stands.

At start the agent asks the kernel for no core dump of itself and for its
memory to be out of reach of the other processes of its account, and then reads
back what the kernel says rather than trusting that the calls returned.
`agent_core_dumps` reports `withheld`; a host where it did not take gets a
warning naming what the service unit should do instead. On Linux that is a hard
`RLIMIT_CORE` of 0, which the process can no longer raise, and `PR_SET_DUMPABLE`
of 0, which also keeps another process of the same account out of
`/proc/<pid>/mem` while leaving the process visible to `ps` and to the service
manager. A core dump of the agent would be its key in a file the agent neither
writes nor protects, so none is written even when an operator would like one: a
crash is investigated from the log and from a reproduction, and a panic's
traceback names the functions that were running rather than the bytes they held.

What none of that claims:

- the agent does not erase a key from memory. Go copies values as it collects
  them, so only the buffers it reads and writes a key through are cleared, and
  a key in use is in memory;
- memory is not locked. The service the package installs keeps the agent's
  memory off the swap device, on a kernel that accounts for swap; an agent run
  any other way on a host that swaps may have its key written to that device,
  and encrypting it belongs to the deployment;
- redaction is a rule about what the agent copies, not a filter over what
  somebody else wrote. The agent bounds and escapes what it repeats and refuses
  the one setting where a credential could arrive; it does not search text for
  what looks like a secret. A collector admits what it understood of its
  source and nothing else: the authentication collector keeps what an outcome
  of sshd says, and the line sshd wrote it in, which says nothing more;
- the spool keeps records as they are handed to it and never looks inside one,
  so what a record holds is decided by the collector that admits it. What the
  agent writes about a record is where it is in the spool and the identifier it
  was admitted under, never what it holds.

## Boundaries

`tests/architecture` holds the repository boundaries as tests rather than as
conventions:

- no source file, whatever its build constraints, imports another Seagull
  repository except the contracts;
- the contracts are required at a published release, and no module is replaced;
- no submodule or committed workspace brings a sibling checkout into the build;
- ignore rules never hide a source file, a packaging asset or a test fixture,
  and the local skills never reach Git;
- only the composition root imports the runtime, and the runtime depends on no
  other package of the agent and on none of the contracts;
- collectors, under `internal/modules`, reach no HTTP, gRPC, RPC or TLS package,
  directly or through another package: they hand observations to admission,
  and delivery owns the network;
- neither does `internal/protocol`, which speaks in contract terms: the versions
  the agent writes and the refusals the platform answers with;
- `internal/identity` imports no network package at all: an installation never
  takes its identity from an address, an interface or a server's answer;
- `internal/pki` imports no HTTP, gRPC, RPC or TLS package: a key signs where it
  is held, and transport owns requests, connections and TLS;
- no production code outside `internal/pki` draws a private key, writes one out
  or reads one in, so every other part of the agent uses a key through
  `crypto.Signer` alone and a certificate request carries its public half;
- no build of the agent carries a key, a certificate or an authority, as PEM or
  as DER, anywhere in its bytes: an installation is given its identity and its
  trust on its host, and a copied binary holds neither;
- `internal/renewal` reads no configuration and reaches no collector, directly
  or through another package, and imports no TLS package itself: it is handed
  the listener, the authorities and the key lifetime it works with, and reaches
  the platform through the transport alone;
- `internal/delivery` reads no configuration, reaches no collector and holds no
  key, directly or through another package, and imports no TLS package itself:
  it is handed the listener, the batch limits, the spool and the transport it
  delivers with, and presenting the credential is the transport's;
- `internal/enrollment` imports neither the configuration, nor the transport,
  nor an HTTP, gRPC, RPC or TLS package, directly or through another package:
  the request and the certificate travel through the operator, and it is handed
  the authorities it verifies against;
- `internal/config` imports neither the installation, nor the keys, nor an HTTP,
  gRPC, RPC or TLS package, directly or through another package: the
  configuration is read before any of them exists, and each component opens what
  its own settings name;
- no collector reaches `internal/pki`, directly or through another package, so
  collectors never hold the keys the agent proves its identity with;
- no collector imports `os/exec`, `syscall`, `unsafe` or `golang.org/x/sys`
  itself: it reaches the operating system through an adapter under
  `internal/platform`, which owns the commands it runs and the calls it makes;
- an adapter under `internal/platform` imports nothing of the agent but the
  other adapters and `internal/secrets`, nothing of the contracts and no network
  package, directly or through another package: what it reads means something
  to whoever asked for it alone;
- no `.proto` file, generated binding or descriptor built at run time defines a
  message of the agent's own, so it has no handshake or envelope beside the
  published contracts;
- a source file that only some of linux, windows and darwin build belongs to an
  adapter under `internal/platform`;
- `internal/secrets`, which decides what a message may carry of what the agent
  read, imports nothing of the agent, nothing of the contracts and neither `os`
  nor `net`: what may be written down is a question about text;
- `internal/spool` reads no contract, reaches no network, holds no key and opens
  neither the installation nor the configuration: it keeps records as the bytes
  admission hands it, in the directory and within the budget it is given;
- `internal/governor` imports nothing of the agent and nothing of the contracts,
  and reaches no network: it bounds work and knows none of it, so what a scan
  reads, what an upload carries and how it travels stay with the work;
- `internal/diagnostics` imports nothing of the agent but `internal/secrets` and
  `internal/platform/files`, nothing of the contracts and no network package,
  directly or through another package: it writes down what the composition
  root hands it and lists what a directory holds without opening it, so a
  bundle holds no key, no record and nothing else the root did not choose;
- `internal/transport` imports nothing of the agent but `internal/secrets`, and
  nothing of the contracts: it authenticates connections and moves bytes, while
  what they carry, whose records they are and where the credential it presents
  is kept belong to others;
- `internal/link` imports nothing of the agent but the transport and
  `internal/secrets`, and nothing of the contracts: it keeps whether a listener
  answers and when it is tried again, while what travels to the listener, what
  an answer means and whose records wait on it belong to delivery and renewal;
- no production code names `InsecureSkipVerify`, or uses the default client,
  the default transport or the environment's proxy of `net/http`: the agent
  sends only to a platform it authenticated, over a client whose every bound it
  set;
- production code reads nothing from the environment the agent was started in;
- production code never recovers from a panic.

The dependency rules are checked against the build graph Go computes for each
of linux, windows and darwin, so they also hold for files only another platform
builds.

`tests/compatibility` reads the ingest messages from bytes written against the
wire format rather than with the generated types, so a contracts release that
renumbers or retypes a field the agent depends on fails the suite instead of
changing what the agent reads.

## Compatibility with the platform

Three versions describe an agent, and none stands in for another. The release
names a build. The protocol version, `protocol_version` on every batch, shapes
a batch and the answer to it. The schema version, `schema_version` on every
event and on every inventory record, shapes a record of that kind, and each
kind moves on its own. This build speaks protocol 1, event schema 1 and
inventory schema 1: `-version` prints them and `agent_starting` logs them.

What the platform accepts is the platform's to say, and an agent hears it in
one place: the answer to a batch. The platform's descriptor names the versions
it supports, but it is served on the operator listener, which an agent's
certificate cannot reach, and it names no inventory schema. So the agent
negotiates nothing before it sends, and it advertises no capability or build
metadata, because the contracts have no field to carry them. It reads a refusal
with `internal/protocol` instead:

- a refused protocol or schema version the agent set is an `Incompatibility`;
- so is a refused value the agent's contracts declare, such as an event class,
  an inventory kind or a service state: the platform was built from contracts
  that lack it;
- a refused value the agent left unset, or one no contracts declare, is the
  agent's own mistake, and like every other refusal it is no incompatibility;
- a refusal of the agent itself is an `Exclusion`, never an incompatibility:
  [Reaching the platform](#reaching-the-platform) says what it means.

An `Incompatibility` names the field, the value and the record the platform
refused, with the platform's own explanation. It does not make those records
invalid: a platform that speaks what they carry accepts them unchanged.

What one side does not know follows from the same rule:

- a reply field the pinned contracts do not declare is ignored and changes
  nothing the agent concludes, so a change to what a reply means has to come
  with a new protocol version, which an older agent sees refused;
- no reply the agent reads carries an enum, and a contracts release that adds
  one fails the suite until the agent decides how to read a value it does not
  declare;
- the agent writes only what its contracts declare, and since a platform built
  from older contracts ignores a field it does not know instead of refusing it,
  nothing the agent sends may depend on a field no recorded platform consumes.

`tests/compatibility/testdata` holds exchanges recorded from the ingest gateway
of a backend commit, driven in process by that commit's end-to-end harness: the
bytes of every batch sent and of every answer, including batches sent under a
certificate the platform refuses the agent of, and the answers the same gateway
gives an agent delivering, as [Delivery](#delivery) describes, with a batch sent
again that was also measured on a real broker. Beside them are the exchanges of
[enrollment](#enrollment) and [renewal](#renewal), recorded from the control
plane of the same commit with the agent's own binary asking for, importing and
renewing the certificates, and the measurement of how long that commit takes to
carry a revocation to the roster its gateway follows. That commit, 6fae345, is
what every other section means by the recorded backend commit. A later one,
2829b0d, built from the same contracts, was recorded where it answers
differently or where [Forgery, replay and copies](#forgery-replay-and-copies)
needed it: its renewal handler, its gateway answering batches that claim another
agent, a copied certificate and a copied credential, and its pipeline keeping
and deciding a batch sent again. The latest, 0656b2a, built from the same
contracts, kept and decided what the [authentication collector](#authentication)
delivered of a real sshd: the native gate recorded what the sshd of an Ubuntu
24.04 host wrote to its journal and the batches the installed agent delivered of
it, and that commit's own admitter, broker, event writer, analysis engine with
the rules it deploys and detection writer took those batches, then took them all
again. Each batch was acknowledged as durable; the 26 events were stored once
both times; the 25 failures from outside the estate, the count of twenty failures
in a minute and the guess that succeeded were each decided and stored, and
sending the batches again stored and decided nothing more. The suite derives the
same events from the recorded entries with the collector of the build under
test, byte for byte, so a change to what the collector makes of sshd fails it
until the scenario is recorded again. The suite fails when `go.mod`
pins contracts no recorded platform was built with, when a recorded platform
never durably accepted a version the agent speaks, or when a recorded refusal
reads differently. Compatibility is claimed only with recorded platforms, for
what each was recorded doing, and with no earlier release of the agent, because
none exists.

## Working against a local contracts checkout

While a contract change is in progress, a `go.work` beside `go.mod` may `use` a
sibling checkout of the contracts. Git ignores it, and every `make` target runs
with `GOWORK=off`, so the gates always verify the published release `go.mod`
pins rather than the sibling.

## License

GPL-3.0. See [LICENSE](LICENSE).
