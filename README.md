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
  through `systemd-sysusers`;
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
| Account | `User=seagull-agent` and `Group=seagull-agent`, and no other group |
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
  account, no capability and `no_new_privs`, and `agent_resources` the
  ceilings, with nothing unenforced. A drop-in, `systemctl edit seagull-agent`,
  changes a ceiling for the next start, and the agent reports the new one, as a
  warning when `resources.memory_limit` is not below `MemoryMax`;
- `MemorySwapMax=0` keeps the agent's memory, and its key with it, off the swap
  device, on a kernel that accounts for swap;
- the agent logs to the journal: `journalctl -u seagull-agent`.

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
  versions as Go does; that the same commit gives the same bytes; and that the
  service, the account, the directories and the settings agree with one another
  and with the agent's defaults;
- `tests/native` is the native gate. On a host systemd runs, as root, it
  installs the package and takes it through its life against an emulated
  platform: install, check the settings and the platform as the account,
  enroll, start, renew a certificate valid for 30 seconds under the service's
  permissions, reload, stop, admit records to the spool as the account, start,
  kill the agent, upgrade to the next version, override a ceiling, remove,
  reinstall, purge and install again. At each step it checks what the agent
  reported, the account and the modes and owners of what it keeps, and after
  the upgrade and the removal that the installation and its backlog are the
  same bytes. CI runs it on Ubuntu 24.04 with `make native-gate`, which installs
  the package on the host it runs on, so it belongs on a disposable one.

What it does not claim:

- another distribution, an RPM, arm64, Windows or macOS. `make package
  ARCH=arm64` builds an arm64 package, and none of them is supported until its
  own native gate passes;
- confinement beyond the account: the service leaves the filesystem, the
  kernel's interfaces and the system calls as that account finds them;
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

Two components are composed: the configuration the agent holds, which reads the
file again whenever the agent is asked to, and, once the installation is
enrolled, the [renewal](#renewal) that keeps its credential current, which is
optional, so an agent whose renewal failed keeps collecting what it will deliver
once it holds a certificate again. The spool is not a component, since
it starts no work of its own: the agent opens it with the installation, reads
back what it holds before it starts, and closes it as it stops. Neither is the
governor, which bounds the expensive work of whoever asks it and starts none of
its own. Collection, local admission and delivery will each arrive as a
component of its own.

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
  }
}
```

That is a whole configuration: those settings are the deployment, so the agent
has no default to offer for them, and every other setting has one it documents
below. `seagull-agent -config FILE config print` prints what the agent would run
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
| `modules` | `{}` | the collectors this build has, which are none |
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
  `identity.state_directory`, `identity.key_provider`, `server.renewal_url`,
  `server.trust_bundle`, `logging.format` and `resources.shutdown_timeout` take
  stopping the agent and starting it again. The agent reads the authorities
  `server.trust_bundle` holds as it starts, so a bundle rewritten in place takes
  a restart too.

What a setting does today follows what the agent has. `identity`, `logging`,
`spool`, `resources`, `server`, `transport.connect_timeout`,
`transport.max_batch_bytes` and `transport.max_upload_bytes_per_second` are in
force: they decide where the installation is opened, what the log says, how
much the spool keeps and for how long, how large a record it takes, what the
agent and its expensive work may spend, which platform `platform check`
authenticates and how long it waits for it, which authorities a certificate the
agent imports has to chain to, and where, how long and how often the agent
renews its credential. The governor keeps the budgets for
scans and uploads before anything spends them, since no collector scans and
nothing delivers yet. The rest of `transport` is validated here and takes effect
as delivery arrives, so a deployment is configured once rather than as each
component lands. `modules` and `updates.enabled` are the settings this
build refuses outright: an agent that accepted them would be promising
collection it cannot do and updates it cannot install.

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
state, bounded, and is never a label.

The set of modules that should be collecting is applied whole: a name this build
does not have refuses the set, so nothing is half applied; a module the set
leaves out is cancelled, and the agent waits for it to return, so disabling a
collector releases what it held; and a module that spent its budget is started
once more when it is named again, because the budget bounds what the agent
retries on its own, not what an operator asks for. Stopping cancels every
module, and the collection names the ones that did not return rather than wait
for them. A panic inside a module is not recovered, as anywhere else in the
agent.

No collector exists yet, so the composition root composes no collection: the
first one arrives with the authentication collector, and until then the
configuration refuses every module named in `modules`.

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
| Collect | nothing yet: this build has no collector |

Nothing on that list needs the superuser, a Linux capability, or a helper of its
own. A collector that needs more — the authentication log will be the first —
names it there, and the packaging grants that much: a group where a group is
enough, and a capability only where it is not.

At start the agent reports what it actually may do as `agent_privileges`: the
account, the groups it belongs to, the capabilities it holds and whether
`no_new_privs` is set. A capability counts as held when it is permitted or
effective, since a permitted one can be raised into use. When the agent holds
anything the table above does not need, that line is a warning that names it: a
claim about privileges is about the process that is running, not about the one
the packaging intended.

The agent does not drop privileges itself. Go runs it on several threads and
Linux keeps a capability set for each of them, so a program that drops what it
holds part way through its life promises it for the thread that made the call
and no other. Bounding the process belongs to the service manager, before the
agent starts, and the service the package installs does it: it runs the agent
as an account of its own, with no capability and with `no_new_privs` set, as
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
- a failure the network or a busy platform explains, a lost connection, a 5xx
  or a 429, is retried after a minute, doubling up to an hour, each wait a fifth
  longer or shorter at random; a failure somebody has to act on, a refusal, a
  certificate the listener refused, a listener the agent cannot authenticate or
  an answer that does not verify, is retried every hour. Each is logged as
  `credential_not_renewed`, a warning or an error, with the attempt, the next
  one and a `recovery`, and the agent never enrolls itself again whatever the
  platform answers;
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
  revoked or decommissioned agent is replaced, never revived.

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
- the exchanges were recorded from the renewal handler of the recorded backend
  commit, served as its control plane serves it, with the agent's binary
  renewing its credential: keeping its key, rotating it, while the platform
  published its next authority, signed with it, retired the current one before
  and after moving its listener, and finally revoked the agent. The recording
  also shows the platform renewing a generation two renewals had replaced.
  `tests/compatibility` verifies every answer as the agent does, and checks
  which key each renewal asked with and which authorities each answer
  published.

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
| One batch | `transport.max_batch_bytes`, `transport.max_events_per_batch` and `transport.max_inventory_records_per_batch` | delivery, when it arrives |
| Uploads at once | `resources.max_concurrent_uploads` | the governor, for delivery when it arrives |
| Upload bandwidth | `transport.max_upload_bytes_per_second` | the governor, for delivery when it arrives |
| Scans | `resources.max_concurrent_scans`, `resources.max_scan_bytes_per_second` and the room left in the stream a scan admits to | the governor, for collectors when they arrive |
| Reading a source as it is written | the room admission leaves | collectors, when they arrive |

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
  it: the first one arrives with the authentication log;
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
Deciding which refusals are for good belongs to delivery.

Nothing is evicted. The spool never drops a record to make room for another: a
record leaves it undelivered only when it is counted as lost, expired or
quarantined, and each of those is reported and counted apart from what was
delivered, in the ledger, in `spool_opened` and in the spool's stats.

What the agent must still write is never refused for room: the spool keeps
64 KiB of its budget for its ledgers, and refuses a record that would leave the
filesystem it is on with less than 64 MiB free, so its acknowledgements, the
installation beside it and, once collectors keep their place there, their
checkpoints can still be written while records are refused. An acknowledgement
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
  agent presents it to renew it; delivery, which sends records, arrives with its
  own work;
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
- `ErrUnreachable`: the network, a timeout, or a listener that never finished
  the handshake;
- a reply, whatever its status: a refusal is an answer like any other, read
  whole up to `transport.max_response_bytes` or not at all, as
  `ErrReplyTooLarge`.

Being authenticated is not being admitted. Once the handshake is done, the
platform decides whether it still admits the agent its certificate names, and
`internal/protocol` reads that refusal as an `Exclusion`, apart from any refusal
of a record: a certificate naming no agent the platform reads
(`unauthenticated_agent`), an agent it never registered
(`agent_not_registered`), and one it no longer admits because it was revoked,
decommissioned or disabled (`agent_not_admitted`). An exclusion refuses no record, whatever record it
points at: every record stays as valid as it was, none is quarantined for it,
and none is sent as that agent until an operator acts. Delivery, when it
arrives, keeps to that.

What a request may take:

- connecting and the TLS handshake take at most `transport.connect_timeout`, and
  a whole request, from dialing to the end of the reply, at most
  `transport.request_timeout`;
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
  request; release a cancelled request and its connection, and every goroutine
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

## What the agent writes down

The agent holds one secret, the private key of its installation, and it reads
text it did not write: its configuration, its installation state, its trust
bundle, its key files, the certificates the platform issued it and what it finds
in its spool. `internal/secrets` is the
one place that decides what any of that may become in a log line, a refusal or a
message on the terminal.

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
  what looks like a secret. When collection arrives, each collector drops what
  its source holds before it is admitted, where the source is understood;
- the spool keeps records as admission hands them and never looks inside one,
  so what a record holds is decided before it is admitted: admission, which
  arrives with the first collector, reads the same rule. What the agent writes
  about a record is where it is in the spool, never what it holds.

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
- `internal/renewal` reads no configuration and reaches no collector, directly
  or through another package, and imports no TLS package itself: it is handed
  the listener, the authorities and the key lifetime it works with, and reaches
  the platform through the transport alone;
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
- `internal/transport` imports nothing of the agent but `internal/secrets`, and
  nothing of the contracts: it authenticates connections and moves bytes, while
  what they carry, whose records they are and where the credential it presents
  is kept belong to others;
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
certificate the platform refuses the agent of. Beside them are the exchanges of
[enrollment](#enrollment) and [renewal](#renewal), recorded from the control
plane of the same commit with the agent's own binary asking for, importing and
renewing the certificates, and the measurement of how long that commit takes to
carry a revocation to the roster its gateway follows. The suite fails when `go.mod`
pins contracts no recorded platform was built with, when a recorded platform
never durably accepted a version the agent speaks, or when a recorded refusal
reads differently. Compatibility is claimed only with recorded platforms, and
with no earlier release of the agent, because none exists.

## Working against a local contracts checkout

While a contract change is in progress, a `go.work` beside `go.mod` may `use` a
sibling checkout of the contracts. Git ignores it, and every `make` target runs
with `GOWORK=off`, so the gates always verify the published release `go.mod`
pins rather than the sibling.

## License

GPL-3.0. See [LICENSE](LICENSE).
