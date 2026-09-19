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
```

`seagull-agent -version` prints the build identity, which is the version Go
stamps from this repository's history, the toolchain and the platform, and then
the wire versions the build speaks. `go version -m` lists every module and build
setting that went into a binary. Both are metadata about a build, not proof of
which build is running.

## Running

`seagull-agent -config FILE run` starts the agent on the configuration held in
`FILE` and keeps it running until it receives SIGINT or SIGTERM. It logs to
stderr, and exits with 0 after a requested stop, 1 when it could not start, an
essential component failed or the stop overran its deadline, and 2 on a usage
error.

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

One component is composed: the configuration the agent holds, which reads the
file again whenever the agent is asked to. Collection, local admission, the
spool and delivery will each arrive as a component of its own.

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
refuses without starting the agent.

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
| `server.ingest_url` | — | an `https` URL, with no credentials and nothing to resolve |
| `server.renewal_url` | — | an `https` URL, for the platform's renewal listener |
| `server.trust_bundle` | — | an absolute path to PEM certificates |
| `transport.connect_timeout` | `10s` | `1s` to `1m` |
| `transport.request_timeout` | `30s` | `5s` to `10m`, never shorter than the connect timeout |
| `transport.max_batch_bytes` | `4MiB` | `64KiB` to `8MiB`, the recorded platform's request ceiling |
| `transport.max_response_bytes` | `64KiB` | `4KiB` to `1MiB` |
| `spool.max_bytes` | `512MiB` | `16MiB` to `64GiB`, and at least four batches |
| `spool.max_age` | `72h` | `1h` to `720h` |
| `modules` | `{}` | the collectors this build has, which are none |
| `resources.memory_limit` | `256MiB` | `64MiB` to `8GiB` |
| `resources.max_concurrent_collections` | `2` | 1 to 64 |
| `resources.max_concurrent_uploads` | `1` | 1 to 16 |
| `resources.shutdown_timeout` | `10s` | `1s` to `5m` |
| `logging.level` | `info` | `debug`, `info`, `warn` or `error` |
| `logging.format` | `json` | `json` or `text` |
| `updates.enabled` | `false` | `false`: this build installs no update |

The defaults are what a supported deployment reaches the recorded platform with.
Its ingest listener reads at most 8 MiB per request, and admits events up to
seven days old and inventory up to thirty, so a spool kept far beyond that keeps
records the platform will not take. `resources.memory_limit` is the target the
garbage collector works to, not a ceiling the kernel enforces: that one belongs
to the service the agent is installed as. None of the defaults turns a check off
or leaves a budget unlimited, and there is no setting that does either.

The file is the agent's instructions, so who may write it is who decides what
the agent does:

- the file and the directory that holds it belong to the account the agent runs
  as or to root, and neither their group nor anybody else may write them. They
  may be read by anyone: the settings are public;
- `server.trust_bundle` is read under the same rule, and has to hold
  certificates the agent can parse. Whoever changes it decides which platform
  the agent trusts, and the agent verifies against that bundle alone;
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
  `identity.state_directory`, `identity.key_provider`, `logging.format` and
  `resources.shutdown_timeout` take stopping the agent and starting it again.

What a setting does today follows what the agent has. `identity`, `logging` and
`resources.memory_limit` and `resources.shutdown_timeout` are in force: they
decide where the installation is opened, what the log says and what the agent
spends. `server`, `transport`, `spool` and the concurrency budgets are validated
here and take effect as the components that spend them arrive, so a deployment
is configured once rather than as each one lands. `modules` and
`updates.enabled` are the settings this build refuses outright: an agent that
accepted them would be promising collection it cannot do and updates it cannot
install.

## The installation

An installation is one agent installed on one machine, and
`identity.state_directory` names the directory that holds it. The first start in
a new or empty directory draws its `installation_id`, 122 random bits written as
a UUID; every later start reads the same one. It is never derived from the
hostname, an address, a MAC or a machine identifier, which stay observations
about the machine.

The installation is not the agent the platform knows. The platform issues a
certificate for an `agent_id` an operator registered, and once enrollment
activates a credential generation, `installation.json` records it: that agent,
the generation number, the `key_id` of its key and what the certificate says.
It holds no key, token or other secret, and a field it does not declare, such
as a key, makes the file damaged, so copying it or the agent's public settings
authenticates nothing. Each generation follows the active one by exactly one
and is issued to the same agent; enrolling as another agent takes a new
installation.

The state is the agent's alone:

- the directory and its files belong to the account the agent runs as and are
  closed to its group and to others, and the agent reads nothing that is not;
- a running agent holds the directory locked, so a second agent or a
  replacement on the same directory is refused, and the lock goes away however
  the agent ends;
- a write lands in a temporary file that is synced and renamed over
  `installation.json` before the directory is synced, and a start discards what
  an interrupted write left behind;
- whatever else the installation keeps, such as its keys, lives in a private
  directory of its own inside the state directory, which the installation holds
  under the same lock and closes when it is closed.

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
that admitted them, so a spool kept in the state directory is set aside with
that installation rather than handed to its replacement.

Packaging follows the same line: an uninstall leaves the state where it is, so
a reinstall is the same installation, and only a purge removes the directory,
after which the next start is a new installation.

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

At start, the agent opens `keys/` and, once the installation is enrolled, the
key of its active credential generation. When `keys/` or a key in it is
reachable by another account, or that key is missing or damaged, the agent logs
`agent_not_started` with a `recovery` and does not start, as for damaged
installation state. A key another account could read has to be treated as
exposed: revoke the certificate issued for it and replace the installation.
`agent_starting` names the provider in `key_provider` and says in
`key_exportable` whether a key can be read out of it; no log line carries a key.

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

## Boundaries

`tests/architecture` holds the repository boundaries as tests rather than as
conventions:

- no source file, whatever its build constraints, imports another Seagull
  repository except the contracts;
- the contracts are required at a published release, and no module is replaced;
- no submodule or committed workspace brings a sibling checkout into the build;
- ignore rules never hide a source file or a test fixture, and the local skills
  never reach Git;
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
  agent's own mistake, and like every other refusal it is no incompatibility.

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
bytes of every batch sent and of every answer. The suite fails when `go.mod`
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
