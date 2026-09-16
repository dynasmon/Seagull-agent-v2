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

`seagull-agent -state DIR run` starts the agent on the installation held in
`DIR` and keeps it running until it receives SIGINT or SIGTERM. It logs JSON
lines to stderr, and exits with 0 after a requested stop, 1 when it could not
start, an essential component failed or the stop overran its deadline, and 2 on
a usage error.

`cmd/seagull-agent` is the composition root: it builds each component and hands
the enabled ones to `internal/runtime`, which owns their lifecycle.

- A component is a `Run(ctx)` call that returns once everything it started has
  stopped. Building one must start no work, so a component left out of the
  composition, such as a disabled one, never runs.
- Every component declares a failure policy. An optional component that fails
  is reported and the agent carries on without it; an essential one that fails,
  or stops before it is asked to, stops the agent.
- Stopping cancels every component and waits at most ten seconds for them. A
  component still running after that is named in the log, and the process
  exits rather than wait any longer.
- A panic is never recovered. It ends the process, because the goroutine that
  panicked may have left shared state inconsistent; durable state has to
  survive that just as it survives any other crash.

No component is composed yet: collection, local admission, the spool and
delivery will each arrive as a component of its own.

## The installation

An installation is one agent installed on one machine, and `-state` names the
directory that holds it. The first start in a new or empty directory draws its
`installation_id`, 122 random bits written as a UUID; every later start reads
the same one. It is never derived from the hostname, an address, a MAC or a
machine identifier, which stay observations about the machine.

The installation is not the agent the platform knows. The platform issues a
certificate for an `agent_id` an operator registered, and once enrollment
activates a credential generation, `installation.json` records it: that agent,
the generation number, the SHA-256 identifier of the key and what the
certificate says. It holds no key, token or other secret, and a field it does
not declare, such as a key, makes the file damaged, so copying it or the agent's
public settings authenticates nothing. Each generation follows the active one by
exactly one and is issued to the same agent; enrolling as another agent takes a
new installation.

The state is the agent's alone:

- the directory and its files belong to the account the agent runs as and are
  closed to its group and to others, and the agent reads nothing that is not;
- a running agent holds the directory locked, so a second agent or a
  replacement on the same directory is refused, and the lock goes away however
  the agent ends;
- a write lands in a temporary file that is synced and renamed over
  `installation.json` before the directory is synced, and a start discards what
  an interrupted write left behind.

When the state cannot be used, the agent does not start: it logs
`agent_not_started` with the reason and a `recovery`, and never creates a new
identity in its place. A damaged `installation.json`, or a directory that holds
something but no `installation.json`, is restored from a backup of this
installation or replaced; a state written by a newer agent is read by that
release or replaced; a state others can reach is made private again.

`seagull-agent -state DIR installation replace` is that replacement, made on
purpose while the agent is stopped. It keeps the previous `installation.json`
under `replaced/`, draws a new `installation_id` that names the one it replaces
whenever that one could be read, and leaves the new installation unenrolled.
Records belong to the installation that admitted them, so the spool, when it
arrives, must not hand a predecessor's backlog to its replacement.

Packaging follows the same line: an uninstall leaves the state where it is, so
a reinstall is the same installation, and only a purge removes the directory,
after which the next start is a new installation.

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
