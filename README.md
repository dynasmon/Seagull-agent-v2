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
file again whenever the agent is asked to. The spool is not a component, since
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

What a setting does today follows what the agent has. `identity`, `logging`,
`spool`, `resources`, `transport.max_batch_bytes` and
`transport.max_upload_bytes_per_second` are in force: they decide where the
installation is opened, what the log says, how much the spool keeps and for how
long, how large a record it takes, and what the agent and its expensive work
may spend. The governor keeps the budgets for scans and uploads before anything
spends them, since no collector scans and nothing delivers yet. `server` and the
rest of `transport` are validated here and take effect as the components that
spend them arrive, so a deployment is configured once rather than as each one
lands. `modules` and `updates.enabled` are the settings this
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
agent starts, and the unit that does it arrives with the packaging.

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
- whatever else the installation keeps, such as its keys and its spool, lives
  in a private directory of its own inside the state directory, which the
  installation holds under the same lock and closes when it is closed.

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
enforced.

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

## What the agent writes down

The agent holds one secret, the private key of its installation, and it reads
text it did not write: its configuration, its installation state, its trust
bundle, its key files and what it finds in its spool. `internal/secrets` is the
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
- memory is not locked, so a host that swaps may write a key to its swap
  device. Encrypting that device belongs to the deployment;
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
- `internal/secrets`, which decides what a message may carry of what the agent
  read, imports nothing of the agent, nothing of the contracts and neither `os`
  nor `net`: what may be written down is a question about text;
- `internal/spool` reads no contract, reaches no network, holds no key and opens
  neither the installation nor the configuration: it keeps records as the bytes
  admission hands it, in the directory and within the budget it is given;
- `internal/governor` imports nothing of the agent and nothing of the contracts,
  and reaches no network: it bounds work and knows none of it, so what a scan
  reads, what an upload carries and how it travels stay with the work;
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
