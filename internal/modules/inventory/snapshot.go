package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const (
	Name      = "inventory"
	Processes = "processes"
)

var (
	ErrUnsupported = errors.New("the agent does not take this kind of inventory on this host")
	ErrTooLarge    = errors.New("the platform takes no inventory record this large")
)

// A Snapshot is what the collector admits of one kind: the record, its bytes,
// and the digest of what it says of the host, which leaves out when it was
// taken and its name so that two snapshots of an unchanged host share it.
type Snapshot struct {
	Kind    string
	Record  *inventoryv1.Record
	Encoded []byte
	Digest  string
	Merged  []string
	Skipped int
}

func Kinds() []inventoryv1.Kind {
	listed := make([]inventoryv1.Kind, len(kinds))
	for i, held := range kinds {
		listed[i] = held.kind
	}
	return listed
}

func KindName(kind inventoryv1.Kind) string {
	return strings.ToLower(strings.TrimPrefix(kind.String(), "KIND_"))
}

// The module that takes a kind: what runs on the host is taken by a module of
// its own, as only an operator can let the agent see every process.
func moduleOf(kind inventoryv1.Kind) string {
	if kind == inventoryv1.Kind_KIND_PROCESS {
		return Processes
	}
	return Name
}

// Take reads one kind of what the host has and makes it a complete snapshot
// taken at the moment given, or says why it cannot: a host that does not hold
// the kind's source, an enumeration that failed, or a record the platform
// would refuse. A snapshot is never a part of the kind.
func Take(ctx context.Context, host Host, installation string, kind inventoryv1.Kind, at time.Time) (Snapshot, error) {
	index := slices.IndexFunc(kinds, func(held taker) bool { return held.kind == kind })
	if index < 0 {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrUnsupported, kind)
	}
	described := kinds[index]
	items, skipped, err := described.take(ctx, host)
	switch {
	case errors.Is(err, errors.ErrUnsupported), errors.Is(err, dpkg.ErrAbsent), errors.Is(err, services.ErrAbsent):
		return Snapshot{}, fmt.Errorf("%w: %w", ErrUnsupported, err)
	case err != nil:
		return Snapshot{}, err
	case len(items) > protocol.MaxInventoryItemsPerRecord:
		return Snapshot{}, fmt.Errorf("%w: the host holds %d of them, and the platform takes %d in one record", ErrTooLarge, len(items), protocol.MaxInventoryItemsPerRecord)
	}
	identities := make([]string, len(items))
	for i, item := range items {
		identities[i] = strings.Join(protocol.InventoryIdentity(kind, item), "\x00")
	}
	order := make([]int, len(items))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return strings.Compare(identities[a], identities[b]) })
	sorted := make([]*inventoryv1.Item, len(items))
	for i, from := range order {
		sorted[i] = items[from]
	}
	hostname, _ := host.Hostname()
	record := &inventoryv1.Record{
		RecordId:      identify(moduleOf(kind), installation, KindName(kind), at),
		SchemaVersion: protocol.InventorySchemaVersion,
		Kind:          kind,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(at),
		Origin:        &eventv1.Origin{Host: &eventv1.Host{Hostname: hostname, Os: runtime.GOOS, Architecture: runtime.GOARCH}},
		Collection:    &eventv1.Collection{Collector: moduleOf(kind), Source: described.source},
		Items:         sorted,
	}
	if err := protocol.CheckInventory(record); err != nil {
		return Snapshot{}, err
	}
	deterministic := proto.MarshalOptions{Deterministic: true}
	encoded, err := deterministic.Marshal(record)
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode what the host holds of %s: %w", KindName(kind), err)
	}
	if len(encoded) > protocol.MaxInventoryRecordBytes {
		return Snapshot{}, fmt.Errorf("%w: its %d items encode to %d bytes, and the platform carries %d", ErrTooLarge, len(sorted), len(encoded), protocol.MaxInventoryRecordBytes)
	}
	stated, err := deterministic.Marshal(&inventoryv1.Record{
		SchemaVersion: record.GetSchemaVersion(), Kind: kind, Mode: record.GetMode(), Origin: record.GetOrigin(), Collection: record.GetCollection(), Items: sorted,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode what the host holds of %s: %w", KindName(kind), err)
	}
	digest := sha256.Sum256(stated)
	return Snapshot{
		Kind:    KindName(kind),
		Record:  record,
		Encoded: encoded,
		Digest:  hex.EncodeToString(digest[:]),
		Merged:  merged(kind, sorted, identities, order),
		Skipped: skipped,
	}, nil
}

// merged names the items the platform would hold as one because they share
// the identity it derives, which it keeps one of, whichever it is.
func merged(kind inventoryv1.Kind, sorted []*inventoryv1.Item, identities []string, order []int) []string {
	var held []string
	for start := 0; start < len(sorted); {
		end := start + 1
		for end < len(sorted) && identities[order[end]] == identities[order[start]] {
			end++
		}
		if end-start > 1 {
			var names []string
			for _, item := range sorted[start:end] {
				names = append(names, secrets.Shown(called(item)))
			}
			parts := protocol.InventoryIdentity(kind, sorted[start])
			for i := range parts {
				parts[i] = secrets.Shown(parts[i])
			}
			held = append(held, fmt.Sprintf("%s %s: %s", KindName(kind), strings.Join(parts, " "), strings.Join(names, ", ")))
		}
		start = end
	}
	return held
}

func called(item *inventoryv1.Item) string {
	switch {
	case item.GetUser() != nil:
		return item.GetUser().GetName()
	case item.GetPackage() != nil:
		return item.GetPackage().GetName() + " " + item.GetPackage().GetVersion()
	case item.GetService() != nil:
		return item.GetService().GetName()
	case item.GetNetworkInterface() != nil:
		return item.GetNetworkInterface().GetName()
	}
	encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	return hex.EncodeToString(encoded[:min(len(encoded), 16)])
}

func identify(collector, installation, kind string, at time.Time) string {
	sum := sha256.Sum256(bytes.Join([][]byte{[]byte("seagull-agent/" + collector), []byte(installation), []byte(kind), []byte(at.UTC().Format(time.RFC3339Nano))}, []byte{0}))
	sum[6] = sum[6]&0x0f | 0x80
	sum[8] = sum[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
