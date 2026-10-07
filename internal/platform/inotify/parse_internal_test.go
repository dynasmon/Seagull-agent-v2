//go:build linux

package inotify

import (
	"encoding/binary"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func event(watch int32, mask, cookie uint32, name string, padded int) []byte {
	held := make([]byte, header+padded)
	binary.NativeEndian.PutUint32(held, uint32(watch))
	binary.NativeEndian.PutUint32(held[4:], mask)
	binary.NativeEndian.PutUint32(held[8:], cookie)
	binary.NativeEndian.PutUint32(held[12:], uint32(padded))
	copy(held[header:], name)
	return held
}

func TestParseReadsWhatTheKernelQueued(t *testing.T) {
	buffer := slices.Concat(
		event(1, syscall.IN_CREATE|syscall.IN_ISDIR, 0, "sub", 16),
		event(2, syscall.IN_MOVED_FROM, 7, "a", 16),
		event(3, syscall.IN_MOVED_TO, 7, strings.Repeat("n", 255), 256),
		event(-1, syscall.IN_Q_OVERFLOW, 0, "", 0),
		event(4, syscall.IN_DELETE_SELF, 0, "", 0),
		event(4, syscall.IN_IGNORED, 0, "", 0),
	)
	events, err := parse(buffer)
	want := []Event{
		{Watch: 1, What: Created | OfDirectory, Name: "sub"},
		{Watch: 2, What: MovedFrom, Cookie: 7, Name: "a"},
		{Watch: 3, What: MovedTo, Cookie: 7, Name: strings.Repeat("n", 255)},
		{Watch: -1, What: Overflowed},
		{Watch: 4, What: SelfDeleted},
		{Watch: 4, What: Ignored},
	}
	if err != nil || !slices.Equal(events, want) {
		t.Fatalf("read %+v, %v", events, err)
	}
	if names := (Created | MovedTo | OfDirectory).Names(); !slices.Equal(names, []string{"created", "moved to", "of a directory"}) {
		t.Errorf("named %q", names)
	}
	for _, cut := range []int{1, header - 1, header + 1, len(buffer) - 1} {
		if events, err := parse(buffer[:cut]); err == nil {
			t.Errorf("%d bytes of events read as %+v", cut, events)
		}
	}
	if events, err := parse(event(1, syscall.IN_CREATE, 0, "x", maxName+16)); err == nil {
		t.Errorf("an event naming more than %d bytes read as %+v", maxName, events)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(event(1, syscall.IN_CREATE|syscall.IN_ISDIR, 0, "sub", 16))
	f.Add(slices.Concat(event(1, syscall.IN_MOVED_FROM, 7, "a", 16), event(2, syscall.IN_MOVED_TO, 7, "b", 16)))
	f.Add(event(-1, syscall.IN_Q_OVERFLOW, 0, "", 0))
	f.Add(event(3, syscall.IN_IGNORED, 0, "", 0)[:10])
	f.Add(event(3, syscall.IN_MODIFY, 0, "x\x00y", 16))
	f.Fuzz(func(t *testing.T, buffer []byte) {
		events, err := parse(buffer)
		if err == nil && len(buffer) > 0 && len(events) == 0 {
			t.Fatalf("%d bytes read as no event", len(buffer))
		}
		if len(events)*header > len(buffer) {
			t.Fatalf("%d bytes read as %d events", len(buffer), len(events))
		}
		for _, event := range events {
			if len(event.Name) > maxName || strings.ContainsRune(event.Name, 0) {
				t.Fatalf("read the name %q", event.Name)
			}
		}
	})
}
