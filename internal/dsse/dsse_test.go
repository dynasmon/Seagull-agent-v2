package dsse_test

import (
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
)

func TestPAEIsTheEncodingDSSESigns(t *testing.T) {
	if encoded := dsse.PAE("http://example.com/HelloWorld", []byte("hello world")); string(encoded) != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("the pre-authentication encoding is %q", encoded)
	}
}

func TestAnEmptyPayloadIsStillEncodedWithItsLength(t *testing.T) {
	if encoded := dsse.PAE("t", nil); string(encoded) != "DSSEv1 1 t 0 " {
		t.Fatalf("the pre-authentication encoding of nothing is %q", encoded)
	}
}
