// Package dsse is DSSE's pre-authentication encoding
// (https://github.com/secure-systems-lab/dsse), the bytes a signature over an
// envelope covers. The payload type is part of them, so a signature over one
// kind of payload cannot stand for any other the same key signs.
package dsse

import "strconv"

func PAE(payloadType string, payload []byte) []byte {
	encoded := make([]byte, 0, len(payloadType)+len(payload)+32)
	encoded = append(encoded, "DSSEv1 "...)
	encoded = strconv.AppendInt(encoded, int64(len(payloadType)), 10)
	encoded = append(encoded, ' ')
	encoded = append(encoded, payloadType...)
	encoded = append(encoded, ' ')
	encoded = strconv.AppendInt(encoded, int64(len(payload)), 10)
	encoded = append(encoded, ' ')
	return append(encoded, payload...)
}
