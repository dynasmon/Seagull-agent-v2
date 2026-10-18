package protocol

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// What the platform answers a request with holds a handful of values: a
// newer platform may add some, and none answers with a thousand.
const MaxAnswerValues = 1 << 10

var (
	ErrExcessive = errors.New("the message holds more values than the agent decodes of it")
	errOverspent = errors.New("overspent")
)

// Decode reads content into message once a walk of its wire form, which
// decodes nothing, found at most most values in it: each field written, each
// element of a packed list and each message nested in it counts as one.
// Decoding a message costs memory for every value it holds rather than for
// every byte, so a short message of many empty values is refused before any
// of it is decoded.
func Decode(content []byte, message proto.Message, most int) error {
	left := most
	err := count(content, message.ProtoReflect().Descriptor(), &left, protowire.DefaultRecursionLimit)
	switch {
	case errors.Is(err, errOverspent):
		return fmt.Errorf("%w: it holds more than %d", ErrExcessive, most)
	case err != nil:
		return err
	}
	return proto.Unmarshal(content, message)
}

func count(content []byte, descriptor protoreflect.MessageDescriptor, left *int, depth int) error {
	if depth == 0 {
		return fmt.Errorf("%w: its messages nest deeper than %d", ErrExcessive, protowire.DefaultRecursionLimit)
	}
	fields := descriptor.Fields()
	for len(content) > 0 {
		number, kind, read := protowire.ConsumeTag(content)
		if read < 0 {
			return protowire.ParseError(read)
		}
		content = content[read:]
		var value []byte
		if kind == protowire.BytesType {
			value, read = protowire.ConsumeBytes(content)
		} else {
			read = protowire.ConsumeFieldValue(number, kind, content)
		}
		if read < 0 {
			return protowire.ParseError(read)
		}
		content = content[read:]
		field := fields.ByNumber(number)
		if *left -= elements(field, kind, value); *left < 0 {
			return errOverspent
		}
		if field != nil && kind == protowire.BytesType && field.Message() != nil {
			if err := count(value, field.Message(), left, depth-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func elements(field protoreflect.FieldDescriptor, kind protowire.Type, value []byte) int {
	if field == nil || !field.IsList() || kind != protowire.BytesType {
		return 1
	}
	switch field.Kind() {
	case protoreflect.BoolKind, protoreflect.EnumKind, protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Uint32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		ended := 0
		for _, octet := range value {
			if octet < 0x80 {
				ended++
			}
		}
		return max(ended, 1)
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return max(len(value)/4, 1)
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return max(len(value)/8, 1)
	}
	return 1
}
