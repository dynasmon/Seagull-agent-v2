package spool

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
)

const (
	segmentFormat      = 1
	segmentHeaderBytes = 20
	frameHeaderBytes   = 32
	sectorBytes        = 512
	chunkBytes         = 64 << 10
	maxSequence        = 1 << 62
)

var (
	segmentMagic = []byte("SGSG")
	frameMagic   = []byte("SR")
	castagnoli   = crc32.MakeTable(crc32.Castagnoli)
)

func checksum(content []byte) uint32 { return crc32.Checksum(content, castagnoli) }

func encodeSegmentHeader(stream Stream, first uint64) []byte {
	header := make([]byte, 0, segmentHeaderBytes)
	header = append(header, segmentMagic...)
	header = binary.LittleEndian.AppendUint16(header, segmentFormat)
	header = append(header, byte(stream), 0)
	header = binary.LittleEndian.AppendUint64(header, first)
	return binary.LittleEndian.AppendUint32(header, checksum(header))
}

type segmentHeader struct {
	format uint16
	stream Stream
	first  uint64
}

// A newer format may lay out the rest of its header differently, so the magic
// and the format are all this build reads of one before it refuses it.
func decodeSegmentHeader(header []byte) (segmentHeader, bool) {
	if len(header) < segmentHeaderBytes || !bytes.Equal(header[:len(segmentMagic)], segmentMagic) {
		return segmentHeader{}, false
	}
	described := segmentHeader{
		format: binary.LittleEndian.Uint16(header[4:]),
		stream: Stream(header[6]),
		first:  binary.LittleEndian.Uint64(header[8:]),
	}
	switch {
	case described.format > segmentFormat:
		return described, true
	case described.format != segmentFormat || header[7] != 0:
		return segmentHeader{}, false
	case binary.LittleEndian.Uint32(header[16:]) != checksum(header[:16]):
		return segmentHeader{}, false
	}
	return described, true
}

type frame struct {
	offset   int64
	sequence uint64
	admitted int64
	idBytes  int
	payload  int
	sum      uint32
}

func (f frame) size() int64 { return frameHeaderBytes + int64(f.idBytes) + int64(f.payload) }

func encodeFrameHeader(stream Stream, sequence uint64, admitted int64, id string, payload []byte) []byte {
	header := make([]byte, 0, frameHeaderBytes)
	header = append(header, frameMagic...)
	header = append(header, byte(stream), byte(len(id)))
	header = binary.LittleEndian.AppendUint32(header, uint32(len(payload)))
	header = binary.LittleEndian.AppendUint64(header, sequence)
	header = binary.LittleEndian.AppendUint64(header, uint64(admitted))
	header = binary.LittleEndian.AppendUint32(header, crc32.Update(checksum([]byte(id)), castagnoli, payload))
	return binary.LittleEndian.AppendUint32(header, checksum(header))
}

func decodeFrameHeader(stream Stream, header []byte, offset int64) (frame, bool) {
	if !bytes.Equal(header[:len(frameMagic)], frameMagic) || header[2] != byte(stream) ||
		binary.LittleEndian.Uint32(header[28:]) != checksum(header[:28]) {
		return frame{}, false
	}
	found := frame{
		offset:   offset,
		sequence: binary.LittleEndian.Uint64(header[8:]),
		admitted: int64(binary.LittleEndian.Uint64(header[16:])),
		idBytes:  int(header[3]),
		payload:  int(binary.LittleEndian.Uint32(header[4:])),
		sum:      binary.LittleEndian.Uint32(header[24:]),
	}
	if found.sequence == 0 || found.sequence > maxSequence || found.idBytes == 0 || found.payload == 0 || found.payload > MaxPayloadBytes {
		return frame{}, false
	}
	return found, true
}

// A walk reads the frames of one segment in order and steps over whatever does
// not verify, so damage costs the records it touched and never the ones after
// it. headed is the highest sequence among the frames it stepped over whose
// header verified, which is all that is known of records that did not.
type walk struct {
	file   io.ReaderAt
	stream Stream
	at     int64
	end    int64
	buffer []byte
	headed uint64
}

func newWalk(file io.ReaderAt, stream Stream, at, end int64, buffer []byte) *walk {
	return &walk{file: file, stream: stream, at: at, end: end, buffer: buffer}
}

type reading int

const (
	verified reading = iota
	headerOnly
	kept
)

func (w *walk) next(mode func(frame) reading) (frame, []byte, int64, error) {
	start := w.at
	w.headed = 0
	for w.at < w.end {
		found, ok, err := w.header()
		if err != nil {
			return frame{}, nil, 0, err
		}
		if !ok {
			if err := w.seek(); err != nil {
				return frame{}, nil, 0, err
			}
			continue
		}
		if found.size() > w.end-w.at {
			w.headed = max(w.headed, found.sequence)
			w.at = w.end
			break
		}
		read := verified
		if mode != nil {
			read = mode(found)
		}
		var body []byte
		valid := true
		if read != headerOnly {
			if body, valid, err = w.body(found, read == kept); err != nil {
				return frame{}, nil, 0, err
			}
		}
		w.at += found.size()
		if !valid {
			w.headed = max(w.headed, found.sequence)
			continue
		}
		return found, body, found.offset - start, nil
	}
	return frame{}, nil, w.end - start, io.EOF
}

func (w *walk) header() (frame, bool, error) {
	if w.end-w.at < frameHeaderBytes {
		return frame{}, false, nil
	}
	header := w.buffer[:frameHeaderBytes]
	if _, err := w.file.ReadAt(header, w.at); err != nil {
		return frame{}, false, err
	}
	found, ok := decodeFrameHeader(w.stream, header, w.at)
	return found, ok, nil
}

func (w *walk) body(found frame, keep bool) ([]byte, bool, error) {
	at, length := found.offset+frameHeaderBytes, int64(found.idBytes+found.payload)
	if keep {
		body := make([]byte, length)
		if _, err := w.file.ReadAt(body, at); err != nil {
			return nil, false, err
		}
		return body, checksum(body) == found.sum, nil
	}
	var sum uint32
	for length > 0 {
		chunk := w.buffer[:min(int64(len(w.buffer)), length)]
		if _, err := w.file.ReadAt(chunk, at); err != nil {
			return nil, false, err
		}
		sum = crc32.Update(sum, castagnoli, chunk)
		at, length = at+int64(len(chunk)), length-int64(len(chunk))
	}
	return nil, sum == found.sum, nil
}

func (w *walk) seek() error {
	from := w.at + 1
	for w.end-from >= int64(len(frameMagic)) {
		chunk := w.buffer[:min(int64(len(w.buffer)), w.end-from)]
		if _, err := w.file.ReadAt(chunk, from); err != nil {
			return err
		}
		if found := bytes.Index(chunk, frameMagic); found >= 0 {
			w.at = from + int64(found)
			return nil
		}
		from += int64(len(chunk) - len(frameMagic) + 1)
	}
	w.at = w.end
	return nil
}

// An interrupted write leaves the end of what it wrote missing: a frame cut
// short, or sectors the disk never wrote, which read back as zeros. Bytes that
// hold neither are damage to something that was once written whole.
func torn(file io.ReaderAt, stream Stream, from, end int64, buffer []byte) (bool, error) {
	if end-from < frameHeaderBytes {
		return true, nil
	}
	header := buffer[:frameHeaderBytes]
	if _, err := file.ReadAt(header, from); err != nil {
		return false, err
	}
	limit := end
	if found, ok := decodeFrameHeader(stream, header, from); ok {
		if found.size() > end-from {
			return true, nil
		}
		limit = from + found.size()
	}
	for at := (from + sectorBytes - 1) / sectorBytes * sectorBytes; at+sectorBytes <= limit; {
		chunk := buffer[:min((limit-at)/sectorBytes*sectorBytes, int64(len(buffer)))]
		if _, err := file.ReadAt(chunk, at); err != nil {
			return false, err
		}
		for sector := 0; sector < len(chunk); sector += sectorBytes {
			if zeroed(chunk[sector : sector+sectorBytes]) {
				return true, nil
			}
		}
		at += int64(len(chunk))
	}
	return false, nil
}

func zeroed(content []byte) bool {
	for _, held := range content {
		if held != 0 {
			return false
		}
	}
	return true
}
