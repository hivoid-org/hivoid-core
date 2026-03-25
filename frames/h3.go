package frames

import (
	"bytes"
	"encoding/binary"
	"io"
)

// H3 Frame Types
const (
	H3FrameData     = 0x00
	H3FrameHeaders  = 0x01
	H3FrameSettings = 0x04
)

// H3 Settings IDs
const (
	H3SettingMaxFieldSectionSize     = 0x06
	H3SettingEnableConnectProtocol   = 0x08
	H3SettingH3Datagram             = 0x33
	H3SettingEnableWebTransport      = 0x2b603742 // RFC draft-ietf-webtrans-http3
)

// EncodeH3Frame header (type + length)
func EncodeH3Frame(t uint64, length uint64) []byte {
	buf := make([]byte, 16)
	n1 := putVarint(buf, t)
	n2 := putVarint(buf[n1:], length)
	return buf[:n1+n2]
}

// EncodeH3Settings builds a standard HTTP/3 Settings frame for MASQUE.
func EncodeH3Settings() []byte {
	var body bytes.Buffer
	// Enable CONNECT protocol (RFC 8441 / RFC 9298)
	writeSetting(&body, H3SettingEnableConnectProtocol, 1)
	// Enable Datagrams (RFC 9297)
	writeSetting(&body, H3SettingH3Datagram, 1)
	// Enable WebTransport (RFC draft)
	writeSetting(&body, H3SettingEnableWebTransport, 1)
	
	header := EncodeH3Frame(H3FrameSettings, uint64(body.Len()))
	return append(header, body.Bytes()...)
}

// EncodeMasqueRequest builds a minimal H3 HEADERS frame for CONNECT-UDP.
// Highly optimized for stealth without a full QPACK implementation.
func EncodeMasqueRequest(authority string) []byte {
	// Minimal pseudo-QPACK for CONNECT-UDP:
	// We use Literal Headers with Name Reference (indexing existing pseudo-headers)
	var body bytes.Buffer
	body.WriteByte(0x00) // Required QPACK prefix (Instruction Byte)
	
	// :method: CONNECT
	body.Write([]byte{0xd1}) // Indexed Header Field (pseudo-header :method: CONNECT is 17 in static table)
	// :protocol: connect-udp (RFC 9298)
	writeLiteralHeader(&body, ":protocol", "connect-udp")
	// :scheme: https
	body.Write([]byte{0xc7}) // Static :scheme: https (15)
	// :path: /
	body.Write([]byte{0xc1}) // Static :path: / (1)
	// :authority: <server>
	writeLiteralHeader(&body, ":authority", authority)

	header := EncodeH3Frame(H3FrameHeaders, uint64(body.Len()))
	return append(header, body.Bytes()...)
}

// EncodeMasqueResponse builds a 200 OK H3 response.
func EncodeMasqueResponse() []byte {
	var body bytes.Buffer
	body.WriteByte(0x00)
	body.Write([]byte{0xd9}) // :status: 200 (Static 25)
	
	header := EncodeH3Frame(H3FrameHeaders, uint64(body.Len()))
	return append(header, body.Bytes()...)
}

// EncodeWebTransportRequest builds a minimal H3 HEADERS frame for WebTransport CONNECT.
func EncodeWebTransportRequest(authority string) []byte {
	var body bytes.Buffer
	body.WriteByte(0x00) 
	
	// :method: CONNECT
	body.Write([]byte{0xd1}) 
	// :protocol: webtransport
	writeLiteralHeader(&body, ":protocol", "webtransport")
	// :scheme: https
	body.Write([]byte{0xc7}) 
	// :path: /
	body.Write([]byte{0xc1}) 
	// :authority: <server>
	writeLiteralHeader(&body, ":authority", authority)

	header := EncodeH3Frame(H3FrameHeaders, uint64(body.Len()))
	return append(header, body.Bytes()...)
}

func writeSetting(w io.Writer, id uint64, val uint64) {
	buf := make([]byte, 16)
	n1 := putVarint(buf, id)
	n2 := putVarint(buf[n1:], val)
	_, _ = w.Write(buf[:n1+n2])
}

func writeLiteralHeader(w io.Writer, name, value string) {
	// Minimal QPACK literal: 
	// 0x20 = Literal Header Field with Incremental Indexing (Name Index=0, for Custom Names)
	// But let's use 0x00 prefix for Literal Header Field without Indexing.
	w.Write([]byte{0x00}) 
	writeH3String(w, name)
	writeH3String(w, value)
}

func writeH3String(w io.Writer, s string) {
	buf := make([]byte, 8)
	n := putVarint(buf, uint64(len(s)))
	_, _ = w.Write(buf[:n])
	_, _ = w.Write([]byte(s))
}

// putVarint encodes a QUIC-style variable length integer.
func putVarint(b []byte, v uint64) int {
	if v <= 63 {
		b[0] = byte(v)
		return 1
	} else if v <= 16383 {
		binary.BigEndian.PutUint16(b, uint16(v)|0x4000)
		return 2
	} else if v <= 1073741823 {
		binary.BigEndian.PutUint32(b, uint32(v)|0x80000000)
		return 4
	} else {
		binary.BigEndian.PutUint64(b, v|0xc000000000000000)
		return 8
	}
}

// ReadH3Frame reads and verifies an H3 frame header from a stream.
func ReadH3Frame(r io.Reader) (uint64, uint64, error) {
	t, err := ReadVarint(r)
	if err != nil {
		return 0, 0, err
	}
	l, err := ReadVarint(r)
	if err != nil {
		return 0, 0, err
	}
	return t, l, nil
}

// ReadVarint reads a QUIC-style variable length integer from an io.Reader.
func ReadVarint(r io.Reader) (uint64, error) {
	first, err := readByte(r)
	if err != nil {
		return 0, err
	}
	length := 1 << (first >> 6)
	v := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		b, err := readByte(r)
		if err != nil {
			return 0, err
		}
		v = (v << 8) | uint64(b)
	}
	return v, nil
}

func readByte(r io.Reader) (byte, error) {
	b := []byte{0}
	_, err := io.ReadFull(r, b)
	return b[0], err
}
