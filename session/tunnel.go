// Package session — TunnelConn implements net.Conn over an encrypted QUIC stream.
//
// TunnelConn provides the pipe between an OS-level TCP connection (from the local
// SOCKS5/HTTP proxy) and a QUIC stream to the HiVoid server. Every Write call
// encrypts data with the session's AEAD cipher using a random nonce, and every
// Read call decrypts an incoming frame.
//
// Frame format on the tunnel stream (FrameData):
//
//	[Header: 6B][Nonce: 12B][Ciphertext: N+16B]
//
// where N is the plaintext length and 16 is the AEAD auth tag.
package session

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hivoid-org/hivoid-core/frames"
	"github.com/quic-go/quic-go"
)

const (
	// tunnelReadBufSize is the maximum plaintext chunk for a single Write call.
	// 128 KB keeps frame overhead low while allowing large data transfers.
	tunnelReadBufSize = 128 * 1024
	// nonceSize matches the AEAD nonce length (12 for both AES-GCM and ChaCha20-Poly1305).
	nonceSize = 12
	// frameHeaderSize duplicates frames.HeaderSize to avoid import in the fast path.
	frameHeaderSize = 6
)

// frameBufPool recycles write buffers: header(6) + nonce(12) + max ciphertext(128KB+16).
var frameBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, frameHeaderSize+nonceSize+tunnelReadBufSize+16)
		return &b
	},
}

// TunnelConn wraps a QUIC bidirectional stream, exposing a net.Conn interface
// with application-layer AEAD encryption/decryption.
type TunnelConn struct {
	stream *quic.Stream
	sess   *Session
	target string

	// Read-side: leftover plaintext from the last decrypted frame.
	rmu   sync.Mutex
	rbuf  []byte
	rdead time.Time

	// Write-side mutex prevents concurrent Writes from interleaving frames.
	wmu   sync.Mutex
	wdead time.Time

	closed chan struct{}
	once   sync.Once
}

// newTunnelConn constructs a TunnelConn over the given stream.
func newTunnelConn(stream *quic.Stream, sess *Session, target string) *TunnelConn {
	return &TunnelConn{
		stream: stream,
		sess:   sess,
		target: target,
		closed: make(chan struct{}),
	}
}

// Read decrypts the next frame from the tunnel stream and returns the plaintext.
// Partial reads are supported: leftover bytes are buffered and returned on the
// next call.
func (c *TunnelConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	// Serve from leftover buffer first
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}

	// Read the next encrypted frame from the stream
	plain, err := c.readFrame()
	if err != nil {
		return 0, err
	}

	n := copy(b, plain)
	if n < len(plain) {
		c.rbuf = plain[n:]
	}
	c.sess.TrafficRecv.Add(uint64(n)) // Track received traffic
	return n, nil
}

// readFrame reads one FrameData from the tunnel and returns the decrypted plaintext.
func (c *TunnelConn) readFrame() ([]byte, error) {
	f, err := frames.Decode(c.stream)
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("tunnel read frame: %w", err)
	}
	if f.Type != frames.FrameData {
		return nil, fmt.Errorf("tunnel: unexpected frame type 0x%02x", f.Type)
	}
	if len(f.Payload) < nonceSize {
		return nil, fmt.Errorf("tunnel frame payload too short: %d", len(f.Payload))
	}

	nonce := f.Payload[:nonceSize]
	ciphertext := f.Payload[nonceSize:]

	plain, err := c.sess.DecryptForTunnel(nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("tunnel decrypt: %w", err)
	}
	return plain, nil
}

// Write encrypts plaintext and writes it as one or more FrameData frames.
// Large writes are chunked to tunnelReadBufSize bytes per frame.
// Uses a pooled buffer and writes each frame fully even if the stream performs
// short writes under backpressure.
func (c *TunnelConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > tunnelReadBufSize {
			chunk = chunk[:tunnelReadBufSize]
		}

		nonce, ciphertext, err := c.sess.EncryptForTunnel(chunk)
		if err != nil {
			return total, fmt.Errorf("tunnel encrypt: %w", err)
		}

		// Pack header + nonce + ciphertext into ONE pooled buffer → ONE Write.
		// Wire format: [type:1][flags:1][length:4][nonce:12][ciphertext:N]
		payloadLen := nonceSize + len(ciphertext)
		frameLen := frameHeaderSize + payloadLen

		bufp := frameBufPool.Get().(*[]byte)
		buf := (*bufp)[:frameLen]

		buf[0] = 0x01 // FrameData
		buf[1] = 0x01 // FlagEncrypted
		binary.BigEndian.PutUint32(buf[2:6], uint32(payloadLen))
		copy(buf[frameHeaderSize:frameHeaderSize+nonceSize], nonce)
		copy(buf[frameHeaderSize+nonceSize:], ciphertext)

		_, writeErr := writeFull(c.stream, buf)
		frameBufPool.Put(bufp)
		if writeErr != nil {
			return total, fmt.Errorf("tunnel write frame: %w", writeErr)
		}

		total += len(chunk)
		b = b[len(chunk):]
	}
	c.sess.TrafficSent.Add(uint64(total)) // Track sent traffic
	return total, nil
}

// CloseWrite closes only the write side of the tunnel (sends QUIC FIN).
// The read side remains open so the peer can finish sending.
func (c *TunnelConn) CloseWrite() error {
	return c.stream.Close()
}

// Close fully shuts down the tunnel stream.
func (c *TunnelConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		c.stream.CancelRead(quic.StreamErrorCode(0))
		err = c.stream.Close()
	})
	return err
}

// LocalAddr returns a placeholder local address.
func (c *TunnelConn) LocalAddr() net.Addr {
	return quicAddr{c.sess.conn.LocalAddr()}
}

// RemoteAddr returns the target address of this tunnel.
func (c *TunnelConn) RemoteAddr() net.Addr {
	return quicAddr{c.sess.conn.RemoteAddr()}
}

// SetDeadline sets both read and write deadlines.
func (c *TunnelConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *TunnelConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *TunnelConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// SendProxyOkToStream writes a success ProxyResponse directly to the stream.
// This is called by the server forwarder before entering data relay mode.
func SendProxyOkToStream(stream *quic.Stream) error {
	resp := frames.ProxyResponse{Success: true}
	f := &frames.Frame{Type: frames.FrameProxy, Payload: resp.Encode()}
	_, err := f.WriteTo(stream)
	return err
}

// SendProxyErrToStream writes a failure ProxyResponse to the stream.
func SendProxyErrToStream(stream *quic.Stream, msg string) {
	resp := frames.ProxyResponse{Success: false, ErrMsg: msg}
	f := &frames.Frame{Type: frames.FrameProxy, Payload: resp.Encode()}
	_, _ = f.WriteTo(stream)
}

// quicAddr wraps a net.Addr to satisfy the net.Addr interface.
type quicAddr struct{ net.Addr }

// RawStream returns the underlying QUIC stream for low-level access by the forwarder.
func (c *TunnelConn) RawStream() *quic.Stream { return c.stream }

// tunnelPayloadSize computes the binary-encoded size of a frame with given payload.
func tunnelPayloadSize(payloadLen int) int {
	return tunnelLengthFieldSize + payloadLen
}

const tunnelLengthFieldSize = 4 // uint32 big-endian length field in frame header

// writeTunnelLength writes a uint32 length prefix — used by the raw relay path.
func writeTunnelLength(w io.Writer, n uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], n)
	_, err := writeFull(w, buf[:])
	return err
}

// readTunnelLength reads a uint32 length prefix.
func readTunnelLength(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

func writeFull(w io.Writer, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
