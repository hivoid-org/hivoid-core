//go:build android

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hivoid-org/hivoid-core/utils"
	"go.uber.org/zap"
)

const (
	protoTCP = 0x06
	protoUDP = 0x11
	mtu      = 1500
)

// dnsCache: IP → hostname از DNS responses
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]string
}

var globalDNSCache = &dnsCache{entries: make(map[string]string)}

func (c *dnsCache) set(ip, hostname string) {
	if ip == "" || hostname == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = hostname
}

func (c *dnsCache) get(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.entries[ip]
	return h, ok
}

type tunEngine struct {
	fd        int
	file      *os.File
	socksAddr string
	dnsAddr   string
	conns     sync.Map
	writeMu   sync.Mutex
}

type fourTuple struct {
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
}

func runTunForwarder(tunFD int, socksPort, dnsPort int) {
	file := os.NewFile(uintptr(tunFD), "/dev/tun")
	if file == nil {
		utils.Logger.Error("TUN: failed to open fd")
		return
	}

	engine := &tunEngine{
		fd:        tunFD,
		file:      file,
		socksAddr: fmt.Sprintf("127.0.0.1:%d", socksPort),
		dnsAddr:   fmt.Sprintf("127.0.0.1:%d", dnsPort),
	}

	utils.Logger.Info("TUN engine started",
		zap.Int("fd", tunFD),
		zap.String("socks", engine.socksAddr),
		zap.String("dns", engine.dnsAddr))

	packet := make([]byte, mtu)
	for {
		n, err := file.Read(packet)
		if err != nil {
			utils.Logger.Error("TUN read error", zap.Error(err))
			break
		}
		pkt := make([]byte, n)
		copy(pkt, packet[:n])
		go engine.handlePacket(pkt)
	}
}

func (e *tunEngine) writeTUN(packet []byte) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if _, err := e.file.Write(packet); err != nil {
		utils.Logger.Warn("TUN write error", zap.Error(err))
	}
}

func (e *tunEngine) handlePacket(packet []byte) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	proto := packet[9]
	headerLen := int(packet[0]&0x0F) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return
	}

	k := fourTuple{}
	copy(k.srcIP[:], packet[12:16])
	copy(k.dstIP[:], packet[16:20])

	switch proto {
	case protoUDP:
		if len(packet) < headerLen+8 {
			return
		}
		k.srcPort = binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
		k.dstPort = binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
		payload := make([]byte, len(packet[headerLen+8:]))
		copy(payload, packet[headerLen+8:])
		go e.handleUDP(k, payload)

	case protoTCP:
		if len(packet) < headerLen+20 {
			return
		}
		k.srcPort = binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
		k.dstPort = binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
		seg := make([]byte, len(packet[headerLen:]))
		copy(seg, packet[headerLen:])
		e.handleTCP(k, seg)
	}
}

// ── UDP / DNS ─────────────────────────────────────────────────────

func (e *tunEngine) handleUDP(k fourTuple, payload []byte) {
	isDNS := k.dstPort == 53
	target := fmt.Sprintf("%s:%d", net.IP(k.dstIP[:]).String(), k.dstPort)
	if isDNS {
		target = e.dnsAddr
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { InternalProtectSocket(int(fd)) })
		},
	}

	maxAttempts := 1
	if isDNS {
		maxAttempts = 3
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		conn, err := dialer.Dial("udp", target)
		if err != nil {
			continue
		}
		conn.Write(payload)
		resp := make([]byte, mtu)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(resp)
		conn.Close()
		if err != nil {
			continue
		}
		if isDNS {
			parseDNSAndCache(resp[:n])
		}
		e.writeUDPResponse(k, resp[:n])
		return
	}
}

// parseDNSAndCache: A record های DNS response رو cache میکنه
func parseDNSAndCache(data []byte) {
	if len(data) < 12 {
		return
	}
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	if anCount == 0 {
		return
	}
	offset := 12
	// skip question section
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	for i := 0; i < qdCount && offset < len(data); i++ {
		_, offset = dnsName(data, offset)
		offset += 4
	}
	// parse answers
	for i := 0; i < anCount && offset < len(data); i++ {
		hostname, newOffset := dnsName(data, offset)
		offset = newOffset
		if offset+10 > len(data) {
			return
		}
		rType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(data) {
			return
		}
		if rType == 1 && rdLen == 4 { // A record
			ip := net.IP(data[offset : offset+4]).String()
			// hostname ممکنه trailing dot داشته باشه
			host := strings.TrimSuffix(hostname, ".")
			if host != "" && ip != "" {
				globalDNSCache.set(ip, host)
			}
		}
		offset += rdLen
	}
}

func dnsName(data []byte, offset int) (string, int) {
	var parts []string
	for {
		if offset >= len(data) {
			break
		}
		l := int(data[offset])
		if l == 0 {
			offset++
			break
		}
		if l&0xC0 == 0xC0 { // pointer
			if offset+1 >= len(data) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			offset += 2
			name, _ := dnsName(data, ptr)
			if name != "" {
				parts = append(parts, name)
			}
			return strings.Join(parts, "."), offset
		}
		offset++
		if offset+l > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+l]))
		offset += l
	}
	return strings.Join(parts, "."), offset
}

func (e *tunEngine) writeUDPResponse(k fourTuple, payload []byte) {
	totalLen := 20 + 8 + len(payload)
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], uint16(rand.Uint32()))
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = protoUDP
	copy(packet[12:16], k.dstIP[:])
	copy(packet[16:20], k.srcIP[:])
	binary.BigEndian.PutUint16(packet[10:12], ipCksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], k.dstPort)
	binary.BigEndian.PutUint16(packet[22:24], k.srcPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(packet[26:28], 0)
	copy(packet[28:], payload)
	e.writeTUN(packet)
}

// ── TCP ───────────────────────────────────────────────────────────

type tcpConn struct {
	engine  *tunEngine
	tuple   fourTuple
	remote  net.Conn
	seq     uint32
	ack     uint32
	mu      sync.Mutex
	// buffer اولین bytes داده رو نگه میداره تا SNI استخراج بشه
	buf     []byte
	target  string
	dialing bool
}

func (e *tunEngine) handleTCP(k fourTuple, segment []byte) {
	if len(segment) < 20 {
		return
	}
	flags := segment[13]
	val, ok := e.conns.Load(k)

	if flags&0x02 != 0 { // SYN
		if ok {
			val.(*tcpConn).remote.Close()
			e.conns.Delete(k)
		}

		dstIP := net.IP(k.dstIP[:]).String()
		target := fmt.Sprintf("%s:%d", dstIP, k.dstPort)

		// اول DNS cache چک کن
		if hostname, found := globalDNSCache.get(dstIP); found {
			target = fmt.Sprintf("%s:%d", hostname, k.dstPort)
		}

		if k.dstPort == 53 {
			target = e.dnsAddr
		}

		c := &tcpConn{
			engine: e,
			tuple:  k,
			seq:    rand.Uint32(),
			ack:    binary.BigEndian.Uint32(segment[4:8]) + 1,
			target: target,
		}

		// برای HTTPS (port 443)، اگه hostname از cache نداشتیم،
		// اول SYN-ACK بده، صبر کن ClientHello بیاد، SNI رو بخون
		if k.dstPort == 443 {
			if _, hasHostname := globalDNSCache.get(dstIP); !hasHostname {
				c.dialing = true // pending — منتظر داده
			}
		}

		e.conns.Store(k, c)
		e.writeTCPResponse(k, c.seq, c.ack, 0x12) // SYN-ACK
		c.seq++

		if !c.dialing {
			// hostname داریم، مستقیم dial کن
			remote, err := e.dialSOCKS5(target)
			if err != nil {
				e.conns.Delete(k)
				return
			}
			c.mu.Lock()
			c.remote = remote
			c.mu.Unlock()
			go c.pumpRemote()
		}
		return
	}

	if !ok {
		return
	}
	c := val.(*tcpConn)

	if flags&0x04 != 0 { // RST
		if c.remote != nil {
			c.remote.Close()
		}
		e.conns.Delete(k)
		return
	}

	if flags&0x01 != 0 { // FIN
		if c.remote != nil {
			c.remote.Close()
		}
		e.conns.Delete(k)
		e.writeTCPResponse(k, c.seq, binary.BigEndian.Uint32(segment[4:8])+1, 0x11)
		return
	}

	tcpHL := int(segment[12]>>4) * 4
	if tcpHL < 20 || tcpHL > len(segment) {
		return
	}
	payload := segment[tcpHL:]
	if len(payload) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dialing {
		// در حال جمع‌آوری داده برای SNI extraction
		c.buf = append(c.buf, payload...)

		// سعی کن SNI رو از TLS ClientHello بخونیم
		if sni := extractSNI(c.buf); sni != "" {
			// SNI پیدا شد — hostname رو update کن و cache کن
			dstIP := net.IP(c.tuple.dstIP[:]).String()
			globalDNSCache.set(dstIP, sni)
			c.target = fmt.Sprintf("%s:%d", sni, c.tuple.dstPort)
			c.dialing = false

			// الان dial کن
			go func(buf []byte, target string) {
				remote, err := e.dialSOCKS5(target)
				if err != nil {
					e.conns.Delete(k)
					return
				}
				c.mu.Lock()
				c.remote = remote
				c.ack += uint32(len(buf))
				ack := c.ack
				seq := c.seq
				c.mu.Unlock()

				// داده‌های buffered رو بفرست
				remote.Write(buf)
				e.writeTCPResponse(k, seq, ack, 0x10)
				go c.pumpRemote()
			}(c.buf, c.target)
			c.buf = nil
		} else if len(c.buf) > 4096 {
			// اگه خیلی داده جمع شد و SNI پیدا نشد، با IP dial کن
			c.dialing = false
			buf := c.buf
			c.buf = nil
			go func() {
				remote, err := e.dialSOCKS5(c.target)
				if err != nil {
					e.conns.Delete(k)
					return
				}
				c.mu.Lock()
				c.remote = remote
				c.ack += uint32(len(buf))
				ack := c.ack
				seq := c.seq
				c.mu.Unlock()
				remote.Write(buf)
				e.writeTCPResponse(k, seq, ack, 0x10)
				go c.pumpRemote()
			}()
		}
		// ACK بده حتی وقتی در حال buffer کردنیم
		c.ack += uint32(len(payload))
		e.writeTCPResponse(k, c.seq, c.ack, 0x10)
		return
	}

	if c.remote == nil {
		return
	}
	c.remote.Write(payload)
	c.ack += uint32(len(payload))
	e.writeTCPResponse(k, c.seq, c.ack, 0x10)
}

// extractSNI: SNI رو از TLS ClientHello استخراج میکنه
// TLS record: ContentType(1) Version(2) Length(2) Handshake...
// Handshake: Type(1) Length(3) ClientHello...
// ClientHello: Version(2) Random(32) SessionID(1+N) CipherSuites(2+N) Compression(1+N) Extensions(2+N)
// Extension SNI: Type=0x0000 Length(2) ServerNameList(2) ServerNameType(1) NameLength(2) Name
func extractSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// TLS record header
	if data[0] != 0x16 { // ContentType: Handshake
		return ""
	}
	// TLS version: 0x0301 (TLS 1.0) to 0x0303 (TLS 1.2) or 0x0301 for 1.3 compat
	if data[1] != 0x03 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "" // هنوز کافی نیست
	}

	pos := 5
	if pos >= len(data) || data[pos] != 0x01 { // HandshakeType: ClientHello
		return ""
	}
	pos++ // skip HandshakeType

	if pos+3 > len(data) {
		return ""
	}
	// handshake length (3 bytes)
	pos += 3

	// ClientHello Version (2 bytes)
	pos += 2
	if pos > len(data) {
		return ""
	}

	// Random (32 bytes)
	pos += 32
	if pos > len(data) {
		return ""
	}

	// Session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos > len(data) {
		return ""
	}

	// Cipher Suites
	if pos+2 > len(data) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherLen
	if pos > len(data) {
		return ""
	}

	// Compression Methods
	if pos >= len(data) {
		return ""
	}
	comprLen := int(data[pos])
	pos += 1 + comprLen
	if pos > len(data) {
		return ""
	}

	// Extensions
	if pos+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extLen
	if end > len(data) {
		return ""
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extDataLen > end {
			break
		}

		if extType == 0x0000 { // SNI extension
			// ServerNameList length (2) + ServerNameType (1) + NameLength (2) + Name
			if extDataLen < 5 {
				break
			}
			nameListLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			_ = nameListLen
			nameType := data[pos+2]
			if nameType != 0x00 { // host_name
				break
			}
			nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
			if pos+5+nameLen > end {
				break
			}
			return string(data[pos+5 : pos+5+nameLen])
		}
		pos += extDataLen
	}
	return ""
}

func (c *tcpConn) pumpRemote() {
	buf := make([]byte, mtu-40)
	for {
		n, err := c.remote.Read(buf)
		if n > 0 {
			c.mu.Lock()
			seq, ack := c.seq, c.ack
			c.seq += uint32(n)
			c.mu.Unlock()
			c.engine.writeTCPPayload(c.tuple, seq, ack, buf[:n])
		}
		if err != nil {
			break
		}
	}
	c.mu.Lock()
	seq, ack := c.seq, c.ack
	c.mu.Unlock()
	c.engine.writeTCPResponse(c.tuple, seq, ack, 0x11)
	c.engine.conns.Delete(c.tuple)
}

func (e *tunEngine) writeTCPResponse(k fourTuple, seq, ack uint32, flags byte) {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 40)
	binary.BigEndian.PutUint16(packet[4:6], uint16(rand.Uint32()))
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = protoTCP
	copy(packet[12:16], k.dstIP[:])
	copy(packet[16:20], k.srcIP[:])
	binary.BigEndian.PutUint16(packet[10:12], ipCksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], k.dstPort)
	binary.BigEndian.PutUint16(packet[22:24], k.srcPort)
	binary.BigEndian.PutUint32(packet[24:28], seq)
	binary.BigEndian.PutUint32(packet[28:32], ack)
	packet[32] = 0x50
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], 65535)
	binary.BigEndian.PutUint16(packet[36:38], tcpCksum(packet[:20], packet[20:]))
	e.writeTUN(packet)
}

func (e *tunEngine) writeTCPPayload(k fourTuple, seq, ack uint32, payload []byte) {
	totalLen := 40 + len(payload)
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], uint16(rand.Uint32()))
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = protoTCP
	copy(packet[12:16], k.dstIP[:])
	copy(packet[16:20], k.srcIP[:])
	binary.BigEndian.PutUint16(packet[10:12], ipCksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], k.dstPort)
	binary.BigEndian.PutUint16(packet[22:24], k.srcPort)
	binary.BigEndian.PutUint32(packet[24:28], seq)
	binary.BigEndian.PutUint32(packet[28:32], ack)
	packet[32] = 0x50
	packet[33] = 0x18
	binary.BigEndian.PutUint16(packet[34:36], 65535)
	copy(packet[40:], payload)
	binary.BigEndian.PutUint16(packet[36:38], tcpCksum(packet[:20], packet[20:]))
	e.writeTUN(packet)
}

func ipCksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpCksum(ipHdr, tcpSeg []byte) uint16 {
	psh := make([]byte, 12+len(tcpSeg))
	copy(psh[0:4], ipHdr[12:16])
	copy(psh[4:8], ipHdr[16:20])
	psh[9] = protoTCP
	binary.BigEndian.PutUint16(psh[10:12], uint16(len(tcpSeg)))
	copy(psh[12:], tcpSeg)
	return ipCksum(psh)
}

func (e *tunEngine) dialSOCKS5(target string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { InternalProtectSocket(int(fd)) })
		},
	}
	conn, err := dialer.Dial("tcp", e.socksAddr)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 %s: %w", e.socksAddr, err)
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target %s: %w", target, err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect refused, code=%d", hdr[1])
	}

	switch hdr[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		var l [1]byte
		io.ReadFull(conn, l[:])
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 unknown atype: %d", hdr[3])
	}

	return conn, nil
}