package client

import (
	"encoding/hex"
	"testing"
)

func TestDNSFirstQuestionName(t *testing.T) {
	// dig-style A query for example.com (wire format snippet built manually).
	// ID=0x1234, flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	// QNAME: 7example3com0, QTYPE A(1), QCLASS IN(1)
	raw, err := hex.DecodeString("123400000001000000000000076578616d706c6503636f6d0000010001")
	if err != nil {
		t.Fatal(err)
	}
	name, ok := dnsFirstQuestionName(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if name != "example.com" {
		t.Fatalf("name = %q", name)
	}
}

func TestDNSFirstQuestionNameCompressionRejected(t *testing.T) {
	raw := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}
	if _, ok := dnsFirstQuestionName(raw); ok {
		t.Fatal("expected compression in QNAME to be rejected")
	}
}

func TestHostMatchesBypass(t *testing.T) {
	if !HostMatchesBypass("foo.shaparak.ir", []string{"ir"}, nil) {
		t.Fatal("suffix .ir should match")
	}
	if HostMatchesBypass("example.com", []string{"ir"}, nil) {
		t.Fatal("should not match")
	}
}
