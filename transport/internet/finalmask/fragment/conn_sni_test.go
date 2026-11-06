package fragment

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func testClientHello(host string, target int) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	cs := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b}
	body = append(body, byte(len(cs)>>8), byte(len(cs)))
	body = append(body, cs...)
	body = append(body, 1, 0)

	var ext []byte
	add := func(typ uint16, data []byte) {
		ext = append(ext, byte(typ>>8), byte(typ), byte(len(data)>>8), byte(len(data)))
		ext = append(ext, data...)
	}
	name := []byte(host)
	sni := []byte{byte((len(name) + 3) >> 8), byte(len(name) + 3), 0, byte(len(name) >> 8), byte(len(name))}
	sni = append(sni, name...)
	add(0x0000, sni)
	cur := 5 + 4 + len(body) + 2 + len(ext) + 4
	if pad := target - cur; pad > 0 {
		add(0x0015, make([]byte, pad))
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(body)+4))
	rec = append(rec, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(rec, body...)
}

func TestSniMidCut(t *testing.T) {
	hello := testClientHello("www.example.com", 1024)
	cut := sniMidCut(hello)
	start := bytes.Index(hello, []byte("www.example.com"))
	if cut == 0 {
		t.Fatal("sniMidCut returned 0 for a ClientHello with SNI")
	}
	if !(start < cut && cut < start+len("www.example.com")) {
		t.Fatalf("cut %d not inside SNI [%d,%d)", cut, start, start+len("www.example.com"))
	}
	if want := start + len("www.example.com")/2; cut != want {
		t.Fatalf("cut = %d, want middle %d", cut, want)
	}
	if sniMidCut([]byte{0x17, 0x03, 0x03, 0, 5, 1, 2, 3, 4}) != 0 {
		t.Fatal("non-handshake record must not produce a cut")
	}
	if sniMidCut(testClientHello("", 0)) != 0 {
		t.Fatal("ClientHello without SNI must not produce a cut")
	}
}

type collectConn struct {
	net.Conn
	writes [][]byte
}

func (c *collectConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestWriteSniSplit(t *testing.T) {
	hello := testClientHello("www.example.com", 1024)
	cut := sniMidCut(hello)
	c := &fragmentConn{
		Conn:   &collectConn{},
		config: &Config{PacketsFrom: 0, PacketsTo: 1, SniMid: true, DelaysMin: []int64{0}, DelaysMax: []int64{0}},
	}
	if _, err := c.writeSniSplit(hello, len(hello), cut); err != nil {
		t.Fatal(err)
	}
	writes := c.Conn.(*collectConn).writes
	if len(writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(writes))
	}
	if len(writes[0]) != cut {
		t.Fatalf("first record = %d bytes, want %d", len(writes[0]), cut)
	}
	if got := int(binary.BigEndian.Uint16(writes[0][3:5])) + 5; got != cut {
		t.Fatalf("first record header says %d, want %d", got, cut)
	}
	// The two records must reassemble into exactly the original record body.
	var got []byte
	for _, w := range writes {
		got = append(got, w[5:]...)
	}
	if !bytes.Equal(got, hello[5:]) {
		t.Fatal("reframed records do not reassemble to the original record body")
	}
}
