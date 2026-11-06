package fragment

import "testing"

// The expected sequences below were produced by the reference implementation
// (MistSail/Direct/HelloShaper.cs) for the same 1024-byte ClientHello with
// "www.example.com" at offset 99, and must stay byte-for-byte identical.
func TestLayoutsMatchReference(t *testing.T) {
	hello := testClientHello("www.example.com", 1024)
	start, end, ok := sniNameRange(hello)
	if !ok || start != 99 || end != 114 {
		t.Fatalf("SNI range = %d..%d ok=%v, want 99..114", start, end, ok)
	}

	bytes15 := make([]int, 15)
	for i := range bytes15 {
		bytes15[i] = 6
	}
	gaps16 := make([]int64, 16)
	for i := range gaps16 {
		gaps16[i] = 15
	}
	expected := map[string]struct {
		lengths []int
		delays  []int64
	}{
		LayoutPlain:           {[]int{1024}, []int64{0}},
		LayoutRecord2:         {[]int{1029}, []int64{0}},
		LayoutTcpMid:          {[]int{106, 918}, []int64{15, 0}},
		LayoutRecordMisalign:  {[]int{101, 12, 13, 913}, []int64{15, 15, 15, 0}},
		LayoutRecordMisalignB: {[]int{52, 61, 13, 913}, []int64{15, 15, 15, 0}},
		LayoutRecordBytes:     {append(append([]int{101}, bytes15...), 913), append(gaps16, 0)},
		LayoutRecordMid:       {[]int{99, 12, 13, 915}, []int64{15, 15, 15, 0}},
		LayoutRecordMidDelay:  {[]int{106, 923}, []int64{1200, 0}},
		LayoutTcpMidDelay:     {[]int{106, 918}, []int64{1200, 0}},
		LayoutRecordZero4:     {[]int{1049}, []int64{0}},
	}

	for layout, want := range expected {
		writes := shapeHello(hello, start, end, layout, layoutDefaultGap(layout))
		if len(writes) != len(want.lengths) {
			t.Fatalf("%s: %d writes, want %d", layout, len(writes), len(want.lengths))
		}
		for i, w := range writes {
			if len(w.data) != want.lengths[i] || w.delay != want.delays[i] {
				t.Fatalf("%s: write %d = %d/%d, want %d/%d", layout, i, len(w.data), w.delay, want.lengths[i], want.delays[i])
			}
		}
		// Every layout must leave the handshake bytes unchanged.
		if layout == LayoutTcpMid || layout == LayoutTcpMidDelay {
			var got []byte
			for _, w := range writes {
				got = append(got, w.data...)
			}
			if string(got) != string(hello) {
				t.Fatalf("%s: reassembled bytes differ from the original record", layout)
			}
			continue
		}
		assertRecordPayloads(t, layout, writes, hello)
	}
}

func TestRecordZero4HasEmptyPrefix(t *testing.T) {
	hello := testClientHello("www.example.com", 1024)
	start, end, _ := sniNameRange(hello)
	writes := shapeHello(hello, start, end, LayoutRecordZero4, 0)
	if len(writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(writes))
	}
	data := writes[0].data
	pos := 0
	for i := 0; i < 4; i++ {
		if pos+5 > len(data) || data[pos] != 0x16 || data[pos+3] != 0 || data[pos+4] != 0 {
			t.Fatalf("record %d is not an empty handshake record", i)
		}
		pos += 5
	}
}

// assertRecordPayloads re-parses the emitted stream as TLS records and checks that their
// handshake payload is exactly the original record's payload.
func assertRecordPayloads(t *testing.T, layout string, writes []helloWrite, hello []byte) {
	t.Helper()
	var stream []byte
	for _, w := range writes {
		stream = append(stream, w.data...)
	}
	var payload []byte
	for pos := 0; pos < len(stream); {
		if pos+5 > len(stream) || stream[pos] != 0x16 {
			t.Fatalf("%s: not a handshake record at %d", layout, pos)
		}
		n := int(stream[pos+3])<<8 | int(stream[pos+4])
		if pos+5+n > len(stream) {
			t.Fatalf("%s: truncated record at %d", layout, pos)
		}
		payload = append(payload, stream[pos+5:pos+5+n]...)
		pos += 5 + n
	}
	if string(payload) != string(hello[5:]) {
		t.Fatalf("%s: record payload differs from the original ClientHello body", layout)
	}
}
