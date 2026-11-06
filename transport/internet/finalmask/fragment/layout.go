package fragment

// Hello layouts ported from MistSail's HelloShaper (Direct/HelloShaper.cs). Every layout only
// changes TLS record boundaries, TCP write boundaries and pacing; the handshake bytes are never
// touched, so the server reassembles the original ClientHello and the transcript hash matches.

const (
	LayoutPlain           = "plain"
	LayoutRecord2         = "record-2"
	LayoutTcpMid          = "tcp-mid"
	LayoutRecordMisalign  = "record-misalign"
	LayoutRecordMisalignB = "record-misalign-b"
	LayoutRecordBytes     = "record-bytes"
	LayoutRecordMid       = "record-mid"
	LayoutRecordMidDelay  = "record-mid-delay"
	LayoutTcpMidDelay     = "tcp-mid-delay"
	LayoutRecordZero4     = "record-zero4"
)

const (
	defaultGapMs = int64(15)
	longPauseMs  = int64(1200)
)

// KnownLayout reports whether name is one of the ported MistSail layouts.
func KnownLayout(name string) bool {
	switch name {
	case LayoutPlain, LayoutRecord2, LayoutTcpMid, LayoutRecordMisalign, LayoutRecordMisalignB,
		LayoutRecordBytes, LayoutRecordMid, LayoutRecordMidDelay, LayoutTcpMidDelay, LayoutRecordZero4:
		return true
	}
	return false
}

// layoutDefaultGap mirrors HelloStrategy.GapMs: 15 ms between shaped writes, 1.2 s for the two
// probe layouts that test reassembly timeouts, and no pacing for the single-write layouts.
func layoutDefaultGap(layout string) int64 {
	switch layout {
	case LayoutPlain, LayoutRecord2, LayoutRecordZero4:
		return 0
	case LayoutRecordMidDelay, LayoutTcpMidDelay:
		return longPauseMs
	}
	return defaultGapMs
}

type helloWrite struct {
	data  []byte
	delay int64 // milliseconds to wait after this write, 0 = none
}

func concatRecords(records [][]byte) []byte {
	n := 0
	for _, r := range records {
		n += len(r)
	}
	out := make([]byte, 0, n)
	for _, r := range records {
		out = append(out, r...)
	}
	return out
}

// frameRecord re-frames record[start:end] as a standalone TLS record, keeping content type and
// version from the original header.
func frameRecord(record []byte, start, end int) []byte {
	framed := make([]byte, 5+end-start)
	framed[0], framed[1], framed[2] = record[0], record[1], record[2]
	framed[3] = byte((end - start) >> 8)
	framed[4] = byte(end - start)
	copy(framed[5:], record[start:end])
	return framed
}

// frameRecords cuts the record body at the absolute offsets in cuts (5 <= cut < len) and returns
// one TLS record per piece, optionally preceded by zero-length handshake records.
func frameRecords(record []byte, cuts []int, zeroPrefix int) [][]byte {
	out := make([][]byte, 0, len(cuts)+1+zeroPrefix)
	for i := 0; i < zeroPrefix; i++ {
		out = append(out, []byte{record[0], record[1], record[2], 0, 0})
	}
	sorted := append([]int(nil), cuts...)
	sortInts(sorted)
	start := 5
	for _, cut := range sorted {
		if cut <= 5 || cut >= len(record) || cut == start {
			continue
		}
		out = append(out, frameRecord(record, start, cut))
		start = cut
	}
	out = append(out, frameRecord(record, start, len(record)))
	return out
}

func sortInts(v []int) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// misalignWrites concatenates records and cuts the TCP writes 2 bytes past every record boundary,
// so no write ends exactly where a record ends. With firstInsideBody the first write instead ends
// inside the first record's body.
func misalignWrites(records [][]byte, firstInsideBody bool, gap int64) []helloWrite {
	all := concatRecords(records)
	cuts := make([]int, 0, len(records))
	boundary := 0
	for i := 0; i < len(records)-1; i++ {
		boundary += len(records[i])
		cut := boundary + 2
		if i == 0 && firstInsideBody {
			cut = len(records[0]) - maxInt(1, (len(records[0])-5)/2)
			if cut < 6 {
				cut = 6
			}
		}
		if cut < len(all) && (len(cuts) == 0 || cut > cuts[len(cuts)-1]) {
			cuts = append(cuts, cut)
		}
	}
	writes := make([]helloWrite, 0, len(cuts)+1)
	start := 0
	for _, cut := range cuts {
		writes = append(writes, helloWrite{data: all[start:cut], delay: gap})
		start = cut
	}
	writes = append(writes, helloWrite{data: all[start:]})
	return writes
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// shapeHello returns the exact write sequence for one ClientHello record. nameStart and nameEnd
// are the absolute bounds of the SNI host name inside record; gap is the pause between writes.
func shapeHello(record []byte, nameStart, nameEnd int, layout string, gap int64) []helloWrite {
	mid := nameStart + (nameEnd-nameStart)/2
	switch layout {
	case LayoutPlain:
		return []helloWrite{{data: record}}
	case LayoutRecord2:
		return []helloWrite{{data: concatRecords(frameRecords(record, []int{mid}, 0))}}
	case LayoutRecordZero4:
		return []helloWrite{{data: concatRecords(frameRecords(record, []int{mid}, 4))}}
	case LayoutTcpMid, LayoutTcpMidDelay:
		return []helloWrite{{data: record[:mid], delay: gap}, {data: record[mid:]}}
	case LayoutRecordMidDelay:
		records := frameRecords(record, []int{mid}, 0)
		return []helloWrite{{data: records[0], delay: gap}, {data: records[1]}}
	case LayoutRecordMid:
		records := frameRecords(record, []int{nameStart, mid, nameEnd}, 0)
		writes := make([]helloWrite, len(records))
		for i, r := range records {
			writes[i] = helloWrite{data: r}
			if i < len(records)-1 {
				writes[i].delay = gap
			}
		}
		return writes
	case LayoutRecordMisalign:
		return misalignWrites(frameRecords(record, []int{nameStart, mid, nameEnd}, 0), false, gap)
	case LayoutRecordMisalignB:
		return misalignWrites(frameRecords(record, []int{nameStart, mid, nameEnd}, 0), true, gap)
	case LayoutRecordBytes:
		cuts := make([]int, 0, nameEnd-nameStart+1)
		for i := nameStart; i <= nameEnd; i++ {
			cuts = append(cuts, i)
		}
		return misalignWrites(frameRecords(record, cuts, 0), false, gap)
	}
	return []helloWrite{{data: record}}
}
