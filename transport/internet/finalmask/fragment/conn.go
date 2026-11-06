package fragment

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

type fragmentConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool
}

func NewConnClient(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	conn := &fragmentConn{
		Conn:   raw,
		config: c,

		server: server,
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	return NewConnClient(c, raw, server)
}

func (c *fragmentConn) TcpMaskConn() {}

func (c *fragmentConn) RawConn() net.Conn {
	return c.Conn
}

func (c *fragmentConn) Splice() bool {
	if c.server {
		return false
	}
	return true
}

// lengthForSegment returns the length range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) lengthForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.LengthsMin) {
		segIdx = len(c.config.LengthsMin) - 1
	}
	return c.config.LengthsMin[segIdx], c.config.LengthsMax[segIdx]
}

// delayForSegment returns the delay range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) delayForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.DelaysMin) {
		segIdx = len(c.config.DelaysMin) - 1
	}
	return c.config.DelaysMin[segIdx], c.config.DelaysMax[segIdx]
}

// mergeTlsHelloSegments returns true only when delays has exactly one zero entry.
func (c *fragmentConn) mergeTlsHelloSegments() bool {
	return len(c.config.DelaysMax) == 1 && c.config.DelaysMax[0] == 0
}

func (c *fragmentConn) Write(p []byte) (n int, err error) {
	c.count++

	if c.config.PacketsFrom == 0 && c.config.PacketsTo == 1 {
		if c.count != 1 || len(p) <= 5 || p[0] != 22 {
			return c.Conn.Write(p)
		}
		recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
		if len(p) < recordLen {
			return c.Conn.Write(p)
		}
		if c.config.Layout != "" {
			if start, end, ok := sniNameRange(p[:recordLen]); ok && end-start >= 2 {
				gap := layoutDefaultGap(c.config.Layout)
				if len(c.config.DelaysMax) > 0 {
					gap = crypto.RandBetween(c.config.DelaysMin[0], c.config.DelaysMax[0])
					if gap < 0 {
						gap = 0
					}
				}
				return c.writeShaped(p, recordLen, shapeHello(p[:recordLen], start, end, c.config.Layout, gap))
			}
		}
		if c.config.SniMid {
			if cut := sniMidCut(p[:recordLen]); cut > 5 && cut < recordLen {
				return c.writeSniSplit(p, recordLen, cut)
			}
		}
		data := p[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		mergeHello := c.mergeTlsHelloSegments()
		maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
		var splitNum int64
		for from := 0; ; {
			lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
			to := from + int(crypto.RandBetween(lengthMin, lengthMax))
			if to > len(data) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], p)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if mergeHello {
				hello = append(hello, buff[:5+l]...)
			} else {
				delayMin, delayMax := c.delayForSegment(int(splitNum))
				_, err := c.Conn.Write(buff[:5+l])
				if delayMax > 0 {
					time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
				}
				if err != nil {
					return 0, err
				}
			}
			splitNum++
			if from == len(data) {
				if len(hello) > 0 {
					_, err := c.Conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(p) > recordLen {
					n, err := c.Conn.Write(p[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(p), nil
			}
		}
	}

	if c.config.PacketsFrom != 0 && (c.count < uint64(c.config.PacketsFrom) || c.count > uint64(c.config.PacketsTo)) {
		return c.Conn.Write(p)
	}
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	var splitNum int64
	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(crypto.RandBetween(lengthMin, lengthMax))
		if to > len(p) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		delayMin, delayMax := c.delayForSegment(int(splitNum))
		if delayMax > 0 {
			time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
		}
		splitNum++
		if from >= len(p) {
			return from, nil
		}
	}
}

// sniMidCut returns the absolute offset inside record at which the ClientHello should be cut:
// the middle of the server_name host name. It returns 0 when the record does not carry a
// parseable SNI, in which case the caller falls back to length-based splitting.
func sniMidCut(record []byte) int {
	start, end, ok := sniNameRange(record)
	if !ok || end-start < 2 {
		return 0
	}
	return start + (end-start)/2
}

// sniNameRange returns the absolute [start,end) of the server_name host name inside a TLS
// handshake record, header included.
func sniNameRange(record []byte) (int, int, bool) {
	if len(record) < 44 || record[0] != 22 || record[5] != 1 {
		return 0, 0, false
	}
	helloEnd := 9 + (int(record[6])<<16 | int(record[7])<<8 | int(record[8]))
	if helloEnd > len(record) || helloEnd < 44 {
		return 0, 0, false
	}
	p := 43
	if p >= helloEnd {
		return 0, 0, false
	}
	p += 1 + int(record[p]) // session_id
	if p+2 > helloEnd {
		return 0, 0, false
	}
	p += 2 + (int(record[p])<<8 | int(record[p+1])) // cipher_suites
	if p >= helloEnd {
		return 0, 0, false
	}
	p += 1 + int(record[p]) // compression_methods
	if p+2 > helloEnd {
		return 0, 0, false
	}
	p += 2 // extensions length
	extEnd := p + (int(record[p-2])<<8 | int(record[p-1]))
	if extEnd > helloEnd {
		return 0, 0, false
	}
	for p+4 <= extEnd {
		kind := int(record[p])<<8 | int(record[p+1])
		l := int(record[p+2])<<8 | int(record[p+3])
		p += 4
		if p+l > extEnd {
			return 0, 0, false
		}
		if kind == 0 && l >= 5 {
			q := p + 2
			listEnd := q + (int(record[p])<<8 | int(record[p+1]))
			for q+3 <= listEnd {
				nameType := record[q]
				n := int(record[q+1])<<8 | int(record[q+2])
				q += 3
				if q+n > listEnd {
					return 0, 0, false
				}
				if nameType == 0 && n >= 2 {
					return q, q + n, true
				}
				q += n
			}
		}
		p += l
	}
	return 0, 0, false
}

// writeSniSplit emits the first ClientHello record as two records cut at cut, one write each, so
// the first TCP segment ends inside the SNI host name.
func (c *fragmentConn) writeSniSplit(p []byte, recordLen, cut int) (int, error) {
	head := make([]byte, cut)
	copy(head, p[:cut])
	head[3] = byte((cut - 5) >> 8)
	head[4] = byte(cut - 5)

	tail := make([]byte, 5+recordLen-cut)
	copy(tail, p[:3])
	tail[3] = byte((recordLen - cut) >> 8)
	tail[4] = byte(recordLen - cut)
	copy(tail[5:], p[cut:recordLen])

	if _, err := c.Conn.Write(head); err != nil {
		return 0, err
	}
	if len(c.config.DelaysMax) > 0 {
		delayMin, delayMax := c.delayForSegment(0)
		if delayMax > 0 {
			time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
		}
	}
	if _, err := c.Conn.Write(tail); err != nil {
		return recordLen, err
	}
	if len(p) > recordLen {
		n, err := c.Conn.Write(p[recordLen:])
		if err != nil {
			return recordLen + n, err
		}
	}
	return len(p), nil
}

// writeShaped emits the exact write sequence produced by shapeHello, then any bytes that followed
// the shaped record.
func (c *fragmentConn) writeShaped(p []byte, recordLen int, writes []helloWrite) (int, error) {
	for _, w := range writes {
		if _, err := c.Conn.Write(w.data); err != nil {
			return 0, err
		}
		if w.delay > 0 {
			time.Sleep(time.Duration(w.delay) * time.Millisecond)
		}
	}
	if len(p) > recordLen {
		if _, err := c.Conn.Write(p[recordLen:]); err != nil {
			return recordLen, err
		}
	}
	return len(p), nil
}
