//    Copyright 2017 drillbits
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package ts

import (
	"bufio"
	"bytes"
	"io"
)

const packetDefaultSize = 188

// PacketScanner is a wrapper of bufio.Scanner.
type PacketScanner struct {
	*bufio.Scanner
}

// NewPacketScanner returns a new Scanner to read from r.
func NewPacketScanner(r io.Reader) *PacketScanner {
	s := bufio.NewScanner(r)
	s.Split(splitPacket)

	return &PacketScanner{s}
}

func splitPacket(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if len(data) < packetDefaultSize {
		return 0, nil, nil
	}
	i := bytes.IndexByte(data[packetDefaultSize:len(data)], byte(SyncByte))
	if i >= 0 {
		return i + packetDefaultSize, data[0 : i+packetDefaultSize], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// Packet returns bytes as Packet.
func (s *PacketScanner) Packet() Packet {
	buf := make([]byte, len(s.Bytes()))
	copy(buf, s.Bytes())
	return buf
}

// SectionScanner reads the sections.
type SectionScanner struct {
	r      io.Reader  // The reader provided by the client.
	filter FilterFunc // The function to filter the tokens.
	buf    map[PID]*sectionBuffer
	ch     chan *SectionReceiver
	done   chan bool
	fail   chan error
}

// FilterFunc is the signature of the filter function used to filter the
// packet by PID.
type FilterFunc func(pid PID) bool

// SectionReceiver is a section bytes with PID.
type SectionReceiver struct {
	PID PID
	buf []byte
}

// Bytes returns the bytes.
func (rx *SectionReceiver) Bytes() []byte {
	return rx.buf
}

// NewSectionScanner returns a new SectionScanner to read from r.
func NewSectionScanner(r io.Reader, ch chan *SectionReceiver, done chan bool, fail chan error) *SectionScanner {
	return &SectionScanner{
		r:      r,
		filter: NoopFilter,
		buf:    make(map[PID]*sectionBuffer),
		ch:     ch,
		done:   done,
		fail:   fail,
	}
}

// Scan scans packets, merges by PID and send it to the channel.
func (s *SectionScanner) Scan() {
	ps := NewPacketScanner(s.r)
	for ps.Scan() {
		p := ps.Packet()
		pid := p.PID()
		if !s.filter(pid) {
			continue
		}

		sec, ok := s.buf[pid]
		if !ok {
			sec = newSectionBuffer(pid)
			s.buf[pid] = sec
		}

		// reset cc by discontinuity indicator
		af, err := p.AdaptationField()
		if err != nil {
			s.fail <- err
			return
		}
		if af != nil && af.IsDiscontinuous() {
			sec.cc = -1
		}

		// check continuously
		if !sec.isContinuous(pid, int(p.ContinuityCounter())) {
			continue
		}

		// append
		sec.sendWithDepacketize(s.ch, p.Payload(), p.IsPayloadUnitStart())
	}
	err := ps.Err()
	if err != nil {
		s.fail <- err
	}
	s.done <- true
}

type sectionBuffer struct {
	pid  PID
	buf  []byte
	cc   int
	dup  int
	size int
	n    int
}

func newSectionBuffer(pid PID) *sectionBuffer {
	return &sectionBuffer{
		pid: pid,
		cc:  -1,
	}
}

func (sec *sectionBuffer) init(payload Payload) int {
	sec.n = 0
	sec.size = PSI(payload).SectionLength()
	headsize := 3 // table_id .. section_length
	sec.buf = payload[:headsize]
	return headsize
}

func (sec *sectionBuffer) isContinuous(pid PID, cc int) bool {
	if sec.cc == -1 || pid == PIDNull {
		sec.cc = cc
		return true
	}

	pre := sec.cc
	exp := pre + 1
	if exp > 15 {
		exp = 0
	}
	sec.cc = cc

	// duplication
	if pre == cc {
		// pass to drop if first dup
		if sec.dup >= 1 {
			sec.drop()
		}
		sec.dup++
		return false
	}
	sec.dup = 0

	// continuous
	if exp != cc {
		sec.drop()
		return false
	}

	return true
}

func (sec *sectionBuffer) drop() {
	sec.flush()
}

func (sec *sectionBuffer) flush() {
	sec.buf = []byte{}
	sec.size = 0
	sec.n = 0
}

func (sec *sectionBuffer) sendWithDepacketize(ch chan *SectionReceiver, payload Payload, atStart bool) {
	if !atStart {
		sec.mergesend(payload, ch)
		return
	}

	pos := 0
	size := len(payload)

	if payload.IsPSI() {
		pf := payload.PointerField()
		pos++
		if pf > 0 {
			// append buffer indicated by pointer_field to previous payload
			high := pos + pf
			if high > size {
				high = size
			}
			buf := payload[pos:high]
			pos += len(buf)
			sec.mergesend(buf, ch)
		}

		for pos+minSectionSize < size {
			pos += sec.init(payload[pos:])

			high := pos + sec.size
			if high > size {
				high = size
			}
			buf := payload[pos:high]
			pos += len(buf)
			sec.mergesend(buf, ch)
		}
	} else {
		panic("TODO: PES")
	}
}

func (sec *sectionBuffer) mergesend(payload Payload, ch chan *SectionReceiver) {
	sec.buf = append(sec.buf, payload...)
	sec.n += len(payload)
	if sec.n == sec.size && len(sec.buf) > 0 {
		ch <- &SectionReceiver{sec.pid, sec.buf}
		sec.flush()
	}
}

// Filter sets the filter function for the SectionScanner.
// The default filter function is NoopFilter.
//
// Filter NOT panics if it is called after scanning has started.
func (s *SectionScanner) Filter(filter FilterFunc) {
	s.filter = filter
}

// NoopFilter is a filter function for a SectionScanner that always returns true.
func NoopFilter(pid PID) bool {
	return true
}
