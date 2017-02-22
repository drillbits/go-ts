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
	"errors"
	"io"
)

// table_id                  8 bit(s)
// section_syntax_indicator  1
// '0'                       1
// reserved                  2
// section_length           12
const minSectionSize = 3

// PacketReceiver is a receiver for TS packet.
type PacketReceiver struct {
	PID    PID
	Ch     chan []byte
	cc     int
	dup    int
	buf    []byte
	secLen int
	tmpLen int
}

// NewPacketReceiver creates a new PacketReceiver.
func NewPacketReceiver(pid PID, ch chan []byte) *PacketReceiver {
	return &PacketReceiver{
		PID:    pid,
		Ch:     ch,
		cc:     -1,
		dup:    0,
		secLen: 0,
		tmpLen: 0,
	}
}

func (rx *PacketReceiver) checkContinuously(pid PID, cc uint8) bool {
	intCC := int(cc)
	if rx.cc == -1 || pid == 0x1FFF { // Null packet
		rx.cc = intCC
	} else {
		// check drop
		drop := false
		pre := rx.cc
		exp := pre + 1
		rx.cc = intCC
		// dup
		if pre == intCC {
			if rx.dup < 1 {
				// pass: not drop, skip this packet
				return false
			}
			drop = true
		} else {
			rx.dup = 0
		}
		// continuous
		if exp != intCC {
			drop = true
		}
		// drop
		if drop {
			rx.drop()
			return false
		}
	}
	return true
}

func (rx *PacketReceiver) drop() {
	// TODO
	rx.buf = []byte{}
	rx.secLen = 0
	rx.tmpLen = 0
}

func (rx *PacketReceiver) mergePSI(data []byte, atStart bool) error {
	if !atStart {
		rx.appendBuffer(data)
		rx.sendIfSectionMerged()
	}

	pos := 0
	dataSize := len(data)

	pointerField := int(data[0])
	pos++

	if pointerField > 0 {
		// merge to previous packet data
		high := pos + pointerField
		if high > dataSize {
			high = dataSize
		}
		// merge buffer indicated by pointer_field
		buf := data[pos:high]
		pos += len(buf)
		rx.appendBuffer(buf)
		rx.sendIfSectionMerged()
	}

	for pos+minSectionSize < dataSize {
		pos = rx.initBuffer(data, pos)

		high := pos + rx.secLen
		if high > dataSize {
			high = dataSize
		}
		buf := data[pos:high]
		pos += len(buf)
		rx.appendBuffer(buf)
		rx.sendIfSectionMerged()
	}
	return nil
}

func (rx *PacketReceiver) initBuffer(data []byte, pos int) int {
	rx.tmpLen = 0
	rx.secLen = int(uint16(data[pos+1]&0x0F)<<8 | uint16(data[pos+2]))
	// set table_id .. section_length
	rx.buf = data[pos : pos+3]
	pos += 3 // table_id .. section_length
	return pos
}

func (rx *PacketReceiver) appendBuffer(b []byte) {
	rx.buf = append(rx.buf, b...)
	rx.tmpLen += len(b)
}

func (rx *PacketReceiver) sendIfSectionMerged() {
	if rx.tmpLen != rx.secLen || len(rx.buf) == 0 {
		return
	}
	rx.Ch <- rx.buf

	// clear
	rx.buf = []byte{}
	rx.secLen = 0
	rx.tmpLen = 0
}

// ReadPacket reads the packets from 'r' and sends the marged packet by PID
// to each channel.
func ReadPacket(r io.Reader, rxs []*PacketReceiver, done chan bool, fail chan error) {
	s := NewPacketScanner(r)
	for s.Scan() {
		p := s.Packet()
	loop:
		for _, rx := range rxs {
			if rx.PID == p.PID() {
				// reset cc by discontinuity indicator
				af, err := p.AdaptationField()
				if err != nil {
					fail <- err
				}
				if af != nil && af.IsDiscontinuous() {
					rx.cc = -1
				}

				// check continuously
				ok := rx.checkContinuously(p.PID(), p.ContinuityCounter())
				if !ok {
					continue loop
				}

				// merge
				if p.IsPES() {
					err = errors.New("TODO: PES cannot merge")
				} else {
					err = rx.mergePSI(p.Payload(), p.PayloadUnitStartIndicator() == 1)
				}
				if err != nil {
					fail <- err
				}
			}
		}
	}
	err := s.Err()
	if err != nil {
		fail <- err
	}
	done <- true
}
