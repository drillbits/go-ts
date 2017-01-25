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

import "io"

// Packet is a Transport Stream(TS) packet.
type Packet []byte

// PID is a Packet Identifier, describing the payload data.
type PID uint16

// AdaptationField is an extended TS header.
type AdaptationField []byte

// AdaptationExtensionField is an extention of adaptation field.
type AdaptationExtensionField []byte

const (
	// SyncByte is used to identify the start of the TS Packet.
	SyncByte = 0x47
)

// TS Header

// SyncByte returns the Sync byte.
func (p Packet) SyncByte() byte {
	return p[0]
}

// TransportErrorIndicator returns the Transport Error Indicator(TEI).
func (p Packet) TransportErrorIndicator() bool {
	return p[1]&0x80>>7 == 1
}

// PayloadUnitStartIndicator returns the Payload Unit Start Indicator(PUSI).
func (p Packet) PayloadUnitStartIndicator() bool {
	return p[1]&0x40>>6 == 1
}

// TransportPriority returns the Transport Priority.
func (p Packet) TransportPriority() bool {
	return p[1]&0x20>>5 == 1
}

// PID returns the Packet Identifier(PID).
func (p Packet) PID() PID {
	return PID(uint16(p[1]&0x1f)<<8 | uint16(p[2]))
}

// TransportScramblingControl returns the Transport Scrambling Control(TSC).
// - 0x00(00): not scrambled
// - 0x01(01): reserved for future use
// - 0x02(10): scrambled with even key
// - 0x03(11): scrambled with odd key
func (p Packet) TransportScramblingControl() byte {
	return p[3] & 0xc0 >> 6
}

// AdaptationFieldControl returns the Adaptation field control code.
// - 0x00(00): reserved for future use
// - 0x01(01): no adaptation field, payload only
// - 0x02(10): adaptation field only, no payload
// - 0x03(11): adaptation field followed by payload
func (p Packet) AdaptationFieldControl() byte {
	return p[3] & 0x30 >> 4
}

// HasAdaptationField reports whether the packet has adaptation field.
func (p Packet) HasAdaptationField() bool {
	ctrl := p.AdaptationFieldControl()
	return ctrl == 0x02 || ctrl == 0x03
}

// HasPayload reports whether the packet has payload.
func (p Packet) HasPayload() bool {
	ctrl := p.AdaptationFieldControl()
	return ctrl == 0x01 || ctrl == 0x03
}

// ContinuityCounter returns Continuity counter.
func (p Packet) ContinuityCounter() uint8 {
	return p[3] & 0x0F
}

// AdaptationFieldLength returns number of bytes in the adaptation field immediately following this byte.
func (p Packet) AdaptationFieldLength() int {
	if !p.HasAdaptationField() {
		return 0
	}
	return int(p[4])
}

// AdaptationField returns the adaptation field.
func (p Packet) AdaptationField() (AdaptationField, error) {
	if !p.HasAdaptationField() {
		return nil, nil
	}
	l := p.AdaptationFieldLength()
	if l <= 0 {
		return nil, nil
	}
	low := 4
	high := 5 + l
	if high > len(p) {
		return nil, io.ErrUnexpectedEOF
	}
	return AdaptationField(p[low:high]), nil
}

// Payload returns the payload.
func (p Packet) Payload() []byte {
	if !p.HasPayload() {
		return nil
	}
	low := 4
	if p.HasAdaptationField() {
		low += p.AdaptationFieldLength() + 1
	}
	return p[low:len(p)]
}

// Length returns number of bytes in the adaptation field immediately following this byte.
func (af AdaptationField) Length() int {
	return int(af[0])
}

// DiscontinuityIndicator returns Discontinuity indicator.
func (af AdaptationField) DiscontinuityIndicator() bool {
	i := af[1] & 0x80 >> 7
	return i == 1
}

// RandomAccessIndicator returns Random Access indicator.
func (af AdaptationField) RandomAccessIndicator() bool {
	i := af[1] & 0x40 >> 6
	return i == 1
}

// ElementaryStreamPriorityIndicator returns Elementary stream priority indicator.
func (af AdaptationField) ElementaryStreamPriorityIndicator() bool {
	i := af[1] & 0x20 >> 5
	return i == 1
}

// PCRFlag returns PCR flag.
func (af AdaptationField) PCRFlag() bool {
	i := af[1] & 0x10 >> 4
	return i == 1
}

// HasPCR reports whether the adaptation field has PCR.
func (af AdaptationField) HasPCR() bool {
	return af.PCRFlag()
}

// OPCRFlag returns OPCR flag.
func (af AdaptationField) OPCRFlag() bool {
	i := af[1] & 0x08 >> 3
	return i == 1
}

// HasOPCR reports whether the adaptation field has OPCR.
func (af AdaptationField) HasOPCR() bool {
	return af.OPCRFlag()
}

// SplicingPointFlag returns Splicing point flag.
func (af AdaptationField) SplicingPointFlag() bool {
	i := af[1] & 0x04 >> 2
	return i == 1
}

// HasSpliceCountdown reports whether the adaptation field has splice countdown.
func (af AdaptationField) HasSpliceCountdown() bool {
	return af.SplicingPointFlag()
}

// TransportPrivateDataFlag returns Transport private data flag.
func (af AdaptationField) TransportPrivateDataFlag() bool {
	i := af[1] & 0x02 >> 1
	return i == 1
}

// HasTransportPrivateData reports whether the adaptation field has transport private data.
func (af AdaptationField) HasTransportPrivateData() bool {
	return af.TransportPrivateDataFlag()
}

// AdaptationFieldExtensionFlag returns Adaptation field extension flag.
func (af AdaptationField) AdaptationFieldExtensionFlag() bool {
	i := af[1] & 0x01
	return i == 1
}

// HasExtension reports whether the adaptation field has extension.
func (af AdaptationField) HasExtension() bool {
	return af.AdaptationFieldExtensionFlag()
}

// PCR returns Program clock reference.
func (af AdaptationField) PCR() []byte {
	if !af.HasPCR() {
		return nil
	}
	return af[2:8]
}

// OPCR returns Original program clock reference.
func (af AdaptationField) OPCR() []byte {
	if !af.HasOPCR() {
		return nil
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	high := low + 6
	return af[low:high]
}

// SpliceCountdown indicates how many TS packets from this one a splicing point occurs.
func (af AdaptationField) SpliceCountdown() int8 {
	if !af.HasSpliceCountdown() {
		return 0
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	if af.HasOPCR() {
		low += 6
	}
	// tcimsbf
	return int8(af[low])
}

// TransportPrivateDataLength returns number of bytes in the transport private data immediately following this byte.
func (af AdaptationField) TransportPrivateDataLength() int {
	if !af.HasTransportPrivateData() {
		return 0
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	if af.HasOPCR() {
		low += 6
	}
	if af.HasSpliceCountdown() {
		low++
	}
	return int(af[low])
}

// TransportPrivateData returns private data.
func (af AdaptationField) TransportPrivateData() []byte {
	if !af.HasTransportPrivateData() {
		return nil
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	if af.HasOPCR() {
		low += 6
	}
	if af.HasSpliceCountdown() {
		low++
	}
	// Transport private data length
	low++
	high := low + af.TransportPrivateDataLength()
	return af[low:high]
}

// AdaptationExtension returns Adaptation field extension.
func (af AdaptationField) AdaptationExtension() (AdaptationExtensionField, error) {
	if !af.HasExtension() {
		return nil, nil
	}
	l := af.AdaptationExtensionLength()
	if l <= 0 {
		return nil, nil
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	if af.HasOPCR() {
		low += 6
	}
	if af.HasSpliceCountdown() {
		low++
	}
	if af.HasTransportPrivateData() {
		low++ // Transport private data length
		low += af.TransportPrivateDataLength()
	}
	high := low + l
	if high > len(af) {
		return nil, io.ErrUnexpectedEOF
	}
	return AdaptationExtensionField(af[low:high]), nil
}

// AdaptationExtensionLength returns number of bytes in the adaptation extension field immediately following this byte.
func (af AdaptationField) AdaptationExtensionLength() int {
	if !af.HasExtension() {
		return 0
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	if af.HasOPCR() {
		low += 6
	}
	if af.HasSpliceCountdown() {
		low++
	}
	if af.HasTransportPrivateData() {
		low++ // Transport private data length
		low += af.TransportPrivateDataLength()
	}
	return int(af[low])
}

// TODO: methods of AdaptationExtensionField
