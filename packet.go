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

// SyncByte is used to identify the start of the TS Packet.
const SyncByte = 0x47

// Packet is a Transport Stream(TS) packet.
type Packet []byte

// PID is a packet identifier, describing the payload data.
type PID uint16

// AdaptationField is an extended TS header.
type AdaptationField []byte

// AdaptationExtensionField is an extension of the adaptation field.
type AdaptationExtensionField []byte

// PCR is a Program clock reference.
type PCR []byte

// OPCR is a Original program clock reference.
type OPCR []byte

// SyncByte returns the sync_byte.
func (p Packet) SyncByte() byte {
	return p[0]
}

// TransportErrorIndicator returns the transport_error_indicator(TEI).
func (p Packet) TransportErrorIndicator() byte {
	return p[1] & 0x80 >> 7
}

// HasTransportError indicates that the packet has at least 1 uncorrectable bit error.
func (p Packet) HasTransportError() bool {
	return p.TransportErrorIndicator() == 1
}

// PayloadUnitStartIndicator returns the payload_unit_start_indicator(PUSI).
func (p Packet) PayloadUnitStartIndicator() byte {
	return p[1] & 0x40 >> 6
}

// TransportPriority returns the transport_priority.
func (p Packet) TransportPriority() byte {
	return p[1] & 0x20 >> 5
}

// PID returns the PID.
func (p Packet) PID() PID {
	return PID(uint16(p[1]&0x1f)<<8 | uint16(p[2]))
}

// TransportScramblingControl returns the transport_scrambling_control(TSC).
// - 0x00(00): not scrambled
// - 0x01(01): reserved for future use
// - 0x02(10): scrambled with even key
// - 0x03(11): scrambled with odd key
func (p Packet) TransportScramblingControl() byte {
	return p[3] & 0xc0 >> 6
}

// AdaptationFieldControl returns the adaptation_field_control.
// - 0x00(00): reserved for future use
// - 0x01(01): no adaptation field, payload only
// - 0x02(10): adaptation field only, no payload
// - 0x03(11): adaptation field followed by payload
func (p Packet) AdaptationFieldControl() byte {
	return p[3] & 0x30 >> 4
}

// HasAdaptationField reports whether the packet has the adaptation_field.
func (p Packet) HasAdaptationField() bool {
	ctrl := p.AdaptationFieldControl()
	return ctrl == 0x02 || ctrl == 0x03
}

// HasPayload reports whether the packet has payload.
func (p Packet) HasPayload() bool {
	ctrl := p.AdaptationFieldControl()
	return ctrl == 0x01 || ctrl == 0x03
}

// ContinuityCounter returns the continuity_counter.
func (p Packet) ContinuityCounter() uint8 {
	return p[3] & 0x0F
}

// AdaptationFieldLength returns the adaptation_field_length that specifying the number of bytes in the adaptation field immediately following this byte.
func (p Packet) AdaptationFieldLength() int {
	if !p.HasAdaptationField() {
		return 0
	}
	return int(p[4])
}

// AdaptationField returns the adaptation_field.
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

// IsPES reports whether the packet is Packetized Elementary Stream(PES).
func (p Packet) IsPES() bool {
	if !p.HasPayload() {
		return false
	}
	payload := p.Payload()
	if len(payload) < 3 {
		return false
	}
	return (payload[0] == 0x00 &&
		payload[1] == 0x00 &&
		payload[2] == 0x01)
}

// Length returns the adaptation_field_length that specifying the number of bytes in the adaptation field immediately following this byte.
func (af AdaptationField) Length() int {
	return int(af[0])
}

// DiscontinuityIndicator returns the discontinuity_indicator.
func (af AdaptationField) DiscontinuityIndicator() byte {
	return af[1] & 0x80 >> 7
}

// IsDiscontinuous reports whether the packet is discontinuous.
func (af AdaptationField) IsDiscontinuous() bool {
	return af.DiscontinuityIndicator() == 1
}

// RandomAccessIndicator returns the random_access_indicator.
func (af AdaptationField) RandomAccessIndicator() byte {
	return af[1] & 0x40 >> 6
}

// ElementaryStreamPriorityIndicator returns the elementary_stream_priority_indicator.
func (af AdaptationField) ElementaryStreamPriorityIndicator() byte {
	return af[1] & 0x20 >> 5
}

// PCRFlag returns the PCR_flag.
func (af AdaptationField) PCRFlag() byte {
	return af[1] & 0x10 >> 4
}

// HasPCR reports whether the adaptation field has the PCR.
func (af AdaptationField) HasPCR() bool {
	return af.PCRFlag() == 1
}

// OPCRFlag returns the OPCR_flag.
func (af AdaptationField) OPCRFlag() byte {
	return af[1] & 0x08 >> 3
}

// HasOPCR reports whether the adaptation field has the OPCR.
func (af AdaptationField) HasOPCR() bool {
	return af.OPCRFlag() == 1
}

// SplicingPointFlag returns the splicing_point_flag.
func (af AdaptationField) SplicingPointFlag() byte {
	return af[1] & 0x04 >> 2
}

// HasSpliceCountdown reports whether the adaptation field has the splice_countdown.
func (af AdaptationField) HasSpliceCountdown() bool {
	return af.SplicingPointFlag() == 1
}

// TransportPrivateDataFlag returns the transport_private_data_flag.
func (af AdaptationField) TransportPrivateDataFlag() byte {
	return af[1] & 0x02 >> 1
}

// HasTransportPrivateData reports whether the adaptation field has the private_data.
func (af AdaptationField) HasTransportPrivateData() bool {
	return af.TransportPrivateDataFlag() == 1
}

// AdaptationFieldExtensionFlag returns the adaptation_field_extension_flag.
func (af AdaptationField) AdaptationFieldExtensionFlag() byte {
	return af[1] & 0x01
}

// HasExtension reports whether the adaptation field has the extension.
func (af AdaptationField) HasExtension() bool {
	return af.AdaptationFieldExtensionFlag() == 1
}

// PCR returns the PCR.
func (af AdaptationField) PCR() PCR {
	if !af.HasPCR() {
		return nil
	}
	return PCR(af[2:8])
}

// OPCR returns the OPCR.
func (af AdaptationField) OPCR() OPCR {
	if !af.HasOPCR() {
		return nil
	}
	low := 2
	if af.HasPCR() {
		low += 6
	}
	high := low + 6
	return OPCR(af[low:high])
}

// SpliceCountdown returns the splice_countdown that indicates how many TS packets from this one a splicing point occurs.
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

// TransportPrivateDataLength returns the transport_private_data_length that indicates the number of bytes in the transport private data immediately following this byte.
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

// TransportPrivateData returns the private_data_byte.
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

// AdaptationExtension returns the AdaptationExtensionField.
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

// AdaptationExtensionLength returns the adaptation_field_extension_length that indicates the number of bytes in the adaptation extension field immediately following this byte.
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
