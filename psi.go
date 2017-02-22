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
	"encoding/binary"
	"errors"
)

const crc32size = 4

var (
	// ErrTooShort is passed to panic if bytes too short to assign.
	ErrTooShort = errors.New("ts: bytes too short")

	// ErrNoNetworkID is returned when no network_PID was found for a given PAT.
	ErrNoNetworkID = errors.New("ts: no network_PID")
)

// PSI is a Program Specific Information.
type PSI []byte

// TableID is a table_id which identifies the contents of a transport stream
// section as shown below.
// - 0x00: program_association_section
// - 0x01: conditional_access_section
// - 0x02: TS_program_map_section
// - 0x03: TS_description_section
// - 0x04: ISO_IEC_14496_scene_description_section
// - 0x05: ISO_IEC_14496_object_descriptor_section
// - 0x06: Metadata_section
// - 0x07: IPMP_Control_Information_section (defined in ISO/IEC 13818-11)
// - 0x08-0x3F: Rec. ITU-T H.222.0 | ISO/IEC 13818-1 reserved
// - 0x40-0xFE: User private
// - 0xFF: Forbidden
type TableID byte

// CRC32 is a CRC value.
type CRC32 []byte

// TransportStreamID is a transport_stream_id which serves as a label to
// identify this transport stream from any other multiplex within a network.
// Its value is defined by the user.
type TransportStreamID uint16

// ProgramNumber is a program_number. It specifies the program to which
// the program_map_PID is applicable.
type ProgramNumber uint16

// TableID returns the TableID.
func (p PSI) TableID() TableID {
	return TableID(p[0])
}

// SectionSyntaxIndicator returns the section_syntax_indicator.
func (p PSI) SectionSyntaxIndicator() byte {
	return p[1] & 0x80 >> 7
}

// SectionLength returns the section_length.
func (p PSI) SectionLength() int {
	return int(uint16(p[2]) | uint16(p[1]&0x0F)<<8)
}

// CRC32 returns the CRC32
func (p PSI) CRC32() CRC32 {
	return CRC32(p[len(p)-4:])
}

// PAT is a Program Association Table.
type PAT PSI

// NewPAT returns a new PAT.
func NewPAT(b []byte) (PAT, error) {
	minsize := 12
	if len(b) < minsize {
		return nil, ErrTooShort
	}
	return PAT(b), nil
}

// TransportStreamID returns the TransportStreamID.
func (t PAT) TransportStreamID() TransportStreamID {
	return TransportStreamID(binary.BigEndian.Uint16(t[3:5]))
}

// VersionNumber returns the version_number.
func (t PAT) VersionNumber() int {
	return versionNumber(t)
}

// CurrentNextIndicator returns the current_next_indicator.
func (t PAT) CurrentNextIndicator() byte {
	return currentNextIndicator(t)
}

// SectionNumber returns the section_number.
func (t PAT) SectionNumber() byte {
	return sectionNumber(t)
}

// LastSectionNumber returns the last_section_number.
func (t PAT) LastSectionNumber() byte {
	return lastSectionNumber(t)
}

type assoc []byte

func (a assoc) number() ProgramNumber {
	return ProgramNumber(binary.BigEndian.Uint16(a[:2]))
}

func (a assoc) pid() PID {
	return PID(uint16(a[3]) | uint16(a[2]&0x1f)<<8)
}

func (t PAT) associations() []assoc {
	var associations []assoc
	pos := 8
	fixedsize := 5 // transport_stream_id .. last_section_number
	n := (PSI(t).SectionLength() - fixedsize - crc32size) / 4
	for i := 0; i < n; i++ {
		a := assoc(t[pos : pos+4])
		pos += len(a)
		associations = append(associations, a)
	}
	return associations
}

// NetworkPID returns the network_PID.
func (t PAT) NetworkPID() (PID, error) {
	for _, a := range t.associations() {
		if a.number() == 0x00000 {
			return a.pid(), nil
		}
	}
	return 0, ErrNoNetworkID
}

// ProgramPIDMap returns the PID mapping for PMT.
func (t PAT) ProgramPIDMap() map[ProgramNumber]PID {
	m := make(map[ProgramNumber]PID)
	for _, a := range t.associations() {
		if a.number() != 0x00000 {
			m[a.number()] = a.pid()
		}
	}
	return m
}

// CAT is a Conditional Access Table.
type CAT PSI

// NewCAT returns a new CAT.
func NewCAT(b []byte) (CAT, error) {
	minsize := 12
	if len(b) < minsize {
		return nil, ErrTooShort
	}
	return CAT(b), nil
}

// VersionNumber returns the version_number.
func (t CAT) VersionNumber() int {
	return versionNumber(t)
}

// CurrentNextIndicator returns the current_next_indicator.
func (t CAT) CurrentNextIndicator() byte {
	return currentNextIndicator(t)
}

// SectionNumber returns the section_number.
func (t CAT) SectionNumber() byte {
	return sectionNumber(t)
}

// LastSectionNumber returns the last_section_number.
func (t CAT) LastSectionNumber() byte {
	return lastSectionNumber(t)
}

// Descriptors returns the descriptors.
func (t CAT) Descriptors() []Descriptor {
	return Descriptors(t[8:])
}
