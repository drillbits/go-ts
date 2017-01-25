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
	"bytes"
	"io"
	"testing"
)

func appendBytes(bs ...[]byte) []byte {
	var buf []byte
	for _, b := range bs {
		buf = append(buf, b...)
	}
	return buf
}

func bx(b []byte, times int) []byte {
	var buf []byte
	for i := 0; i < times; i++ {
		buf = append(buf, b...)
	}
	return buf
}

func TestPacketSyncByte(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp byte
	}{
		{Packet{0x47, 0x01, 0x11, 0x37}, 0x47},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.SyncByte()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b SyncByte() => 0x%X, want 0x%X", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketTransportErrorIndicator(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp bool
	}{
		{Packet{0x47, 0x80}, true},
		{Packet{0x47, 0x00}, false},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.TransportErrorIndicator()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b TransportErrorIndicator() => %t, want %t", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketPayloadUnitStartIndicator(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp bool
	}{
		{Packet{0x47, 0x40}, true},
		{Packet{0x47, 0x00}, false},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.PayloadUnitStartIndicator()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b PayloadUnitStartIndicator() => %t, want %t", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketTransportPriority(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp bool
	}{
		{Packet{0x47, 0x20}, true},
		{Packet{0x47, 0x00}, false},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.TransportPriority()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b TransportPriority() => %t, want %t", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketPID(t *testing.T) {
	p := Packet{0x47, 0x01, 0x11, 0x37}
	exp := PID(0x111)

	got := p.PID()
	if got != exp {
		t.Errorf("Packet %08b PID() => %#v, want %#v", p, got, exp)
	}
}

func TestPacketTransportScramblingControl(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp byte
	}{
		{Packet{0x47, 0x01, 0x11, 0x37}, 0x00},
		{Packet{0x47, 0x01, 0x11, 0x77}, 0x01},
		{Packet{0x47, 0x01, 0x11, 0xb7}, 0x02},
		{Packet{0x47, 0x01, 0x11, 0xf7}, 0x03},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.TransportScramblingControl()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b TransportScramblingControl() => %02b, want %02b", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketAdaptationFieldControl(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp byte
	}{
		{Packet{0x47, 0x01, 0x11, 0x00}, 0x00},
		{Packet{0x47, 0x01, 0x11, 0x10}, 0x01},
		{Packet{0x47, 0x01, 0x11, 0x20}, 0x02},
		{Packet{0x47, 0x01, 0x11, 0x30}, 0x03},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.AdaptationFieldControl()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b AdaptationFieldControl() => %02b, want %02b", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketHasAdaptationField(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp bool
	}{
		{Packet{0x47, 0x01, 0x11, 0x00}, false},
		{Packet{0x47, 0x01, 0x11, 0x10}, false},
		{Packet{0x47, 0x01, 0x11, 0x20}, true},
		{Packet{0x47, 0x01, 0x11, 0x30}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.HasAdaptationField()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b HasAdaptationField() => %t, want %t", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketPayloadFlag(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp bool
	}{
		{Packet{0x47, 0x01, 0x11, 0x00}, false},
		{Packet{0x47, 0x01, 0x11, 0x10}, true},
		{Packet{0x47, 0x01, 0x11, 0x20}, false},
		{Packet{0x47, 0x01, 0x11, 0x30}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.HasPayload()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b HasPayload() => %t, want %t", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketContinuityCounter(t *testing.T) {
	p := Packet{0x47, 0x01, 0x11, 0x37}
	var exp uint8 = 7

	got := p.ContinuityCounter()
	if got != exp {
		t.Errorf("Packet %08b ContinuityCounter() => %d, want %d", p, got, exp)
	}
}

func TestPacketAdaptationFieldLength(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp int
	}{
		{Packet{0x47, 0x01, 0x11, 0x37, 0x01}, 1},
		{Packet{0x47, 0x01, 0x11, 0x37, 0x00}, 0},
		{Packet{0x47, 0x01, 0x11, 0x10, 0x01}, 0},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.p.AdaptationFieldLength()
			if got != tc.exp {
				t.Errorf("%0d: Packet %08b AdaptationFieldLength() => %d, want %d", i, tc.p, got, tc.exp)
			}
		})
	}
}

func TestPacketAdaptationField(t *testing.T) {
	for i, tc := range []struct {
		p   Packet
		exp AdaptationField
		err error
	}{
		{
			p:   Packet{0x47, 0x01, 0x11, 0x37, 0x01, 0x10},
			exp: AdaptationField{0x01, 0x10},
			err: nil,
		},
		{
			p:   Packet{0x47, 0x01, 0x11, 0x37, 0x00, 0x10},
			exp: nil,
			err: nil,
		},
		{
			p:   Packet{0x47, 0x01, 0x11, 0x10, 0x01, 0x10},
			exp: nil,
			err: nil,
		},
		{
			p:   Packet{0x47, 0x01, 0x11, 0x37, 0x02, 0x10},
			exp: nil,
			err: io.ErrUnexpectedEOF,
		},
		{
			p:   Packet{0x47, 0x01, 0x11, 0x37, 0x03, 0x10},
			exp: nil,
			err: io.ErrUnexpectedEOF,
		},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got, err := tc.p.AdaptationField()
			if err != tc.err {
				t.Errorf("%0d: Packet %08b AdaptationField() causes %s, want %s", i, tc.p, err, tc.err)
			}
			if !bytes.Equal(got, tc.exp) {
				t.Errorf("%0d: Packet %08b AdaptationField() => %#v, want %#v", i, tc.p, got, tc.exp)
			}
		})
	}
}

// TODO
func TestPacketPayload(t *testing.T) {}

func TestAdaptationFieldAdaptationFieldLength(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp int
	}{
		{AdaptationField{0xB7}, 183},
		{AdaptationField{0x00}, 0},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.Length()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b Length() => %d, want %d", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestDiscontinuityIndicator(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0x7F}, false},
		{AdaptationField{0xB7, 0x80}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.DiscontinuityIndicator()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b DiscontinuityIndicator() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestRandomAccessIndicator(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xBF}, false},
		{AdaptationField{0xB7, 0x40}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.RandomAccessIndicator()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b RandomAccessIndicator() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestElementaryStreamPriorityIndicator(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xDF}, false},
		{AdaptationField{0xB7, 0x20}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.ElementaryStreamPriorityIndicator()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b ElementaryStreamPriorityIndicator() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestHasPCR(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xEF}, false},
		{AdaptationField{0xB7, 0x10}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.HasPCR()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b HasPCR() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestHasOPCR(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xE7}, false},
		{AdaptationField{0xB7, 0x08}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.HasOPCR()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b HasOPCR() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestHasSpliceCountdown(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xFB}, false},
		{AdaptationField{0xB7, 0x04}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.HasSpliceCountdown()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b HasSpliceCountdown() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestHasTransportPrivateData(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xFD}, false},
		{AdaptationField{0xB7, 0x02}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.HasTransportPrivateData()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b HasTransportPrivateData() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestAdaptationFieldHasExtension(t *testing.T) {
	for i, tc := range []struct {
		af  AdaptationField
		exp bool
	}{
		{AdaptationField{0xB7, 0xFE}, false},
		{AdaptationField{0xB7, 0x01}, true},
	} {
		i, tc := i, tc
		t.Run("", func(t *testing.T) {
			t.Parallel()

			got := tc.af.HasExtension()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b HasExtension() => %t, want %t", i, tc.af, got, tc.exp)
			}
		})
	}
}

func TestPCR(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}

	for i, tc := range []struct {
		name string
		ctrl byte
		pcr  []byte
		opcr []byte
		exp  []byte
	}{
		{"Only PCR", 0x10, pcr, nil, pcr},
		{"Only OPCR", 0x08, nil, opcr, nil},
		{"PCR & OPCR", 0x18, pcr, opcr, pcr},
		{"No PCR No OPCR", 0x00, nil, nil, nil},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			got := af.PCR()
			if !bytes.Equal(got, tc.exp) {
				t.Errorf("%0d: AdaptationField %08b PCR() => 0x%X, want 0x%X", i, af, got, tc.exp)
			}
		})
	}
}

func TestOPCR(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}

	for i, tc := range []struct {
		name string
		ctrl byte
		pcr  []byte
		opcr []byte
		exp  []byte
	}{
		{"Only PCR", 0x10, pcr, nil, nil},
		{"Only OPCR", 0x08, nil, opcr, opcr},
		{"PCR & OPCR", 0x18, pcr, opcr, opcr},
		{"No PCR No OPCR", 0x00, nil, nil, nil},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			got := af.OPCR()
			if !bytes.Equal(got, tc.exp) {
				t.Errorf("%0d: AdaptationField %08b OPCR() => 0x%X, want 0x%X", i, af, got, tc.exp)
			}
		})
	}
}

func TestSpliceCountdown(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	sc := int8(0xD)

	for i, tc := range []struct {
		name string
		ctrl byte
		pcr  []byte
		opcr []byte
		sc   []byte
		exp  int8
	}{
		{"Only PCR",
			0x10, pcr, nil, nil, 0},
		{"Only OPCR",
			0x08, nil, opcr, nil, 0},
		{"Only SC",
			0x04, nil, nil, []byte{byte(sc)}, sc},
		{"PCR & SC",
			0x14, pcr, nil, []byte{byte(sc)}, sc},
		{"OPCR & SC",
			0x0C, nil, opcr, []byte{byte(sc)}, sc},
		{"PCR & OPCR & SC",
			0x1C, pcr, opcr, []byte{byte(sc)}, sc},
		{"No PCR No OPCR No SC",
			0x00, nil, nil, nil, 0},
		{"tcimsbf",
			0x04, nil, nil, []byte{0xF9}, int8(-7)},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			if tc.sc != nil {
				af = append(af, tc.sc...)
			}
			got := af.SpliceCountdown()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b SpliceCountdown() => 0x%X, want 0x%X", i, af, got, tc.exp)
			}
		})
	}
}

func TestTransportPrivateDataLength(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	sc := byte(0xD)
	tpLen := 13

	for i, tc := range []struct {
		name  string
		ctrl  byte
		pcr   []byte
		opcr  []byte
		sc    []byte
		tpLen []byte
		exp   int
	}{
		{"With PCR",
			0x12, pcr, nil, nil, []byte{byte(tpLen)}, tpLen},
		{"With OPCR",
			0x0A, nil, opcr, nil, []byte{byte(tpLen)}, tpLen},
		{"With SC",
			0x06, nil, nil, []byte{sc}, []byte{byte(tpLen)}, tpLen},
		{"With PCR & OPCR",
			0x1A, pcr, opcr, nil, []byte{byte(tpLen)}, tpLen},
		{"With PCR & OPCR & SC",
			0x1E, pcr, opcr, []byte{sc}, []byte{byte(tpLen)}, tpLen},
		{"With PCR & SC",
			0x16, pcr, nil, []byte{sc}, []byte{byte(tpLen)}, tpLen},
		{"With OPCR & SC",
			0x0E, nil, opcr, []byte{sc}, []byte{byte(tpLen)}, tpLen},
		{"No PCR No OPCR No SC",
			0x02, nil, nil, nil, []byte{byte(tpLen)}, tpLen},
		{"None",
			0x00, nil, nil, nil, nil, 0},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			if tc.sc != nil {
				af = append(af, tc.sc...)
			}
			if tc.tpLen != nil {
				af = append(af, tc.tpLen...)
			}
			got := af.TransportPrivateDataLength()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b TransportPrivateDataLength() => %d, want %d", i, af, got, tc.exp)
			}
		})
	}
}

func TestTransportPrivateData(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	sc := byte(0xD)
	tpLen := 1
	tp := []byte{0x47}

	for i, tc := range []struct {
		name  string
		ctrl  byte
		pcr   []byte
		opcr  []byte
		sc    []byte
		tpLen []byte
		tp    []byte
		exp   []byte
	}{
		{"With PCR",
			0x12, pcr, nil, nil, []byte{byte(tpLen)}, tp, tp},
		{"With OPCR",
			0x0A, nil, opcr, nil, []byte{byte(tpLen)}, tp, tp},
		{"With SC",
			0x06, nil, nil, []byte{sc}, []byte{byte(tpLen)}, tp, tp},
		{"With PCR & OPCR",
			0x1A, pcr, opcr, nil, []byte{byte(tpLen)}, tp, tp},
		{"With PCR & OPCR & SC",
			0x1E, pcr, opcr, []byte{sc}, []byte{byte(tpLen)}, tp, tp},
		{"With PCR & SC",
			0x16, pcr, nil, []byte{sc}, []byte{byte(tpLen)}, tp, tp},
		{"With OPCR & SC",
			0x0E, nil, opcr, []byte{sc}, []byte{byte(tpLen)}, tp, tp},
		{"No PCR No OPCR No SC",
			0x02, nil, nil, nil, []byte{byte(tpLen)}, tp, tp},
		{"None",
			0x00, nil, nil, nil, nil, nil, nil},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			if tc.sc != nil {
				af = append(af, tc.sc...)
			}
			if tc.tpLen != nil {
				af = append(af, tc.tpLen...)
			}
			if tc.tp != nil {
				af = append(af, tc.tp...)
			}
			got := af.TransportPrivateData()
			if !bytes.Equal(got, tc.exp) {
				t.Errorf("%0d: AdaptationField %08b TransportPrivateData() => 0x%X, want 0x%X", i, af, got, tc.exp)
			}
		})
	}
}

// TODO

func TestAdaptationExtension(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	sc := byte(0xD)
	tpLen := 1
	tp := []byte{0x47}
	ae := []byte{0x02, 0xAA}

	for i, tc := range []struct {
		name  string
		ctrl  byte
		pcr   []byte
		opcr  []byte
		sc    []byte
		tpLen []byte
		tp    []byte
		ae    AdaptationExtensionField
		exp   AdaptationExtensionField
		err   error
	}{
		{"With PCR",
			0x11, pcr, nil, nil, nil, nil, ae, ae, nil},
		{"With OPCR",
			0x09, nil, opcr, nil, nil, nil, ae, ae, nil},
		{"With SC",
			0x05, nil, nil, []byte{sc}, nil, nil, ae, ae, nil},
		{"With TP",
			0x03, nil, nil, nil, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"With PCR & OPCR",
			0x19, pcr, opcr, nil, nil, nil, ae, ae, nil},
		{"With PCR & OPCR & SC",
			0x1D, pcr, opcr, []byte{sc}, nil, nil, ae, ae, nil},
		{"With PCR & OPCR & SC & TP",
			0x1F, pcr, opcr, []byte{sc}, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"With PCR & SC",
			0x15, pcr, nil, []byte{sc}, nil, nil, ae, ae, nil},
		{"With PCR & TP",
			0x13, pcr, nil, nil, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"With PCR & SC & TP",
			0x17, pcr, nil, []byte{sc}, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"With OPCR & SC",
			0x0D, nil, opcr, []byte{sc}, nil, nil, ae, ae, nil},
		{"With OPCR & TP",
			0x0B, nil, opcr, nil, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"With OPCR & SC & TP",
			0x0F, nil, opcr, []byte{sc}, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"With SC & TP",
			0x07, nil, nil, []byte{sc}, []byte{byte(tpLen)}, tp, ae, ae, nil},
		{"No PCR No OPCR No SC No TP",
			0x01, nil, nil, nil, nil, nil, ae, ae, nil},
		{"None",
			0x00, nil, nil, nil, nil, nil, nil, nil, nil},
		{"With error",
			0x01, nil, nil, nil, nil, nil, []byte{0x02}, nil, io.ErrUnexpectedEOF},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			if tc.sc != nil {
				af = append(af, tc.sc...)
			}
			if tc.tpLen != nil {
				af = append(af, tc.tpLen...)
			}
			if tc.tp != nil {
				af = append(af, tc.tp...)
			}
			if tc.ae != nil {
				af = append(af, tc.ae...)
			}
			got, err := af.AdaptationExtension()
			if err != tc.err {
				t.Errorf("%0d: AdaptationField %08b AdaptationExtension() causes %s, want %s", i, af, err, tc.err)
			}
			if !bytes.Equal(got, tc.exp) {
				t.Errorf("%0d: AdaptationField %08b AdaptationExtension() => 0x%X, want 0x%X", i, af, got, tc.exp)
			}
		})
	}
}

func TestAdaptationExtensionLength(t *testing.T) {
	afLen := byte(0x7B)
	pcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	opcr := []byte{0x7A, 0x34, 0x0F, 0x14, 0x7E, 0x78}
	sc := byte(0xD)
	tpLen := 1
	tp := []byte{0x47}
	ae := []byte{0x02, 0xAA}
	aeLen := 2

	for i, tc := range []struct {
		name  string
		ctrl  byte
		pcr   []byte
		opcr  []byte
		sc    []byte
		tpLen []byte
		tp    []byte
		ae    AdaptationExtensionField
		exp   int
	}{
		{"With PCR",
			0x11, pcr, nil, nil, nil, nil, ae, aeLen},
		{"With OPCR",
			0x09, nil, opcr, nil, nil, nil, ae, aeLen},
		{"With SC",
			0x05, nil, nil, []byte{sc}, nil, nil, ae, aeLen},
		{"With TP",
			0x03, nil, nil, nil, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"With PCR & OPCR",
			0x19, pcr, opcr, nil, nil, nil, ae, aeLen},
		{"With PCR & OPCR & SC",
			0x1D, pcr, opcr, []byte{sc}, nil, nil, ae, aeLen},
		{"With PCR & OPCR & SC & TP",
			0x1F, pcr, opcr, []byte{sc}, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"With PCR & SC",
			0x15, pcr, nil, []byte{sc}, nil, nil, ae, aeLen},
		{"With PCR & TP",
			0x13, pcr, nil, nil, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"With PCR & SC & TP",
			0x17, pcr, nil, []byte{sc}, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"With OPCR & SC",
			0x0D, nil, opcr, []byte{sc}, nil, nil, ae, aeLen},
		{"With OPCR & TP",
			0x0B, nil, opcr, nil, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"With OPCR & SC & TP",
			0x0F, nil, opcr, []byte{sc}, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"With SC & TP",
			0x07, nil, nil, []byte{sc}, []byte{byte(tpLen)}, tp, ae, aeLen},
		{"No PCR No OPCR No SC No TP",
			0x01, nil, nil, nil, nil, nil, ae, aeLen},
		{"None",
			0x00, nil, nil, nil, nil, nil, nil, 0},
	} {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			af := AdaptationField{afLen, tc.ctrl}
			if tc.pcr != nil {
				af = append(af, tc.pcr...)
			}
			if tc.opcr != nil {
				af = append(af, tc.opcr...)
			}
			if tc.sc != nil {
				af = append(af, tc.sc...)
			}
			if tc.tpLen != nil {
				af = append(af, tc.tpLen...)
			}
			if tc.tp != nil {
				af = append(af, tc.tp...)
			}
			if tc.ae != nil {
				af = append(af, tc.ae...)
			}
			got := af.AdaptationExtensionLength()
			if got != tc.exp {
				t.Errorf("%0d: AdaptationField %08b AdaptationExtensionLength() => %d, want %d", i, af, got, tc.exp)
			}
		})
	}
}
