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
	return s.Bytes()
}
