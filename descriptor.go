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

// Descriptor is a program element descriptor.
type Descriptor []byte

// Tag returns the descriptor_tag.
func (d Descriptor) Tag() byte {
	return d[0]
}

// Length returns the descriptor_length.
func (d Descriptor) Length() int {
	return int(d[1])
}

// Descriptors returns the descriptors from b.
func Descriptors(b []byte) []Descriptor {
	headsize := 2 // size of descriptor_tag .. descriptor_length
	var descriptors []Descriptor
	for pos := 0; pos < len(b)-crc32size; {
		size := headsize + int(b[pos+1]) // descriptor_length
		d := Descriptor(b[pos : pos+size])
		pos += len(d)
		descriptors = append(descriptors, d)
	}
	return descriptors
}
