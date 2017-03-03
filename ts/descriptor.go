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

// Tags for descriptor.
const (
	TagVideoStream                  DescriptorTag = 0x02 // video_stream_descriptor
	TagAudioStream                  DescriptorTag = 0x03 // audio_stream_descriptor
	TagHierarchy                    DescriptorTag = 0x04 // hierarchy_descriptor
	TagRegistration                 DescriptorTag = 0x05 // registration_descriptor
	TagDataStreamAlignment          DescriptorTag = 0x06 // data_stream_alignment_descriptor
	TagTargetBackgroundGrid         DescriptorTag = 0x07 // target_background_grid_descriptor
	TagVideoWindow                  DescriptorTag = 0x08 // video_window_descriptor
	TagCA                           DescriptorTag = 0x09 // CA_descriptor
	TagISO639Language               DescriptorTag = 0x0A // ISO_639_language_descriptor
	TagSystemClock                  DescriptorTag = 0x0B // system_clock_descriptor
	TagMultiplexBufferUtilization   DescriptorTag = 0x0C // multiplex_buffer_utilization_descriptor
	TagCopyright                    DescriptorTag = 0x0D // copyright_descriptor
	TagMaximumBitrate               DescriptorTag = 0x0E // maximum_bitrate_descriptor
	TagPrivateDataIndicator         DescriptorTag = 0x0F // private_data_indicator_descriptor
	TagSmoothingBuffer              DescriptorTag = 0x10 // smoothing_buffer_descriptor
	TagSTD                          DescriptorTag = 0x11 // STD_descriptor
	TagIBP                          DescriptorTag = 0x12 // IBP_descriptor
	TagMPEG4Video                   DescriptorTag = 0x1B // MPEG-4_video_descriptor
	TagMPEG4Audio                   DescriptorTag = 0x1C // MPEG-4_audio_descriptor
	TagIOD                          DescriptorTag = 0x1D // IOD_descriptor
	TagSL                           DescriptorTag = 0x1E // SL_descriptor
	TagFMC                          DescriptorTag = 0x1F // FMC_descriptor
	TagExternalESID                 DescriptorTag = 0x20 // external_ES_ID_descriptor
	TagMuxCode                      DescriptorTag = 0x21 // MuxCode_descriptor
	TagFmxBufferSize                DescriptorTag = 0x22 // FmxBufferSize_descriptor
	TagMultiplexbuffer              DescriptorTag = 0x23 // multiplexbuffer_descriptor
	TagContentLabeling              DescriptorTag = 0x24 // content_labeling_descriptor
	TagMetadataPointer              DescriptorTag = 0x25 // metadata_pointer_descriptor
	TagMetadata                     DescriptorTag = 0x26 // metadata_descriptor
	TagMetadataSTD                  DescriptorTag = 0x27 // metadata_STD_descriptor
	TagAVCVideo                     DescriptorTag = 0x28 // AVC video descriptor
	TagIPMP                         DescriptorTag = 0x29 // IPMP_descriptor
	TagAVCTimingAndHRD              DescriptorTag = 0x2A // AVC timing and HRD descriptor
	TagMPEG2AACAudio                DescriptorTag = 0x2B // MPEG-2_AAC_audio_descriptor
	TagFlexMuxTiming                DescriptorTag = 0x2C // FlexMuxTiming_descriptor
	TagMPEG4Text                    DescriptorTag = 0x2D // MPEG-4_text_descriptor
	TagMPEG4AudioExtension          DescriptorTag = 0x2E // MPEG-4_audio_extension_descriptor
	TagAuxiliaryVideoStream         DescriptorTag = 0x2F // auxiliary_video_stream_descriptor
	TagSVCExtension                 DescriptorTag = 0x30 // SVC extension descriptor
	TagMVCExtension                 DescriptorTag = 0x31 // MVC extension descriptor
	TagJ2KVideo                     DescriptorTag = 0x32 // J2K video descriptor
	TagMVCOperationPoint            DescriptorTag = 0x33 // MVC operation point descriptor
	TagMPEG2StereoscopicVideoFormat DescriptorTag = 0x34 // MPEG2_stereoscopic_video_format_descriptor
	TagStereoscopicProgramInfo      DescriptorTag = 0x35 // Stereoscopic_program_info_descriptor
	TagStereoscopicVideoInfo        DescriptorTag = 0x36 // Stereoscopic_video_info_descriptor
	// 0x13 .. 0x1A Defined in ISO/IEC 13818-6
	// 0x37 .. 0x3F Rec. ITU-T H.222.0 | ISO/IEC 13818-1 Reserved
	// 0x40 .. 0xFF User Private
)

// Descriptor is a program element descriptor.
type Descriptor []byte

// DescriptorTag identifies each descriptor.
type DescriptorTag byte

// Tag returns the descriptor_tag.
func (d Descriptor) Tag() DescriptorTag {
	return DescriptorTag(d[0])
}

// Length returns the descriptor_length.
func (d Descriptor) Length() int {
	return int(d[1])
}

// Descriptors returns the descriptors from b.
func Descriptors(b []byte) []Descriptor {
	headsize := 2 // size of descriptor_tag .. descriptor_length
	var descriptors []Descriptor
	for pos := 0; pos < len(b); {
		size := headsize + Descriptor(b[pos:]).Length()
		d := Descriptor(b[pos : pos+size])
		pos += len(d)
		descriptors = append(descriptors, d)
	}
	return descriptors
}
