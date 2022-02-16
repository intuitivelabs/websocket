package websocket

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
)

/*
  https://www.rfc-editor.org/rfc/rfc1951.html#page-11

    3.2.4. Non-compressed blocks (BTYPE=00)

         Any bits of input up to the next byte boundary are ignored.
         The rest of the block consists of the following information:

              0   1   2   3   4...
            +---+---+---+---+================================+
            |  LEN  | NLEN  |... LEN bytes of literal data...|
            +---+---+---+---+================================+

         LEN is the number of data bytes in the block.  NLEN is the
         one's complement of LEN.
*/
// deflate empty block
var (
	deflateNonCompressedEmptyBlock = []byte{0x00, 0x00, 0xFF, 0xFF}
)

// errors
var (
	ErrMsgOk              = errors.New("header OK")
	ErrHdrMoreBytes       = errors.New("need more bytes for WebSocket frame header")
	ErrDataMoreBytes      = errors.New("need more bytes for WebSocket frame data")
	ErrFragBufTooSmall    = errors.New("defragmentation buffer is too small")
	ErrFragCopy           = errors.New("fragment copy failure")
	ErrNotDecoded         = errors.New("frame (fragment) is not decoded")
	ErrDeflateBufTooSmall = errors.New("deflate buffer is too small")
	ErrCritical           = errors.New("critical error")
)

// A websockets message can be sent using a number of frames (by fragmenting it)
type Message struct {
	// all the message's fragments
	Frames []Frame
	// this is the index of the last read and decoded fragment
	LastFrame int
	// were all the fragments read?
	CompleteF bool
	// is the compression stateful (across the stream)?
	StatefulCompression bool
	// buffer used for internal defragmentation
	payloadBuf    []byte
	payloadBufLen int
	bufWriter     bytes.Buffer
	// low-level buffer reader (used for reading compressed input)
	bufReader *bytes.Reader
	// (de)flate reader
	flateReader io.ReadCloser
}

// NewMessage returns a pointer to a newly initialized, empty message which has at most 'maxFrames' frames and
// a payload of at most 'maxPayloadSize' bytes.
func NewMessage(maxPayloadSize, maxFrames int, statefulCompression bool) *Message {
	var frame Message = Message{
		Frames:              make([]Frame, maxFrames, maxFrames),
		LastFrame:           0,
		payloadBuf:          make([]byte, maxPayloadSize+len(deflateNonCompressedEmptyBlock), maxPayloadSize+len(deflateNonCompressedEmptyBlock)),
		payloadBufLen:       0,
		StatefulCompression: statefulCompression,
	}
	for i, _ := range frame.Frames[:] {
		frame.Frames[i].Reset()
	}
	frame.bufReader = bytes.NewReader(frame.payloadBuf)
	frame.flateReader = flate.NewReader(frame.bufReader)
	frame.bufWriter.Reset()
	return &frame
}

// Reset re-initializes all the fragments in the frame. It sets the index of
// the last decoded fragment to 0.
func (f *Message) Reset() {
	for i, _ := range f.Frames[0:f.LastFrame] {
		f.Frames[i].Reset()
	}
	f.LastFrame = 0
}

// Len returns the total length of the frame fragments (including headers)
func (f Message) Len() uint64 {
	var l uint64 = 0
	for _, frag := range f.Frames[0:f.LastFrame] {
		l += frag.Len()
	}
	return l
}

func (f Message) Compressed() bool {
	return f.Frames[0].Compressed()
}

// Complete returns true if all the message fragments were read and false otherwise
func (f Message) Complete() bool {
	return f.CompleteF
}

// Decoded returns "true" if all the fragments in the frame were decoded.
func (f Message) Decoded() bool {
	for _, frag := range f.Frames[0:f.LastFrame] {
		if !frag.Header.DecodedF {
			return false
		}
	}
	return true
}

// PayloadLen returns the total length of the frame fragments' payloads (excluding headers)
func (f Message) PayloadLen() uint64 {
	var l uint64 = 0
	for _, frag := range f.Frames[0:f.LastFrame] {
		l += frag.Header.PayloadLen
	}
	return l
}

func (f *Message) NextFragment() *Frame {
	if f.LastFrame >= len(f.Frames) {
		fragments := make([]Frame, len(f.Frames), len(f.Frames))
		f.Frames = append(f.Frames, fragments...)
	}
	fragment := &f.Frames[f.LastFrame]
	f.LastFrame++
	return fragment
}

func (f *Message) DropFragment() {
	if f.LastFrame > 0 {
		f.LastFrame--
	}
	f.Frames[f.LastFrame].Reset()
}

// Decode decodes fragments from the input buffer "b" starting at "offset"; "mask" flag controls if the
// masking should be performed on the payload.
// Once decoded fragments are stored in the "Message" and can be further processed.
// For example here is how to iterate over the fragments in a frame:
//
// 	func (f Message) DumpPayloadDataIterator(buf []byte) {
//		for _, frag := range f.Frames[0:f.LastFrame] {
//			fmt.Printf("payload data:%v\n", frag.PayloadDataPf.Get(buf))
//      }
//	}
//
// In case of success it returns the offset where the new fragment should start and the error "ErrMsgOk"
// In case of failure it returns the value of the input parameter "offset" and either of the errors:
// "ErrHdrMoreBytes", "ErrDataMoreBytes" meaning that more data is needed for decoding the frame
func (f *Message) Decode(b []byte, offset int, mask bool) (int, error) {
	var (
		err error
	)
	for {
		fragment := f.NextFragment()
		if offset, err = fragment.Decode(b, offset, mask); err != ErrMsgOk {
			fmt.Println("err: ", err)
			f.DropFragment()
			break
		}
		// control frames may be injected in between fragments
		if fragment.Ctrl() {
			f.DropFragment()
			continue
		}
		if err == nil || err == ErrMsgOk {
			if fragment.Last() {
				// it is either a stand-alone frame or it is the last fragment of the frame
				fmt.Printf("either not fragmented or last fragment\n")
				f.CompleteF = true
				break
			}
			// try to read next fragment
			continue
		}
	}
	return offset, err
}

// Mask uses xor encryption for masking all fragment payloads which are part of this frame.
// Warning: it overwrites input memory.
// See: https://www.rfc-editor.org/rfc/rfc6455.html#section-5.3
func (f *Message) Mask(buf []byte) {
	for _, frag := range f.Frames[0:f.LastFrame] {
		frag.Mask(buf)
	}
}

// FragmentCount returns the number of fragments in this frame
func (f Message) FragmentCount() int {
	return f.LastFrame
}

// Defragment unmasks fragments which were decoded from the "src" buffer and copies their payload
// data into "dst" memory buffer. If there is only one fragment, no copy is performed.
// It returns the buffer containing the unmasked payload data, its length and error if the operation
// could not be performed correctly.
func (f *Message) Defragment(dst, src []byte) ([]byte, int, error) {
	if !f.Decoded() {
		return nil, 0, ErrNotDecoded
	}
	f.Mask(src)
	if len(f.Frames) == 1 {
		// only one fragment
		return f.Frames[0].PayloadDataPf.Get(src), int(f.Frames[0].PayloadDataPf.Len), nil
	}
	if int(f.PayloadLen()) > len(dst) {
		return nil, 0, ErrFragBufTooSmall
	}
	offset := 0
	for _, frag := range f.Frames[0:f.LastFrame] {
		slice := frag.PayloadDataPf.Get(src)
		n := copy(dst[offset:], slice)
		if n < int(frag.Header.PayloadLen) {
			return nil, 0, ErrFragCopy
		}
		offset += n
	}
	return dst, offset, nil
}

// PayloadDataRaw returns the raw frame payload data without applying any Per-Message Extensions algorithm (i.e. PCME).
func (f *Message) PayloadDataRaw(dst, src []byte) ([]byte, int, error) {
	return f.Defragment(dst, src)
}

// PayloadData returns the raw frame payload data after applying Per-Message Compression Extension.
func (f *Message) PayloadData(dst, src []byte) ([]byte, int, error) {
	if f.Compressed() {
		var err error
		if _, f.payloadBufLen, err = f.Defragment(f.payloadBuf, src); err != nil {
			return nil, 0, err
		}
		//fmt.Printf("payload: % x\n", f.payloadBuf[0:f.payloadBufLen])
		return f.Deflate()
	}
	return f.Defragment(dst, src)
}

/*
  https://www.rfc-editor.org/rfc/rfc7692.html#section-7.2.2


	7.2.2.  Decompression

	   An endpoint uses the following algorithm to decompress a message.

	   1.  Append 4 octets of 0x00 0x00 0xff 0xff to the tail end of the
		   payload of the message.

	   2.  Decompress the resulting data using DEFLATE.

	   If the "agreed parameters" contain the "server_no_context_takeover"
	   extension parameter, the client MAY decompress each new message with
	   an empty LZ77 sliding window.  Otherwise, the client MUST decompress
	   each new message using the LZ77 sliding window used to process the
	   last compressed message.

	   If the "agreed parameters" contain the "client_no_context_takeover"
	   extension parameter, the server MAY decompress each new message with
	   an empty LZ77 sliding window.  Otherwise, the server MUST decompress
	   each new message using the LZ77 sliding window used to process the
	   last compressed message.  Note that even if the client has included
	   the "client_no_context_takeover" extension parameter in its offer,
	   the server MUST decompress each new message using the LZ77 sliding
	   window used to process the last compressed message if the "agreed
	   parameters" don't contain the "client_no_context_takeover" extension
	   parameter.  The client-to-server "client_no_context_takeover"
	   extension parameter is just a hint for the server to build an
	   extension negotiation response.

*/
// Deflate decompresses the frame using PCME
func (f *Message) Deflate() ([]byte, int, error) {
	if len(f.payloadBuf[f.payloadBufLen:]) < len(deflateNonCompressedEmptyBlock) {
		return nil, 0, ErrDeflateBufTooSmall
	}
	copy(f.payloadBuf[f.payloadBufLen:], deflateNonCompressedEmptyBlock)
	//fmt.Printf("payload: % x\n", f.payloadBuf[0:f.payloadBufLen+len(deflateNonCompressedEmptyBlock)])
	f.bufReader.Reset(f.payloadBuf[0 : f.payloadBufLen+len(deflateNonCompressedEmptyBlock)])
	if f.StatefulCompression {
		f.flateReader.(flate.Resetter).Reset(f.bufReader, f.bufWriter.Bytes())
	} else {
		f.flateReader.(flate.Resetter).Reset(f.bufReader, nil)
		f.bufWriter.Reset()
	}
	l, err := io.Copy(&f.bufWriter, f.flateReader)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, 0, fmt.Errorf("frame deflate error: %w", err)
	}
	//fmt.Printf("copied %d bytes\n", l)
	return f.bufWriter.Bytes(), int(l), err
}
