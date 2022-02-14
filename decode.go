package websocket

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"github.com/intuitivelabs/httpsp"
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
	ErrHdrOk           = errors.New("header OK")
	ErrHdrMoreBytes    = errors.New("need more bytes for WebSocket frame header")
	ErrDataMoreBytes   = errors.New("need more bytes for WebSocket frame data")
	ErrFragBufTooSmall = errors.New("defragmentation buffer is too small")
	ErrFragCopy        = errors.New("fragment copy failure")
	ErrNotDecoded      = errors.New("frame (fragment) is not decoded")
	ErrCritical        = errors.New("critical error")
)

// Fin, Reserved flags & opcode bitmask
const (
	Rsv3F    uint8 = 1 << (iota + 4)
	Rsv2F    uint8 = 1 << (iota + 4)
	Rsv1F    uint8 = 1 << (iota + 4)
	FinF     uint8 = 1 << (iota + 4)
	OpcodeBM uint8 = 0x0F
)

// Mask flag & payload bitmask
const (
	MaskingF     uint8 = 1 << 7
	PayloadLenBM uint8 = 0x7F
)

// Frame length
const (
	MinFrameLen     = 2   // bytes
	Max64KFrameLen  = 126 // length is encoded on 16 bits; maximum frame length is 64 KB
	Max16EBFrameLen = 127 // length is encoded on 64 bits; maximum frame length is 16EiB (exbibyte)
)

// opcodes
const (
	ContOp = iota
	TxtOp
	BinOp
	Rsv3Op
	Rsv4Op
	Rsv5Op
	Rsv6Op
	Rsv7Op
	CloseOp
	PingOp
	PongOp
	RsvBOp
	RsvCOp
	RsvDOp
	RsvEOp
	RsvFOp
)

/*
   Header of an WebSocket frame
   see https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2
*/
type Header struct {
	// mark that the header was fully decoded
	DecodedF bool
	// fields from the actual WebSocket frame
	FinF          bool
	Rsv1F         bool
	Rsv2F         bool
	Rsv3F         bool
	MaskingF      bool
	Opcode        uint8
	PayloadLenInd uint8
	PayloadLen    uint64
	MaskingKey    [4]byte
}

func (h Header) Len() int {
	if !h.DecodedF {
		return 0
	}
	length := MinFrameLen
	switch h.PayloadLenInd {
	case Max64KFrameLen:
		length += 2
	case Max16EBFrameLen:
		length += 8
	}
	if h.MaskingF {
		length += 4
	}
	return length
}

func (h *Header) Decode(b []byte) error {
	h.DecodedF = false
	fmt.Printf("len(b): %d\n", len(b))
	if len(b) < MinFrameLen {
		return ErrHdrMoreBytes
	}
	i, flagsOpcode := readUint8(b, 0)
	h.FinF = (flagsOpcode&FinF == FinF)
	h.Rsv1F = (flagsOpcode&Rsv1F == Rsv1F)
	h.Rsv2F = (flagsOpcode&Rsv2F == Rsv2F)
	h.Rsv3F = (flagsOpcode&Rsv3F == Rsv3F)
	h.Opcode = flagsOpcode & OpcodeBM
	i, maskPayloadLen := readUint8(b, i)
	h.MaskingF = (maskPayloadLen&MaskingF == MaskingF)
	h.PayloadLenInd = maskPayloadLen & PayloadLenBM
	h.PayloadLen = uint64(h.PayloadLenInd)
	h.DecodedF = true
	fmt.Printf("h.Len(): %d\n", h.Len())
	if len(b) < h.Len() {
		h.DecodedF = false
		return ErrHdrMoreBytes
	}
	switch h.PayloadLenInd {
	case Max64KFrameLen:
		tmpLen := uint16(0)
		i, tmpLen = readUint16(b, i)
		h.PayloadLen = uint64(tmpLen)
	case Max16EBFrameLen:
		i, h.PayloadLen = readUint64(b, i)
	}
	if h.MaskingF {
		copy(h.MaskingKey[:], b[i:])
	}
	return ErrHdrOk
}

/*
   WebSocket frame
   see https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+

*/
type FrameFragment struct {
	Header Header
	// mark that data was already masked
	WasMaskedF    bool
	PayloadDataPf httpsp.PField
}

func (f *FrameFragment) Reset() {
	f.Header = Header{}
	f.WasMaskedF = false
	f.PayloadDataPf = httpsp.PField{}
}

func (f FrameFragment) Len() uint64 {
	if !f.Header.DecodedF {
		return 0
	}
	return uint64(f.Header.Len()) + f.Header.PayloadLen
}

func (f FrameFragment) Ctrl() bool {
	return f.Header.Opcode >= CloseOp
}

func (f FrameFragment) First() bool {
	return f.Header.Opcode != ContOp
}

func (f FrameFragment) Continuation() bool {
	return !f.Header.FinF && f.Header.Opcode == ContOp
}

func (f FrameFragment) Last() bool {
	return f.Header.FinF
}

func (f FrameFragment) OnlyOne() bool {
	return f.First() && f.Last()
}

func (f FrameFragment) Compressed() bool {
	return f.Header.Rsv1F && f.First()
}

func (f FrameFragment) Pf() httpsp.PField {
	return f.PayloadDataPf
}

func (f FrameFragment) PayloadData(b []byte) []byte {
	return f.PayloadDataPf.Get(b)
}

func (f *FrameFragment) Decode(b []byte, offset int) (int, error) {
	var err error
	if f.Header.DecodedF {
		// this fragment was already decoded
		fmt.Println("decoded")
		return offset + int(f.Len()), ErrHdrOk
	}
	currentBuf := b[offset:]
	if err = f.Header.Decode(currentBuf); err == ErrHdrOk {
		f.PayloadDataPf = httpsp.PField{
			Offs: httpsp.OffsT(offset) + httpsp.OffsT(f.Header.Len()),
			Len:  httpsp.OffsT(f.Header.PayloadLen),
		}
		if len(currentBuf) < f.Header.Len()+int(f.Header.PayloadLen) {
			err = ErrDataMoreBytes
		}
	}
	switch err {
	case ErrHdrOk:
		return offset + int(f.Len()), err
	case ErrHdrMoreBytes, ErrDataMoreBytes:
		fmt.Println("err:", err)
		return offset, err
	}
	return offset, ErrCritical
}

// Mask uses xor encryption for masking fragment payloads. Warning: it overwrites input memory.
// See: https://www.rfc-editor.org/rfc/rfc6455.html#section-5.3
func (f *FrameFragment) Mask(buf []byte) {
	if !f.Header.MaskingF {
		return
	}
	if f.WasMaskedF {
		return
	}
	slice := f.PayloadDataPf.Get(buf)
	for i, b := range slice {
		slice[i] = b ^ f.Header.MaskingKey[i%4]
	}
	f.WasMaskedF = true
}

type Frame struct {
	// all the frame's fragments
	Fragments []FrameFragment
	// this is the index of the last read and decoded fragment
	LastFragment int
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

// NewFrame returns a pointer to a newly initialized, empty frame which has at most 'maxFragments' fragments and
// a payload of at most 'maxPayloadSize' bytes.
func NewFrame(maxPayloadSize, maxFragments int) *Frame {
	var frame Frame = Frame{
		Fragments:     make([]FrameFragment, maxFragments, maxFragments),
		LastFragment:  0,
		payloadBuf:    make([]byte, maxPayloadSize+len(deflateNonCompressedEmptyBlock), maxPayloadSize+len(deflateNonCompressedEmptyBlock)),
		payloadBufLen: 0,
	}
	for i, _ := range frame.Fragments[:] {
		frame.Fragments[i].Reset()
	}
	frame.bufReader = bytes.NewReader(frame.payloadBuf)
	frame.flateReader = flate.NewReader(nil)
	return &frame
}

// Reset re-initializes all the fragments in the frame. It sets the index of
// the last decoded fragment to 0.
func (f *Frame) Reset() {
	for i, _ := range f.Fragments[0:f.LastFragment] {
		f.Fragments[i].Reset()
	}
	f.LastFragment = 0
}

// Len returns the total length of the frame fragments (including headers)
func (f Frame) Len() uint64 {
	var l uint64 = 0
	for _, frag := range f.Fragments[0:f.LastFragment] {
		l += frag.Len()
	}
	return l
}

func (f Frame) Compressed() bool {
	return f.Fragments[0].Compressed()
}

// Complete returns true if all the message fragments were read and false otherwise
func (f Frame) Complete() bool {
	return f.CompleteF
}

// Decoded returns "true" if all the fragments in the frame were decoded.
func (f Frame) Decoded() bool {
	for _, frag := range f.Fragments[0:f.LastFragment] {
		if !frag.Header.DecodedF {
			return false
		}
	}
	return true
}

// PayloadLen returns the total length of the frame fragments' payloads (excluding headers)
func (f Frame) PayloadLen() uint64 {
	var l uint64 = 0
	for _, frag := range f.Fragments[0:f.LastFragment] {
		l += frag.Header.PayloadLen
	}
	return l
}

func (f *Frame) NextFragment() *FrameFragment {
	if f.LastFragment >= len(f.Fragments) {
		fragments := make([]FrameFragment, len(f.Fragments), len(f.Fragments))
		f.Fragments = append(f.Fragments, fragments...)
	}
	fragment := &f.Fragments[f.LastFragment]
	f.LastFragment++
	return fragment
}

func (f *Frame) DropFragment() {
	if f.LastFragment > 0 {
		f.LastFragment--
	}
	f.Fragments[f.LastFragment].Reset()
}

// Decode decodes fragments from the input buffer "b" starting at "offset". Once decoded
// fragments are stored in the "Frame" and can be further processed. For example here is how
// to iterate over the fragments in a frame:
//
// 	func (f Frame) DumpPayloadDataIterator(buf []byte) {
//		for _, frag := range f.Fragments[0:f.LastFragment] {
//			fmt.Printf("payload data:%v\n", frag.PayloadDataPf.Get(buf))
//      }
//	}
//
// Please note that Decode does not perform masking!
// In case of success it returns the offset where the new fragment should start and the error "ErrHdrOk"
// In case of failure it returns the value of the input parameter "offset" and either of the errors:
// "ErrHdrMoreBytes", "ErrDataMoreBytes" meaning that more data is needed for decoding the frame
func (f *Frame) Decode(b []byte, offset int) (int, error) {
	var (
		err error
	)
	for {
		fragment := f.NextFragment()
		if offset, err = fragment.Decode(b, offset); err != ErrHdrOk {
			fmt.Println("err: ", err)
			f.DropFragment()
			break
		}
		// control frames may be injected in between fragments
		if fragment.Ctrl() {
			f.DropFragment()
			continue
		}
		if err == nil || err == ErrHdrOk {
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
func (f *Frame) Mask(buf []byte) {
	for _, frag := range f.Fragments[0:f.LastFragment] {
		frag.Mask(buf)
	}
}

// FragmentCount returns the number of fragments in this frame
func (f Frame) FragmentCount() int {
	return f.LastFragment
}

// Defragment unmasks fragments which were decoded from the "src" buffer and copies their payload
// data into "dst" memory buffer. If there is only one fragment, no copy is performed.
// It returns the buffer containing the unmasked payload data, its length and error if the operation
// could not be performed correctly.
func (f *Frame) Defragment(dst, src []byte) ([]byte, int, error) {
	if !f.Decoded() {
		return nil, 0, ErrNotDecoded
	}
	f.Mask(src)
	if len(f.Fragments) == 1 {
		// only one fragment
		return f.Fragments[0].PayloadDataPf.Get(src), int(f.Fragments[0].PayloadDataPf.Len), nil
	}
	if int(f.PayloadLen()) > len(dst) {
		return nil, 0, ErrFragBufTooSmall
	}
	offset := 0
	for _, frag := range f.Fragments[0:f.LastFragment] {
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
func (f *Frame) PayloadDataRaw(dst, src []byte) ([]byte, int, error) {
	return f.Defragment(dst, src)
}

// PayloadData returns the raw frame payload data after applying Per-Message Compression Extension.
func (f *Frame) PayloadData(dst, src []byte) ([]byte, int, error) {
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
func (f *Frame) Deflate() ([]byte, int, error) {
	copy(f.payloadBuf[f.payloadBufLen:], deflateNonCompressedEmptyBlock)
	//fmt.Printf("payload: % x\n", f.payloadBuf[0:f.payloadBufLen+len(deflateNonCompressedEmptyBlock)])
	f.bufReader.Reset(f.payloadBuf[0 : f.payloadBufLen+len(deflateNonCompressedEmptyBlock)])
	if !f.StatefulCompression {
		f.flateReader.(flate.Resetter).Reset(f.bufReader, nil)
	}
	f.bufWriter.Reset()
	l, err := io.Copy(&f.bufWriter, f.flateReader)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, 0, fmt.Errorf("frame deflate error: %w", err)
	}
	//fmt.Printf("copied %d bytes\n", l)
	return f.bufWriter.Bytes(), int(l), err
}
