package webrtc

import (
	"errors"
	"fmt"
	"github.com/intuitivelabs/httpsp"
)

// errors
var (
	ErrHdrOk           = errors.New("Header OK")
	ErrHdrMoreBytes    = errors.New("Need more bytes for WebSocket frame header")
	ErrDataMoreBytes   = errors.New("Need more bytes for WebSocket frame data")
	ErrFragBufTooSmall = errors.New("Defragmentation buffer is too small")
	ErrFragCopy        = errors.New("Fragment copy failure")
	ErrCritical        = errors.New("Critical error")
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
	fmt.Printf("h.PayloadLenInd: %d\n", h.PayloadLenInd)
	fmt.Printf("len(b): %d\n", len(b))
	h.DecodedF = true
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
	fmt.Printf("header of %d bytes decoded: %v\n", h.Len(), h)
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
	Header        Header
	PayloadDataPf httpsp.PField
	//PayloadData   []byte
}

func (f FrameFragment) Reset() {
	f.Header = Header{}
	//f.PayloadData = nil
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

func (f FrameFragment) OnlyOne() bool {
	return f.Header.FinF && f.Header.Opcode != ContOp
}

func (f FrameFragment) First() bool {
	return !f.Header.FinF && f.Header.Opcode != ContOp
}

func (f FrameFragment) Continuation() bool {
	return !f.Header.FinF && f.Header.Opcode == ContOp
}

func (f FrameFragment) Last() bool {
	return f.Header.FinF && f.Header.Opcode == ContOp
}

func (f FrameFragment) Pf() httpsp.PField {
	return f.PayloadDataPf
}

func (f *FrameFragment) Decode(b []byte, offset int) (int, error) {
	var err error
	currentBuf := b[offset:]
	if !f.Header.DecodedF {
		if err = f.Header.Decode(currentBuf); err == ErrHdrOk {
			f.PayloadDataPf = httpsp.PField{
				Offs: httpsp.OffsT(offset) + httpsp.OffsT(f.Header.Len()),
				Len:  httpsp.OffsT(f.Header.PayloadLen),
			}
		}
	}
	if err == ErrHdrOk && (len(currentBuf) < f.Header.Len()+int(f.Header.PayloadLen)) {
		err = ErrDataMoreBytes
	}
	switch err {
	case ErrHdrOk:
		//f.PayloadData = currentBuf[f.Header.Len():]
		return offset + int(f.Len()), err
	case ErrHdrMoreBytes, ErrDataMoreBytes:
		return offset, err
	}
	return offset, ErrCritical
}

func (f *FrameFragment) Mask(buf []byte) {
	if f.Header.MaskingF {
		return
	}
	slice := f.PayloadDataPf.Get(buf)
	for i, b := range slice {
		slice[i] = b ^ f.Header.MaskingKey[i%4]
	}
}

type Frame struct {
	Fragments []FrameFragment
	Idx       int
}

func NewFrame(capacity int) *Frame {
	return &Frame{
		Fragments: make([]FrameFragment, capacity, capacity),
		Idx:       0,
	}
}

func (f *Frame) Reset() {
	f.Idx = 0
	for _, frag := range f.Fragments {
		frag.Reset()
	}
}

// Len returns the total length of the frame fragments (including headers)
func (f Frame) Len() uint64 {
	var l uint64 = 0
	for _, frag := range f.Fragments {
		fmt.Printf("frag.Len(): %d\n", frag.Len())
		l += frag.Len()
	}
	return l
}

// PayloadLen returns the total length of the frame fragments' payloads (excluding headers)
func (f Frame) PayloadLen() uint64 {
	var l uint64 = 0
	for _, frag := range f.Fragments {
		l += frag.Header.PayloadLen
	}
	return l
}

func (f *Frame) Append(fragment FrameFragment) {
	if f.Idx < len(f.Fragments) {
		f.Fragments[f.Idx] = fragment
	} else {
		f.Fragments = append(f.Fragments, fragment)
	}
	f.Idx++
}

func (f *Frame) Decode(b []byte, offset int) (int, error) {
	var (
		fragmented bool
		fragment   = FrameFragment{}
		err        error
	)
	for {
		offset, err = fragment.Decode(b, offset)
		// control frames may be injected in between fragments
		if !fragment.Ctrl() {
			f.Append(fragment)
		}
		if err == nil || err == ErrHdrOk {
			if fragment.First() {
				// this is a fragmented frame
				fragmented = true
			}
			if fragment.OnlyOne() || fragment.Last() {
				// it is either a stand-alone frame or it is the last fragment of the frame
				fmt.Println("either not fragmented or last fragment")
				break
			}
			if fragment.Ctrl() && !fragmented {
				// only a control frame (which cannot be fragmented)
				break
			}
			// try to read next fragment
			continue
		}
		// error while decoding the fragment
		break
	}
	return offset, err
}

func (f *Frame) Mask(buf []byte) {
	for _, frag := range f.Fragments {
		frag.Mask(buf)
	}
}

func (f Frame) FragmentCount() int {
	return len(f.Fragments)
}

func (f Frame) Defragment(dst, src []byte) ([]byte, error) {
	if len(f.Fragments) == 1 {
		// only one fragment
		return f.Fragments[0].PayloadDataPf.Get(src), nil
	}
	if int(f.PayloadLen()) > len(dst) {
		return nil, ErrFragBufTooSmall
	}
	offset := 0
	for _, frag := range f.Fragments {
		slice := frag.PayloadDataPf.Get(src)
		n := copy(dst[offset:], slice)
		if n < int(frag.Header.PayloadLen) {
			return nil, ErrFragCopy
		}
		offset += n
	}
	return dst, nil
}

func (f *Frame) GetPayloadData(dst, src []byte) ([]byte, error) {
	f.Mask(src)
	return f.Defragment(dst, src)
}
