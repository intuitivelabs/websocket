package websocket

import (
	"fmt"
	"github.com/intuitivelabs/httpsp"
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
type Frame struct {
	Header Header
	// mark that data was already masked
	WasMaskedF    bool
	PayloadDataPf httpsp.PField
}

func (f *Frame) Reset() {
	f.Header = Header{}
	f.WasMaskedF = false
	f.PayloadDataPf = httpsp.PField{}
}

func (f Frame) Len() uint64 {
	if !f.Header.DecodedF {
		return 0
	}
	return uint64(f.Header.Len()) + f.Header.PayloadLen
}

func (f Frame) Ctrl() bool {
	return f.Header.Opcode >= CloseOp
}

func (f Frame) First() bool {
	return f.Header.Opcode != ContOp
}

func (f Frame) Continuation() bool {
	return !f.Header.FinF && f.Header.Opcode == ContOp
}

func (f Frame) Last() bool {
	return f.Header.FinF
}

func (f Frame) OnlyOne() bool {
	return f.First() && f.Last()
}

func (f Frame) Compressed() bool {
	return f.Header.Rsv1F && f.First()
}

func (f Frame) Pf() httpsp.PField {
	return f.PayloadDataPf
}

func (f Frame) PayloadData(b []byte) []byte {
	return f.PayloadDataPf.Get(b)
}

func (f *Frame) Decode(b []byte, offset int) (int, error) {
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
func (f *Frame) Mask(buf []byte) {
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
