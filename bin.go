package webrtc

import (
	"encoding/binary"
)

func readUint8(b []byte, i int) (int, uint8) {
	return i + 1, b[i]
}

func readUint16(b []byte, i int) (int, uint16) {
	return i + 2, binary.BigEndian.Uint16(b[i : i+2])
}

func readUint32(b []byte, i int) (int, uint32) {
	return i + 4, binary.BigEndian.Uint32(b[i : i+4])
}

func readUint64(b []byte, i int) (int, uint64) {
	return i + 8, binary.BigEndian.Uint64(b[i : i+8])
}
