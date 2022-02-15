package websocket

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
)

func readPkt(dirName, fileName string, b []byte) (int, error) {
	file, fsErr := os.Open(dirName + "/" + fileName)
	if fsErr != nil {
		return 0, fsErr
	}
	n, readErr := file.Read(b[:])
	return n, readErr
}

func TestDecoderUncompressed(t *testing.T) {
	// set-up if needed
	var plainPkt, maskedPkt [2048]byte
	message := NewMessage(64535, 10)
	dirName := "test_files"
	fileName := "404"
	plainPktCnt, readErr := readPkt(dirName, fileName, plainPkt[:])
	if readErr != nil {
		t.Fatalf(`could not read data file "%s/%s": %s`, dirName, fileName, readErr)
	}
	fileName = "register"
	maskedPktCnt, readErr := readPkt(dirName, fileName, maskedPkt[:])
	if readErr != nil {
		t.Fatalf(`could not read data file "%s/%s": %s`, dirName, fileName, readErr)
	}
	t.Run("rfc6455 single unmasked message", func(t *testing.T) {
		plainPkt := []byte{
			0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}
		pktBytes := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}
		message.Reset()
		if offs, err := message.Decode(plainPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(message.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], plainPkt[:]); err != nil {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], pktBytes) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(pktBytes), string(pd[0:length]))
		}
	})
	t.Run("rfc6455 single masked message", func(t *testing.T) {
		maskedPkt := []byte{
			0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
		}
		pktBytes := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}
		message.Reset()
		if offs, err := message.Decode(maskedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(message.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], maskedPkt[:]); err != nil {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], pktBytes) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(pktBytes), string(pd[0:length]))
		}
	})
	t.Run("rfc6455 fragmented unmasked message", func(t *testing.T) {
		plainPkt := []byte{
			/*first message*/ 0x01, 0x03, 0x48, 0x65, 0x6c,
			/*last message*/ 0x80, 0x02, 0x6c, 0x6f,
		}
		pktBytes := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}
		message.Reset()

		// read first fragment
		offs, err := message.Decode(plainPkt[:5], 0, true)
		if err == ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(message.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], plainPkt[:]); err != nil {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], pktBytes[0:3]) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(pktBytes[0:3]), string(pd[0:length]))
		}

		// read last fragment
		if offs, err = message.Decode(plainPkt[:], offs, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(plainPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		if pd, length, err := message.PayloadData(dst[:], plainPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], pktBytes) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(pktBytes), string(pd[0:length]))
		}
	})
	t.Run("iterating fragmented unmasked message", func(t *testing.T) {
		plainPkt := []byte{
			/*first message*/ 0x01, 0x03, 0x48, 0x65, 0x6c,
			/*last message*/ 0x80, 0x02, 0x6c, 0x6f,
		}
		pktBytes := [][]byte{
			{0x48, 0x65, 0x6c},
			{0x6c, 0x6f},
		}
		message.Reset()

		// read first fragment
		offs, err := message.Decode(plainPkt[:5], 0, true)
		if err == ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(message.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		} else if message.LastFrame != 1 {
			t.Fatalf("expected LastFrame: %d, got LastFrame: %d", 1, message.LastFrame)
		}
		for i, f := range message.Frames[0:message.LastFrame] {
			if !bytes.Equal(f.PayloadDataPf.Get(plainPkt[:5]), pktBytes[i]) {
				t.Fatalf("payload data mismatch expected:\n%v\n, got:\n%v\n", pktBytes[i], f.PayloadDataPf.Get(plainPkt[:5]))
			}
		}
		// read last fragment
		if offs, err = message.Decode(plainPkt[:], offs, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(plainPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		} else if message.LastFrame != 2 {
			t.Fatalf("expected LastFrame: %d, got LastFrame: %d", 2, message.LastFrame)
		}
		for i, f := range message.Frames[0:message.LastFrame] {
			fmt.Printf("message %d: %v\n", i, string(f.PayloadDataPf.Get(plainPkt[:])))
			if !bytes.Equal(f.PayloadDataPf.Get(plainPkt[:]), pktBytes[i]) {
				t.Fatalf("payload data mismatch expected:\n%v\n, got:\n%v\n", pktBytes[i], f.PayloadDataPf.Get(plainPkt[:]))
			}
		}
	})
	t.Run("plain full", func(t *testing.T) {
		pktBytes := []byte{
			0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x20,
			0x34, 0x30, 0x34, 0x20, 0x4e, 0x6f, 0x74, 0x20,
			0x66, 0x6f, 0x75, 0x6e, 0x64, 0x0d, 0x0a, 0x56,
			0x69, 0x61, 0x3a, 0x20, 0x53, 0x49, 0x50, 0x2f,
			0x32, 0x2e, 0x30, 0x2f, 0x57, 0x53, 0x53, 0x20,
			0x6d, 0x38, 0x6f, 0x67, 0x6f, 0x75, 0x66, 0x6b,
			0x76, 0x6f, 0x6b, 0x6a, 0x2e, 0x69, 0x6e, 0x76,
			0x61, 0x6c, 0x69, 0x64, 0x3b, 0x62, 0x72, 0x61,
			0x6e, 0x63, 0x68, 0x3d, 0x7a, 0x39, 0x68, 0x47,
			0x34, 0x62, 0x4b, 0x36, 0x38, 0x31, 0x31, 0x33,
			0x37, 0x39, 0x3b, 0x72, 0x65, 0x63, 0x65, 0x69,
			0x76, 0x65, 0x64, 0x3d, 0x3a, 0x3a, 0x66, 0x66,
			0x66, 0x66, 0x3a, 0x31, 0x37, 0x32, 0x2e, 0x33,
			0x31, 0x2e, 0x32, 0x33, 0x2e, 0x31, 0x33, 0x36,
			0x0d, 0x0a, 0x54, 0x6f, 0x3a, 0x20, 0x3c, 0x73,
			0x69, 0x70, 0x3a, 0x76, 0x6c, 0x61, 0x64, 0x61,
			0x40, 0x69, 0x6e, 0x74, 0x6c, 0x61, 0x62, 0x73,
			0x2e, 0x74, 0x65, 0x73, 0x74, 0x3e, 0x3b, 0x74,
			0x61, 0x67, 0x3d, 0x32, 0x35, 0x30, 0x32, 0x34,
			0x32, 0x31, 0x34, 0x2d, 0x36, 0x31, 0x36, 0x35,
			0x36, 0x38, 0x42, 0x43, 0x30, 0x30, 0x30, 0x32,
			0x46, 0x46, 0x45, 0x43, 0x2d, 0x39, 0x42, 0x37,
			0x44, 0x42, 0x37, 0x30, 0x30, 0x0d, 0x0a, 0x46,
			0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x22, 0x76, 0x6c,
			0x61, 0x64, 0x61, 0x22, 0x20, 0x3c, 0x73, 0x69,
			0x70, 0x3a, 0x76, 0x6c, 0x61, 0x64, 0x61, 0x40,
			0x69, 0x6e, 0x74, 0x6c, 0x61, 0x62, 0x73, 0x2e,
			0x74, 0x65, 0x73, 0x74, 0x3e, 0x3b, 0x74, 0x61,
			0x67, 0x3d, 0x6b, 0x32, 0x70, 0x71, 0x32, 0x35,
			0x62, 0x70, 0x38, 0x72, 0x0d, 0x0a, 0x43, 0x61,
			0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x20, 0x66,
			0x38, 0x69, 0x67, 0x76, 0x37, 0x6f, 0x74, 0x62,
			0x33, 0x39, 0x73, 0x70, 0x67, 0x31, 0x75, 0x70,
			0x6c, 0x37, 0x6b, 0x6d, 0x35, 0x0d, 0x0a, 0x43,
			0x53, 0x65, 0x71, 0x3a, 0x20, 0x31, 0x20, 0x52,
			0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52, 0x0d,
			0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
			0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a,
			0x20, 0x30, 0x0d, 0x0a, 0x0d, 0x0a,
		}
		message.Reset()
		if offs, err := message.Decode(plainPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(message.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], plainPkt[:]); err != nil {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], pktBytes) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(pktBytes), string(pd[0:length]))
		}
	})
	t.Run("plain partial", func(t *testing.T) {
		message.Reset()
		if offs, err := message.Decode(plainPkt[0:3], 0, true); err != ErrHdrMoreBytes {
			t.Fatalf("decode error: %s", err)
		} else if offs != 0 {
			t.Fatalf("decode error: %s", err)
		}
		if offs, err := message.Decode(plainPkt[0:4], 0, true); err != ErrDataMoreBytes {
			t.Fatalf("decode error %s", err)
		} else if offs != 0 {
			t.Fatalf("decode error %s", err)
		}
		if offs, err := message.Decode(plainPkt[0:100], 0, true); err != ErrDataMoreBytes {
			t.Fatalf("decode error %s", err)
		} else if offs != 0 {
			t.Fatalf("decode error %s", err)
		}
		if offs, err := message.Decode(plainPkt[0:314], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != plainPktCnt {
			t.Fatalf("decode error %s", err)
		}
	})
	t.Run("masked full", func(t *testing.T) {
		pktBytes := []byte{
			0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52,
			0x20, 0x73, 0x69, 0x70, 0x3a, 0x69, 0x6e, 0x74,
			0x6c, 0x61, 0x62, 0x73, 0x2e, 0x74, 0x65, 0x73,
			0x74, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e,
			0x30, 0x0d, 0x0a, 0x56, 0x69, 0x61, 0x3a, 0x20,
			0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f,
			0x57, 0x53, 0x53, 0x20, 0x6d, 0x38, 0x6f, 0x67,
			0x6f, 0x75, 0x66, 0x6b, 0x76, 0x6f, 0x6b, 0x6a,
			0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64,
			0x3b, 0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d,
			0x7a, 0x39, 0x68, 0x47, 0x34, 0x62, 0x4b, 0x36,
			0x38, 0x31, 0x31, 0x33, 0x37, 0x39, 0x0d, 0x0a,
			0x4d, 0x61, 0x78, 0x2d, 0x46, 0x6f, 0x72, 0x77,
			0x61, 0x72, 0x64, 0x73, 0x3a, 0x20, 0x36, 0x39,
			0x0d, 0x0a, 0x54, 0x6f, 0x3a, 0x20, 0x3c, 0x73,
			0x69, 0x70, 0x3a, 0x76, 0x6c, 0x61, 0x64, 0x61,
			0x40, 0x69, 0x6e, 0x74, 0x6c, 0x61, 0x62, 0x73,
			0x2e, 0x74, 0x65, 0x73, 0x74, 0x3e, 0x0d, 0x0a,
			0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x22, 0x76,
			0x6c, 0x61, 0x64, 0x61, 0x22, 0x20, 0x3c, 0x73,
			0x69, 0x70, 0x3a, 0x76, 0x6c, 0x61, 0x64, 0x61,
			0x40, 0x69, 0x6e, 0x74, 0x6c, 0x61, 0x62, 0x73,
			0x2e, 0x74, 0x65, 0x73, 0x74, 0x3e, 0x3b, 0x74,
			0x61, 0x67, 0x3d, 0x6b, 0x32, 0x70, 0x71, 0x32,
			0x35, 0x62, 0x70, 0x38, 0x72, 0x0d, 0x0a, 0x43,
			0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x20,
			0x66, 0x38, 0x69, 0x67, 0x76, 0x37, 0x6f, 0x74,
			0x62, 0x33, 0x39, 0x73, 0x70, 0x67, 0x31, 0x75,
			0x70, 0x6c, 0x37, 0x6b, 0x6d, 0x35, 0x0d, 0x0a,
			0x43, 0x53, 0x65, 0x71, 0x3a, 0x20, 0x31, 0x20,
			0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52,
			0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63,
			0x74, 0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a,
			0x65, 0x34, 0x61, 0x71, 0x62, 0x6a, 0x74, 0x69,
			0x40, 0x6d, 0x38, 0x6f, 0x67, 0x6f, 0x75, 0x66,
			0x6b, 0x76, 0x6f, 0x6b, 0x6a, 0x2e, 0x69, 0x6e,
			0x76, 0x61, 0x6c, 0x69, 0x64, 0x3b, 0x74, 0x72,
			0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x3d,
			0x77, 0x73, 0x3e, 0x3b, 0x2b, 0x73, 0x69, 0x70,
			0x2e, 0x69, 0x63, 0x65, 0x3b, 0x72, 0x65, 0x67,
			0x2d, 0x69, 0x64, 0x3d, 0x31, 0x3b, 0x2b, 0x73,
			0x69, 0x70, 0x2e, 0x69, 0x6e, 0x73, 0x74, 0x61,
			0x6e, 0x63, 0x65, 0x3d, 0x22, 0x3c, 0x75, 0x72,
			0x6e, 0x3a, 0x75, 0x75, 0x69, 0x64, 0x3a, 0x65,
			0x38, 0x38, 0x62, 0x39, 0x32, 0x33, 0x64, 0x2d,
			0x32, 0x35, 0x39, 0x65, 0x2d, 0x34, 0x65, 0x65,
			0x64, 0x2d, 0x61, 0x38, 0x30, 0x33, 0x2d, 0x38,
			0x65, 0x63, 0x37, 0x63, 0x34, 0x38, 0x64, 0x36,
			0x63, 0x62, 0x30, 0x3e, 0x22, 0x3b, 0x65, 0x78,
			0x70, 0x69, 0x72, 0x65, 0x73, 0x3d, 0x36, 0x30,
			0x30, 0x0d, 0x0a, 0x45, 0x78, 0x70, 0x69, 0x72,
			0x65, 0x73, 0x3a, 0x20, 0x36, 0x30, 0x30, 0x0d,
			0x0a, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x3a, 0x20,
			0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x2c, 0x41,
			0x43, 0x4b, 0x2c, 0x43, 0x41, 0x4e, 0x43, 0x45,
			0x4c, 0x2c, 0x42, 0x59, 0x45, 0x2c, 0x55, 0x50,
			0x44, 0x41, 0x54, 0x45, 0x2c, 0x4d, 0x45, 0x53,
			0x53, 0x41, 0x47, 0x45, 0x2c, 0x4f, 0x50, 0x54,
			0x49, 0x4f, 0x4e, 0x53, 0x2c, 0x52, 0x45, 0x46,
			0x45, 0x52, 0x2c, 0x49, 0x4e, 0x46, 0x4f, 0x2c,
			0x4e, 0x4f, 0x54, 0x49, 0x46, 0x59, 0x0d, 0x0a,
			0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65,
			0x64, 0x3a, 0x20, 0x70, 0x61, 0x74, 0x68, 0x2c,
			0x67, 0x72, 0x75, 0x75, 0x2c, 0x6f, 0x75, 0x74,
			0x62, 0x6f, 0x75, 0x6e, 0x64, 0x0d, 0x0a, 0x55,
			0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e,
			0x74, 0x3a, 0x20, 0x4a, 0x73, 0x53, 0x49, 0x50,
			0x20, 0x33, 0x2e, 0x37, 0x2e, 0x31, 0x0d, 0x0a,
			0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,
			0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20,
			0x30, 0x0d, 0x0a, 0x0d, 0x0a,
		}
		message.Reset()
		if offs, err := message.Decode(maskedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != maskedPktCnt {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], maskedPkt[:]); err != nil {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], pktBytes) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(pktBytes), string(pd[0:length]))
		}
	})
}

func TestDecoderCompressed(t *testing.T) {
	message := NewMessage(64535, 10)
	// https://www.rfc-editor.org/rfc/rfc7692.html#section-7.2.3 Examples
	// https://www.rfc-editor.org/rfc/rfc7692.html#section-7.2.3.1
	t.Run("rfc7692 one deflate block", func(t *testing.T) {
		compressedPkt := []byte{
			0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
			0x00,
		}

		plainPkt := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}

		message.Reset()
		if offs, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})
	t.Run("rfc7692 one deflate block fragmented", func(t *testing.T) {
		compressedPkt := []byte{
			/*first fragment*/
			0x41, 0x03, 0xf2, 0x48, 0xcd,
			/*last fragment*/
			0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00,
		}

		plainPkt := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}

		message.Reset()
		if offs, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})
	// https://www.rfc-editor.org/rfc/rfc7692.html#section-7.2.3.3
	t.Run("rfc7692 one deflate block w/ no compression", func(t *testing.T) {
		compressedPkt := []byte{
			0xc1, 0x0b, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x48,
			0x65, 0x6c, 0x6c, 0x6f, 0x00,
		}

		plainPkt := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}

		message.Reset()
		if offs, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})
	// https://www.rfc-editor.org/rfc/rfc7692.html#section-7.2.3.4
	t.Run("rfc7692 one deflate block w/ BFINAL set to 1", func(t *testing.T) {
		compressedPkt := []byte{
			0xc1, 0x08, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00,
		}

		plainPkt := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}

		message.Reset()
		if offs, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})
	// https://www.rfc-editor.org/rfc/rfc7692.html#section-7.2.3.5
	t.Run("rfc7692 two deflate blocks in one message", func(t *testing.T) {
		compressedPkt := []byte{
			0xc1, 0x0d, 0xf2, 0x48, 0x05, 0x00, 0x00, 0x00,
			0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00,
		}

		plainPkt := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}

		message.Reset()
		if offs, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})

	// packets generated by libwebsockets
	t.Run("compressed libwebsockets", func(t *testing.T) {
		compressedPkt := []byte{
			0xc1, 0x7e, 0x00, 0xd3, 0x2c, 0x8d, 0x4f, 0x6b,
			0x02, 0x31, 0x10, 0xc5, 0xbf, 0xca, 0x90, 0x93,
			0x82, 0x9b, 0xcd, 0xbf, 0xcd, 0x76, 0xed, 0xa9,
			0xf4, 0xd0, 0x82, 0x7a, 0xaa, 0x60, 0xa1, 0x94,
			0x25, 0xca, 0xd8, 0x0d, 0xc6, 0x64, 0x49, 0x56,
			0x2b, 0x15, 0xbf, 0x7b, 0xb3, 0xb6, 0xcc, 0x61,
			0xe6, 0xbd, 0xf9, 0x3d, 0xde, 0x15, 0xc8, 0x19,
			0x63, 0xb2, 0xc1, 0x93, 0x39, 0x51, 0x54, 0xd2,
			0xa6, 0x29, 0xce, 0xe3, 0x66, 0x05, 0xaf, 0xea,
			0xe2, 0x6b, 0xab, 0x14, 0x72, 0xc1, 0x18, 0x99,
			0x01, 0xf9, 0x4e, 0xa9, 0x0d, 0x99, 0x6e, 0x3b,
			0x91, 0xe1, 0xbb, 0xd5, 0x85, 0x34, 0x78, 0x73,
			0xc4, 0xac, 0xf7, 0x36, 0x5a, 0x74, 0x7f, 0x9c,
			0xcd, 0x9a, 0x8f, 0xe7, 0x2e, 0x78, 0x9f, 0xc8,
			0xfc, 0xe3, 0x4a, 0x7a, 0xc4, 0x38, 0xba, 0xa2,
			0xa6, 0x2c, 0x4f, 0xfe, 0x92, 0xc1, 0xde, 0x83,
			0x5c, 0x2b, 0x25, 0x85, 0xd4, 0x42, 0x66, 0xef,
			0x64, 0x32, 0xb4, 0x0a, 0x3f, 0xd6, 0x39, 0x53,
			0x56, 0x94, 0xc1, 0xe4, 0x9d, 0xf3, 0x47, 0x58,
			0x5a, 0x7f, 0xba, 0xc0, 0xe5, 0x41, 0xb7, 0x5a,
			0x4d, 0xe1, 0xa9, 0xef, 0x1d, 0x6e, 0x70, 0xbb,
			0xb0, 0x43, 0x59, 0xc9, 0x9a, 0x4a, 0x0d, 0x93,
			0xc5, 0xeb, 0x7a, 0xb5, 0x9c, 0x81, 0xb3, 0x07,
			0x84, 0x17, 0xdc, 0x1d, 0xc2, 0x14, 0x9e, 0xbb,
			0x18, 0x8e, 0x58, 0x36, 0x3a, 0xf7, 0x29, 0xad,
			0x15, 0xe5, 0x9c, 0xc1, 0x9b, 0xd9, 0x9b, 0x68,
			0xff, 0x63, 0xe4, 0xf6, 0x79, 0xfb, 0x05,
		}

		plainPkt := []byte{
			0x7b, 0x20, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69,
			0x6f, 0x6e, 0x22, 0x3a, 0x22, 0x34, 0x2e, 0x33,
			0x2e, 0x39, 0x39, 0x2d, 0x76, 0x34, 0x2e, 0x33,
			0x2e, 0x30, 0x2d, 0x31, 0x35, 0x37, 0x2d, 0x67,
			0x62, 0x34, 0x34, 0x65, 0x31, 0x32, 0x30, 0x30,
			0x22, 0x2c, 0x20, 0x22, 0x77, 0x73, 0x73, 0x5f,
			0x6f, 0x76, 0x65, 0x72, 0x5f, 0x68, 0x32, 0x22,
			0x3a, 0x22, 0x30, 0x22, 0x2c, 0x20, 0x22, 0x68,
			0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x22,
			0x3a, 0x22, 0x66, 0x69, 0x72, 0x69, 0x65, 0x6c,
			0x22, 0x2c, 0x20, 0x22, 0x77, 0x73, 0x69, 0x22,
			0x3a, 0x22, 0x31, 0x22, 0x2c, 0x20, 0x22, 0x63,
			0x6f, 0x6e, 0x6e, 0x73, 0x22, 0x3a, 0x5b, 0x7b,
			0x22, 0x70, 0x65, 0x65, 0x72, 0x22, 0x3a, 0x22,
			0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e,
			0x31, 0x22, 0x2c, 0x22, 0x74, 0x69, 0x6d, 0x65,
			0x22, 0x3a, 0x22, 0x31, 0x36, 0x34, 0x34, 0x33,
			0x32, 0x33, 0x36, 0x32, 0x33, 0x22, 0x2c, 0x22,
			0x75, 0x61, 0x22, 0x3a, 0x22, 0x4d, 0x6f, 0x7a,
			0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30,
			0x20, 0x28, 0x58, 0x31, 0x31, 0x3b, 0x20, 0x4c,
			0x69, 0x6e, 0x75, 0x78, 0x20, 0x78, 0x38, 0x36,
			0x5f, 0x36, 0x34, 0x29, 0x20, 0x41, 0x70, 0x70,
			0x6c, 0x65, 0x57, 0x65, 0x62, 0x4b, 0x69, 0x74,
			0x2f, 0x35, 0x33, 0x37, 0x2e, 0x33, 0x36, 0x20,
			0x28, 0x4b, 0x48, 0x54, 0x4d, 0x4c, 0x2c, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x47, 0x65, 0x63,
			0x6b, 0x6f, 0x29, 0x20, 0x43, 0x68, 0x72, 0x6f,
			0x6d, 0x65, 0x2f, 0x39, 0x36, 0x2e, 0x30, 0x2e,
			0x34, 0x36, 0x36, 0x34, 0x2e, 0x31, 0x31, 0x30,
			0x20, 0x53, 0x61, 0x66, 0x61, 0x72, 0x69, 0x2f,
			0x35, 0x33, 0x37, 0x2e, 0x33, 0x36, 0x22, 0x7d,
			0x5d, 0x7d,
		}

		message.Reset()
		if offs, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})
	t.Run("compressed chrome bug", func(t *testing.T) {
		compressedPkt := []byte{
			/*1st fragment*/
			0x41, 0x0b, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
			0x00, 0x00, 0x00, 0xff, 0xff,
			/*2nd and last fragment*/
			0xc0, 0x01, 0x00,
		}

		plainPkt := []byte{
			0x48, 0x65, 0x6c, 0x6c, 0x6f,
		}

		message.Reset()

		// read first fragment
		offs, err := message.Decode(compressedPkt[:13], 0, true)
		if err == ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(message.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		var dst [2048]byte
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}

		// read last fragment
		if offs, err = message.Decode(compressedPkt[:], offs, true); err != ErrMsgOk {
			t.Fatalf("decode error %s", err)
		} else if offs != len(compressedPkt) {
			t.Fatalf("expected offs: %d, got offs: %d", int(message.Len()), offs)
		}
		if pd, length, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("message processing error: %s", err)
		} else if !bytes.Equal(pd[0:length], plainPkt) {
			t.Fatalf("content mismatch, expected:\n%v\ngot:\n%v", string(plainPkt), string(pd[0:length]))
		}
	})
}

func BenchmarkDeflate(b *testing.B) {
	b.Run("compressed", func(b *testing.B) {
		message := NewMessage(64535, 10)
		compressedPkt := []byte{
			0xc1, 0x7e, 0x00, 0xd3, 0x2c, 0x8d, 0x4f, 0x6b,
			0x02, 0x31, 0x10, 0xc5, 0xbf, 0xca, 0x90, 0x93,
			0x82, 0x9b, 0xcd, 0xbf, 0xcd, 0x76, 0xed, 0xa9,
			0xf4, 0xd0, 0x82, 0x7a, 0xaa, 0x60, 0xa1, 0x94,
			0x25, 0xca, 0xd8, 0x0d, 0xc6, 0x64, 0x49, 0x56,
			0x2b, 0x15, 0xbf, 0x7b, 0xb3, 0xb6, 0xcc, 0x61,
			0xe6, 0xbd, 0xf9, 0x3d, 0xde, 0x15, 0xc8, 0x19,
			0x63, 0xb2, 0xc1, 0x93, 0x39, 0x51, 0x54, 0xd2,
			0xa6, 0x29, 0xce, 0xe3, 0x66, 0x05, 0xaf, 0xea,
			0xe2, 0x6b, 0xab, 0x14, 0x72, 0xc1, 0x18, 0x99,
			0x01, 0xf9, 0x4e, 0xa9, 0x0d, 0x99, 0x6e, 0x3b,
			0x91, 0xe1, 0xbb, 0xd5, 0x85, 0x34, 0x78, 0x73,
			0xc4, 0xac, 0xf7, 0x36, 0x5a, 0x74, 0x7f, 0x9c,
			0xcd, 0x9a, 0x8f, 0xe7, 0x2e, 0x78, 0x9f, 0xc8,
			0xfc, 0xe3, 0x4a, 0x7a, 0xc4, 0x38, 0xba, 0xa2,
			0xa6, 0x2c, 0x4f, 0xfe, 0x92, 0xc1, 0xde, 0x83,
			0x5c, 0x2b, 0x25, 0x85, 0xd4, 0x42, 0x66, 0xef,
			0x64, 0x32, 0xb4, 0x0a, 0x3f, 0xd6, 0x39, 0x53,
			0x56, 0x94, 0xc1, 0xe4, 0x9d, 0xf3, 0x47, 0x58,
			0x5a, 0x7f, 0xba, 0xc0, 0xe5, 0x41, 0xb7, 0x5a,
			0x4d, 0xe1, 0xa9, 0xef, 0x1d, 0x6e, 0x70, 0xbb,
			0xb0, 0x43, 0x59, 0xc9, 0x9a, 0x4a, 0x0d, 0x93,
			0xc5, 0xeb, 0x7a, 0xb5, 0x9c, 0x81, 0xb3, 0x07,
			0x84, 0x17, 0xdc, 0x1d, 0xc2, 0x14, 0x9e, 0xbb,
			0x18, 0x8e, 0x58, 0x36, 0x3a, 0xf7, 0x29, 0xad,
			0x15, 0xe5, 0x9c, 0xc1, 0x9b, 0xd9, 0x9b, 0x68,
			0xff, 0x63, 0xe4, 0xf6, 0x79, 0xfb, 0x05,
		}

		message.Reset()
		if _, err := message.Decode(compressedPkt[:], 0, true); err != ErrMsgOk {
			b.Fatalf("decode error %s", err)
		}
		var dst [2048]byte
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := message.PayloadData(dst[:], compressedPkt[:]); err != nil && err != io.ErrUnexpectedEOF {
				b.Fatalf("message processing error: %s", err)
			}
		}
	})
}
