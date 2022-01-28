package webrtc

import (
	"os"
	"testing"
)

func TestDecoder(t *testing.T) {
	// set-up if needed
	frame := NewFrame(10)
	file, fsErr := os.Open("404")
	if fsErr != nil {
		t.Fatalf(`could not open data file "404": %s`, fsErr)
	}
	var wsPkt [2048]byte
	n, readErr := file.Read(wsPkt[:])
	if readErr != nil {
		t.Fatalf(`could not read data file "404": %s`, readErr)
	}
	t.Run("decode full", func(t *testing.T) {
		if offs, err := frame.Decode(wsPkt[:], 0); err != ErrHdrOk {
			t.Fatalf("decode error %s", err)
		} else if offs != int(frame.Len()) {
			t.Fatalf("expected offs: %d, got offs: %d", int(frame.Len()), offs)
		}
	})
	t.Run("decode partial", func(t *testing.T) {
		if offs, err := frame.Decode(wsPkt[0:3], 0); err != ErrHdrMoreBytes {
			t.Fatalf("decode error %s", err)
		} else if offs != 0 {
			t.Fatalf("decode error %s", err)
		}
		if offs, err := frame.Decode(wsPkt[0:4], 0); err != ErrDataMoreBytes {
			t.Fatalf("decode error %s", err)
		} else if offs != 0 {
			t.Fatalf("decode error %s", err)
		}
		if offs, err := frame.Decode(wsPkt[0:100], 0); err != ErrDataMoreBytes {
			t.Fatalf("decode error %s", err)
		} else if offs != 0 {
			t.Fatalf("decode error %s", err)
		}
		if offs, err := frame.Decode(wsPkt[0:314], 0); err != ErrHdrOk {
			t.Fatalf("decode error %s", err)
		} else if offs != n {
			t.Fatalf("decode error %s", err)
		}
	})
}
