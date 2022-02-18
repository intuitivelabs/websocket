// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the INTUITIVE_LABS-LICENSE.txt file in the root of the source
// tree.

package websocket

import (
	"errors"
)

type ErrorWs uint32

const (
	ErrMsgOk ErrorWs = iota
	ErrHdrMoreBytes
	ErrDataMoreBytes
	ErrWrongOffset
	ErrFrameAlreadyDecoded
	ErrFragBufTooSmall
	ErrFragCopy
	ErrNotDecoded
	ErrDeflateBufTooSmall
	ErrDeflate
	ErrCritical
	ErrConvBUG
	ErrBUG
)

// errors
var err2ErrorVal = [...]error{
	ErrMsgOk:               errors.New("header OK"),
	ErrHdrMoreBytes:        errors.New("need more bytes for WebSocket frame header"),
	ErrDataMoreBytes:       errors.New("need more bytes for WebSocket frame data"),
	ErrWrongOffset:         errors.New("wrong buffer offset"),
	ErrFrameAlreadyDecoded: errors.New("frame was already decoded"),
	ErrFragBufTooSmall:     errors.New("defragmentation buffer is too small"),
	ErrFragCopy:            errors.New("fragment copy failure"),
	ErrNotDecoded:          errors.New("frame (fragment) is not decoded"),
	ErrDeflateBufTooSmall:  errors.New("deflate buffer is too small"),
	ErrDeflate:             errors.New("deflate failure"),
	ErrCritical:            errors.New("critical error"),
	ErrConvBUG:             errors.New("error conversion BUG"),
	ErrBUG:                 errors.New("BUG"),
}

// ErrorConv converts the ErrorHdr value to error.
// It uses "boxed" values to prevent runtime allocations.
func (e ErrorWs) Error() string {
	if 0 <= int(e) && int(e) < len(err2ErrorVal) {
		return err2ErrorVal[e].Error()
	}
	return ErrConvBUG.Error()
}
