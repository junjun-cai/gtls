// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 00:51:59                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base62                                                                                                      *
// * File: base62.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base62

import (
	"github.com/pkg/errors"
	"math"
	"strconv"
)

type Encoding struct {
	encode    [62]byte
	decodeMap [256]byte
}

const (
	encodeStd  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	encodeSize = 62
)

var (
	StdEncoding, _     = NewEncoding(encodeStd)
	invalidEncoderSize = errors.Errorf("reflect str lenght must be %d.", encodeSize)
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:52:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string) (*Encoding, error) {
	if len(encoder) != encodeSize {
		return nil, invalidEncoderSize
	}
	e := new(Encoding)
	copy(e.encode[:], encoder)

	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(encoder); i++ {
		e.decodeMap[encoder[i]] = byte(i)
	}
	return e, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:53:20 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Encode(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}

	// e is a pointer receiver, so the use of e.encode within the hot
	// loop below means a nil check at every operation. Lift that nil check
	// outside the loop to speed up the encoder.
	_ = e.encode

	rs := 0
	cs := e.EncodedLen(len(src))
	dst := make([]byte, cs)
	for i := range src {
		c := 0
		v := int(src[i])
		for j := cs - 1; j >= 0 && (v != 0 || c < rs); j-- {
			v += 256 * int(dst[j])
			dst[j] = byte(v % 62)
			v /= 62
			c++
		}
		rs = c
	}
	for i := range dst {
		dst[i] = e.encode[dst[i]]
	}
	if cs > rs {
		return dst[cs-rs:], nil
	}
	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 13:57:22 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) EncodedLen(n int) int {
	return int(math.Ceil(math.Log(256) / math.Log(62) * float64(n)))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:54:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}

	// Lift the nil check outside the loop. e.decodeMap is directly
	// used later in this function, to let the compiler know that the
	// receiver can't be nil.
	_ = e.decodeMap

	rs := 0
	cs := e.DecodedLen(len(src))
	dst := make([]byte, cs)
	for i := range src {
		if src[i] == '\n' || src[i] == '\r' {
			continue
		}
		c := 0
		v := int(e.decodeMap[src[i]])
		if v == 255 {
			return nil, errors.Errorf("illegal base62 data at input byte " + strconv.FormatInt(int64(src[i]), 10))
		}
		for j := cs - 1; j >= 0 && (v != 0 || c < rs); j-- {
			v += 62 * int(dst[j])
			dst[j] = byte(v % 256)
			v /= 256
			c++
		}
		rs = c
	}
	if cs > rs {
		return dst[cs-rs:], nil
	}
	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 13:58:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) DecodedLen(n int) int {
	return int(math.Ceil(math.Log(62) / math.Log(256) * float64(n)))
}
