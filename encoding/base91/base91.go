// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 01:10:09                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base91                                                                                                      *
// * File: base91.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base91

import (
	"github.com/caijunjun/gotils/encoding/base"
	"github.com/pkg/errors"
	"math"
)

type Base91Encoding struct {
	encode    [91]byte
	decodeMap [256]byte
}

const (
	encodeStd  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
	encodeSize = 91
)

var (
	invalidEncoderSize = errors.Errorf("base91: reflect str lenght must be %d.", encodeSize)
	StdEncoding, _     = NewEncoding(encodeStd)
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:10:32 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string) (base.IEncoding, error) {
	if len(encoder) != encodeSize {
		return nil, invalidEncoderSize
	}
	e := new(Base91Encoding)
	copy(e.encode[:], encoder)

	for i := 0; i < len(e.decodeMap); i++ {
		// 0xff indicates that this entry in the decode map is not in the encoding alphabet.
		e.decodeMap[i] = 0xff
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
// *    -create: 2023/10/31 01:11:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Base91Encoding) Encode(src []byte) ([]byte, error) {
	var queue, numBits uint

	dst := make([]byte, e.EncodedLen(len(src)))
	n := 0
	for i := 0; i < len(src); i++ {
		queue |= uint(src[i]) << numBits
		numBits += 8
		if numBits > 13 {
			var v = queue & 8191

			if v > 88 {
				queue >>= 13
				numBits -= 13
			} else {
				// We can take 14 bits.
				v = queue & 16383
				queue >>= 14
				numBits -= 14
			}
			dst[n] = e.encode[v%91]
			n++
			dst[n] = e.encode[v/91]
			n++
		}
	}

	if numBits > 0 {
		dst[n] = e.encode[queue%91]
		n++

		if numBits > 7 || queue > 90 {
			dst[n] = e.encode[queue/91]
			n++
		}
	}

	return dst[:n], nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:11:20 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Base91Encoding) EncodedLen(n int) int {
	// At worst, base91 encodes 13 bits into 16 bits. Even though 14 bits can
	// sometimes be encoded into 16 bits, assume the worst case to get the upper
	// bound on encoded length.
	return int(math.Ceil(float64(n) * 16.0 / 13.0))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:11:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Base91Encoding) Decode(src []byte) ([]byte, error) {
	var queue, numBits uint
	var v = -1

	dst := make([]byte, e.DecodedLen(len(src)))
	n := 0
	for i := 0; i < len(src); i++ {
		if e.decodeMap[src[i]] == 0xff {
			// The character is not in the encoding alphabet.
			return nil, errors.New("base91: invalid character, the he character is not in the encoding alphabet")
		}

		if v == -1 {
			// Start the next value.
			v = int(e.decodeMap[src[i]])
		} else {
			v += int(e.decodeMap[src[i]]) * 91
			queue |= uint(v) << numBits

			if (v & 8191) > 88 {
				numBits += 13
			} else {
				numBits += 14
			}

			for ok := true; ok; ok = numBits > 7 {
				dst[n] = byte(queue)
				n++

				queue >>= 8
				numBits -= 8
			}

			// Mark this value complete.
			v = -1
		}
	}

	if v != -1 {
		dst[n] = byte(queue | uint(v)<<numBits)
		n++
	}

	return dst[:n], nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:11:42 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Base91Encoding) DecodedLen(n int) int {
	// At best, base91 encodes 14 bits into 16 bits, so assume that the input is
	// optimally encoded to get the upper bound on decoded length.
	return int(math.Ceil(float64(n) * 14.0 / 16.0))
}
