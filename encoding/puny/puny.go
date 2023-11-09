// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 16:13:49                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: puny                                                                                                        *
// * File: puny.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package puny

import (
	"bytes"
	"github.com/caijunjun/gotils/encoding/base"
	"github.com/pkg/errors"
)

const (
	// Bootstring parameters specified in RFC 3492
	baseC            = 36
	tMin             = 1
	tMax             = 26
	skew             = 38
	damp             = 700
	initialBias      = 72
	initialN         = 128  // 0x80
	delimiter   byte = 0x2D // hyphen
	maxRune          = '\U0010FFFF'
)

var (
	invalidCharater    = errors.New("Non-ASCCI codepoint found in src")
	overFlowErr        = errors.New("Overflow")
	inputError         = errors.New("Bad Input")
	digit2codepointErr = errors.New("digit2codepoint")
)

type PunyEncoding struct{}

var StdEncoding = NewPunyEncoding()

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:10:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewPunyEncoding() base.IEncoding {
	return &PunyEncoding{}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:15:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func (p *PunyEncoding) Encode(src []byte) ([]byte, error) {
	n := initialN
	delta := 0
	bias := initialBias
	runes := bytes.Runes(src)

	var result bytes.Buffer
	var err error

	basicRunes := 0
	for i := 0; i < len(runes); i++ {
		// Write all basic codepoints to result
		if runes[i] < 0x80 {
			result.WriteRune(runes[i])
			if err != nil {
				return nil, err
			}
			basicRunes++
		}
	}

	// Append delimiter
	if basicRunes > 0 {
		err = result.WriteByte(delimiter)
		if err != nil {
			return nil, err
		}
	}

	for h := basicRunes; h < len(runes); {
		minRune := maxRune

		// Find the minimum rune >= n in the input
		for i := 0; i < len(runes); i++ {
			if int(runes[i]) >= n && runes[i] < minRune {
				minRune = runes[i]
			}
		}

		delta = delta + (int(minRune)-n)*(h+1) // ??
		n = int(minRune)

		for i := 0; i < len(runes); i++ {
			if int(runes[i]) < n {
				delta++
			}
			if int(runes[i]) == n {
				q := delta
				for k := baseC; true; k += baseC {
					var t int

					switch {
					case k <= bias:
						t = tMin
						break
					case k >= (bias + tMax):
						t = tMax
						break
					default:
						t = k - bias
					}

					if q < t {
						break
					}
					result, err = writeBytesDigitToCodepoint(result, t+(q-t)%(baseC-t))
					if err != nil {
						return nil, err
					}
					q = (q - t) / (baseC - t)
				}
				result, err = writeBytesDigitToCodepoint(result, q)
				if err != nil {
					return nil, err
				}

				bias = adapt(delta, h == basicRunes, h+1)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return result.Bytes(), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:10:50 ColeCai.                                                                          *
// *********************************************************************************************************************
func (p *PunyEncoding) EncodedLen(n int) int {
	return n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:17:49 ColeCai.                                                                          *
// *********************************************************************************************************************
func (p *PunyEncoding) Decode(src []byte) ([]byte, error) {
	// Decoding procedure explained in detail in RFC 3492.
	n := initialN
	i := 0
	bias := initialBias

	pos := 0
	delimIndex := -1

	result := make([]rune, 0, len(src))

	// Only ASCII allowed in decoding procedure
	for j := 0; j < len(src); j++ {
		if src[j] >= 0x80 {
			return nil, invalidCharater

		}
	}

	// Consume all codepoints before the last delimiter
	delimIndex = bytes.LastIndex(src, []byte{delimiter})
	for pos = 0; pos < delimIndex; pos++ {
		result = append(result, rune(src[pos]))
	}

	// Consume delimiter
	pos = delimIndex + 1

	for pos < len(src) {
		oldi := i
		w := 1
		for k := baseC; true; k += baseC {
			var t int

			if pos == len(src) {
				return nil, inputError
			}

			// consume a code point, or fail if there was none to consume
			cp := rune(src[pos])
			pos++

			digit := codepoint2digit(cp)

			if digit > ((maxRune - i) / w) {
				return nil, inputError
			}

			i = i + digit*w

			switch {
			case k <= bias:
				t = tMin
				break
			case k >= bias+tMax:
				t = tMax
				break
			default:
				t = k - bias
			}

			if digit < t {
				break
			}
			w = w * (baseC - t)
		}
		bias = adapt(i-oldi, oldi == 0, len(result)+1)

		if i/(len(result)+1) > (maxRune - n) {
			return nil, overFlowErr
		}

		n = n + i/(len(result)+1)
		i = i % (len(result) + 1)

		if n < 0x80 {
			return nil, errors.Errorf("%v is a basic code point.", n)
		}

		result = insert(result, i, rune(n))
		i++
	}

	return writeRune(result), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:11:11 ColeCai.                                                                          *
// *********************************************************************************************************************
func (p *PunyEncoding) DecodedLen(n int) int {
	return n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:14:20 ColeCai.                                                                          *
// *********************************************************************************************************************
func adapt(delta int, first bool, numchars int) (bias int) {
	if first {
		delta = delta / damp
	} else {
		delta = delta / 2
	}

	delta = delta + (delta / numchars)

	k := 0
	for delta > ((baseC-tMin)*tMax)/2 {
		delta = delta / (baseC - tMin)
		k = k + baseC
	}
	bias = k + ((baseC-tMin+1)*delta)/(delta+skew)
	return
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:14:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func codepoint2digit(r rune) int {
	switch {
	case r-48 < 10:
		return int(r - 22)
	case r-65 < 26:
		return int(r - 65)
	case r-97 < 26:
		return int(r - 97)
	}
	return baseC
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:24:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func writeBytesDigitToCodepoint(bytes bytes.Buffer, d int) (bytes.Buffer, error) {
	var val rune
	switch {
	case d < 26:
		// 0..25 : 'a'..'z'
		val = rune(d + 'a')
	case d < 36:
		// 26..35 : '0'..'9';
		val = rune(d - 26 + '0')
	default:
		return bytes, digit2codepointErr
	}
	err := bytes.WriteByte(byte(val))
	return bytes, err
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:15:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func writeRune(r []rune) []byte {
	str := string(r)
	return []byte(str)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:15:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func insert(s []rune, pos int, r rune) []rune {
	return append(s[:pos], append([]rune{r}, s[pos:]...)...)
}
