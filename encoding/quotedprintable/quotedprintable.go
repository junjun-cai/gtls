// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 16:43:00                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: quotedprintable                                                                                             *
// * File: quotedprintable.go                                                                                          *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package quotedprintable

import (
	"bytes"
	"github.com/pkg/errors"
	"io"
)

const (
	stdEncoder  = "0123456789ABCDEF"
	encoderSize = len(stdEncoder)
)

var (
	invalidEncoderSize = errors.Errorf("quotedprintable: reflect str lenght must be %d.", encoderSize)
	StdEncoding, _     = NewEncoding(stdEncoder)
)

type Encoding struct {
	encoder string
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:46:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string) (*Encoding, error) {
	if len(encoder) != encoderSize {
		return nil, invalidEncoderSize
	}
	return &Encoding{encoder: encoder}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:46:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) EncodedLen(n int) int {
	return 3 * n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:47:31 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Encode(src []byte) ([]byte, error) {
	dst := make([]byte, e.EncodedLen(len(src)))
	n := 0
	for i, c := range src {
		switch {
		case c != '=' && (c >= '!' && c <= '~' || c == '\n' || c == '\r'):
			dst[n] = c
			n++
		case c == ' ' || c == '\t':
			if isLastChar(i, src) {
				e.encodeByte(dst[n:], c)
				n += 3
			} else {
				dst[n] = c
				n++
			}
		default:
			e.encodeByte(dst[n:], c)
			n += 3
		}
	}
	return dst[:n], nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:49:58 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) DecodedLen(n int) int {
	return n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:49:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	dst := make([]byte, e.DecodedLen(len(src)))
	var eol, trimLen, eolLen, n int
	var err error
	for i := 0; i < len(src); i++ {
		if i == eol {
			eol = bytes.IndexByte(src[i:], '\n') + i + 1
			if eol == i {
				eol = len(src)
				eolLen = 0
			} else if eol-2 >= i && src[eol-2] == '\r' {
				eolLen = 2
			} else {
				eolLen = 1
			}

			// Count the number of bytes to trim
			trimLen = 0
			for {
				if trimLen == eol-eolLen-i {
					break
				}

				switch src[eol-eolLen-trimLen-1] {
				case '\n', '\r', ' ', '\t':
					trimLen++
					continue
				case '=':
					if trimLen > 0 {
						trimLen += eolLen + 1
						eolLen = 0
						err = errors.Errorf("quotedprintable: invalid bytes after =: %q", src[eol-trimLen+1:eol])
					} else {
						trimLen = eolLen + 1
						eolLen = 0
					}
				}
				break
			}
		}

		// Skip trimmable bytes
		if trimLen > 0 && i == eol-trimLen-eolLen {
			if err != nil {
				return nil, err
			}

			i += trimLen - 1
			continue
		}

		switch c := src[i]; {
		case c == '=':
			if i+2 >= len(src) {
				return nil, io.ErrUnexpectedEOF
			}
			b, convErr := readHexByte(src[i+1:])
			if convErr != nil {
				return nil, convErr
			}
			dst[n] = b
			n++
			i += 2
		case (c >= ' ' && c <= '~') || c == '\n' || c == '\r' || c == '\t':
			dst[n] = c
			n++
		default:
			return nil, errors.Errorf("quotedprintable: invalid unescaped byte 0x%02x in quoted-printable body", c)
		}
	}

	return dst[:n], nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:43:15 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) encodeByte(dst []byte, b byte) {
	dst[0] = '='
	dst[1] = e.encoder[b>>4]
	dst[2] = e.encoder[b&0x0f]
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:44:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func fromHex(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	// Accept badly encoded bytes
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	}
	return 0, errors.Errorf("quotedprintable: invalid quoted-printable hex byte %#02x", b)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:44:25 ColeCai.                                                                          *
// *********************************************************************************************************************
func readHexByte(v []byte) (b byte, err error) {
	var hb, lb byte
	if hb, err = fromHex(v[0]); err != nil {
		return 0, err
	}
	if lb, err = fromHex(v[1]); err != nil {
		return 0, err
	}
	return hb<<4 | lb, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:48:26 ColeCai.                                                                          *
// *********************************************************************************************************************
func isLastChar(i int, src []byte) bool {
	return i == len(src)-1 ||
		(i < len(src)-1 && src[i+1] == '\n') ||
		(i < len(src)-2 && src[i+1] == '\r' && src[i+2] == '\n')
}
