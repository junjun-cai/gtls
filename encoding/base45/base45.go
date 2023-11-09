// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 23:08:36                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base45                                                                                                      *
// * File: base45.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base45

import (
	"encoding/binary"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"unicode/utf8"
)

const (
	base        = 45
	baseSquare  = 45 * 45
	maxUint16   = 0xFFFF
	encoderSize = 45
	encoderStd  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
)

var (
	stdEncodingMap = map[byte]rune{
		byte(0):  '0',
		byte(1):  '1',
		byte(2):  '2',
		byte(3):  '3',
		byte(4):  '4',
		byte(5):  '5',
		byte(6):  '6',
		byte(7):  '7',
		byte(8):  '8',
		byte(9):  '9',
		byte(10): 'A',
		byte(11): 'B',
		byte(12): 'C',
		byte(13): 'D',
		byte(14): 'E',
		byte(15): 'F',
		byte(16): 'G',
		byte(17): 'H',
		byte(18): 'I',
		byte(19): 'J',
		byte(20): 'K',
		byte(21): 'L',
		byte(22): 'M',
		byte(23): 'N',
		byte(24): 'O',
		byte(25): 'P',
		byte(26): 'Q',
		byte(27): 'R',
		byte(28): 'S',
		byte(29): 'T',
		byte(30): 'U',
		byte(31): 'V',
		byte(32): 'W',
		byte(33): 'X',
		byte(34): 'Y',
		byte(35): 'Z',
		byte(36): ' ',
		byte(37): '$',
		byte(38): '%',
		byte(39): '*',
		byte(40): '+',
		byte(41): '-',
		byte(42): '.',
		byte(43): '/',
		byte(44): ':',
	}
	stdDecodingMap = map[rune]byte{
		'0': byte(0),
		'1': byte(1),
		'2': byte(2),
		'3': byte(3),
		'4': byte(4),
		'5': byte(5),
		'6': byte(6),
		'7': byte(7),
		'8': byte(8),
		'9': byte(9),
		'A': byte(10),
		'B': byte(11),
		'C': byte(12),
		'D': byte(13),
		'E': byte(14),
		'F': byte(15),
		'G': byte(16),
		'H': byte(17),
		'I': byte(18),
		'J': byte(19),
		'K': byte(20),
		'L': byte(21),
		'M': byte(22),
		'N': byte(23),
		'O': byte(24),
		'P': byte(25),
		'Q': byte(26),
		'R': byte(27),
		'S': byte(28),
		'T': byte(29),
		'U': byte(30),
		'V': byte(31),
		'W': byte(32),
		'X': byte(33),
		'Y': byte(34),
		'Z': byte(35),
		' ': byte(36),
		'$': byte(37),
		'%': byte(38),
		'*': byte(39),
		'+': byte(40),
		'-': byte(41),
		'.': byte(42),
		'/': byte(43),
		':': byte(44),
	}
	invalidEncoderSize = errors.Errorf("base45: reflect str lenght must be %d.", encoderSize)
	StdEncoding        = &Encoding{encodingMap: stdEncodingMap, decodingMap: stdDecodingMap}
)

type Encoding struct {
	encodingMap map[byte]rune
	decodingMap map[rune]byte
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 13:41:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string) (*Encoding, error) {
	if len(encoder) != encoderSize {
		return nil, invalidEncoderSize
	}
	e := &Encoding{
		encodingMap: make(map[byte]rune),
		decodingMap: make(map[rune]byte),
	}
	for k, v := range encoder {
		e.encodingMap[byte(k)] = v
		e.decodingMap[v] = byte(k)
	}
	return e, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:39:50 ColeCai.                                                                          *
// *********************************************************************************************************************
func invalidLenghtErr(size, mod int) error {
	return errors.Errorf("invalid length n=%d. It should be n mod 3 = [0, 2] NOT n mod 3 = %d", size, mod)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:40:57 ColeCai.                                                                          *
// *********************************************************************************************************************
func invalidCharacterErr(char string, pos int) error {
	return errors.Errorf("invalid character %s at position: %d\n", char, pos)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:12:25 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Encode(src []byte) ([]byte, error) {
	pairs := encodePairs(src)
	var dst []byte
	for i, pair := range pairs {
		res := encodeBase45(pair)
		if i+1 == len(pairs) && res[2] == 0 {
			for _, b := range res[:2] {
				if c, ok := e.encodingMap[b]; ok {
					utf8.AppendRune(dst, c)
				}
			}
		} else {
			for _, b := range res {
				if c, ok := e.encodingMap[b]; ok {
					utf8.AppendRune(dst, c)
				}
			}
		}
	}
	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: do not use,only implement Encoding interface.                                                            *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:06:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) EncodedLen(n int) int {
	return n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:19:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	strSrc := tools.BytesToString(src)
	size := len(strSrc)
	mod := size % 3
	if mod != 0 && mod != 2 {
		return nil, invalidLenghtErr(size, mod)
	}
	bytes := make([]byte, 0, size)
	for pos, char := range strSrc {
		v, ok := e.decodingMap[char]
		if !ok {
			return nil, invalidCharacterErr(string(char), pos)
		}
		bytes = append(bytes, v)
	}
	chunks := decodeChunks(bytes)
	triplets, err := decodeTriplets(chunks)
	if err != nil {
		return nil, err
	}
	tripletsLength := len(triplets)
	decoded := make([]byte, 0, tripletsLength*2)
	for i := 0; i < tripletsLength-1; i++ {
		bytes := tools.Uint16ToBytes(triplets[i])
		decoded = append(decoded, bytes[0])
		decoded = append(decoded, bytes[1])
	}
	if mod == 2 {
		bytes := tools.Uint16ToBytes(triplets[tripletsLength-1])
		decoded = append(decoded, bytes[1])
	} else {
		bytes := tools.Uint16ToBytes(triplets[tripletsLength-1])
		decoded = append(decoded, bytes[0])
		decoded = append(decoded, bytes[1])
	}
	return decoded, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: do not use,only implement Encoding interface.                                                            *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:06:59 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) DecodedLen(n int) int {
	return n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:10:10 ColeCai.                                                                          *
// *********************************************************************************************************************
func decodeChunks(in []byte) [][]byte {
	size := len(in)
	ret := make([][]byte, 0, size/2)
	for i := 0; i < size; i += 3 {
		var f, s, l byte
		if i+2 < size {
			f = in[i]
			s = in[i+1]
			l = in[i+2]
			ret = append(ret, []byte{f, s, l})
		} else {
			f = in[i]
			s = in[i+1]
			ret = append(ret, []byte{f, s})
		}
	}
	return ret
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:10:53 ColeCai.                                                                          *
// *********************************************************************************************************************
func encodePairs(in []byte) [][]byte {
	size := len(in)
	ret := make([][]byte, 0, size/2)
	for i := 0; i < size; i += 2 {
		var high, low byte
		if i+1 < size {
			high = in[i]
			low = in[i+1]
		} else {
			low = in[i]
		}
		ret = append(ret, []byte{high, low})
	}
	return ret
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:11:01 ColeCai.                                                                          *
// *********************************************************************************************************************
func encodeBase45(in []byte) []byte {
	n := binary.BigEndian.Uint16(in)
	c := n % base
	e := (n - c) / (baseSquare)
	d := (n - (c + (e * baseSquare))) / base
	return []byte{byte(c), byte(d), byte(e)}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:11:12 ColeCai.                                                                          *
// *********************************************************************************************************************
func decodeTriplets(in [][]byte) ([]uint16, error) {
	size := len(in)
	ret := make([]uint16, 0, size)
	for pos, chunk := range in {
		if len(chunk) == 3 {
			// n = c + (d*45) + (e*45*45)
			c := int(chunk[0])
			d := int(chunk[1])
			e := int(chunk[2])
			n := c + (d * base) + (e * baseSquare)
			if n > maxUint16 {
				return nil, errors.Errorf("illegal base45 data at byte position %d\n", pos)
			}
			ret = append(ret, uint16(n))
		}
		if len(chunk) == 2 {
			// n = c + (d*45)
			c := uint16(chunk[0])
			d := uint16(chunk[1])
			n := c + (d * base)
			ret = append(ret, n)
		}
	}
	return ret, nil
}
