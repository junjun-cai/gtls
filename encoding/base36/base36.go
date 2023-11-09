// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 15:23:03                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base36                                                                                                      *
// * File: base36.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base36

import (
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"math/big"
	"strings"
)

type Encoding struct {
	reflectStr string
}

const (
	encoderStd  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	encoderSize = 36
)

var (
	StdEncoding, _     = NewEncoding(encoderStd)
	invalidEncoderSize = errors.Errorf("base36: reflect str lenght must be %d.", encoderSize)
	bigRadix           = big.NewInt(36)
	bigZero            = big.NewInt(0)
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:25:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string) (*Encoding, error) {
	if len(encoder) != encoderSize {
		return nil, invalidEncoderSize
	}
	return &Encoding{reflectStr: encoder}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:27:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) EncodedLen(n int) int {
	return n * 136 / 100
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:28:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Encode(src []byte) ([]byte, error) {
	x := new(big.Int)
	x.SetBytes(src)

	dst := make([]byte, 0, e.EncodedLen(len(src)))
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		dst = append(dst, e.reflectStr[mod.Int64()])
	}

	// leading zero bytes
	for _, i := range src {
		if i != 0 {
			break
		}
		dst = append(dst, e.reflectStr[0])
	}

	// reverse
	alen := len(dst)
	for i := 0; i < alen/2; i++ {
		dst[i], dst[alen-1-i] = dst[alen-1-i], dst[i]
	}

	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:30:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) DecodedLen(n int) int {
	return 0
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:32:04 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	answer := big.NewInt(0)
	j := big.NewInt(1)
	b := tools.BytesToString(src)
	for i := len(b) - 1; i >= 0; i-- {
		tmp := strings.IndexAny(e.reflectStr, string(b[i]))
		if tmp == -1 {
			return nil, invalidCharacterErr(string(b[i]), i)
		}
		idx := big.NewInt(int64(tmp))
		tmp1 := big.NewInt(0)
		tmp1.Mul(j, idx)

		answer.Add(answer, tmp1)
		j.Mul(j, bigRadix)
	}

	tmpval := answer.Bytes()

	var numZeros int
	for numZeros = 0; numZeros < len(b); numZeros++ {
		if b[numZeros] != e.reflectStr[0] {
			break
		}
	}
	flen := numZeros + len(tmpval)
	dst := make([]byte, flen)
	copy(dst[numZeros:], tmpval)

	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:35:04 ColeCai.                                                                          *
// *********************************************************************************************************************
func invalidCharacterErr(char string, pos int) error {
	return errors.Errorf("invalid character %s at position: %d\n", char, pos)
}
