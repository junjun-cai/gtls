// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 23:45:19                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base58                                                                                                      *
// * File: base58.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base58

import (
	"bytes"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"math"
	"math/big"
)

const (
	encoderStd  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	encoderSize = 58
)

type Encoding struct {
	reflectStr string
}

var (
	StdEncoding, _     = NewEncoding(encoderStd)
	invalidEncoderSize = errors.Errorf("base58: reflect str lenght must be %d.", encoderSize)
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 13:28:17 ColeCai.                                                                          *
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
// *    -create: 2023/10/30 23:45:40 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Encode(src []byte) ([]byte, error) {
	intBytes := big.NewInt(0).SetBytes(src)
	int0, int58 := big.NewInt(0), big.NewInt(58)
	lenght := e.EncodedLen(len(src))
	var dst = make([]byte, 0, lenght)
	for intBytes.Cmp(big.NewInt(0)) > 0 {
		intBytes.DivMod(intBytes, int58, int0)
		dst = append(dst, []byte(e.reflectStr)[int0.Int64()])
	}
	return tools.ReverseSlice(dst), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:02:15 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) EncodedLen(n int) int {
	return int(math.Ceil(math.Log(256) / math.Log(58) * float64(n)))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 23:49:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	bigInt := big.NewInt(0)
	for _, v := range src {
		index := bytes.IndexByte([]byte(e.reflectStr), v)
		bigInt.Mul(bigInt, big.NewInt(58))
		bigInt.Add(bigInt, big.NewInt(int64(index)))
	}
	return bigInt.Bytes(), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:02:24 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) DecodedLen(n int) int {
	return int(math.Ceil(math.Log(58) / math.Log(256) * float64(n)))
}
