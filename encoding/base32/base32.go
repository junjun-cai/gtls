// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 14:52:37                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base32                                                                                                      *
// * File: base32.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base32

import (
	"encoding/base32"
	"github.com/pkg/errors"
)

type Encoding struct {
	*base32.Encoding
}

const (
	StdPadding = base32.StdPadding
	NoPadding  = base32.NoPadding
)

var (
	StdEncoding = &Encoding{Encoding: base32.StdEncoding}
	HexEncoding = &Encoding{Encoding: base32.HexEncoding}
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:55:46 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string, padding rune) (enc *Encoding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
	}()
	return &Encoding{Encoding: base32.NewEncoding(encoder).WithPadding(padding)}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:53:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Encode(src []byte) ([]byte, error) {
	dst := make([]byte, e.EncodedLen(len(src)))
	e.Encoding.Encode(dst, src)
	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:54:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	dst := make([]byte, e.DecodedLen(len(src)))
	n, err := e.Encoding.Decode(dst, src)
	return dst[:n], err
}
