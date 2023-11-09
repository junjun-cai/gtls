// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 14:29:12                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: base64                                                                                                      *
// * File: base64.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package base64

import (
	"encoding/base64"
	"github.com/pkg/errors"
)

type Encoding struct {
	*base64.Encoding
}

const (
	StdPadding = base64.StdPadding
	NoPadding  = base64.NoPadding
)

var (
	StdEncoding    = &Encoding{Encoding: base64.StdEncoding}
	URLEncoding    = &Encoding{Encoding: base64.URLEncoding}
	RawStdEncoding = &Encoding{Encoding: base64.RawStdEncoding}
	RawURLEncoding = &Encoding{Encoding: base64.RawURLEncoding}
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:38:10 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncoding(encoder string, padding rune) (enc *Encoding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
	}()
	return &Encoding{Encoding: base64.NewEncoding(encoder).WithPadding(padding)}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:30:38 ColeCai.                                                                          *
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
// *    -create: 2023/10/31 14:32:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *Encoding) Decode(src []byte) ([]byte, error) {
	dst := make([]byte, e.DecodedLen(len(src)))
	n, err := e.Encoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
