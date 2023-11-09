// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 21:55:33                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: ofb8.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package mode

import (
	"crypto/cipher"
	"github.com/pkg/errors"
	cipher2 "gotils/crypto/cipher"
)

type ofb8Mode struct {
	stream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:58:12 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewOFB8Mode(block cipher.Block, iv []byte) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &ofb8Mode{stream: cipher2.NewOFB8(block, iv)}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:58:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ofb8Mode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	o.stream.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:58:53 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ofb8Mode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	o.stream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
