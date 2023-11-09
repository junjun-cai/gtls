// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 21:47:40                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: cfb32.go                                                                                                    *
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

type cfb32Mode struct {
	enStream cipher.Stream
	deStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:50:42 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB32Mode(block cipher.Block, iv []byte) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &cfb32Mode{
		enStream: cipher2.NewCFB32Encrypter(block, iv),
		deStream: cipher2.NewCFB32Decrypter(block, iv),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:51:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb32Mode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	c.enStream.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:54:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb32Mode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	c.deStream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
