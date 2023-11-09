// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 21:52:01                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: cfb64.go                                                                                                    *
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

type cfb64Mode struct {
	enStream cipher.Stream
	deStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:54:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB64Mode(block cipher.Block, iv []byte) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &cfb64Mode{
		enStream: cipher2.NewCFB64Encrypter(block, iv),
		deStream: cipher2.NewCFB64Decrypter(block, iv),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:54:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb64Mode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	c.enStream.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 21:54:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb64Mode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	c.deStream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
