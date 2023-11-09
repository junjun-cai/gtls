// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 02:01:58                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: cfb8.go                                                                                                     *
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

type cfb8Mode struct {
	enStream cipher.Stream
	deStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 02:17:15 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB8Mode(block cipher.Block, iv []byte) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &cfb8Mode{
		enStream: cipher2.NewCFB8Encrypter(block, iv),
		deStream: cipher2.NewCFB8Decrypter(block, iv),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 02:17:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb8Mode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	c.enStream.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 02:17:53 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb8Mode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	c.deStream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
