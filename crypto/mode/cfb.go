// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 21:53:50                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: cfb.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package mode

import (
	"crypto/cipher"
	"github.com/pkg/errors"
)

type cfbMode struct {
	enStream cipher.Stream
	deStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 21:58:56 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFBMode(block cipher.Block, iv []byte) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &cfbMode{
		enStream: cipher.NewCFBEncrypter(block, iv),
		deStream: cipher.NewCFBDecrypter(block, iv),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 21:59:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfbMode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	c.enStream.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:01:09 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfbMode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	c.deStream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
