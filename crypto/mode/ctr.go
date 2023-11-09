// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 22:02:16                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: ctr.go                                                                                                      *
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

type ctrMode struct {
	enStream cipher.Stream
	deStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:03:49 ColeCai.                                                                          *
// *    -update: 2023/10/28 00:34:44 ColeCai.                                                                          *
// *		-recover panic,and return err.                                                                             *
// *********************************************************************************************************************
func NewCTRMode(block cipher.Block, iv []byte) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &ctrMode{enStream: cipher.NewCTR(block, iv), deStream: cipher.NewCTR(block, iv)}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:02:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *ctrMode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	c.enStream.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:03:22 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *ctrMode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	c.deStream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
