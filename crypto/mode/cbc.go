// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 21:48:32                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: cbc.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package mode

import (
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/pkg/errors"
)

type cbcMode struct {
	padding padding.IPadding
	enBlock cipher.BlockMode
	deBlock cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 21:50:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCBCMode(block cipher.Block, iv []byte, padding padding.IPadding) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &cbcMode{
		padding: padding,
		enBlock: cipher.NewCBCEncrypter(block, iv),
		deBlock: cipher.NewCBCDecrypter(block, iv),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 21:51:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cbcMode) Encode(src []byte) ([]byte, error) {
	paddingText := c.padding.Padding(src, c.enBlock.BlockSize())
	encrypted := make([]byte, len(paddingText))
	c.enBlock.CryptBlocks(encrypted, paddingText)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 21:52:57 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cbcMode) Decode(src []byte) ([]byte, error) {
	decryped := make([]byte, len(src))
	c.deBlock.CryptBlocks(decryped, src)
	return c.padding.UnPadding(decryped)
}
