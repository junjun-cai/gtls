// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 22:04:49                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: ecb.go                                                                                                      *
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
	cipher2 "gotils/crypto/cipher"
)

type ecbMode struct {
	padding padding.IPadding
	enBlock cipher.BlockMode
	deBlock cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:10:01 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewECBMode(block cipher.Block, padding padding.IPadding) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &ecbMode{
		padding: padding,
		enBlock: cipher2.NewECBEncrypter(block),
		deBlock: cipher2.NewECBDecrypter(block),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:10:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *ecbMode) Encode(src []byte) ([]byte, error) {
	paddingText := e.padding.Padding(src, e.enBlock.BlockSize())
	encrypted := make([]byte, len(paddingText))
	e.enBlock.CryptBlocks(encrypted, paddingText)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:11:42 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *ecbMode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	e.deBlock.CryptBlocks(decrypted, src)
	return e.padding.UnPadding(decrypted)
}
