// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 23:05:23                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: pcbc.go                                                                                                     *
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

type pcbcMode struct {
	enBlock cipher.BlockMode
	deBlock cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:07:10 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewPCBCMode(block cipher.Block) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return &pcbcMode{
		enBlock: cipher2.NewECBEncrypter(block),
		deBlock: cipher2.NewECBDecrypter(block),
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:07:36 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *pcbcMode) Encode(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	e.enBlock.CryptBlocks(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:08:03 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *pcbcMode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	e.deBlock.CryptBlocks(decrypted, src)
	return decrypted, nil
}
