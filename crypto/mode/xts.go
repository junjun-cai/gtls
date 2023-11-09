// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 22:17:39                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: mode                                                                                                        *
// * File: xts.go                                                                                                      *
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
	"golang.org/x/crypto/xts"
)

type xtsMode struct {
	padding padding.IPadding
	cipher  *xts.Cipher
	sector  uint64
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:18:52 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewXTSMode(cipherFunc func([]byte) (cipher.Block, error), key []byte, sector uint64, padding padding.IPadding) (mode IMode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	c, err := xts.NewCipher(cipherFunc, key)
	if err != nil {
		return nil, err
	}
	return &xtsMode{cipher: c, sector: sector, padding: padding}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:19:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *xtsMode) Encode(src []byte) ([]byte, error) {
	paddingText := x.padding.Padding(src, 16)
	encrypted := make([]byte, len(paddingText))
	x.cipher.Encrypt(encrypted, paddingText, x.sector)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/27 22:20:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *xtsMode) Decode(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	x.cipher.Decrypt(decrypted, src, x.sector)
	return x.padding.UnPadding(decrypted)
}
