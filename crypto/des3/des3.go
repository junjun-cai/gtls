// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/28 16:31:16                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: des3                                                                                                        *
// * File: des3.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package des3

import (
	"crypto/cipher"
	"crypto/des"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/pkg/errors"
)

type Des3Crypter struct {
	cface.Crypter
	Key     []byte
	Iv      []byte
	Padding padding.IPadding
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 21:12:24 ColeCai.                                                                          *
// *********************************************************************************************************************
func des3BlockBuilder(key []byte) (block cipher.Block, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return des.NewTripleDESCipher(key)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:49:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func New3DesCBCrypter(key []byte, iv []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := des3BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewCBCMode(block, iv, padding)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:50:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func New3DesCFBrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := des3BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewCFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:51:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func New3DesTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := des3BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewCTRMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:52:02 ColeCai.                                                                          *
// *********************************************************************************************************************
func New3DesECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := des3BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewECBMode(block, padding)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:52:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func New3DesOFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := des3BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
