// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 17:55:28                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cast5                                                                                                       *
// * File: cast5.go                                                                                                    *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cast5

import (
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/cast5"
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:24:08 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateCast5Key() []byte {
	return tools.RandNBytes(cast5.KeySize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:24:37 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateCast5Iv() []byte {
	return tools.RandNBytes(cast5.BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 17:56:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func cast5BlockBuilder(key []byte) (block cipher.Block, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return cast5.NewCipher(key)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 17:57:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast5CBCCrypter(key []byte, iv []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := cast5BlockBuilder(key)
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
// *    -create: 2023/10/30 17:57:45 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast5CFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := cast5BlockBuilder(key)
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
// *    -create: 2023/10/30 17:58:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast5CTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := cast5BlockBuilder(key)
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
// *    -create: 2023/10/30 17:58:29 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast5ECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := cast5BlockBuilder(key)
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
// *    -create: 2023/10/30 17:59:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast5OFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := cast5BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
