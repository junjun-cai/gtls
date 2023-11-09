// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 22:53:29                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: crypto                                                                                                      *
// * File: aes.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
)

type AesType uint8

const (
	AES128 AesType = 16
	AES192 AesType = 24
	AES256 AesType = 32
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 21:02:49 ColeCai.                                                                          *
// *********************************************************************************************************************
func aesBlockBuilder(key []byte) (block cipher.Block, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return aes.NewCipher(key)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 01:39:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateAesKey(aesType AesType) []byte {
	return tools.RandNBytes(int(aesType))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 02:09:49 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateAesXtsKey(aesType AesType) []byte {
	return tools.RandNBytes(int(aesType) * 2)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 01:42:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateAesIV() []byte {
	return tools.RandNBytes(aes.BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:26:49 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesCBCCrypter(key []byte, iv []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
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
// *    -create: 2023/10/28 19:28:13 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesCFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
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
// *    -create: 2023/10/28 19:29:59 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesCTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
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
// *    -create: 2023/10/28 19:31:11 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
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
// *    -create: 2023/10/28 19:32:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesGCMCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewGCMMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:33:36 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesOFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:34:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesXTSCrypter(key []byte, sector uint64, padding padding.IPadding) (crypter cface.ICrypter, err error) {
	m, err := mode.NewXTSMode(aes.NewCipher, key, sector, padding)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 02:19:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewAesCFB8Crypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := aesBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewCFB8Mode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
