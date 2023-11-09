// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 16:22:10                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: saferplus                                                                                                    *
// * File: safe.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package safeplus

import (
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
)

type SaferplusType uint8

const (
	SAFE128 SaferplusType = 16
	SAFE192 SaferplusType = 24
	SAFE256 SaferplusType = 32
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 16:28:11 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateSaferplusKey(safeplusType SaferplusType) []byte {
	return tools.RandNBytes(int(safeplusType))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 16:28:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateSaferplusIV() []byte {
	return tools.RandNBytes(BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 16:23:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func saferPlusBlockBuilder(key []byte) (block cipher.Block, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return NewCipher(key)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 16:23:31 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSaferplusCBCCrypter(key []byte, iv []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := saferPlusBlockBuilder(key)
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
// *    -create: 2023/10/30 16:24:15 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSaferplusCFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := saferPlusBlockBuilder(key)
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
// *    -create: 2023/10/30 16:25:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSaferplusCTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := saferPlusBlockBuilder(key)
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
// *    -create: 2023/10/30 16:25:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSaferplusECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := saferPlusBlockBuilder(key)
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
// *    -create: 2023/10/30 16:26:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSaferplusOFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := saferPlusBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
