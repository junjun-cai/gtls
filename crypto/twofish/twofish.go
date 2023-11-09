// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/28 21:25:51                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: twofish                                                                                                     *
// * File: twofish.go                                                                                                  *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package twofish

import (
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/twofish"
)

type TwofishType uint8

const (
	Twofish128 TwofishType = 16
	Twofish192 TwofishType = 24
	Twofish256 TwofishType = 32
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 01:12:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateTwofishKey(twType TwofishType) []byte {
	return tools.RandNBytes(int(twType))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 01:13:18 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateTwofishIV() []byte {
	return tools.RandNBytes(twofish.BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 21:26:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func twfBlockBuilder(key []byte) (block *twofish.Cipher, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%v", r)
			return
		}
	}()
	return twofish.NewCipher(key)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 21:27:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTwoFishCBCrypter(key []byte, iv []byte, padding padding.IPadding) (crypter cface.ICrypter, err error) {
	block, err := twfBlockBuilder(key)
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
// *    -create: 2023/10/28 21:28:24 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTwoFishCFBrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := twfBlockBuilder(key)
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
// *    -create: 2023/10/28 21:28:51 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTwoFishCTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := twfBlockBuilder(key)
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
// *    -create: 2023/10/28 21:29:18 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTwoFishECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := twfBlockBuilder(key)
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
// *    -create: 2023/10/28 21:29:44 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTwoFishOFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := twfBlockBuilder(key)
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
// *    -create: 2023/10/28 21:30:48 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTwoFishGCMCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := twfBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewGCMMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
