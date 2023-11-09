// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 00:19:12                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: xtea                                                                                                        *
// * File: xtea.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package xtea

import (
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/xtea"
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 01:14:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenertaeXteaKey() []byte {
	return tools.RandNBytes(16)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 01:14:32 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateXteaIV() []byte {
	return tools.RandNBytes(xtea.BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 00:20:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func xteaBlockBuilder(key []byte) (block *xtea.Cipher, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return xtea.NewCipher(key)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 00:21:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewXteaCBCrypter(key []byte, iv []byte, padding padding.IPadding) (crypter cface.ICrypter, err error) {
	block, err := xteaBlockBuilder(key)
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
// *    -create: 2023/10/30 00:22:09 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewXteaCFBrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := xteaBlockBuilder(key)
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
// *    -create: 2023/10/30 00:22:45 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewXteaCTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := xteaBlockBuilder(key)
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
// *    -create: 2023/10/30 00:23:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewXteaECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := xteaBlockBuilder(key)
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
// *    -create: 2023/10/30 00:23:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewXteaOFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := xteaBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
