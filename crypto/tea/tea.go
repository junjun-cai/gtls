// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 00:26:34                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: tea                                                                                                         *
// * File: tea.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package tea

import (
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/tea"
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 00:33:40 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateTeaKey() []byte {
	return tools.RandNBytes(16)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 00:34:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateTeaIV() []byte {
	return tools.RandNBytes(tea.BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 00:27:04 ColeCai.                                                                          *
// *********************************************************************************************************************
func teaBlockBuilder(key []byte, rounds int) (block cipher.Block, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	if rounds == 0 {
		return tea.NewCipher(key)
	}
	return tea.NewCipherWithRounds(key, rounds)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 00:29:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTeaCBCrypter(key, iv []byte, rounds int, padding padding.IPadding) (crypter cface.ICrypter, err error) {
	block, err := teaBlockBuilder(key, rounds)
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
// *    -create: 2023/10/30 00:30:04 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTeaCFBrypter(key, iv []byte, rounds int) (cface.ICrypter, error) {
	block, err := teaBlockBuilder(key, rounds)
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
// *    -create: 2023/10/30 00:30:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTeaCTRCrypter(key, iv []byte, rounds int) (cface.ICrypter, error) {
	block, err := teaBlockBuilder(key, rounds)
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
// *    -create: 2023/10/30 00:31:26 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTeaECBCrypter(key []byte, rounds int, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := teaBlockBuilder(key, rounds)
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
// *    -create: 2023/10/30 00:32:13 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewTeaOFBCrypter(key, iv []byte, rounds int) (cface.ICrypter, error) {
	block, err := teaBlockBuilder(key, rounds)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
