// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 18:22:07                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cast256                                                                                                     *
// * File: cast256.go                                                                                                  *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cast256

import (
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:27:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateCast256Key() []byte {
	return tools.RandNBytes(KeySize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:27:21 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateCast256IV() []byte {
	return tools.RandNBytes(BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:22:25 ColeCai.                                                                          *
// *********************************************************************************************************************
func cast256BlockBuilder(key []byte) (block cipher.Block, err error) {
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
// *    -create: 2023/10/30 18:23:28 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast256CBCCrypter(key []byte, iv []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := cast256BlockBuilder(key)
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
// *    -create: 2023/10/30 18:24:52 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast256CFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := cast256BlockBuilder(key)
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
// *    -create: 2023/10/30 18:25:27 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast256CTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := cast256BlockBuilder(key)
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
// *    -create: 2023/10/30 18:26:56 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast256ECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := cast256BlockBuilder(key)
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
// *    -create: 2023/10/30 18:27:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCast256OFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := cast256BlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
