// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 17:43:36                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: serpent                                                                                                     *
// * File: serpent.go                                                                                                  *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package serpent

import (
	"crypto/cipher"
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
)

type SerpentType uint8

const (
	SERPENT128 SerpentType = 16
	SERPENT192 SerpentType = 24
	SERPENT256 SerpentType = 32
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 17:51:27 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateSerpentKey(serpentType SerpentType) []byte {
	return tools.RandNBytes(int(serpentType))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 17:52:03 ColeCai.                                                                          *
// *********************************************************************************************************************
func GenerateSerpentIV() []byte {
	return tools.RandNBytes(BlockSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 17:44:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func serpentBlockBuilder(key []byte) (block cipher.Block, err error) {
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
// *    -create: 2023/10/30 17:44:51 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSerpentCBCCrypter(key []byte, iv []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := serpentBlockBuilder(key)
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
// *    -create: 2023/10/30 17:45:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSerpentCFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := serpentBlockBuilder(key)
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
// *    -create: 2023/10/30 17:45:58 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSerpentCTRCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := serpentBlockBuilder(key)
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
// *    -create: 2023/10/30 17:47:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSerpentECBCrypter(key []byte, padding padding.IPadding) (cface.ICrypter, error) {
	block, err := serpentBlockBuilder(key)
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
// *    -create: 2023/10/30 17:47:17 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewSerpenmtOFBCrypter(key []byte, iv []byte) (cface.ICrypter, error) {
	block, err := serpentBlockBuilder(key)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
