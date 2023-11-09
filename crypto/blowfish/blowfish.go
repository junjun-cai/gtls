// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/28 19:54:30                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: blowfish                                                                                                    *
// * File: blowfish.go                                                                                                 *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package blowfish

import (
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/caijunjun/gotils/crypto/padding"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blowfish"
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 21:19:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func blfBlockBuilder(key, salt []byte) (block *blowfish.Cipher, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%v", r)
			return
		}
	}()
	return blowfish.NewSaltedCipher(key, salt)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 20:03:12 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewBlowFishCBCrypter(key, salt []byte, iv []byte, padding padding.PadType) (crypter cface.ICrypter, err error) {
	block, err := blfBlockBuilder(key, salt)
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
// *    -create: 2023/10/28 20:09:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewBlowFishCFBrypter(key, salt []byte, iv []byte) (cface.ICrypter, error) {
	block, err := blfBlockBuilder(key, salt)
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
// *    -create: 2023/10/28 20:10:18 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewBlowFishCTRCrypter(key, salt []byte, iv []byte) (cface.ICrypter, error) {
	block, err := blfBlockBuilder(key, salt)
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
// *    -create: 2023/10/28 21:23:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewBlowFishECBCrypter(key, salt []byte, padding padding.PadType) (cface.ICrypter, error) {
	block, err := blfBlockBuilder(key, salt)
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
// *    -create: 2023/10/28 21:24:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewBlowFishOFBCrypter(key, salt []byte, iv []byte) (cface.ICrypter, error) {
	block, err := blfBlockBuilder(key, salt)
	if err != nil {
		return nil, err
	}
	m, err := mode.NewOFBMode(block, iv)
	if err != nil {
		return nil, err
	}
	return &cface.Crypter{Mode: m}, nil
}
