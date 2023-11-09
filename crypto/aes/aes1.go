// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/10 00:01:59                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: aes                                                                                                         *
// * File: aes1.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package aes

import (
	"crypto/cipher"
	"gotils/crypto/cface"
	"gotils/crypto/mode"
	"gotils/crypto/padding"
)

func ByAes(key []byte) AesMode {
	block, err := aesBlockBuilder(key)
	return AesMode{err: err, block: block}
}

type AesMode struct {
	err   error
	block cipher.Block
}

func (a AesMode) WihtCBC(iv []byte, padding padding.IPadding) Crypter {
	if a.err != nil {
		return Crypter{err: a.err}
	}
	m, err := mode.NewCBCMode(a.block, iv, padding)
	return Crypter{
		err:     err,
		Crypter: cface.Crypter{Mode: m},
	}
}

func (a AesMode) WithCFB(iv []byte) Crypter {
	if a.err != nil {
		return Crypter{err: a.err}
	}
	m, err := mode.NewCFBMode(a.block, iv)
	return Crypter{
		err:     err,
		Crypter: cface.Crypter{Mode: m},
	}
}

type Crypter struct {
	err error
	cface.Crypter
}
