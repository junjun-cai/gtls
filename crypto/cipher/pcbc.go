// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:58:33                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: pcbc.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"gotils/crypto/internal/alias"
)

type pcbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:59:12 ColeCai.                                                                          *
// *********************************************************************************************************************
func newPCBC(b cipher.Block, iv []byte) *pcbc {
	return &pcbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
	}
}

type pcbcEncrypter pcbc

type pcbcEncAble interface {
	NewPCBCEncrypter(iv []byte) cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:01:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewPCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewPCBCEncrypter: IV length must equal block size")
	}

	if pcbc, ok := b.(pcbcEncAble); ok {
		return pcbc.NewPCBCEncrypter(iv)
	}

	return (*pcbcEncrypter)(newPCBC(b, iv))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:01:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *pcbcEncrypter) BlockSize() int {
	return x.blockSize
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:01:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *pcbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cipher/pcbc: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("cipher/pcbc: output smaller than input")
	}

	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher/pcbc: invalid buffer overlap")
	}

	iv := x.iv

	bs := x.blockSize
	for i := 0; i < len(src); i += bs {
		subtle.XORBytes(dst[i:i+bs], src[i:i+bs], iv)
		x.b.Encrypt(dst[i:i+bs], dst[i:i+bs])

		subtle.XORBytes(iv, src[i:i+bs], dst[i:i+bs])
	}
}

type pcbcDecrypter pcbc

type pcbcDecAble interface {
	NewPCBCDecrypter(iv []byte) cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:02:27 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewPCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewPCBCDecrypter: IV length must equal block size")
	}

	if pcbc, ok := b.(pcbcDecAble); ok {
		return pcbc.NewPCBCDecrypter(iv)
	}

	return (*pcbcDecrypter)(newPCBC(b, iv))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:02:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *pcbcDecrypter) BlockSize() int {
	return x.blockSize
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:02:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *pcbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cipher/pcbc: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("cipher/pcbc: output smaller than input")
	}

	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher/pcbc: invalid buffer overlap")
	}

	if len(src) == 0 {
		return
	}

	iv := x.iv

	bs := x.blockSize
	for i := 0; i < len(src); i += bs {
		x.b.Decrypt(dst[i:i+bs], src[i:i+bs])
		subtle.XORBytes(dst[i:i+bs], dst[i:i+bs], iv)

		subtle.XORBytes(iv, dst[i:i+bs], src[i:i+bs])
	}
}
