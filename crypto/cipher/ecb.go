// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:44:11                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: ecb.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import "crypto/cipher"

type ecb struct {
	b         cipher.Block
	blockSize int
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:44:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:44:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:45:20 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *ecbEncrypter) BlockSize() int { return e.blockSize }

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:45:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("cipher/ecb: input not full blocks.")
	}
	if len(dst) < len(src) {
		panic("cipher/ecb: output smaller than input.")
	}
	for len(src) > 0 {
		e.b.Encrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

type ecbDecrypter ecb

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:45:48 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:45:59 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *ecbDecrypter) BlockSize() int { return e.blockSize }

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:46:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/ecb: input not full blocks.")
	}
	if len(dst) < len(src) {
		panic("crypto/ecb: output smaller than input.")
	}
	for len(src) > 0 {
		e.b.Decrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}
