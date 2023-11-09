// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:36:54                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: cfb64.go                                                                                                    *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"gotils/crypto/internal/alias"
)

type cfb64 struct {
	b       cipher.Block
	in      []byte
	out     []byte
	decrypt bool
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:37:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func newCFB64(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		panic("cipher/cfb64: iv length must equal block size")
	}

	c := &cfb64{
		b:       block,
		in:      make([]byte, blockSize),
		out:     make([]byte, blockSize),
		decrypt: decrypt,
	}
	copy(c.in, iv)

	return c
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:38:08 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB64Encrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB64(block, iv, false)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:38:17 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB64Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB64(block, iv, true)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:37:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb64) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher/cfb64: output smaller than input")
	}

	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher/cfb64: invalid buffer overlap")
	}

	bs := 8
	for i := 0; i < len(src); i += bs {
		c.b.Encrypt(c.out, c.in)

		end := i + bs
		if end > len(src) {
			end = len(src)
		}

		dstBytes := make([]byte, end-i)
		srcBytes := src[i:end]

		subtle.XORBytes(dstBytes, srcBytes, c.out[:])

		startIn := end - i
		copy(c.in, c.in[startIn:])

		if c.decrypt {
			copy(c.in[startIn:], srcBytes)
		} else {
			copy(c.in[startIn:], dstBytes)
		}

		copy(dst[i:end], dstBytes)
	}
}
