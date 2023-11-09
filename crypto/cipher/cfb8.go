// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:26:56                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: cfb8.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import (
	"crypto/cipher"
	"gotils/crypto/internal/alias"
)

type cfb8 struct {
	b       cipher.Block
	in      []byte
	out     []byte
	decrypt bool
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:29:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func newCFB8(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		// stack trace will indicate whether it was de or encryption
		panic("cipher/cfb8: IV length must equal block size")
	}

	c := &cfb8{
		b:       block,
		out:     make([]byte, blockSize),
		in:      make([]byte, blockSize),
		decrypt: decrypt,
	}
	copy(c.in, iv)

	return c
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:30:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB8Encrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB8(block, iv, false)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:30:53 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB8Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB8(block, iv, true)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:27:27 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *cfb8) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher/cfb8: output smaller than input")
	}

	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher/cfb8: invalid buffer overlap")
	}

	blockSize := x.b.BlockSize()
	for i := range src {
		x.b.Encrypt(x.out, x.in)

		copy(x.in[:blockSize-1], x.in[1:])
		if x.decrypt {
			x.in[blockSize-1] = src[i]
		}

		dst[i] = src[i] ^ x.out[0]
		if !x.decrypt {
			x.in[blockSize-1] = dst[i]
		}
	}
}
