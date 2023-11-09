// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:32:30                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: cfb16.go                                                                                                    *
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

type cfb16 struct {
	b       cipher.Block
	in      []byte
	out     []byte
	decrypt bool
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:33:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func newCFB16(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		panic("cipher/cfb16: iv length must equal block size")
	}
	c := &cfb16{
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
// *    -create: 2023/11/08 22:33:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB16Encrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB16(block, iv, false)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:34:02 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB16Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB16(block, iv, true)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:32:53 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb16) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher/cfb16: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher/cfb16: invalid buffer overlap")
	}

	bs := 2
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
