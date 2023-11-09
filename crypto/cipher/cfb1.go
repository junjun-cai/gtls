// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:21:59                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: cfb1.go                                                                                                     *
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

type cfb1 struct {
	b       cipher.Block
	in      []byte
	out     []byte
	decrypt bool
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:24:37 ColeCai.                                                                          *
// *********************************************************************************************************************
func newCFB1(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		panic("cipher/cfb1: IV length must equal block size")
	}
	c := &cfb1{
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
// *    -create: 2023/11/08 22:24:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB1Encrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB1(block, iv, false)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:24:50 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCFB1Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB1(block, iv, true)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:23:18 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cfb1) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher/cfb1: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher/cfb1: invalid buffer overlap")
	}
	for i := range src {
		for j := 0; j < 8; j++ {
			c.b.Encrypt(c.out, c.in)

			// 获取高位
			outbit := (c.out[0] >> 7) & 1
			srcbit := (src[i] >> (7 - j)) & 1

			dstbit := outbit ^ srcbit

			var movebit byte
			if c.decrypt {
				movebit = srcbit
			} else {
				movebit = dstbit
			}

			c.in = leftShiftBytes(c.in, movebit)

			if dstbit == 1 {
				dst[i] |= 1 << (7 - j)
			} else {
				dst[i] &= ^(1 << (7 - j))
			}

		}
	}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:23:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func leftShiftBytes(bytes []byte, carry byte) []byte {
	// 如果字节数组长度为1时
	if len(bytes) == 1 {
		shiftedByte := (bytes[0] << 1) | carry
		return []byte{shiftedByte}
	}

	shiftedBytes := make([]byte, len(bytes))

	for i := 0; i < len(bytes)-1; i++ {
		currByte := bytes[i]
		nextByte := bytes[i+1]

		shiftedBytes[i] = (currByte << 1) | ((nextByte >> 7) & 1)
	}

	// 处理最后一个字节
	lastByte := (bytes[len(bytes)-1] << 1) | carry
	shiftedBytes[len(bytes)-1] = lastByte

	return shiftedBytes
}
