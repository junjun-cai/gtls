// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 22:40:35                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: ofb8.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import "crypto/cipher"

type ofb8 struct {
	b       cipher.Block
	cipher  []byte
	out     []byte
	outUsed int
}

const streamBufferSize = 512

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:40:48 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewOFB8(b cipher.Block, iv []byte) cipher.Stream {
	blockSize := b.BlockSize()
	if len(iv) != blockSize {
		panic("crypto/ofb8: IV length must equal block size")
	}

	bufSize := streamBufferSize
	if bufSize < blockSize {
		bufSize = blockSize
	}

	x := &ofb8{
		b:       b,
		cipher:  make([]byte, blockSize),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}

	copy(x.cipher, iv)
	return x
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:41:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *ofb8) refill() {
	remain := len(x.out) - x.outUsed
	if remain > x.outUsed {
		return
	}

	copy(x.out, x.out[x.outUsed:])

	x.out = x.out[:cap(x.out)]

	dst := make([]byte, len(x.cipher))

	for remain <= len(x.out)-1 {
		x.b.Encrypt(dst, x.cipher)

		x.out[remain] = dst[0]

		copy(x.cipher, x.cipher[1:])

		x.cipher[len(x.cipher)-1] = dst[0]

		remain++
	}

	x.out = x.out[:remain]
	x.outUsed = 0
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 22:41:59 ColeCai.                                                                          *
// *********************************************************************************************************************
func (x *ofb8) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/ofb8: output smaller than input")
	}

	for len(src) > 0 {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			x.refill()
		}

		dst[0] = src[0] ^ x.out[x.outUsed]

		dst = dst[1:]
		src = src[1:]

		x.outUsed++
	}
}
