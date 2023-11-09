// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/09 23:44:00                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: aria                                                                                                        *
// * File: cipher.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *
package aria

import (
	"crypto/cipher"
	"fmt"
	"gotils/crypto/tool/alias"
)

// code from github.com/hallazzang/aria-go

// BlockSize is the ARIA block size in bytes.
const BlockSize = 16

// KeySizeError is returned when key size in bytes
// isn't one of 16, 24, or 32.
type KeySizeError int

func (k KeySizeError) Error() string {
	return fmt.Sprintf("cipher/aria: invalid key size %d", int(k))
}

type ariaCipher struct {
	k   int // Key size in bytes.
	enc []uint32
	dec []uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the ARIA key,
// either 16, 24, or 32 bytes to select
// ARIA-128, ARIA-192, or AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 128 / 8, 192 / 8, 256 / 8:
		break
	}

	n := k + 36
	c := ariaCipher{
		k:   k,
		enc: make([]uint32, n),
		dec: make([]uint32, n),
	}

	c.expandKey(key)

	return &c, nil
}

func (c *ariaCipher) BlockSize() int {
	return BlockSize
}

func (c *ariaCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("aria: input not full block")
	}

	if len(dst) < BlockSize {
		panic("aria: output not full block")
	}

	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("aria: invalid buffer overlap")
	}

	c.cryptBlock(c.enc, dst, src)
}

func (c *ariaCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("aria: input not full block")
	}

	if len(dst) < BlockSize {
		panic("aria: output not full block")
	}

	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("aria: invalid buffer overlap")
	}

	c.cryptBlock(c.dec, dst, src)
}

func (c *ariaCipher) rounds() int {
	return c.k/4 + 8
}

func (c *ariaCipher) cryptBlock(xk []uint32, dst, src []byte) {
	n := c.rounds()

	var p [16]byte

	copy(p[:], src[:BlockSize])

	for i := 1; i <= n-1; i++ {
		if i&1 == 1 {
			p = roundOdd(p, toBytes(xk[(i-1)*4:i*4]))
		} else {
			p = roundEven(p, toBytes(xk[(i-1)*4:i*4]))
		}
	}

	p = xor(substitute2(xor(p, toBytes(xk[(n-1)*4:n*4]))), toBytes(xk[n*4:(n+1)*4]))

	copy(dst[:BlockSize], p[:])
}

func (c *ariaCipher) expandKey(key []byte) {
	n := c.rounds()

	var kl, kr [16]byte

	for i := 0; i < c.k; i++ {
		if i < 16 {
			kl[i] = key[i]
		} else {
			kr[i-16] = key[i]
		}
	}

	var ck1, ck2, ck3 [16]byte

	switch c.k {
	case 128 / 8:
		ck1 = c1
		ck2 = c2
		ck3 = c3
	case 192 / 8:
		ck1 = c2
		ck2 = c3
		ck3 = c1
	case 256 / 8:
		ck1 = c3
		ck2 = c1
		ck3 = c2
	}

	var w0, w1, w2, w3 [16]byte

	w0 = kl // TODO: use kl instead of w0
	w1 = xor(roundOdd(w0, ck1), kr)
	w2 = xor(roundEven(w1, ck2), w0)
	w3 = xor(roundOdd(w2, ck3), w1)

	copyBytes(c.enc, xor(w0, rrot(w1, 19)))
	copyBytes(c.enc[4:], xor(w1, rrot(w2, 19)))
	copyBytes(c.enc[8:], xor(w2, rrot(w3, 19)))
	copyBytes(c.enc[12:], xor(w3, rrot(w0, 19)))
	copyBytes(c.enc[16:], xor(w0, rrot(w1, 31)))
	copyBytes(c.enc[20:], xor(w1, rrot(w2, 31)))
	copyBytes(c.enc[24:], xor(w2, rrot(w3, 31)))
	copyBytes(c.enc[28:], xor(w3, rrot(w0, 31)))
	copyBytes(c.enc[32:], xor(w0, lrot(w1, 61)))
	copyBytes(c.enc[36:], xor(w1, lrot(w2, 61)))
	copyBytes(c.enc[40:], xor(w2, lrot(w3, 61)))
	copyBytes(c.enc[44:], xor(w3, lrot(w0, 61)))
	copyBytes(c.enc[48:], xor(w0, lrot(w1, 31)))
	if n > 12 {
		copyBytes(c.enc[52:], xor(w1, lrot(w2, 31)))
		copyBytes(c.enc[56:], xor(w2, lrot(w3, 31)))
	}
	if n > 14 {
		copyBytes(c.enc[60:], xor(w3, lrot(w0, 31)))
		copyBytes(c.enc[64:], xor(w0, lrot(w1, 19)))
	}

	copy(c.dec, c.enc[n*4:(n+1)*4])

	for i := 1; i <= n-1; i++ {
		var t [16]byte

		t = toBytes(c.enc[(n-i)*4 : (n-i+1)*4])
		t = diffuse(t)

		copyBytes(c.dec[i*4:], t)
	}

	copy(c.dec[n*4:], c.enc[:4])
}
