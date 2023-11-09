// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/09 23:53:13                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: rc2                                                                                                         *
// * File: cipher.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package rc2

import (
	"crypto/cipher"
	"encoding/binary"
)

// The rc2 block size in bytes
const BlockSize = 8

type Cipher struct {
	k [64]uint16
}

// New returns a new rc2 cipher with the given key and effective key length t1
func NewCipher(key []byte, t1 int) (cipher.Block, error) {
	return &Cipher{
		k: expandKey(key, t1),
	}, nil
}

func (*Cipher) BlockSize() int { return BlockSize }

func (c *Cipher) Encrypt(dst, src []byte) {

	r0 := binary.LittleEndian.Uint16(src[0:])
	r1 := binary.LittleEndian.Uint16(src[2:])
	r2 := binary.LittleEndian.Uint16(src[4:])
	r3 := binary.LittleEndian.Uint16(src[6:])

	var j int

	for j <= 16 {
		// mix r0
		r0 = r0 + c.k[j] + (r3 & r2) + ((^r3) & r1)
		r0 = rotl16(r0, 1)
		j++

		// mix r1
		r1 = r1 + c.k[j] + (r0 & r3) + ((^r0) & r2)
		r1 = rotl16(r1, 2)
		j++

		// mix r2
		r2 = r2 + c.k[j] + (r1 & r0) + ((^r1) & r3)
		r2 = rotl16(r2, 3)
		j++

		// mix r3
		r3 = r3 + c.k[j] + (r2 & r1) + ((^r2) & r0)
		r3 = rotl16(r3, 5)
		j++

	}

	r0 = r0 + c.k[r3&63]
	r1 = r1 + c.k[r0&63]
	r2 = r2 + c.k[r1&63]
	r3 = r3 + c.k[r2&63]

	for j <= 40 {

		// mix r0
		r0 = r0 + c.k[j] + (r3 & r2) + ((^r3) & r1)
		r0 = rotl16(r0, 1)
		j++

		// mix r1
		r1 = r1 + c.k[j] + (r0 & r3) + ((^r0) & r2)
		r1 = rotl16(r1, 2)
		j++

		// mix r2
		r2 = r2 + c.k[j] + (r1 & r0) + ((^r1) & r3)
		r2 = rotl16(r2, 3)
		j++

		// mix r3
		r3 = r3 + c.k[j] + (r2 & r1) + ((^r2) & r0)
		r3 = rotl16(r3, 5)
		j++

	}

	r0 = r0 + c.k[r3&63]
	r1 = r1 + c.k[r0&63]
	r2 = r2 + c.k[r1&63]
	r3 = r3 + c.k[r2&63]

	for j <= 60 {

		// mix r0
		r0 = r0 + c.k[j] + (r3 & r2) + ((^r3) & r1)
		r0 = rotl16(r0, 1)
		j++

		// mix r1
		r1 = r1 + c.k[j] + (r0 & r3) + ((^r0) & r2)
		r1 = rotl16(r1, 2)
		j++

		// mix r2
		r2 = r2 + c.k[j] + (r1 & r0) + ((^r1) & r3)
		r2 = rotl16(r2, 3)
		j++

		// mix r3
		r3 = r3 + c.k[j] + (r2 & r1) + ((^r2) & r0)
		r3 = rotl16(r3, 5)
		j++
	}

	binary.LittleEndian.PutUint16(dst[0:], r0)
	binary.LittleEndian.PutUint16(dst[2:], r1)
	binary.LittleEndian.PutUint16(dst[4:], r2)
	binary.LittleEndian.PutUint16(dst[6:], r3)
}

func (c *Cipher) Decrypt(dst, src []byte) {

	r0 := binary.LittleEndian.Uint16(src[0:])
	r1 := binary.LittleEndian.Uint16(src[2:])
	r2 := binary.LittleEndian.Uint16(src[4:])
	r3 := binary.LittleEndian.Uint16(src[6:])

	j := 63

	for j >= 44 {
		// unmix r3
		r3 = rotl16(r3, 16-5)
		r3 = r3 - c.k[j] - (r2 & r1) - ((^r2) & r0)
		j--

		// unmix r2
		r2 = rotl16(r2, 16-3)
		r2 = r2 - c.k[j] - (r1 & r0) - ((^r1) & r3)
		j--

		// unmix r1
		r1 = rotl16(r1, 16-2)
		r1 = r1 - c.k[j] - (r0 & r3) - ((^r0) & r2)
		j--

		// unmix r0
		r0 = rotl16(r0, 16-1)
		r0 = r0 - c.k[j] - (r3 & r2) - ((^r3) & r1)
		j--
	}

	r3 = r3 - c.k[r2&63]
	r2 = r2 - c.k[r1&63]
	r1 = r1 - c.k[r0&63]
	r0 = r0 - c.k[r3&63]

	for j >= 20 {
		// unmix r3
		r3 = rotl16(r3, 16-5)
		r3 = r3 - c.k[j] - (r2 & r1) - ((^r2) & r0)
		j--

		// unmix r2
		r2 = rotl16(r2, 16-3)
		r2 = r2 - c.k[j] - (r1 & r0) - ((^r1) & r3)
		j--

		// unmix r1
		r1 = rotl16(r1, 16-2)
		r1 = r1 - c.k[j] - (r0 & r3) - ((^r0) & r2)
		j--

		// unmix r0
		r0 = rotl16(r0, 16-1)
		r0 = r0 - c.k[j] - (r3 & r2) - ((^r3) & r1)
		j--

	}

	r3 = r3 - c.k[r2&63]
	r2 = r2 - c.k[r1&63]
	r1 = r1 - c.k[r0&63]
	r0 = r0 - c.k[r3&63]

	for j >= 0 {

		// unmix r3
		r3 = rotl16(r3, 16-5)
		r3 = r3 - c.k[j] - (r2 & r1) - ((^r2) & r0)
		j--

		// unmix r2
		r2 = rotl16(r2, 16-3)
		r2 = r2 - c.k[j] - (r1 & r0) - ((^r1) & r3)
		j--

		// unmix r1
		r1 = rotl16(r1, 16-2)
		r1 = r1 - c.k[j] - (r0 & r3) - ((^r0) & r2)
		j--

		// unmix r0
		r0 = rotl16(r0, 16-1)
		r0 = r0 - c.k[j] - (r3 & r2) - ((^r3) & r1)
		j--

	}

	binary.LittleEndian.PutUint16(dst[0:], r0)
	binary.LittleEndian.PutUint16(dst[2:], r1)
	binary.LittleEndian.PutUint16(dst[4:], r2)
	binary.LittleEndian.PutUint16(dst[6:], r3)
}
