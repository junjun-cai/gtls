// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 18:05:39                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cast128                                                                                                     *
// * File: cipher.go                                                                                                   *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cast128

import (
	"crypto/cipher"
	"strconv"
)

const BlockSize = 8
const KeySize = 16

type KeySizeError int

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:05:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (k KeySizeError) Error() string {
	return "cast128: invalid key size " + strconv.Itoa(int(k))
}

type cast128 struct {
	xk     []uint32 // Key, after expansion.
	rounds uint     // Number of rounds to use, 12 or 16.
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:06:26 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k != KeySize {
		return nil, KeySizeError(k)
	}

	block := &cast128{xk: make([]uint32, 32)}
	block.expandKey(key, uint(k))

	return block, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:06:43 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cast128) expandKey(rawkey []byte, keybytes uint) {
	var t, z, x [4]uint32
	var i uint

	// Set number of rounds to 12 or 16, depending on key length.
	if keybytes <= 10 {
		c.rounds = 12
	} else {
		c.rounds = 16
	}

	// Copy key to workspace x.
	for i = 0; i < 4; i++ {
		x[i] = 0
		if i*4+0 < keybytes {
			x[i] = uint32(rawkey[i*4+0]) << 24
		}
		if i*4+1 < keybytes {
			x[i] |= uint32(rawkey[i*4+1]) << 16
		}
		if i*4+2 < keybytes {
			x[i] |= uint32(rawkey[i*4+2]) << 8
		}
		if i*4+3 < keybytes {
			x[i] |= uint32(rawkey[i*4+3])
		}
	}

	// Generate 32 subkeys, four at a time.
	for i = 0; i < 32; i += 4 {
		switch i & 4 {
		case 0:
			t[0] = x[0] ^ castSbox5[u8b(x[3])] ^
				castSbox6[u8d(x[3])] ^ castSbox7[u8a(x[3])] ^
				castSbox8[u8c(x[3])] ^
				castSbox7[u8a(x[2])]
			z[0] = t[0]
			t[1] = x[2] ^ castSbox5[u8a(z[0])] ^
				castSbox6[u8c(z[0])] ^ castSbox7[u8b(z[0])] ^
				castSbox8[u8d(z[0])] ^
				castSbox8[u8c(x[2])]
			z[1] = t[1]
			t[2] = x[3] ^ castSbox5[u8d(z[1])] ^
				castSbox6[u8c(z[1])] ^ castSbox7[u8b(z[1])] ^
				castSbox8[u8a(z[1])] ^
				castSbox5[u8b(x[2])]
			z[2] = t[2]
			t[3] = x[1] ^ castSbox5[u8c(z[2])] ^
				castSbox6[u8b(z[2])] ^ castSbox7[u8d(z[2])] ^
				castSbox8[u8a(z[2])] ^
				castSbox6[u8d(x[2])]
			z[3] = t[3]
		case 4:
			t[0] = z[2] ^ castSbox5[u8b(z[1])] ^
				castSbox6[u8d(z[1])] ^ castSbox7[u8a(z[1])] ^
				castSbox8[u8c(z[1])] ^
				castSbox7[u8a(z[0])]
			x[0] = t[0]
			t[1] = z[0] ^ castSbox5[u8a(x[0])] ^
				castSbox6[u8c(x[0])] ^ castSbox7[u8b(x[0])] ^
				castSbox8[u8d(x[0])] ^
				castSbox8[u8c(z[0])]
			x[1] = t[1]
			t[2] = z[1] ^ castSbox5[u8d(x[1])] ^
				castSbox6[u8c(x[1])] ^ castSbox7[u8b(x[1])] ^
				castSbox8[u8a(x[1])] ^
				castSbox5[u8b(z[0])]
			x[2] = t[2]
			t[3] = z[3] ^ castSbox5[u8c(x[2])] ^
				castSbox6[u8b(x[2])] ^ castSbox7[u8d(x[2])] ^
				castSbox8[u8a(x[2])] ^
				castSbox6[u8d(z[0])]
			x[3] = t[3]
		}

		switch i & 12 {
		case 0:
			fallthrough
		case 12:
			c.xk[i+0] =
				castSbox5[u8a(t[2])] ^ castSbox6[u8b(t[2])] ^
					castSbox7[u8d(t[1])] ^
					castSbox8[u8c(t[1])]
			c.xk[i+1] =
				castSbox5[u8c(t[2])] ^ castSbox6[u8d(t[2])] ^
					castSbox7[u8b(t[1])] ^
					castSbox8[u8a(t[1])]
			c.xk[i+2] =
				castSbox5[u8a(t[3])] ^ castSbox6[u8b(t[3])] ^
					castSbox7[u8d(t[0])] ^
					castSbox8[u8c(t[0])]
			c.xk[i+3] =
				castSbox5[u8c(t[3])] ^ castSbox6[u8d(t[3])] ^
					castSbox7[u8b(t[0])] ^
					castSbox8[u8a(t[0])]
		case 4:
			fallthrough
		case 8:
			c.xk[i+0] =
				castSbox5[u8d(t[0])] ^ castSbox6[u8c(t[0])] ^
					castSbox7[u8a(t[3])] ^
					castSbox8[u8b(t[3])]
			c.xk[i+1] =
				castSbox5[u8b(t[0])] ^ castSbox6[u8a(t[0])] ^
					castSbox7[u8c(t[3])] ^
					castSbox8[u8d(t[3])]
			c.xk[i+2] =
				castSbox5[u8d(t[1])] ^ castSbox6[u8c(t[1])] ^
					castSbox7[u8a(t[2])] ^
					castSbox8[u8b(t[2])]
			c.xk[i+3] =
				castSbox5[u8b(t[1])] ^ castSbox6[u8a(t[1])] ^
					castSbox7[u8c(t[2])] ^
					castSbox8[u8d(t[2])]
		}

		switch i & 12 {
		case 0:
			c.xk[i+0] ^= castSbox5[u8c(z[0])]
			c.xk[i+1] ^= castSbox6[u8c(z[1])]
			c.xk[i+2] ^= castSbox7[u8b(z[2])]
			c.xk[i+3] ^= castSbox8[u8a(z[3])]
		case 4:
			c.xk[i+0] ^= castSbox5[u8a(x[2])]
			c.xk[i+1] ^= castSbox6[u8b(x[3])]
			c.xk[i+2] ^= castSbox7[u8d(x[0])]
			c.xk[i+3] ^= castSbox8[u8d(x[1])]
		case 8:
			c.xk[i+0] ^= castSbox5[u8b(z[2])]
			c.xk[i+1] ^= castSbox6[u8a(z[3])]
			c.xk[i+2] ^= castSbox7[u8c(z[0])]
			c.xk[i+3] ^= castSbox8[u8c(z[1])]
		case 12:
			c.xk[i+0] ^= castSbox5[u8d(x[0])]
			c.xk[i+1] ^= castSbox6[u8d(x[1])]
			c.xk[i+2] ^= castSbox7[u8a(x[2])]
			c.xk[i+3] ^= castSbox8[u8b(x[3])]
		}
		if i >= 16 {
			c.xk[i+0] &= 31
			c.xk[i+1] &= 31
			c.xk[i+2] &= 31
			c.xk[i+3] &= 31
		}
	}

	// Wipe clean.
	for i = 0; i < 4; i++ {
		t[i] = 0
		x[i] = 0
		z[i] = 0
	}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:08:42 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cast128) BlockSize() int {
	return BlockSize
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:08:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cast128) Encrypt(dst, src []byte) {
	encrypt(c.xk, c.rounds, dst, src)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/30 18:09:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *cast128) Decrypt(dst, src []byte) {
	decrypt(c.xk, c.rounds, dst, src)
}
