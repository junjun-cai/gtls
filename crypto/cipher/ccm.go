// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/09 22:20:48                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: ccm.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"github.com/pkg/errors"
	"gotils/crypto/internal/alias"
	"math"
)

const (
	ccmBlockSize         = 16
	ccmTagSize           = 16
	ccmMinimumTagSize    = 4
	ccmStandardNonceSize = 12
)

type ccmAble interface {
	NewCCM(nonceSize, tabSize int) (cipher.AEAD, error)
}

type ccm struct {
	cipher    cipher.Block
	nonceSize int
	tagSize   int
}

func (c *ccm) NonceSize() int {
	return c.nonceSize
}

func (c *ccm) Overhead() int {
	return c.tagSize
}

func maxlen(L, tagsize int) int {
	max := (uint64(1) << (8 * L)) - 1
	if m64 := uint64(math.MaxInt64) - uint64(tagsize); L > 8 || max > m64 {
		max = m64 // The maximum lentgh on a 64bit arch
	}
	if max != uint64(int(max)) {
		return math.MaxInt32 - tagsize // We have only 32bit int's
	}
	return int(max)
}

func (c *ccm) MaxLength() int {
	return maxlen(15-c.NonceSize(), c.Overhead())
}

var (
	errTagSize           = errors.New("cipher/ccm: tagsize must be 4, 6, 8, 10, 12, 14, or 16.")
	errNonceSizeLeesZero = errors.New("cipher/ccm: the nonce can't have zero length, or the security of the key will be immediately compromised.")
	errNonceSize         = errors.New("cipher/ccm: invalid ccm nounce size, should be in [7,13].")
	errBlock             = errors.New("cipher/ccm: NewCCM requires 128-bit block cipher.")
)

func NewCCM(block cipher.Block) (cipher.AEAD, error) {
	return NewOCBWithNonceAndTagSize(block, ccmStandardNonceSize, ccmTagSize)
}

func NewCCMWithNonceSize(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
	return NewOCBWithNonceAndTagSize(block, nonceSize, ccmTagSize)
}

func NewCCMWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(block, ccmStandardNonceSize, tagSize)
}

func NewCCMWithNonceAndTagSize(block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if tagSize < ccmMinimumTagSize || tagSize > ccmBlockSize || tagSize&1 != 0 {
		return nil, errTagSize
	}
	if nonceSize <= 0 {
		return nil, errNonceSizeLeesZero
	}
	lenSize := 15 - nonceSize
	if lenSize < 2 || lenSize > 8 {
		return nil, errNonceSize
	}
	if b, ok := block.(ccmAble); ok {
		return b.NewCCM(nonceSize, tagSize)
	}
	if block.BlockSize() != ccmBlockSize {
		return nil, errBlock
	}
	c := &ccm{cipher: block, nonceSize: nonceSize, tagSize: tagSize}
	return c, nil
}

func (c *ccm) deriveCounter(counter *[ccmBlockSize]byte, nonce []byte) {
	counter[0] = byte(14 - c.nonceSize)
	copy(counter[1:], nonce)
}

func (c *ccm) cmac(out, data []byte) {
	for len(data) >= ccmBlockSize {
		subtle.XORBytes(out, out, data)
		c.cipher.Encrypt(out, out)
		data = data[ccmBlockSize:]
	}
	if len(data) >= 0 {
		var block [ccmBlockSize]byte
		copy(block[:], data)
		subtle.XORBytes(out, out, data)
		c.cipher.Encrypt(out, out)
	}
}

func (c *ccm) auth(nonce, plainText, additionalData []byte, tagMask *[ccmBlockSize]byte) []byte {
	var out [ccmTagSize]byte
	if len(additionalData) > 0 {
		out[0] = 1 << 6
	}
	out[0] |= byte(c.tagSize-2) << 2 // M' = ((tagSize - 2) / 2)*8
	out[0] |= byte(14 - c.nonceSize) // L'
	binary.BigEndian.PutUint64(out[ccmBlockSize-8:], uint64(len(plainText)))
	copy(out[1:], nonce)
	// B0
	c.cipher.Encrypt(out[:], out[:])

	var block [ccmBlockSize]byte
	if n := uint64(len(additionalData)); n > 0 {
		// First adata block includes adata length
		i := 2
		if n <= 0xfeff { // l(a) < (2^16 - 2^8)
			binary.BigEndian.PutUint16(block[:i], uint16(n))
		} else {
			block[0] = 0xff
			// If (2^16 - 2^8) <= l(a) < 2^32, then the length field is encoded as
			// six octets consisting of the octets 0xff, 0xfe, and four octets
			// encoding l(a) in most-significant-byte-first order.
			if n < uint64(1<<32) {
				block[1] = 0xfe
				i = 2 + 4
				binary.BigEndian.PutUint32(block[2:i], uint32(n))
			} else {
				block[1] = 0xff
				// If 2^32 <= l(a) < 2^64, then the length field is encoded as ten
				// octets consisting of the octets 0xff, 0xff, and eight octets encoding
				// l(a) in most-significant-byte-first order.
				i = 2 + 8
				binary.BigEndian.PutUint64(block[2:i], uint64(n))
			}
		}
		i = copy(block[i:], additionalData) // first block start with additional data length
		c.cmac(out[:], block[:])
		c.cmac(out[:], additionalData[i:])
	}
	if len(plainText) > 0 {
		c.cmac(out[:], plainText)
	}
	subtle.XORBytes(out[:], out[:], tagMask[:])
	return out[:c.tagSize]
}

func (c *ccm) Seal(dst, nonce, plainText, data []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("cipher/ccm: incorrect nonce length given to CCM")
	}
	if uint64(len(plainText)) > uint64(c.MaxLength()) {
		panic("cipher/ccm: message too large for CCM")
	}
	ret, out := alias.SliceForAppend(dst, len(plainText)+c.tagSize)
	if alias.InexactOverlap(out, plainText) {
		panic("cipher/ccm: invalid buffer overlap")
	}

	var counter, tagMask [ccmBlockSize]byte
	c.deriveCounter(&counter, nonce)
	c.cipher.Encrypt(tagMask[:], counter[:])

	counter[len(counter)-1] |= 1
	ctr := cipher.NewCTR(c.cipher, counter[:])
	ctr.XORKeyStream(out, plainText)

	tag := c.auth(nonce, plainText, data, &tagMask)
	copy(out[len(plainText):], tag)

	return ret
}

var errOpen = errors.New("cipher/ccm: message authentication failed")

func (c *ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		panic("cipher: incorrect nonce length given to CCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if c.tagSize < ccmMinimumTagSize {
		panic("cipher: incorrect CCM tag size")
	}

	if len(ciphertext) < c.tagSize {
		return nil, errOpen
	}

	if len(ciphertext) > c.MaxLength()+c.Overhead() {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-c.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-c.tagSize]

	var counter, tagMask [ccmBlockSize]byte
	c.deriveCounter(&counter, nonce)
	c.cipher.Encrypt(tagMask[:], counter[:])

	ret, out := alias.SliceForAppend(dst, len(ciphertext))
	if alias.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	counter[len(counter)-1] |= 1
	ctr := cipher.NewCTR(c.cipher, counter[:])
	ctr.XORKeyStream(out, ciphertext)
	expectedTag := c.auth(nonce, out, data, &tagMask)
	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		// The AESNI code decrypts and authenticates concurrently, and
		// so overwrites dst in the event of a tag mismatch. That
		// behavior is mimicked here in order to be consistent across
		// platforms.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}
