// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/09 23:12:25                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: eax.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"github.com/pkg/errors"
	"gotils/crypto/tool/byteutil"
)

const (
	defaultEaxTagSize   = 16
	defaultEaxNonceSize = 16
)

type eax struct {
	block     cipher.Block // Only AES-{128, 192, 256} supported
	tagSize   int          // At least 12 bytes recommended
	nonceSize int
}

func NewEAX(block cipher.Block) (cipher.AEAD, error) {
	return NewEAXWithNonceAndTagSize(block, defaultEaxNonceSize, defaultEaxTagSize)
}

func NewEAXWithNonceSize(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
	return NewEAXWithNonceAndTagSize(block, nonceSize, defaultEaxTagSize)
}

func NewEAXWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	return NewEAXWithNonceAndTagSize(block, defaultEaxNonceSize, tagSize)
}

func NewEAXWithNonceAndTagSize(block cipher.Block, nonceSize int, tagSize int) (cipher.AEAD, error) {
	if nonceSize <= 0 {
		return nil, eaxError("cannot initialize EAX with nonceSize = 0.")
	}
	if tagSize > block.BlockSize() {
		return nil, eaxError("tagsize exceeds blocksize")
	}
	return &eax{block: block, nonceSize: nonceSize, tagSize: tagSize}, nil
}

func (e *eax) NonceSize() int {
	return e.nonceSize
}

func (e *eax) Overhead() int {
	return e.tagSize
}

func (e *eax) Seal(dst, nonce, plaintext, adata []byte) []byte {
	if len(nonce) > e.nonceSize {
		panic("cipher/eax: Nonce too long for this instance")
	}
	ret, out := byteutil.SliceForAppend(dst, len(plaintext)+e.tagSize)
	omacNonce := e.omacT(0, nonce)
	omacAdata := e.omacT(1, adata)

	// Encrypt message using CTR mode and omacNonce as IV
	ctr := cipher.NewCTR(e.block, omacNonce)
	ciphertextData := out[:len(plaintext)]
	ctr.XORKeyStream(ciphertextData, plaintext)

	omacCiphertext := e.omacT(2, ciphertextData)

	tag := out[len(plaintext):]
	for i := 0; i < e.tagSize; i++ {
		tag[i] = omacCiphertext[i] ^ omacNonce[i] ^ omacAdata[i]
	}
	return ret
}

func (e *eax) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(nonce) > e.nonceSize {
		panic("cipher/eax: Nonce too long for this instance")
	}

	if len(ciphertext) < e.tagSize {
		return nil, eaxError(" ciphertext shorter than tag length.")
	}

	sep := len(ciphertext) - e.tagSize

	// Compute tag
	omacNonce := e.omacT(0, nonce)
	omacAdata := e.omacT(1, adata)
	omacCiphertext := e.omacT(2, ciphertext[:sep])

	tag := make([]byte, e.tagSize)
	for i := 0; i < e.tagSize; i++ {
		tag[i] = omacCiphertext[i] ^ omacNonce[i] ^ omacAdata[i]
	}

	// Compare tags
	if subtle.ConstantTimeCompare(ciphertext[sep:], tag) != 1 {
		return nil, eaxError("tag authentication failed.")
	}

	// Decrypt ciphertext
	ret, out := byteutil.SliceForAppend(dst, len(ciphertext))
	ctr := cipher.NewCTR(e.block, omacNonce)
	ctr.XORKeyStream(out, ciphertext[:sep])

	return ret[:sep], nil
}

// Tweakable OMAC - Calls OMAC_K([t]_n || plaintext)
func (e *eax) omacT(t byte, plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	byteT := make([]byte, blockSize)
	byteT[blockSize-1] = t
	concat := append(byteT, plaintext...)
	return e.omac(concat)
}

func (e *eax) omac(plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	// L ← E_K(0^n); B ← 2L; P ← 4L
	L := make([]byte, blockSize)
	e.block.Encrypt(L, L)
	B := byteutil.GfnDouble(L)
	P := byteutil.GfnDouble(B)

	// CBC with IV = 0
	cbc := cipher.NewCBCEncrypter(e.block, make([]byte, blockSize))
	padded := e.pad(plaintext, B, P)
	cbcCiphertext := make([]byte, len(padded))
	cbc.CryptBlocks(cbcCiphertext, padded)

	return cbcCiphertext[len(cbcCiphertext)-blockSize:]
}

func (e *eax) pad(plaintext, B, P []byte) []byte {
	// if |M| in {n, 2n, 3n, ...}
	blockSize := e.block.BlockSize()
	if len(plaintext) != 0 && len(plaintext)%blockSize == 0 {
		return byteutil.RightXor(plaintext, B)
	}

	// else return (M || 1 || 0^(n−1−(|M| % n))) xor→ P
	ending := make([]byte, blockSize-len(plaintext)%blockSize)
	ending[0] = 0x80
	padded := append(plaintext, ending...)
	return byteutil.RightXor(padded, P)
}

func eaxError(err string) error {
	return errors.New("cipher/eax: " + err)
}
