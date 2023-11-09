// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/08 23:12:59                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: cipher                                                                                                      *
// * File: ocb.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"github.com/pkg/errors"
	"gotils/crypto/tool/byteutil"
	"math/bits"
)

type ocb struct {
	block        cipher.Block
	tagSize      int
	nonceSize    int
	mask         mask
	reusableKtop reusableKtop
}

type mask struct {
	lAst []byte
	lDol []byte
	L    [][]byte
}

type reusableKtop struct {
	noncePrefix []byte
	Ktop        []byte
}

const (
	defaultTagSize   = 16
	defaultNonceSize = 15
)

const (
	enc = iota
	dec
)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:13:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ocb) NonceSize() int {
	return o.nonceSize
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:13:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ocb) Overhead() int {
	return o.tagSize
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:19:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewOCB(block cipher.Block) (cipher.AEAD, error) {
	return NewOCBWithNonceAndTagSize(block, defaultNonceSize, defaultTagSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:19:48 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewOCBWithNonceSize(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
	return NewOCBWithNonceAndTagSize(block, nonceSize, defaultTagSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:19:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewOCBWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	return NewOCBWithNonceAndTagSize(block, defaultNonceSize, tagSize)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:16:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewOCBWithNonceAndTagSize(block cipher.Block, nonceSize int, tagSize int) (cipher.AEAD, error) {
	if block.BlockSize() != 16 {
		return nil, ocbError("Block cipher must have 128-bit blocks")
	}
	if nonceSize < 1 {
		return nil, ocbError("Incorrect nonce length")
	}
	if nonceSize >= block.BlockSize() {
		return nil, ocbError("Nonce length exceeds blocksize - 1")
	}
	if tagSize > block.BlockSize() {
		return nil, ocbError("Custom tag length exceeds blocksize")
	}

	return &ocb{
		block:     block,
		tagSize:   tagSize,
		nonceSize: nonceSize,
		mask:      initializeMaskTable(block),
		reusableKtop: reusableKtop{
			noncePrefix: nil,
			Ktop:        nil,
		},
	}, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:18:10 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ocb) Seal(dst, nonce, plaintext, adata []byte) []byte {
	if len(nonce) > o.nonceSize {
		panic("crypto/ocb: Incorrect nonce length given to OCB")
	}

	ret, out := byteutil.SliceForAppend(dst, len(plaintext)+o.tagSize)
	o.crypt(enc, out, nonce, adata, plaintext)

	return ret
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:18:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ocb) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(nonce) > o.nonceSize {
		panic("Nonce too long for this instance")
	}
	if len(ciphertext) < o.tagSize {
		return nil, ocbError("Ciphertext shorter than tag length")
	}

	sep := len(ciphertext) - o.tagSize
	ret, out := byteutil.SliceForAppend(dst, len(ciphertext))

	ciphertextData := ciphertext[:sep]
	tag := ciphertext[sep:]

	o.crypt(dec, out, nonce, adata, ciphertextData)

	if subtle.ConstantTimeCompare(ret[sep:], tag) == 1 {
		ret = ret[:sep]
		return ret, nil
	}

	for i := range out {
		out[i] = 0
	}

	return nil, ocbError("Tag authentication failed")
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:18:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ocb) crypt(instruction int, Y, nonce, adata, X []byte) []byte {
	//
	// Consider X as a sequence of 128-bit blocks
	//
	// Note: For encryption (resp. decryption), X is the plaintext (resp., the
	// ciphertext without the tag).
	blockSize := o.block.BlockSize()

	//
	// Nonce-dependent and per-encryption variables
	//
	// Zero out the last 6 bits of the nonce into truncatedNonce to see if Ktop
	// is already computed.
	truncatedNonce := make([]byte, len(nonce))

	copy(truncatedNonce, nonce)

	truncatedNonce[len(truncatedNonce)-1] &= 192

	Ktop := make([]byte, blockSize)

	if bytes.Equal(truncatedNonce, o.reusableKtop.noncePrefix) {
		Ktop = o.reusableKtop.Ktop
	} else {
		// Nonce = num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N
		paddedNonce := append(make([]byte, blockSize-1-len(nonce)), 1)
		paddedNonce = append(paddedNonce, truncatedNonce...)
		paddedNonce[0] |= byte(((8 * o.tagSize) % (8 * blockSize)) << 1)

		// Last 6 bits of paddedNonce are already zero. Encrypt into Ktop
		paddedNonce[blockSize-1] &= 192

		Ktop = paddedNonce

		o.block.Encrypt(Ktop, Ktop)
		o.reusableKtop.noncePrefix = truncatedNonce
		o.reusableKtop.Ktop = Ktop
	}

	// Stretch = Ktop || ((lower half of Ktop) XOR (lower half of Ktop << 8))
	xorHalves := make([]byte, blockSize/2)
	byteutil.XorBytes(xorHalves, Ktop[:blockSize/2], Ktop[1:1+blockSize/2])

	stretch := append(Ktop, xorHalves...)
	bottom := int(nonce[len(nonce)-1] & 63)
	offset := make([]byte, len(stretch))

	byteutil.ShiftNBytesLeft(offset, stretch, bottom)
	offset = offset[:blockSize]

	//
	// Process any whole blocks
	//
	// Note: For encryption Y is ciphertext || tag, for decryption Y is
	// plaintext || tag.
	checksum := make([]byte, blockSize)
	m := len(X) / blockSize
	for i := 0; i < m; i++ {
		index := bits.TrailingZeros(uint(i + 1))
		if len(o.mask.L)-1 < index {
			o.mask.extendTable(index)
		}

		byteutil.XorBytesMut(offset, o.mask.L[bits.TrailingZeros(uint(i+1))])
		blockX := X[i*blockSize : (i+1)*blockSize]
		blockY := Y[i*blockSize : (i+1)*blockSize]
		byteutil.XorBytes(blockY, blockX, offset)

		switch instruction {
		case enc:
			o.block.Encrypt(blockY, blockY)
			byteutil.XorBytesMut(blockY, offset)
			byteutil.XorBytesMut(checksum, blockX)
		case dec:
			o.block.Decrypt(blockY, blockY)
			byteutil.XorBytesMut(blockY, offset)
			byteutil.XorBytesMut(checksum, blockY)
		}
	}

	//
	// Process any final partial block and compute raw tag
	//
	tag := make([]byte, blockSize)
	if len(X)%blockSize != 0 {
		byteutil.XorBytesMut(offset, o.mask.lAst)
		pad := make([]byte, blockSize)
		o.block.Encrypt(pad, offset)

		chunkX := X[blockSize*m:]
		chunkY := Y[blockSize*m : len(X)]
		byteutil.XorBytes(chunkY, chunkX, pad[:len(chunkX)])

		// P_* || bit(1) || zeroes(127) - len(P_*)
		switch instruction {
		case enc:
			paddedY := append(chunkX, byte(128))
			paddedY = append(paddedY, make([]byte, blockSize-len(chunkX)-1)...)
			byteutil.XorBytesMut(checksum, paddedY)
		case dec:
			paddedX := append(chunkY, byte(128))
			paddedX = append(paddedX, make([]byte, blockSize-len(chunkY)-1)...)
			byteutil.XorBytesMut(checksum, paddedX)
		}

		byteutil.XorBytes(tag, checksum, offset)
		byteutil.XorBytesMut(tag, o.mask.lDol)

		o.block.Encrypt(tag, tag)

		byteutil.XorBytesMut(tag, o.hash(adata))

		copy(Y[blockSize*m+len(chunkY):], tag[:o.tagSize])
	} else {
		byteutil.XorBytes(tag, checksum, offset)
		byteutil.XorBytesMut(tag, o.mask.lDol)

		o.block.Encrypt(tag, tag)

		byteutil.XorBytesMut(tag, o.hash(adata))

		copy(Y[blockSize*m:], tag[:o.tagSize])
	}
	return Y
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:18:52 ColeCai.                                                                          *
// *********************************************************************************************************************
func (o *ocb) hash(adata []byte) []byte {
	//
	// Consider A as a sequence of 128-bit blocks
	//
	A := make([]byte, len(adata))
	copy(A, adata)
	blockSize := o.block.BlockSize()

	//
	// Process any whole blocks
	//
	sum := make([]byte, blockSize)
	offset := make([]byte, blockSize)
	m := len(A) / blockSize
	for i := 0; i < m; i++ {
		chunk := A[blockSize*i : blockSize*(i+1)]
		index := bits.TrailingZeros(uint(i + 1))

		// If the mask table is too short
		if len(o.mask.L)-1 < index {
			o.mask.extendTable(index)
		}

		byteutil.XorBytesMut(offset, o.mask.L[index])
		byteutil.XorBytesMut(chunk, offset)

		o.block.Encrypt(chunk, chunk)

		byteutil.XorBytesMut(sum, chunk)
	}

	//
	// Process any final partial block; compute final hash value
	//
	if len(A)%blockSize != 0 {
		byteutil.XorBytesMut(offset, o.mask.lAst)
		// Pad block with 1 || 0 ^ 127 - bitlength(a)
		ending := make([]byte, blockSize-len(A)%blockSize)
		ending[0] = 0x80
		encrypted := append(A[blockSize*m:], ending...)
		byteutil.XorBytesMut(encrypted, offset)

		o.block.Encrypt(encrypted, encrypted)

		byteutil.XorBytesMut(sum, encrypted)
	}

	return sum
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:19:06 ColeCai.                                                                          *
// *********************************************************************************************************************
func (m *mask) extendTable(limit int) {
	for i := len(m.L); i <= limit; i++ {
		m.L = append(m.L, byteutil.GfnDouble(m.L[i-1]))
	}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:14:01 ColeCai.                                                                          *
// *********************************************************************************************************************
func initializeMaskTable(block cipher.Block) mask {
	//
	// Key-dependent variables
	//
	lAst := make([]byte, block.BlockSize())
	block.Encrypt(lAst, lAst)

	lDol := byteutil.GfnDouble(lAst)

	L := make([][]byte, 1)
	L[0] = byteutil.GfnDouble(lDol)

	return mask{
		lAst: lAst,
		lDol: lDol,
		L:    L,
	}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/08 23:17:02 ColeCai.                                                                          *
// *********************************************************************************************************************
func ocbError(err string) error {
	return errors.New("cipher/ocb: " + err)
}
