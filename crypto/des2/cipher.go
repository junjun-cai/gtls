// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/09 22:02:30                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: des3                                                                                                        *
// * File: block.go                                                                                                    *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package des2

import (
	"crypto/cipher"
	"crypto/des"
	"strconv"
)

const BlockSize = des.BlockSize

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/des: invalid key size " + strconv.Itoa(int(k))
}

type teoDESCipher struct {
	cipher1, cipher2 cipher.Block
}

func NewTwoDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, KeySizeError(len(key))
	}
	c := new(teoDESCipher)
	var err error
	c.cipher1, err = des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}
	c.cipher2, err = des.NewCipher(key[8:])
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *teoDESCipher) BlockSize() int {
	return BlockSize
}

func (c *teoDESCipher) Encrypt(dst, src []byte) {
	encoded := desEncrypt(c.cipher1, src)
	encoded = desEncrypt(c.cipher2, encoded)
	copy(dst, encoded)
}

func (c *teoDESCipher) Decrypt(dst, src []byte) {
	decoded := desDecrypt(c.cipher2, src)
	decoded = desDecrypt(c.cipher1, decoded)
	copy(dst, decoded)
}

func desEncrypt(block cipher.Block, src []byte) []byte {
	dst := make([]byte, len(src))
	block.Encrypt(dst, src)
	return dst
}

func desDecrypt(block cipher.Block, src []byte) []byte {
	dst := make([]byte, len(src))
	block.Decrypt(dst, src)
	return dst
}
