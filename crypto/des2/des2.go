// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/09 22:18:33                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: des2                                                                                                        *
// * File: des2.go                                                                                                     *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package des2

import (
	"crypto/cipher"
	"github.com/pkg/errors"
	"gotils/crypto/cface"
	"gotils/crypto/padding"
)

type Des2Crypter struct {
	cface.Crypter
	Key     []byte
	Iv      []byte
	Padding padding.IPadding
}

func des3BlockBuilder(key []byte) (block cipher.Block, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("%+v", r)
			return
		}
		return
	}()
	return NewTwoDESCipher(key)
}
