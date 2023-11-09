// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 22:53:45                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: padding                                                                                                     *
// * File: cface.go                                                                                                    *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package cface

import (
	"github.com/caijunjun/gotils/crypto/mode"
	"github.com/pkg/errors"
)

type CrypterID uint8

type ICrypter interface {
	Encrypt(key []byte) ([]byte, error)
	Decrypt(key []byte) ([]byte, error)
}

type Crypter struct {
	Mode mode.IMode
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:57:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c Crypter) Encrypt(src []byte) (encrypted []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				return
			}
			if e, ok := r.(string); ok {
				err = errors.New(e)
				return
			}
			err = errors.New("unknown err.")
		}
		return
	}()
	return c.Mode.Encode(src)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/28 19:58:18 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c Crypter) Decrypt(src []byte) (decrypted []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				return
			}
			if e, ok := r.(string); ok {
				err = errors.New(e)
				return
			}
			err = errors.New("unknown err.")
		}
		return
	}()
	return c.Mode.Decode(src)
}
