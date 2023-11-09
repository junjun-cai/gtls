// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 01:09:29                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: twofish                                                                                                     *
// * File: twofish_test.go                                                                                             *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package twofish

import (
	"encoding/base64"
	"fmt"
	"github.com/caijunjun/gotils/crypto/padding"
	"testing"
)

func TestNewTwoFishCBCrypterCBCCrypter(t *testing.T) {
	key := []byte("1234567812345678")
	iv := []byte("8765432187654321")
	plain := []byte("this twofish cbc pain text.")
	ac, err := NewTwoFishCBCrypter(key, iv, padding.PKCS7)
	if err != nil {
		t.Error(err)
		return
	}
	en, err := ac.Encrypt(plain)
	if err != nil {
		t.Error(err)
		return
	}

	//hk3jwha68o2WBYFWaXvYaO8l3d1lXR2XTayFvuV9MhM=
	//hk3jwha68o2WBYFWaXvYaO8l3d1lXR2XTayFvuV9MhM=
	//rdINebAPHiliwhcuAlpOtEi2k0u7ve11NJnzdB/cvGo=
	//rdINebAPHiliwhcuAlpOtEi2k0u7ve11NJnzdB/cvGo=
	fmt.Println("EN:", base64.StdEncoding.EncodeToString(en))
}
