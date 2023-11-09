// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 01:06:37                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: xtea                                                                                                        *
// * File: xtea_test.go                                                                                                *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package xtea

import (
	"encoding/base64"
	"fmt"
	"github.com/caijunjun/gotils/crypto/padding"
	"testing"
)

func TestXteaCBCCrypter(t *testing.T) {
	key := []byte("1234567812345678")
	iv := []byte("87654321")
	plain := []byte("this xtea cbc pain text.")
	ac, err := NewXteaCBCrypter(key, iv, padding.PKCS7)
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
	fmt.Println("EN:", base64.StdEncoding.EncodeToString(en))
}
