// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 16:29:19                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: saferplus                                                                                                    *
// * File: safe_test.go                                                                                                *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package safeplus

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestSafeplusCFBCrypter(t *testing.T) {
	key := []byte("1234567812345678")
	iv := []byte("8765432187654321")
	plain := []byte("this saferplus cfb pain text.")
	ac, err := NewSaferplusCFBCrypter(key, iv)
	if err != nil {
		t.Error(err)
		return
	}
	en, err := ac.Encrypt(plain)
	if err != nil {
		t.Error(err)
		return
	}
	//orWCUL5zWG0+ZrsDVab9cU8bxlTxFye9OSW8sI4wi2k=
	fmt.Println("EN:", base64.StdEncoding.EncodeToString(en))
	de, err := ac.Decrypt(en)
	fmt.Println("de:", string(de))
}
