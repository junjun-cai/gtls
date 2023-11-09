// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/07 22:20:17                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: aes                                                                                                         *
// * File: aes_test.go                                                                                                 *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package aes

import (
	"bytes"
	"github.com/caijunjun/gotils/crypto/padding"
	"testing"
)

func TestAesCBC(t *testing.T) {
	in := []byte("this is aes cbc mode test text.")
	key := []byte("1234567812345678")
	iv := []byte("8765432187654321")
	t.Logf("plaints:%v\n", in)
	crypter, err := NewAesCBCCrypter(key, iv, padding.TBCP)
	if err != nil {
		t.Error(err)
		return
	}
	encrypt, err := crypter.Encrypt(in)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("encrypt:%v\n", encrypt)
	decrypt, err := crypter.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("decrypt:%v\n", decrypt)
	if !bytes.Equal(in, decrypt) {
		t.Log("failed.")
	}
}
