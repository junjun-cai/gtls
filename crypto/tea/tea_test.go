// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 00:34:58                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: tea                                                                                                         *
// * File: tea_test.go                                                                                                 *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package tea

import (
	"encoding/base64"
	"fmt"
	"github.com/caijunjun/gotils/crypto/padding"
	"testing"
)

func TestTeaCBCCrypter(t *testing.T) {
	key := GenerateTeaKey()
	iv := GenerateTeaIV()
	fmt.Println("key: ", key)
	fmt.Println("iv: ", iv)
	key = []byte("1234567812345678")
	iv = []byte("87654321")
	plainText := []byte("this is tea cbc test text.")
	fmt.Println("plaintext:", plainText)
	tc, err := NewTeaCBCrypter(key, iv, 0, padding.PKCS7)
	if err != nil {
		t.Error(err)
		return
	}
	encrypred, err := tc.Encrypt(plainText)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("encrypted:", encrypred)
	fmt.Println("b64:", base64.StdEncoding.EncodeToString(encrypred))
	decrypted, err := tc.Decrypt(encrypred)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("decrypted:", decrypted)

	b, err := base64.StdEncoding.DecodeString("POoGFJjhD8lfABK+rp28FmZgwAv/g4+0bzQNJ1Nifog=")
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("db:", string(b))
}
