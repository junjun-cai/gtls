// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 02:12:48                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: encoding                                                                                                    *
// * File: encoding_test.go                                                                                            *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package encoding

import (
	"fmt"
	"testing"
)

func TestEncoding_EncodeByPunycode(t *testing.T) {
	st, err := Encoding.FromString("试试吧").EncodeByPunycode().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("ST:", st)
	de, err := Encoding.FromString("4qrr90ka").DecodeByPunycode().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("DE:", de)
}

func TestEncoding_EncodeByQp(t *testing.T) {
	st, err := Encoding.FromString("试试吧").EncodeByQPrintable().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("ST:", st)
	de, err := Encoding.FromString("=E8=AF=95=E8=AF=95=E5=90=A7").DecodeByQPrintable().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("DE:", de)
}

func TestEncoding_Custome(t *testing.T) {
	coder := Encoding.CustomeQPrintable("0123456789abcdef")
	st, err := coder.FromString("试试吧").Encode().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("ST:", st)
	de, err := coder.FromString("=E8=AF=95=E8=AF=95=E5=90=A7").Decode().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("DE:", de)
}

func TestNilEncoder(t *testing.T) {
	coder, err := Encoding.FromString("shishibai").EncodeByStdBase32().ToString()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("coder:", coder)
}

func TestByts(t *testing.T) {
	var st []byte = nil
	for _, v := range st {
		fmt.Println(v)
	}
}
