// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/27 21:24:02                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: crypto                                                                                                      *
// * File: padding.go                                                                                                  *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package padding

import (
	"bytes"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
)

var ErrorUnPadding = errors.New("unpadded padding.")
var ErrorInvaildSrc = errors.New("invaild unpadding data len.")

type IPadding interface {
	Padding(src []byte, blockSize int) []byte
	UnPadding(src []byte) ([]byte, error)
}

var (
	PKCS7      = pkcs7{}
	PKCS5      = pkcs5{}
	ZERO       = zero{}
	ANSIX923   = ansix923{}
	ISO97971M1 = iso97971m1{}
	ISO97971M2 = iso97971m2{}
	ISO10126   = iso10126{}
	EMPTY      = empty{}
	X923       = x923{}
	ISO7816_4  = iso7816_4{}
	TBCP       = tbcp{}
)

type pkcs7 struct{}

func (p pkcs7) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingText...)
}

func (p pkcs7) UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length <= 0 {
		return src, ErrorInvaildSrc
	}
	paddingSize := length - int(src[length-1])
	if paddingSize <= 0 {
		return src, ErrorUnPadding
	}
	return src[0:paddingSize], nil
}

type pkcs5 struct{ pkcs7 }

func (p pkcs5) Padding(src []byte) []byte {
	return p.pkcs7.Padding(src, 8)
}

func (p pkcs5) UnPadding(src []byte) ([]byte, error) {
	return p.pkcs7.UnPadding(src)
}

type zero struct{}

func (z zero) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(0)}, paddingSize)...)
}

func (z zero) UnPadding(src []byte) ([]byte, error) {
	return bytes.TrimFunc(src, func(r rune) bool {
		return r == rune(0)
	}), nil
}

type ansix923 struct{}

func (a ansix923) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := append(bytes.Repeat([]byte{byte(0)}, paddingSize-1), byte(paddingSize))
	return append(src, paddingText...)
}

func (a ansix923) UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length <= 0 {
		return src, ErrorInvaildSrc
	}
	paddingSize := length - int(src[length-1])
	if paddingSize <= 0 {
		return src, ErrorUnPadding
	}
	return src[0:paddingSize], nil
}

type iso97971m1 struct{ zero }

func (i iso97971m1) Padding(src []byte, blockSize int) []byte {
	return i.zero.Padding(append(src, 0x00), blockSize)
}

func (i iso97971m1) UnPadding(src []byte) ([]byte, error) {
	dst, err := i.zero.UnPadding(src)
	if err != nil {
		return nil, err
	}
	length := len(dst)
	if length <= 0 {
		return dst, ErrorUnPadding
	}
	return dst[:length-1], nil
}

type iso97971m2 struct{ zero }

func (i iso97971m2) Padding(src []byte, blockSize int) []byte {
	return i.zero.Padding(append(src, 0x80), blockSize)
}

func (i iso97971m2) UnPadding(src []byte) ([]byte, error) {
	dst, err := i.zero.UnPadding(src)
	if err != nil {
		return nil, err
	}
	length := len(dst)
	if length <= 0 {
		return dst, ErrorUnPadding
	}
	return dst[:length-1], nil
}

type iso10126 struct{}

func (i iso10126) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	randBytes := tools.RandNBytes(paddingSize - 1)
	paddingText := append(randBytes, byte(paddingSize))
	return append(src, paddingText...)
}

func (i iso10126) UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length <= 0 {
		return src, ErrorInvaildSrc
	}
	paddingSize := length - int(src[length-1])
	if paddingSize <= 0 {
		return src, ErrorUnPadding
	}
	return src[0:paddingSize], nil
}

type empty struct{}

func (e empty) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := bytes.Repeat([]byte(" "), paddingSize)
	return append(src, paddingText...)
}

func (e empty) UnPadding(src []byte) ([]byte, error) {
	return bytes.TrimRight(src, " "), nil
}

type x923 struct{}

func (x x923) Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize-1)

	src = append(src, paddingText...)
	src = append(src, byte(paddingSize))

	return src
}

func (x x923) UnPadding(src []byte) ([]byte, error) {
	n := len(src)
	if n <= 0 {
		return nil, ErrorInvaildSrc
	}

	unpadding := int(src[n-1])

	num := n - unpadding
	if num < 0 {
		return nil, ErrorUnPadding
	}

	padding := src[num:]
	for i := 0; i < unpadding-1; i++ {
		if padding[i] != byte(0) {
			return nil, ErrorUnPadding
		}
	}

	return src[:num], nil
}

type iso7816_4 struct{}

func (i iso7816_4) Padding(src []byte, blockSize int) []byte {
	// 补位 blockSize 值
	paddingSize := blockSize - len(src)%blockSize

	src = append(src, 0x80)

	paddingText := bytes.Repeat([]byte{0x00}, paddingSize-1)
	src = append(src, paddingText...)

	return src
}

func (i iso7816_4) UnPadding(src []byte) ([]byte, error) {
	n := len(src)
	if n == 0 {
		return nil, ErrorInvaildSrc
	}

	num := bytes.LastIndexByte(src, 0x80)
	if num == -1 {
		return nil, ErrorUnPadding
	}

	padding := src[num:]
	for i := 1; i < n-num; i++ {
		if padding[i] != byte(0) {
			return nil, ErrorUnPadding
		}
	}

	return src[:num], nil
}

type tbcp struct{}

func (t tbcp) Padding(src []byte, blockSize int) []byte {

	// 补位 blockSize 值
	length := len(src)
	paddingSize := blockSize - length%blockSize

	lastBit := src[length-1] & 0x1

	var paddingByte byte
	if lastBit != 0 {
		paddingByte = 0x00
	} else {
		paddingByte = 0xFF
	}

	paddingText := bytes.Repeat([]byte{paddingByte}, paddingSize)
	src = append(src, paddingText...)

	return src
}

func (t tbcp) UnPadding(src []byte) ([]byte, error) {
	n := len(src)
	if n == 0 {
		return nil, ErrorInvaildSrc
	}

	lastByte := src[n-1]

	switch {
	case lastByte == 0x00:
		for i := n - 2; i >= 0; i-- {
			if src[i] != 0x00 {
				return src[:i+1], nil
			}
		}
	case lastByte == 0xFF:
		for i := n - 2; i >= 0; i-- {
			if src[i] != 0xFF {
				return src[:i+1], nil
			}
		}
	}

	return nil, ErrorUnPadding
}
