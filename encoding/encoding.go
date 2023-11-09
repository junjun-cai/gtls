// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 13:14:19                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: *encoding                                                                                                    *
// * File: encding.go                                                                                                  *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package encoding

import (
	"github.com/caijunjun/gotils/encoding/ascii85"
	"github.com/caijunjun/gotils/encoding/base100"
	"github.com/caijunjun/gotils/encoding/base16"
	"github.com/caijunjun/gotils/encoding/base32"
	"github.com/caijunjun/gotils/encoding/base36"
	"github.com/caijunjun/gotils/encoding/base45"
	"github.com/caijunjun/gotils/encoding/base58"
	"github.com/caijunjun/gotils/encoding/base62"
	"github.com/caijunjun/gotils/encoding/base64"
	"github.com/caijunjun/gotils/encoding/base85"
	"github.com/caijunjun/gotils/encoding/base91"
	"github.com/caijunjun/gotils/encoding/hex"
	"github.com/caijunjun/gotils/encoding/morse"
	"github.com/caijunjun/gotils/encoding/puny"
	"github.com/caijunjun/gotils/encoding/quotedprintable"
	"github.com/caijunjun/gotils/tools"
	"net/url"
)

type encoding struct {
	encodData
}

type encodData struct {
	err error
	src []byte
	dst []byte
}

var Encoding = &encoding{}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:15:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encodData) reset() {
	e.err = nil
	e.src = nil
	e.dst = nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:13:09 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) FromString(src string) *encoding {
	e.reset()
	e.src = tools.StringToBytes(src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:14:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) FromBytes(src []byte) *encoding {
	e.reset()
	e.src = src
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:16:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encodData) ToString() (string, error) {
	if e.err != nil {
		return "", e.err
	}
	return tools.BytesToString(e.dst), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:17:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encodData) ToBytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.dst, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:17:50 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encodData) String() string {
	return tools.BytesToString(e.dst)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:11:46 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encodData) Error() error {
	return e.err
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 02:23:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomBase32(encoder string, padding rune) *customEncoding {
	encod, err := base32.NewEncoding(encoder, padding)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:36:51 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomBase36(encoder string) *customEncoding {
	encod, err := base36.NewEncoding(encoder)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:12:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomBase45(encoder string) *customEncoding {
	encod, err := base45.NewEncoding(encoder)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:15:56 ColeCai.                                                                          *
// ********************************************************************************************************************
func (e *encoding) CustomBase58(encoder string) *customEncoding {
	encod, err := base58.NewEncoding(encoder)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:17:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomBase62(encoder string) *customEncoding {
	encod, err := base62.NewEncoding(encoder)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 02:24:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomBase64(encoder string, padding rune) *customEncoding {
	encod, err := base64.NewEncoding(encoder, padding)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 14:17:40 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomBase91(encoder string) *customEncoding {
	encod, err := base91.NewEncoding(encoder)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:57:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomQPrintable(encoder string) *customEncoding {
	encod, err := quotedprintable.NewEncoding(encoder)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.err = err
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:37:08 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) CustomeMorse(separator string, letterToMorse map[string]string) *customEncoding {
	encod := morse.NewMorseEncoding(separator, letterToMorse)
	custome := &customEncoding{}
	custome.encoder = encod
	custome.src = e.src
	custome.dst = e.dst
	return custome
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:21:08 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) verify() bool {
	if len(e.src) > 0 && e.err == nil {
		return true
	}
	return false
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:18:36 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByHex() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = hex.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:20:29 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByHex() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = hex.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:22:51 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByBase16() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base16.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:23:36 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase16() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base16.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:28:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByStdBase32() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base32.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:29:41 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByStdBase32() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base32.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:31:26 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByHexBase32() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base32.HexEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:32:13 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByHexBase32() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base32.HexEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:38:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByStdBase36() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base36.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 15:38:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByStdBase36() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base36.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:24:15 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncdoeByBase45() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base45.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:24:54 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase45() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base45.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:25:24 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByBase58() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base58.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:26:02 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase58() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base58.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:55:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByBase62() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base62.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:57:09 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase62() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base62.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:58:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByStdBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 00:58:58 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByStdBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:01:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByRawStdBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.RawStdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:01:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByRawStdBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:02:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByURLBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.URLEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:02:56 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByURLStdBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.URLEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:03:22 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByRawURLBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.URLEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:03:44 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByRawURLStdBase64() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base64.RawURLEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:06:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByASCII85() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = ascii85.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:07:42 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByASCII85() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = ascii85.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:09:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByBase85() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base85.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:09:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase85() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base85.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:12:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByBase91() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base91.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:13:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase91() *encoding {
	if !e.verify() {
		return e
	}
	buf, err := base91.StdEncoding.Decode(e.src)
	if err != nil {
		e.err = err
		return e
	}
	e.dst = buf
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:16:01 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncdoeByBase100() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base100.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:16:42 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByBase100() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = base100.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:21:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByMorse() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = morse.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:24:35 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByMorse() *encoding {
	if !e.verify() {
		return e
	}

	dst, err := morse.StdEncoding.Decode(e.src)
	if err != nil {
		e.err = err
		return e
	}
	e.dst = dst
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:27:39 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeBySafeURL() *encoding {
	if !e.verify() {
		return e
	}
	e.dst = tools.StringToBytes(url.QueryEscape(tools.BytesToString(e.src)))
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:29:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeBySafeURL() *encoding {
	if !e.verify() {
		return e
	}
	dst, err := url.QueryUnescape(tools.BytesToString(e.src))
	if err != nil {
		e.err = err
		return e
	}
	e.dst = tools.StringToBytes(dst)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:32:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByPunycode() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = puny.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 16:32:47 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByPunycode() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = puny.StdEncoding.Decode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 17:01:37 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) EncodeByQPrintable() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = quotedprintable.StdEncoding.Encode(e.src)
	return e
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 17:03:07 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *encoding) DecodeByQPrintable() *encoding {
	if !e.verify() {
		return e
	}
	e.dst, e.err = quotedprintable.StdEncoding.Decode(e.src)
	return e
}
