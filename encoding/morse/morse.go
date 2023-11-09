// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 01:18:07                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: morse                                                                                                       *
// * File: morse.go                                                                                                    *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package morse

import (
	"github.com/caijunjun/gotils/encoding/base"
	"github.com/caijunjun/gotils/tools"
	"strings"
)

var letterToMorse = map[string]string{
	"a": ".-",
	"b": "-...",
	"c": "-.-.",
	"d": "-..",
	"e": ".",
	"f": "..-.",
	"g": "--.",
	"h": "....",
	"i": "..",
	"j": ".---",
	"k": "-.-",
	"l": ".-..",
	"m": "--",
	"n": "-.",
	"o": "---",
	"p": ".--.",
	"q": "--.-",
	"r": ".-.",
	"s": "...",
	"t": "-",
	"u": "..-",
	"v": "...-",
	"w": ".--",
	"x": "-..-",
	"y": "-.--",
	"z": "--..",
	"0": "-----",
	"1": ".----",
	"2": "..---",
	"3": "...--",
	"4": "....-",
	"5": ".....",
	"6": "-....",
	"7": "--...",
	"8": "---..",
	"9": "----.",
	".": ".-.-.-",
	",": "--..--",
	"?": "..--..",
	"!": "..--.",
	":": "---...",
	";": "-.-.-",
	"'": ".----.",
	"=": "-...-",
	"(": "-.--.",
	")": "-.--.-",
	"$": "...-..-",
	"&": ".-...",
	"@": ".--.-.",
	"+": ".-.-.",
	"-": "-....-",
	"/": "-..-.",
	" ": " ",
}

type MorseEncoding struct {
	letterToMorse map[string]string
	morseToLetter map[string]string
	separator     string
}

var StdEncoding = NewMorseEncoding("|", letterToMorse)

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 22:36:14 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewMorseEncoding(separator string, letterToMorse map[string]string) base.IEncoding {
	morseToLetter := make(map[string]string)
	for k, v := range letterToMorse {
		morseToLetter[v] = k
	}
	return &MorseEncoding{separator: separator, letterToMorse: letterToMorse, morseToLetter: morseToLetter}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:18:22 ColeCai.                                                                          *
// *********************************************************************************************************************
func (m *MorseEncoding) Encode(b []byte) ([]byte, error) {
	s := strings.ToLower(tools.BytesToString(b))
	var dst string
	for _, letter := range s {
		let := string(letter)
		if enc, ok := m.letterToMorse[let]; ok {
			dst += enc + m.separator
		}
	}
	dst = strings.Trim(dst, m.separator)
	return tools.StringToBytes(dst), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 22:36:55 ColeCai.                                                                          *
// *********************************************************************************************************************
func (m *MorseEncoding) EncodedLen(n int) int {
	return n
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 01:18:48 ColeCai.                                                                          *
// *********************************************************************************************************************
func (m *MorseEncoding) Decode(b []byte) ([]byte, error) {
	var dst string
	for _, part := range strings.Split(tools.BytesToString(b), m.separator) {
		if dec, ok := m.morseToLetter[part]; ok {
			dst += dec
		}
	}
	return tools.StringToBytes(dst), nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 22:37:12 ColeCai.                                                                          *
// *********************************************************************************************************************
func (m *MorseEncoding) DecodedLen(n int) int {
	return n
}
