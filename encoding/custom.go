// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/31 19:08:46                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: encoding                                                                                                    *
// * File: custome.go                                                                                                  *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package encoding

import (
	"github.com/caijunjun/gotils/encoding/base"
	"github.com/caijunjun/gotils/tools"
	"github.com/pkg/errors"
)

type customEncoding struct {
	encoder base.IEncoding
	encodData
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 19:29:05 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *customEncoding) FromString(src string) *customEncoding {
	c.reset()
	c.src = tools.StringToBytes(src)
	return c
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 19:30:15 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *customEncoding) FromBytes(src []byte) *customEncoding {
	c.reset()
	c.src = src
	return c
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 19:15:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *customEncoding) verify() bool {
	if len(c.src) <= 0 || c.err != nil {
		return false
	}
	if c.encoder == nil {
		c.err = errors.New("custome *encoding is nil.")
		return false
	}
	return true
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 19:14:34 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *customEncoding) Encode() *customEncoding {
	if !c.verify() {
		return c
	}
	c.dst, c.err = c.encoder.Encode(c.src)
	return c
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/10/31 19:17:29 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *customEncoding) Decode() *customEncoding {
	if !c.verify() {
		return c
	}
	c.dst, c.err = c.encoder.Decode(c.src)
	return c
}
