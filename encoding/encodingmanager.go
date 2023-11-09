// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/06 23:48:00                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: encoding                                                                                                    *
// * File: encodingmanager.go                                                                                          *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package encoding

import (
	"github.com/caijunjun/gotils/encoding/base"
	"github.com/pkg/errors"
	"sync"
)

type EncoderManager struct {
	EncoderMp map[int32]base.IEncoding
	sync.RWMutex
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:48:56 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewEncodingManager() *EncoderManager {
	return &EncoderManager{EncoderMp: make(map[int32]base.IEncoding)}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:49:19 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *EncoderManager) AddEncoding(id int32, encoding base.IEncoding) error {
	e.Lock()
	defer e.Unlock()
	if _, ok := e.EncoderMp[id]; ok {
		return errors.Errorf("Encoder %d already exists.", id)
	}
	e.EncoderMp[id] = encoding
	return nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:51:23 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *EncoderManager) DelEncoder(id int32) {
	e.Lock()
	defer e.Unlock()
	delete(e.EncoderMp, id)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:51:38 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *EncoderManager) Encode(id int32, src []byte) ([]byte, error) {
	e.RLock()
	defer e.RUnlock()
	crypter, ok := e.EncoderMp[id]
	if !ok {
		return nil, errors.Errorf("Encoder %d not exists.", id)
	}
	return crypter.Encode(src)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:52:09 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *EncoderManager) Decode(id int32, src []byte) ([]byte, error) {
	e.RLock()
	defer e.RUnlock()
	crypter, ok := e.EncoderMp[id]
	if !ok {
		return nil, errors.Errorf("Encoder %d not exists.", id)
	}
	return crypter.Decode(src)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:52:58 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *EncoderManager) GetCrypter(id int32) (base.IEncoding, error) {
	e.RLock()
	e.RUnlock()
	encoder, ok := e.EncoderMp[id]
	if !ok {
		return nil, errors.Errorf("Encoder %d not exists.", id)
	}
	return encoder, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/06 23:54:00 ColeCai.                                                                          *
// *********************************************************************************************************************
func (e *EncoderManager) CleanCrypterManager() {
	e.Lock()
	defer e.Unlock()
	clear(e.EncoderMp)
}
