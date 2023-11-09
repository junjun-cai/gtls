// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/11/05 23:36:40                                                                                         *
// * Proj: gotils                                                                                                      *
// * Pack: crypto                                                                                                      *
// * File: cryptermanager.go                                                                                           *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package crypto

import (
	"github.com/caijunjun/gotils/crypto/cface"
	"github.com/pkg/errors"
	"sync"
)

type CrypterManager struct {
	CrypterMap map[int32]cface.ICrypter
	sync.RWMutex
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:46:50 ColeCai.                                                                          *
// *********************************************************************************************************************
func NewCrypterManager() *CrypterManager {
	return &CrypterManager{
		CrypterMap: make(map[int32]cface.ICrypter),
	}
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:47:30 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *CrypterManager) AddCrypter(id int32, crypter cface.ICrypter) error {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.CrypterMap[id]; ok {
		return errors.Errorf("Crypter %d already exists.", id)
	}
	c.CrypterMap[id] = crypter
	return nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:51:16 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *CrypterManager) DelCrypter(id int32) {
	c.Lock()
	defer c.Unlock()
	delete(c.CrypterMap, id)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:52:09 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *CrypterManager) Encrypt(id int32, src []byte) ([]byte, error) {
	c.RLock()
	defer c.RUnlock()
	crypter, ok := c.CrypterMap[id]
	if !ok {
		return nil, errors.Errorf("Crypter %d not exists.", id)
	}
	return crypter.Encrypt(src)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:53:40 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *CrypterManager) Decrypt(id int32, src []byte) ([]byte, error) {
	c.RLock()
	defer c.RUnlock()
	crypter, ok := c.CrypterMap[id]
	if !ok {
		return nil, errors.Errorf("Crypter %d not exists.", id)
	}
	return crypter.Decrypt(src)
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:55:33 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *CrypterManager) GetCrypter(id int32) (cface.ICrypter, error) {
	c.RLock()
	c.RUnlock()
	crypter, ok := c.CrypterMap[id]
	if !ok {
		return nil, errors.Errorf("Crypter %d not exists.", id)
	}
	return crypter, nil
}

// *********************************************************************************************************************
// * SUMMARY: none.                                                                                                    *
// * WARNING: none.                                                                                                    *
// * HISTORY:                                                                                                          *
// *    -create: 2023/11/05 23:56:40 ColeCai.                                                                          *
// *********************************************************************************************************************
func (c *CrypterManager) CleanCrypterManager() {
	c.Lock()
	defer c.Unlock()
	clear(c.CrypterMap)
}
