package main

import (
	"fmt"
	"sync"
)

type DEALCipher struct {
	numRounds int
	roundKeys [][]byte
	mutex     sync.Mutex
}

func NewDEALCipher() *DEALCipher {
	return &DEALCipher{
		numRounds: 6,
	}
}

func (deal *DEALCipher) SetupKeys(key []byte) error {
	if len(key) != 16 {
		return fmt.Errorf("ключ DEAL должен быть 128 бит (16 байт), получено %d", len(key))
	}
	deal.roundKeys = make([][]byte, deal.numRounds)
	for i := 0; i < deal.numRounds; i++ {
		rk := make([]byte, 8)
		for j := 0; j < 8; j++ {
			rk[j] = key[j] ^ key[j+8] ^ byte(i+1)
		}
		deal.roundKeys[i] = rk
	}
	return nil
}

func (deal *DEALCipher) EncryptBlock(block []byte) []byte {
	if len(block) != 16 {
		panic(fmt.Sprintf("блок должен быть 128 бит (16 байт), получено %d", len(block)))
	}

	deal.mutex.Lock()
	defer deal.mutex.Unlock()

	left := make([]byte, 8)
	right := make([]byte, 8)
	copy(left, block[:8])
	copy(right, block[8:])

	for i := 0; i < deal.numRounds; i++ {
		localDES := NewDESCipher()
		if err := localDES.SetupKeys(deal.roundKeys[i]); err != nil {
			panic(fmt.Sprintf("ошибка настройки DES ключа в раунде %d: %v", i, err))
		}

		newLeft := make([]byte, 8)
		copy(newLeft, right)
		f := localDES.EncryptBlock(right)
		newRight := deal.xorBytes(left, f)
		left, right = newLeft, newRight
	}

	result := make([]byte, 16)
	copy(result[:8], left)
	copy(result[8:], right)
	return result
}

func (deal *DEALCipher) DecryptBlock(block []byte) []byte {
	if len(block) != 16 {
		panic(fmt.Sprintf("блок должен быть 128 бит (16 байт), получено %d", len(block)))
	}

	deal.mutex.Lock()
	defer deal.mutex.Unlock()

	left := make([]byte, 8)
	right := make([]byte, 8)
	copy(left, block[:8])
	copy(right, block[8:])

	for i := deal.numRounds - 1; i >= 0; i-- {
		localDES := NewDESCipher()
		if err := localDES.SetupKeys(deal.roundKeys[i]); err != nil {
			panic(fmt.Sprintf("ошибка настройки DES ключа в раунде %d: %v", i, err))
		}

		newRight := make([]byte, 8)
		copy(newRight, left)
		f := localDES.EncryptBlock(left)
		newLeft := deal.xorBytes(right, f)
		left, right = newLeft, newRight
	}

	result := make([]byte, 16)
	copy(result[:8], left)
	copy(result[8:], right)
	return result
}

func (deal *DEALCipher) xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a) && i < len(b); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// DEALCipherContext обертка для контекста DEAL
type DEALCipherContext struct {
	*CipherContext
}

func NewDEALCipherContext(key []byte, cipherMode CipherMode, paddingMode PaddingMode, iv []byte) *DEALCipherContext {
	dealCipher := NewDEALCipher()
	if iv == nil {
		iv = make([]byte, 16)
	}
	ctx, err := NewCipherContext(dealCipher, key, cipherMode, paddingMode, iv, 16)
	if err != nil {
		panic(fmt.Sprintf("ошибка создания контекста DEAL: %v", err))
	}
	return &DEALCipherContext{CipherContext: ctx}
}

// DESAdapter адаптер для использования DES как раундовой функции
type DESAdapter struct {
	desCipher *DESCipher
}

func NewDESAdapter() *DESAdapter {
	return &DESAdapter{desCipher: NewDESCipher()}
}

func (adapter *DESAdapter) SetupKey(key []byte) error {
	return adapter.desCipher.SetupKeys(key)
}

func (adapter *DESAdapter) EncryptBlock(block []byte) []byte {
	return adapter.desCipher.EncryptBlock(block)
}
