package main

import (
	"crypto/des"
	"crypto/rand"
	"fmt"
	"sync"
)

type DEALCipher struct {
	numRounds int
	roundKeys [][]byte
	mutex     sync.Mutex
}

func NewDEALCipher() *DEALCipher {
	return &DEALCipher{}
}

func (deal *DEALCipher) SetupKeys(key []byte) error {
	keyLen := len(key)

	switch keyLen {
	case 16: // 128 бит
		deal.numRounds = 6
	case 24: // 192 бита
		deal.numRounds = 6
	case 32: // 256 бит
		deal.numRounds = 8
	default:
		return fmt.Errorf("ключ DEAL должен быть 128, 192 или 256 бит")
	}

	constantKey := make([]byte, 8)
	desBlockForKeySchedule, err := des.NewCipher(constantKey)
	if err != nil {
		return err
	}

	deal.roundKeys = make([][]byte, deal.numRounds)

	// Разбиваем ключ на блоки по 8 байт
	numKeyBlocks := keyLen / 8
	keyBlocks := make([][]byte, numKeyBlocks)
	for i := 0; i < numKeyBlocks; i++ {
		keyBlocks[i] = key[i*8 : (i+1)*8]
	}

	prevRoundKey := make([]byte, 8)

	for round := 0; round < deal.numRounds; round++ {
		// Выбираем блок ключа
		keyBlockIndex := round % numKeyBlocks

		// XOR с предыдущим раундовым ключом
		temp := make([]byte, 8)
		for j := 0; j < 8; j++ {
			temp[j] = keyBlocks[keyBlockIndex][j] ^ prevRoundKey[j]
		}

		// Добавляем константу для второго прохода
		if round >= numKeyBlocks {
			constant := byte(1 << (round - numKeyBlocks))
			temp[7] ^= constant
		}

		// Шифруем DES с константным ключом
		roundKey := make([]byte, 8)
		desBlockForKeySchedule.Encrypt(roundKey, temp)

		deal.roundKeys[round] = roundKey
		prevRoundKey = roundKey
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

func GenerateDEALKey(keyBits int) ([]byte, error) {
	switch keyBits {
	case 128:
		key := make([]byte, 16)
		_, err := rand.Read(key)
		return key, err
	case 192:
		key := make([]byte, 24)
		_, err := rand.Read(key)
		return key, err
	case 256:
		key := make([]byte, 32)
		_, err := rand.Read(key)
		return key, err
	default:
		return nil, fmt.Errorf("неподдерживаемая длина ключа DEAL: %d (должно быть 128, 192 или 256)", keyBits)
	}
}
