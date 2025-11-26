package main

import (
	"crypto/rand"
	"fmt"
)

// TripleDESCipher реализует Triple DES (3DES) в режиме EDE
type TripleDESCipher struct {
	des1 *DESCipher
	des2 *DESCipher
	des3 *DESCipher
	keyOption int // 1 (3 ключа), 2 (2 ключа), 3 (1 ключ)
}

// NewTripleDESCipher создает экземпляр 3DES
func NewTripleDESCipher() *TripleDESCipher {
	return &TripleDESCipher{
		des1: NewDESCipher(),
		des2: NewDESCipher(),
		des3: NewDESCipher(),
	}
}

// SetupKeys настраивает ключи для 3DES
// Поддерживаемые размеры ключей:
// - 24 байта (192 бита, 3 ключа) - Option 1
// - 16 байт (128 бит, 2 ключа) - Option 2
// - 8 байт (64 бита, 1 ключ) - Option 3 (обратная совместимость с DES)
func (tdes *TripleDESCipher) SetupKeys(key []byte) error {
	keyLen := len(key)
	
	switch keyLen {
	case 24: // 3-ключевой 3DES (K1, K2, K3)
		tdes.keyOption = 1
		if err := tdes.des1.SetupKeys(key[0:8]); err != nil {
			return fmt.Errorf("ошибка настройки ключа K1: %w", err)
		}
		if err := tdes.des2.SetupKeys(key[8:16]); err != nil {
			return fmt.Errorf("ошибка настройки ключа K2: %w", err)
		}
		if err := tdes.des3.SetupKeys(key[16:24]); err != nil {
			return fmt.Errorf("ошибка настройки ключа K3: %w", err)
		}
		
	case 16: // 2-ключевой 3DES (K1, K2, K1)
		tdes.keyOption = 2
		if err := tdes.des1.SetupKeys(key[0:8]); err != nil {
			return fmt.Errorf("ошибка настройки ключа K1: %w", err)
		}
		if err := tdes.des2.SetupKeys(key[8:16]); err != nil {
			return fmt.Errorf("ошибка настройки ключа K2: %w", err)
		}
		if err := tdes.des3.SetupKeys(key[0:8]); err != nil {
			return fmt.Errorf("ошибка настройки ключа K3: %w", err)
		}
		
	case 8: // 1-ключевой 3DES (K1, K1, K1) - эквивалентно обычному DES
		tdes.keyOption = 3
		if err := tdes.des1.SetupKeys(key); err != nil {
			return err
		}
		if err := tdes.des2.SetupKeys(key); err != nil {
			return err
		}
		if err := tdes.des3.SetupKeys(key); err != nil {
			return err
		}
		
	default:
		return fmt.Errorf("некорректный размер ключа 3DES: %d байт (ожидается 8, 16 или 24)", keyLen)
	}
	
	return nil
}

// EncryptBlock шифрует блок данных в режиме EDE (Encrypt-Decrypt-Encrypt)
func (tdes *TripleDESCipher) EncryptBlock(block []byte) []byte {
	if len(block) != 8 {
		panic(fmt.Sprintf("блок 3DES должен быть 64 бита (8 байт), получено %d", len(block)))
	}
	
	// Шаг 1: Зашифровать с ключом K1
	temp1 := tdes.des1.EncryptBlock(block)
	
	// Шаг 2: Расшифровать с ключом K2
	temp2 := tdes.des2.DecryptBlock(temp1)
	
	// Шаг 3: Зашифровать с ключом K3
	result := tdes.des3.EncryptBlock(temp2)
	
	return result
}

// DecryptBlock расшифровывает блок данных в режиме DED (Decrypt-Encrypt-Decrypt)
func (tdes *TripleDESCipher) DecryptBlock(block []byte) []byte {
	if len(block) != 8 {
		panic(fmt.Sprintf("блок 3DES должен быть 64 бита (8 байт), получено %d", len(block)))
	}
	
	// Шаг 1: Расшифровать с ключом K3
	temp1 := tdes.des3.DecryptBlock(block)
	
	// Шаг 2: Зашифровать с ключом K2
	temp2 := tdes.des2.EncryptBlock(temp1)
	
	// Шаг 3: Расшифровать с ключом K1
	result := tdes.des1.DecryptBlock(temp2)
	
	return result
}

// Generate3DESKey генерирует случайный ключ для 3DES
// keySize: 1 (24 байта, 3 ключа), 2 (16 байт, 2 ключа), 3 (8 байт, 1 ключ)
func Generate3DESKey(keyOption int) ([]byte, error) {
	var keyLen int
	
	switch keyOption {
	case 1:
		keyLen = 24 // 3-ключевой 3DES (192 бита)
	case 2:
		keyLen = 16 // 2-ключевой 3DES (128 бит)
	case 3:
		keyLen = 8  // 1-ключевой 3DES (64 бита, эквивалентно DES)
	default:
		return nil, fmt.Errorf("некорректная опция ключа: %d (ожидается 1, 2 или 3)", keyOption)
	}
	
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("ошибка генерации случайного ключа: %w", err)
	}
	
	return key, nil
}
