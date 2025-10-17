package main

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type CipherContext struct {
	cipher         SymmetricCipher
	key            []byte
	cipherMode     CipherMode
	paddingMode    PaddingMode
	iv             []byte
	blockSize      int
	paddingHandler *PaddingHandler
	cipherModes    *CipherModes
	mutex          sync.RWMutex
}

func NewCipherContext(cipher SymmetricCipher, key []byte, cipherMode CipherMode, paddingMode PaddingMode, iv []byte, blockSize int) (*CipherContext, error) {
	ctx := &CipherContext{
		cipher:         cipher,
		key:            append([]byte{}, key...),
		cipherMode:     cipherMode,
		paddingMode:    paddingMode,
		blockSize:      blockSize,
		paddingHandler: &PaddingHandler{},
	}
	if iv != nil {
		ctx.iv = append([]byte{}, iv...)
	} else {
		ctx.iv = make([]byte, blockSize)
	}
	if err := cipher.SetupKeys(key); err != nil {
		return nil, fmt.Errorf("ошибка настройки ключей: %w", err)
	}
	ctx.cipherModes = NewCipherModes(cipher, blockSize)
	return ctx, nil
}

func (ctx *CipherContext) Encrypt(data []byte) ([]byte, error) {
	ctx.mutex.RLock()
	defer ctx.mutex.RUnlock()

	// Сохраняем исходную длину для поточных режимов
	originalLen := len(data)

	isStreamMode := ctx.cipherMode == CFB ||
		ctx.cipherMode == OFB ||
		ctx.cipherMode == CTR

	var padded []byte
	var err error

	if !isStreamMode {
		// Для блочных режимов добавляем padding
		padded, err = ctx.paddingHandler.AddPadding(data, ctx.blockSize, ctx.paddingMode)
		if err != nil {
			return nil, fmt.Errorf("ошибка добавления набивки: %w", err)
		}
	} else {
		// Для поточных режимов выравниваем до размера блока нулями
		padded = make([]byte, len(data))
		copy(padded, data)

		remainder := len(data) % ctx.blockSize
		if remainder != 0 {
			padding := make([]byte, ctx.blockSize-remainder)
			padded = append(padded, padding...)
		}
	}

	blocks := make([][]byte, 0)
	for i := 0; i < len(padded); i += ctx.blockSize {
		end := i + ctx.blockSize
		if end > len(padded) {
			end = len(padded)
		}

		b := make([]byte, ctx.blockSize)
		copy(b, padded[i:end])
		blocks = append(blocks, b)
	}

	var encrypted []byte
	switch ctx.cipherMode {
	case ECB:
		encrypted = ctx.cipherModes.EncryptECB(blocks)
	case CBC:
		encrypted = ctx.cipherModes.EncryptCBC(blocks, ctx.iv)
	case PCBC:
		encrypted = ctx.cipherModes.EncryptPCBC(blocks, ctx.iv)
	case CFB:
		encrypted = ctx.cipherModes.EncryptCFB(blocks, ctx.iv)
	case OFB:
		encrypted = ctx.cipherModes.EncryptOFB(blocks, ctx.iv)
	case CTR:
		encrypted = ctx.cipherModes.EncryptCTR(blocks, ctx.iv)
	case RandomDelta:
		encrypted = ctx.cipherModes.EncryptRandomDelta(blocks, ctx.iv)
	default:
		return nil, fmt.Errorf("неподдерживаемый режим шифрования: %v", ctx.cipherMode)
	}

	// Для поточных режимов добавляем метаданные с исходной длиной
	if isStreamMode {
		// Добавляем 4 байта с исходной длиной в начало
		lenBytes := make([]byte, 4)
		lenBytes[0] = byte(originalLen >> 24)
		lenBytes[1] = byte(originalLen >> 16)
		lenBytes[2] = byte(originalLen >> 8)
		lenBytes[3] = byte(originalLen)

		encrypted = append(lenBytes, encrypted...)
	}

	return encrypted, nil
}

func (ctx *CipherContext) Decrypt(data []byte) ([]byte, error) {
	ctx.mutex.RLock()
	defer ctx.mutex.RUnlock()

	isStreamMode := ctx.cipherMode == CFB ||
		ctx.cipherMode == OFB ||
		ctx.cipherMode == CTR

	var originalLen int
	var dataToDecrypt []byte

	if isStreamMode {
		if len(data) < 4 {
			return nil, fmt.Errorf("недостаточно данных для дешифрования")
		}
		originalLen = int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		dataToDecrypt = data[4:]
	} else {
		dataToDecrypt = data
	}

	if len(dataToDecrypt)%ctx.blockSize != 0 {
		return nil, fmt.Errorf("длина данных не кратна размеру блока")
	}

	blocks := make([][]byte, 0)
	for i := 0; i < len(dataToDecrypt); i += ctx.blockSize {
		b := make([]byte, ctx.blockSize)
		copy(b, dataToDecrypt[i:i+ctx.blockSize])
		blocks = append(blocks, b)
	}

	var out []byte
	switch ctx.cipherMode {
	case ECB:
		out = ctx.cipherModes.DecryptECB(blocks)
	case CBC:
		out = ctx.cipherModes.DecryptCBC(blocks, ctx.iv)
	case PCBC:
		out = ctx.cipherModes.DecryptPCBC(blocks, ctx.iv)
	case CFB:
		out = ctx.cipherModes.DecryptCFB(blocks, ctx.iv)
	case OFB:
		out = ctx.cipherModes.DecryptOFB(blocks, ctx.iv)
	case CTR:
		out = ctx.cipherModes.DecryptCTR(blocks, ctx.iv)
	case RandomDelta:
		out = ctx.cipherModes.DecryptRandomDelta(blocks, ctx.iv)
	default:
		return nil, fmt.Errorf("неподдерживаемый режим дешифрования: %v", ctx.cipherMode)
	}

	if !isStreamMode {
		// Для блочных режимов удаляем padding
		return ctx.paddingHandler.RemovePadding(out, ctx.paddingMode)
	}

	// Для поточных режимов обрезаем до исходной длины
	if originalLen > len(out) {
		return nil, fmt.Errorf("некорректная исходная длина: %d > %d", originalLen, len(out))
	}

	return out[:originalLen], nil
}

func (ctx *CipherContext) EncryptFile(inputPath, outputPath string) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка открытия входного файла: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}
	enc, err := ctx.Encrypt(data)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %w", err)
	}
	return os.WriteFile(outputPath, enc, 0644)
}

func (ctx *CipherContext) DecryptFile(inputPath, outputPath string) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка открытия входного файла: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}
	dec, err := ctx.Decrypt(data)
	if err != nil {
		return fmt.Errorf("ошибка дешифрования: %w", err)
	}
	return os.WriteFile(outputPath, dec, 0644)
}
