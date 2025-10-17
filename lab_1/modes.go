package main

import (
	"crypto/rand"
	"fmt"
)

type CipherMode int

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

func (cm CipherMode) String() string {
	switch cm {
	case ECB:
		return "ECB"
	case CBC:
		return "CBC"
	case PCBC:
		return "PCBC"
	case CFB:
		return "CFB"
	case OFB:
		return "OFB"
	case CTR:
		return "CTR"
	case RandomDelta:
		return "RandomDelta"
	default:
		return "Unknown"
	}
}

// PaddingMode режимы набивки
type PaddingMode int

const (
	Zeros PaddingMode = iota
	ANSIX923
	PKCS7
	ISO10126
)

func (pm PaddingMode) String() string {
	switch pm {
	case Zeros:
		return "Zeros"
	case ANSIX923:
		return "ANSI X.923"
	case PKCS7:
		return "PKCS7"
	case ISO10126:
		return "ISO 10126"
	default:
		return "Unknown"
	}
}

// PaddingHandler обработчик набивки данных
type PaddingHandler struct{}

// AddPadding добавляет набивку к данным
func (ph *PaddingHandler) AddPadding(data []byte, blockSize int, mode PaddingMode) ([]byte, error) {
	paddingLength := blockSize - (len(data) % blockSize)
	if paddingLength == 0 {
		paddingLength = blockSize
	}
	switch mode {
	case Zeros:
		padding := make([]byte, paddingLength)
		padding[0] = 0x80
		return append(data, padding...), nil
	case PKCS7:
		padding := make([]byte, paddingLength)
		for i := range padding {
			padding[i] = byte(paddingLength)
		}
		return append(data, padding...), nil
	case ANSIX923:
		padding := make([]byte, paddingLength)
		padding[paddingLength-1] = byte(paddingLength)
		return append(data, padding...), nil
	case ISO10126:
		padding := make([]byte, paddingLength)
		if _, err := rand.Read(padding[:paddingLength-1]); err != nil {
			return nil, fmt.Errorf("ошибка генерации случайных данных: %w", err)
		}
		padding[paddingLength-1] = byte(paddingLength)
		return append(data, padding...), nil
	default:
		return nil, fmt.Errorf("неподдерживаемый режим набивки: %v", mode)
	}
}

// RemovePadding удаляет набивку из данных
func (ph *PaddingHandler) RemovePadding(data []byte, mode PaddingMode) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	switch mode {
	case Zeros:
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] == 0x80 {
				return data[:i], nil
			}
			if data[i] != 0 {
				break
			}
		}
		return data, nil
	case PKCS7:
		paddingLength := int(data[len(data)-1])
		if paddingLength > len(data) || paddingLength == 0 {
			return nil, fmt.Errorf("некорректная PKCS7 набивка")
		}
		for i := len(data) - paddingLength; i < len(data); i++ {
			if data[i] != byte(paddingLength) {
				return nil, fmt.Errorf("некорректная PKCS7 набивка")
			}
		}
		return data[:len(data)-paddingLength], nil
	case ANSIX923:
		paddingLength := int(data[len(data)-1])
		if paddingLength > len(data) || paddingLength == 0 {
			return nil, fmt.Errorf("некорректная ANSI X.923 набивка")
		}
		for i := len(data) - paddingLength; i < len(data)-1; i++ {
			if data[i] != 0 {
				return nil, fmt.Errorf("некорректная ANSI X.923 набивка")
			}
		}
		return data[:len(data)-paddingLength], nil
	case ISO10126:
		paddingLength := int(data[len(data)-1])
		if paddingLength > len(data) || paddingLength == 0 {
			return nil, fmt.Errorf("некорректная ISO 10126 набивка")
		}
		return data[:len(data)-paddingLength], nil
	default:
		return nil, fmt.Errorf("неподдерживаемый режим набивки: %v", mode)
	}
}
