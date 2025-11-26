package padding

import "errors"

type Padding interface {
	Pad(data []byte, blockSize int) []byte
	Unpad(data []byte) ([]byte, error)
}

type PKCS7Padding struct{}

func (p *PKCS7Padding) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func (p *PKCS7Padding) Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("пустые данные")
	}

	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, errors.New("неверный padding")
	}

	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("неверный padding")
		}
	}

	return data[:length-padding], nil
}

type ZeroPadding struct{}

func (p *ZeroPadding) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == blockSize {
		return data
	}
	padText := make([]byte, padding)
	return append(data, padText...)
}

func (p *ZeroPadding) Unpad(data []byte) ([]byte, error) {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1], nil
		}
	}
	return data, nil
}

type ANSIX923Padding struct{}

func (p *ANSIX923Padding) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	padText[padding-1] = byte(padding)
	return append(data, padText...)
}

func (p *ANSIX923Padding) Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("пустые данные")
	}

	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, errors.New("неверный padding")
	}

	for i := length - padding; i < length-1; i++ {
		if data[i] != 0 {
			return nil, errors.New("неверный padding")
		}
	}

	return data[:length-padding], nil
}

type ISO10126Padding struct{}

func (p *ISO10126Padding) Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := 0; i < padding-1; i++ {
		padText[i] = byte(i)
	}
	padText[padding-1] = byte(padding)
	return append(data, padText...)
}

func (p *ISO10126Padding) Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("пустые данные")
	}

	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, errors.New("неверный padding")
	}

	return data[:length-padding], nil
}
