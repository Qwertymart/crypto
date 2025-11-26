package cipher

import (
	"lab_3/padding"
	"lab_3/rijndael"
	"crypto/rand"
	"errors"
)

type Mode int

const (
    ECB Mode = iota
    CBC
    PCBC  
    CFB
    OFB
    CTR
    RandomDelta  
)


type Cipher struct {
	rijndael *rijndael.Rijndael
	mode     Mode
	padding  padding.Padding
}

func NewCipher(r *rijndael.Rijndael, mode Mode, pad padding.Padding) *Cipher {
	return &Cipher{
		rijndael: r,
		mode:     mode,
		padding:  pad,
	}
}

func (c *Cipher) Encrypt(plaintext, iv []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()

	// Для потоковых режимов padding не нужен
	var dataToEncrypt []byte
	if c.mode == ECB || c.mode == CBC || c.mode == PCBC {
		dataToEncrypt = c.padding.Pad(plaintext, blockSize)
	} else {
		dataToEncrypt = plaintext
	}

	switch c.mode {
	case ECB:
		return c.encryptECB(dataToEncrypt)
	case CBC:
		return c.encryptCBC(dataToEncrypt, iv)
	case CFB:
		return c.encryptCFB(dataToEncrypt, iv)
	case OFB:
		return c.encryptOFB(dataToEncrypt, iv)
	case CTR:
		return c.encryptCTR(dataToEncrypt, iv)
	case PCBC:
    	return c.encryptPCBC(dataToEncrypt, iv)
	default:
		return nil, errors.New("неподдерживаемый режим")
	}
}

func (c *Cipher) Decrypt(ciphertext, iv []byte) ([]byte, error) {
	var decrypted []byte
	var err error

	switch c.mode {
	case ECB:
		decrypted, err = c.decryptECB(ciphertext)
	case CBC:
		decrypted, err = c.decryptCBC(ciphertext, iv)
	case CFB:
		decrypted, err = c.decryptCFB(ciphertext, iv)
	case OFB:
		decrypted, err = c.decryptOFB(ciphertext, iv)
	case CTR:
		decrypted, err = c.decryptCTR(ciphertext, iv)
	case PCBC:
    	decrypted, err = c.decryptPCBC(ciphertext, iv)
	default:
		return nil, errors.New("неподдерживаемый режим")
	}

	if err != nil {
		return nil, err
	}

	// Для потоковых режимов padding не используется
	if c.mode == ECB || c.mode == CBC {
		return c.padding.Unpad(decrypted)
	}
	return decrypted, nil
}

func (c *Cipher) encryptECB(plaintext []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += blockSize {
		block, err := c.rijndael.Encrypt(plaintext[i : i+blockSize])
		if err != nil {
			return nil, err
		}
		copy(ciphertext[i:], block)
	}

	return ciphertext, nil
}

func (c *Cipher) decryptECB(ciphertext []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += blockSize {
		block, err := c.rijndael.Decrypt(ciphertext[i : i+blockSize])
		if err != nil {
			return nil, err
		}
		copy(plaintext[i:], block)
	}

	return plaintext, nil
}

func (c *Cipher) encryptCBC(plaintext, iv []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("неверная длина IV")
	}

	ciphertext := make([]byte, len(plaintext))
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		block := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			block[j] = plaintext[i+j] ^ prevBlock[j]
		}

		encrypted, err := c.rijndael.Encrypt(block)
		if err != nil {
			return nil, err
		}

		copy(ciphertext[i:], encrypted)
		copy(prevBlock, encrypted)
	}

	return ciphertext, nil
}

func (c *Cipher) decryptCBC(ciphertext, iv []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("неверная длина IV")
	}

	plaintext := make([]byte, len(ciphertext))
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		decrypted, err := c.rijndael.Decrypt(ciphertext[i : i+blockSize])
		if err != nil {
			return nil, err
		}

		for j := 0; j < blockSize; j++ {
			plaintext[i+j] = decrypted[j] ^ prevBlock[j]
		}

		copy(prevBlock, ciphertext[i:i+blockSize])
	}

	return plaintext, nil
}

func (c *Cipher) encryptCFB(plaintext, iv []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("неверная длина IV")
	}

	ciphertext := make([]byte, len(plaintext))
	register := make([]byte, blockSize)
	copy(register, iv)

	pos := 0
	for pos < len(plaintext) {
		encrypted, err := c.rijndael.Encrypt(register)
		if err != nil {
			return nil, err
		}

		blockLen := blockSize
		if pos+blockSize > len(plaintext) {
			blockLen = len(plaintext) - pos
		}

		for j := 0; j < blockLen; j++ {
			ciphertext[pos+j] = plaintext[pos+j] ^ encrypted[j]
		}

		// Сдвигаем регистр
		if blockLen == blockSize {
			copy(register, ciphertext[pos:pos+blockSize])
		} else {
			copy(register, register[blockLen:])
			copy(register[blockSize-blockLen:], ciphertext[pos:pos+blockLen])
		}

		pos += blockLen
	}

	return ciphertext, nil
}

func (c *Cipher) decryptCFB(ciphertext, iv []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("неверная длина IV")
	}

	plaintext := make([]byte, len(ciphertext))
	register := make([]byte, blockSize)
	copy(register, iv)

	pos := 0
	for pos < len(ciphertext) {
		encrypted, err := c.rijndael.Encrypt(register)
		if err != nil {
			return nil, err
		}

		blockLen := blockSize
		if pos+blockSize > len(ciphertext) {
			blockLen = len(ciphertext) - pos
		}

		for j := 0; j < blockLen; j++ {
			plaintext[pos+j] = ciphertext[pos+j] ^ encrypted[j]
		}

		// Сдвигаем регистр
		if blockLen == blockSize {
			copy(register, ciphertext[pos:pos+blockSize])
		} else {
			copy(register, register[blockLen:])
			copy(register[blockSize-blockLen:], ciphertext[pos:pos+blockLen])
		}

		pos += blockLen
	}

	return plaintext, nil
}

func (c *Cipher) encryptOFB(plaintext, iv []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("неверная длина IV")
	}

	ciphertext := make([]byte, len(plaintext))
	register := make([]byte, blockSize)
	copy(register, iv)

	pos := 0
	for pos < len(plaintext) {
		encrypted, err := c.rijndael.Encrypt(register)
		if err != nil {
			return nil, err
		}

		copy(register, encrypted)

		blockLen := blockSize
		if pos+blockSize > len(plaintext) {
			blockLen = len(plaintext) - pos
		}

		for j := 0; j < blockLen; j++ {
			ciphertext[pos+j] = plaintext[pos+j] ^ encrypted[j]
		}

		pos += blockLen
	}

	return ciphertext, nil
}

func (c *Cipher) decryptOFB(ciphertext, iv []byte) ([]byte, error) {
	return c.encryptOFB(ciphertext, iv)
}

func (c *Cipher) encryptCTR(plaintext, nonce []byte) ([]byte, error) {
	blockSize := c.rijndael.BlockSize()
	if len(nonce) != blockSize {
		return nil, errors.New("неверная длина nonce")
	}

	ciphertext := make([]byte, len(plaintext))
	counter := make([]byte, blockSize)
	copy(counter, nonce)

	pos := 0
	for pos < len(plaintext) {
		encrypted, err := c.rijndael.Encrypt(counter)
		if err != nil {
			return nil, err
		}

		blockLen := blockSize
		if pos+blockSize > len(plaintext) {
			blockLen = len(plaintext) - pos
		}

		for j := 0; j < blockLen; j++ {
			ciphertext[pos+j] = plaintext[pos+j] ^ encrypted[j]
		}

		c.incrementCounter(counter)
		pos += blockLen
	}

	return ciphertext, nil
}

func (c *Cipher) decryptCTR(ciphertext, nonce []byte) ([]byte, error) {
	return c.encryptCTR(ciphertext, nonce)
}

func (c *Cipher) encryptPCBC(plaintext, iv []byte) ([]byte, error) {
    blockSize := c.rijndael.BlockSize()
    if len(iv) != blockSize {
        return nil, errors.New("неверная длина IV")
    }

    ciphertext := make([]byte, len(plaintext))
    prevCipher := make([]byte, blockSize)
    prevPlain := make([]byte, blockSize)
    copy(prevCipher, iv)
    copy(prevPlain, iv) 

    for i := 0; i < len(plaintext); i += blockSize {
        block := make([]byte, blockSize)
        
        for j := 0; j < blockSize; j++ {
            block[j] = plaintext[i+j] ^ prevCipher[j] ^ prevPlain[j]
        }

        encrypted, err := c.rijndael.Encrypt(block)
        if err != nil {
            return nil, err
        }

        copy(ciphertext[i:], encrypted)
        
        copy(prevPlain, plaintext[i:i+blockSize])
        copy(prevCipher, encrypted)
    }

    return ciphertext, nil
}

func (c *Cipher) decryptPCBC(ciphertext, iv []byte) ([]byte, error) {
    blockSize := c.rijndael.BlockSize()
    if len(iv) != blockSize {
        return nil, errors.New("неверная длина IV")
    }

    plaintext := make([]byte, len(ciphertext))
    prevCipher := make([]byte, blockSize)
    prevPlain := make([]byte, blockSize)
    copy(prevCipher, iv)
    copy(prevPlain, iv)

    for i := 0; i < len(ciphertext); i += blockSize {
        decrypted, err := c.rijndael.Decrypt(ciphertext[i : i+blockSize])
        if err != nil {
            return nil, err
        }

        for j := 0; j < blockSize; j++ {
            plaintext[i+j] = decrypted[j] ^ prevCipher[j] ^ prevPlain[j]
        }

        copy(prevPlain, plaintext[i:i+blockSize])
        copy(prevCipher, ciphertext[i:i+blockSize])
    }

    return plaintext, nil
}



func (c *Cipher) incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func GenerateIV(blockSize int) ([]byte, error) {
	iv := make([]byte, blockSize)
	_, err := rand.Read(iv)
	return iv, err
}
