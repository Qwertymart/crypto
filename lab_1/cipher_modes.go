package main

import (
	"fmt"
	"sync"
)

type CipherModes struct {
	cipher    SymmetricCipher
	blockSize int
}

func NewCipherModes(cipher SymmetricCipher, blockSize int) *CipherModes {
	return &CipherModes{cipher: cipher, blockSize: blockSize}
}

func (cm *CipherModes) xorBytes(a, b []byte) []byte {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	result := make([]byte, minLen)
	for i := 0; i < minLen; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func (cm *CipherModes) incrementCounter(counter []byte) []byte {
	result := make([]byte, len(counter))
	copy(result, counter)
	carry := 1
	for i := len(result) - 1; i >= 0 && carry > 0; i-- {
		sum := int(result[i]) + carry
		result[i] = byte(sum & 0xFF)
		carry = sum >> 8
	}
	return result
}

// ECB

func (cm *CipherModes) EncryptECB(blocks [][]byte) []byte {
	results := make([][]byte, len(blocks))
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for i, block := range blocks {
		wg.Add(1)
		go func(index int, b []byte) {
			defer wg.Done()

			blockCopy := make([]byte, len(b))
			copy(blockCopy, b)

			enc := cm.cipher.EncryptBlock(blockCopy)

			mutex.Lock()
			results[index] = enc
			mutex.Unlock()
		}(i, block)
	}

	wg.Wait()

	var result []byte
	for i, data := range results {
		if data == nil {
			panic(fmt.Sprintf("Блок %d не был зашифрован!", i))
		}
		result = append(result, data...)
	}

	return result
}

func (cm *CipherModes) DecryptECB(blocks [][]byte) []byte {
	var result []byte
	for _, block := range blocks {
		dec := cm.cipher.DecryptBlock(block)
		result = append(result, dec...)
	}
	return result
}

// CBC

func (cm *CipherModes) EncryptCBC(blocks [][]byte, iv []byte) []byte {
	var result []byte
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for _, block := range blocks {
		x := cm.xorBytes(block, prev)
		enc := cm.cipher.EncryptBlock(x)
		result = append(result, enc...)
		copy(prev, enc)
	}
	return result
}

func (cm *CipherModes) DecryptCBC(blocks [][]byte, iv []byte) []byte {
	var result []byte
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for _, block := range blocks {
		dec := cm.cipher.DecryptBlock(block)
		plain := cm.xorBytes(dec, prev)
		result = append(result, plain...)
		copy(prev, block)
	}
	return result
}

// PCBC

func (cm *CipherModes) EncryptPCBC(blocks [][]byte, iv []byte) []byte {
	var result []byte
	prevXor := make([]byte, len(iv))
	copy(prevXor, iv)

	for _, block := range blocks {
		x := cm.xorBytes(block, prevXor)
		enc := cm.cipher.EncryptBlock(x)
		result = append(result, enc...)
		prevXor = cm.xorBytes(block, enc)
	}
	return result
}

func (cm *CipherModes) DecryptPCBC(blocks [][]byte, iv []byte) []byte {
	var result []byte
	prevXor := make([]byte, len(iv))
	copy(prevXor, iv)

	for _, block := range blocks {
		dec := cm.cipher.DecryptBlock(block)
		plain := cm.xorBytes(dec, prevXor)
		result = append(result, plain...)
		prevXor = cm.xorBytes(plain, block)
	}
	return result
}

// CFB

func (cm *CipherModes) EncryptCFB(blocks [][]byte, iv []byte) []byte {
	var result []byte
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for _, block := range blocks {
		encIV := cm.cipher.EncryptBlock(prev)
		enc := cm.xorBytes(block, encIV)
		result = append(result, enc...)
		copy(prev, enc)
	}
	return result
}

func (cm *CipherModes) DecryptCFB(blocks [][]byte, iv []byte) []byte {
	var result []byte
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for _, block := range blocks {
		encIV := cm.cipher.EncryptBlock(prev)
		dec := cm.xorBytes(block, encIV)
		result = append(result, dec...)
		copy(prev, block)
	}
	return result
}

//OFB

func (cm *CipherModes) EncryptOFB(blocks [][]byte, iv []byte) []byte {
	var result []byte
	out := make([]byte, len(iv))
	copy(out, iv)

	for _, block := range blocks {
		out = cm.cipher.EncryptBlock(out)
		enc := cm.xorBytes(block, out)
		result = append(result, enc...)
	}
	return result
}

func (cm *CipherModes) DecryptOFB(blocks [][]byte, iv []byte) []byte {
	return cm.EncryptOFB(blocks, iv)
}

//CTR

func (cm *CipherModes) EncryptCTR(blocks [][]byte, iv []byte) []byte {
	results := make([][]byte, len(blocks))
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for i, block := range blocks {
		wg.Add(1)
		go func(index int, b []byte) {
			defer wg.Done()

			counter := make([]byte, len(iv))
			copy(counter, iv)

			for j := 0; j < index; j++ {
				counter = cm.incrementCounter(counter)
			}

			encCounter := cm.cipher.EncryptBlock(counter)

			enc := cm.xorBytes(b, encCounter)

			mutex.Lock()
			results[index] = enc
			mutex.Unlock()
		}(i, block)
	}

	wg.Wait()

	var result []byte
	for i, data := range results {
		if data == nil {
			panic(fmt.Sprintf("Блок %d не был зашифрован!", i))
		}
		result = append(result, data...)
	}

	return result
}

func (cm *CipherModes) DecryptCTR(blocks [][]byte, iv []byte) []byte {
	return cm.EncryptCTR(blocks, iv)
}

func (cm *CipherModes) EncryptRandomDelta(blocks [][]byte, iv []byte) []byte {
	var result []byte
	delta := make([]byte, len(iv))
	copy(delta, iv)

	for _, block := range blocks {
		x := cm.xorBytes(block, delta)
		enc := cm.cipher.EncryptBlock(x)
		result = append(result, enc...)

		for i := range delta {
			delta[i] ^= enc[i%len(enc)]
		}
	}
	return result
}

func (cm *CipherModes) DecryptRandomDelta(blocks [][]byte, iv []byte) []byte {
	var result []byte
	delta := make([]byte, len(iv))
	copy(delta, iv)

	for _, block := range blocks {
		dec := cm.cipher.DecryptBlock(block)
		plain := cm.xorBytes(dec, delta)
		result = append(result, plain...)

		for i := range delta {
			delta[i] ^= block[i%len(block)]
		}
	}
	return result
}
