package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sync"
)

// RC6 представляет параметризуемый блочный шифр RC6-w/r/b
type RC6 struct {
	w         int      // Размер слова в битах (16, 32, 64)
	r         int      // Количество раундов
	b         int      // Длина ключа в байтах
	S         []uint64 // Расширенный ключ
	blockSize int      // Размер блока в байтах
	P         uint64   // Константа P
	Q         uint64   // Константа Q
	lgw       int      // log₂(w) для циклических сдвигов
}

// NewRC6 создает новый экземпляр RC6 с заданными параметрами
func NewRC6(w, r, b int, key []byte) (*RC6, error) {
	if w != 16 && w != 32 && w != 64 {
		return nil, fmt.Errorf("w должно быть 16, 32 или 64, получено: %d", w)
	}

	if r < 0 {
		return nil, fmt.Errorf("r должно быть >= 0, получено: %d", r)
	}

	if b < 0 || b > 255 {
		return nil, fmt.Errorf("b должно быть от 0 до 255, получено: %d", b)
	}

	if len(key) != b {
		return nil, fmt.Errorf("длина ключа должна быть %d байт, получено: %d", b, len(key))
	}

	rc6 := &RC6{
		w:         w,
		r:         r,
		b:         b,
		blockSize: 4 * (w / 8),
		lgw:       int(math.Log2(float64(w))),
	}

	rc6.computeConstants()
	rc6.keyExpansion(key)
	return rc6, nil
}

// computeConstants вычисляет магические константы P и Q
func (rc6 *RC6) computeConstants() {
	switch rc6.w {
	case 16:
		rc6.P = 0xB7E1
		rc6.Q = 0x9E37
	case 32:
		rc6.P = 0xB7E15163
		rc6.Q = 0x9E3779B9
	case 64:
		rc6.P = 0xB7E151628AED2A6B
		rc6.Q = 0x9E3779B97F4A7C15
	}
}

// keyExpansion выполняет расширение ключа
func (rc6 *RC6) keyExpansion(key []byte) {
	wordBytes := rc6.w / 8
	t := 2*rc6.r + 4
	rc6.S = make([]uint64, t)

	c := max(rc6.b/wordBytes, 1)
	L := make([]uint64, c)
	for i := rc6.b - 1; i >= 0; i-- {
		L[i/wordBytes] = (L[i/wordBytes] << 8) + uint64(key[i])
	}

	rc6.S[0] = rc6.P
	for i := 1; i < t; i++ {
		rc6.S[i] = rc6.add(rc6.S[i-1], rc6.Q)
	}

	A, B := uint64(0), uint64(0)
	i, j := 0, 0
	v := 3 * max(t, c)
	for k := 0; k < v; k++ {
		A = rc6.rotateLeft(rc6.add(rc6.add(rc6.S[i], A), B), 3)
		rc6.S[i] = A
		B = rc6.rotateLeft(rc6.add(rc6.add(L[j], A), B), int(rc6.mod(rc6.add(A, B), uint64(rc6.w))))
		L[j] = B
		i = (i + 1) % t
		j = (j + 1) % c
	}
}

// EncryptBlock шифрует один блок
func (rc6 *RC6) EncryptBlock(plaintext []byte) []byte {
	if len(plaintext) != rc6.blockSize {
		panic(fmt.Sprintf("размер plaintext должен быть %d байт, получено: %d", rc6.blockSize, len(plaintext)))
	}

	wordSize := rc6.w / 8
	A := rc6.bytesToWord(plaintext[0*wordSize : 1*wordSize])
	B := rc6.bytesToWord(plaintext[1*wordSize : 2*wordSize])
	C := rc6.bytesToWord(plaintext[2*wordSize : 3*wordSize])
	D := rc6.bytesToWord(plaintext[3*wordSize : 4*wordSize])

	B = rc6.add(B, rc6.S[0])
	D = rc6.add(D, rc6.S[1])

	for i := 1; i <= rc6.r; i++ {
		t := rc6.rotateLeft(rc6.mul(B, rc6.add(rc6.mul(B, 2), 1)), rc6.lgw)
		u := rc6.rotateLeft(rc6.mul(D, rc6.add(rc6.mul(D, 2), 1)), rc6.lgw)
		A = rc6.add(rc6.rotateLeft(rc6.xor(A, t), int(rc6.mod(u, uint64(rc6.w)))), rc6.S[2*i])
		C = rc6.add(rc6.rotateLeft(rc6.xor(C, u), int(rc6.mod(t, uint64(rc6.w)))), rc6.S[2*i+1])
		A, B, C, D = B, C, D, A
	}

	A = rc6.add(A, rc6.S[2*rc6.r+2])
	C = rc6.add(C, rc6.S[2*rc6.r+3])

	result := make([]byte, rc6.blockSize)
	copy(result[0*wordSize:], rc6.wordToBytes(A))
	copy(result[1*wordSize:], rc6.wordToBytes(B))
	copy(result[2*wordSize:], rc6.wordToBytes(C))
	copy(result[3*wordSize:], rc6.wordToBytes(D))
	return result
}

// DecryptBlock дешифрует один блок
func (rc6 *RC6) DecryptBlock(ciphertext []byte) []byte {
	if len(ciphertext) != rc6.blockSize {
		panic(fmt.Sprintf("размер ciphertext должен быть %d байт", rc6.blockSize))
	}

	wordSize := rc6.w / 8
	A := rc6.bytesToWord(ciphertext[0*wordSize : 1*wordSize])
	B := rc6.bytesToWord(ciphertext[1*wordSize : 2*wordSize])
	C := rc6.bytesToWord(ciphertext[2*wordSize : 3*wordSize])
	D := rc6.bytesToWord(ciphertext[3*wordSize : 4*wordSize])

	C = rc6.sub(C, rc6.S[2*rc6.r+3])
	A = rc6.sub(A, rc6.S[2*rc6.r+2])

	for i := rc6.r; i >= 1; i-- {
		A, B, C, D = D, A, B, C
		u := rc6.rotateLeft(rc6.mul(D, rc6.add(rc6.mul(D, 2), 1)), rc6.lgw)
		t := rc6.rotateLeft(rc6.mul(B, rc6.add(rc6.mul(B, 2), 1)), rc6.lgw)
		C = rc6.xor(rc6.rotateRight(rc6.sub(C, rc6.S[2*i+1]), int(rc6.mod(t, uint64(rc6.w)))), u)
		A = rc6.xor(rc6.rotateRight(rc6.sub(A, rc6.S[2*i]), int(rc6.mod(u, uint64(rc6.w)))), t)
	}

	D = rc6.sub(D, rc6.S[1])
	B = rc6.sub(B, rc6.S[0])

	result := make([]byte, rc6.blockSize)
	copy(result[0*wordSize:], rc6.wordToBytes(A))
	copy(result[1*wordSize:], rc6.wordToBytes(B))
	copy(result[2*wordSize:], rc6.wordToBytes(C))
	copy(result[3*wordSize:], rc6.wordToBytes(D))
	return result
}

// BlockSize возвращает размер блока
func (rc6 *RC6) BlockSize() int {
	return rc6.blockSize
}

// Арифметические операции
func (rc6 *RC6) add(a, b uint64) uint64 {
	return (a + b) & rc6.mask()
}

func (rc6 *RC6) sub(a, b uint64) uint64 {
	return (a - b) & rc6.mask()
}

func (rc6 *RC6) mul(a, b uint64) uint64 {
	return (a * b) & rc6.mask()
}

func (rc6 *RC6) xor(a, b uint64) uint64 {
	return a ^ b
}

func (rc6 *RC6) mod(a, b uint64) uint64 {
	return a % b
}

func (rc6 *RC6) mask() uint64 {
	return (uint64(1) << rc6.w) - 1
}

func (rc6 *RC6) rotateLeft(x uint64, n int) uint64 {
	n = n % rc6.w
	mask := rc6.mask()
	return ((x << n) | (x >> (rc6.w - n))) & mask
}

func (rc6 *RC6) rotateRight(x uint64, n int) uint64 {
	n = n % rc6.w
	mask := rc6.mask()
	return ((x >> n) | (x << (rc6.w - n))) & mask
}

func (rc6 *RC6) bytesToWord(b []byte) uint64 {
	switch rc6.w {
	case 16:
		return uint64(binary.LittleEndian.Uint16(b))
	case 32:
		return uint64(binary.LittleEndian.Uint32(b))
	case 64:
		return binary.LittleEndian.Uint64(b)
	default:
		panic("неподдерживаемый размер слова")
	}
}

func (rc6 *RC6) wordToBytes(x uint64) []byte {
	wordSize := rc6.w / 8
	b := make([]byte, wordSize)
	switch rc6.w {
	case 16:
		binary.LittleEndian.PutUint16(b, uint16(x))
	case 32:
		binary.LittleEndian.PutUint32(b, uint32(x))
	case 64:
		binary.LittleEndian.PutUint64(b, x)
	}
	return b
}

// Остальная часть кода (режимы, padding, параллельная обработка) остается без изменений

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

func (m CipherMode) String() string {
	names := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"}
	if int(m) < len(names) {
		return names[m]
	}
	return "Unknown"
}

// EncryptMode шифрует данные в заданном режиме
func (rc6 *RC6) EncryptMode(plaintext []byte, mode CipherMode, iv []byte) []byte {
	switch mode {
	case ECB:
		return rc6.encryptECB(plaintext)
	case CBC:
		return rc6.encryptCBC(plaintext, iv)
	case PCBC:
		return rc6.encryptPCBC(plaintext, iv)
	case CFB:
		return rc6.encryptCFB(plaintext, iv)
	case OFB:
		return rc6.encryptOFB(plaintext, iv)
	case CTR:
		return rc6.encryptCTR(plaintext, iv)
	case RandomDelta:
		return rc6.encryptRandomDelta(plaintext, iv)
	default:
		panic("неизвестный режим")
	}
}

// DecryptMode дешифрует данные в заданном режиме
func (rc6 *RC6) DecryptMode(ciphertext []byte, mode CipherMode, iv []byte) []byte {
	switch mode {
	case ECB:
		return rc6.decryptECB(ciphertext)
	case CBC:
		return rc6.decryptCBC(ciphertext, iv)
	case PCBC:
		return rc6.decryptPCBC(ciphertext, iv)
	case CFB:
		return rc6.decryptCFB(ciphertext, iv)
	case OFB:
		return rc6.decryptOFB(ciphertext, iv)
	case CTR:
		return rc6.decryptCTR(ciphertext, iv)
	case RandomDelta:
		return rc6.decryptRandomDelta(ciphertext, iv)
	default:
		panic("неизвестный режим")
	}
}

// ECB Mode
func (rc6 *RC6) encryptECB(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += rc6.blockSize {
		block := rc6.EncryptBlock(plaintext[i : i+rc6.blockSize])
		copy(ciphertext[i:], block)
	}
	return ciphertext
}

func (rc6 *RC6) decryptECB(ciphertext []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += rc6.blockSize {
		block := rc6.DecryptBlock(ciphertext[i : i+rc6.blockSize])
		copy(plaintext[i:], block)
	}
	return plaintext
}

// CBC Mode
func (rc6 *RC6) encryptCBC(plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	prevBlock := make([]byte, rc6.blockSize)
	copy(prevBlock, iv)

	for i := 0; i < len(plaintext); i += rc6.blockSize {
		block := make([]byte, rc6.blockSize)
		copy(block, plaintext[i:i+rc6.blockSize])
		xorBytes(block, prevBlock)
		encrypted := rc6.EncryptBlock(block)
		copy(ciphertext[i:], encrypted)
		copy(prevBlock, encrypted)
	}
	return ciphertext
}

func (rc6 *RC6) decryptCBC(ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	prevBlock := make([]byte, rc6.blockSize)
	copy(prevBlock, iv)

	for i := 0; i < len(ciphertext); i += rc6.blockSize {
		currentCipher := make([]byte, rc6.blockSize)
		copy(currentCipher, ciphertext[i:i+rc6.blockSize])
		decrypted := rc6.DecryptBlock(currentCipher)
		xorBytes(decrypted, prevBlock)
		copy(plaintext[i:], decrypted)
		copy(prevBlock, currentCipher)
	}
	return plaintext
}

// PCBC Mode
func (rc6 *RC6) encryptPCBC(plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	prevPlain := make([]byte, rc6.blockSize)
	prevCipher := make([]byte, rc6.blockSize)
	copy(prevCipher, iv)

	for i := 0; i < len(plaintext); i += rc6.blockSize {
		block := make([]byte, rc6.blockSize)
		copy(block, plaintext[i:i+rc6.blockSize])
		copy(prevPlain, block)
		xorBytes(block, prevCipher)
		encrypted := rc6.EncryptBlock(block)
		copy(ciphertext[i:], encrypted)
		xorBytes(prevPlain, encrypted)
		copy(prevCipher, prevPlain)
	}
	return ciphertext
}

func (rc6 *RC6) decryptPCBC(ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	prevPlain := make([]byte, rc6.blockSize)
	prevCipher := make([]byte, rc6.blockSize)
	copy(prevCipher, iv)

	for i := 0; i < len(ciphertext); i += rc6.blockSize {
		currentCipher := make([]byte, rc6.blockSize)
		copy(currentCipher, ciphertext[i:i+rc6.blockSize])
		decrypted := rc6.DecryptBlock(currentCipher)
		xorBytes(decrypted, prevCipher)
		copy(plaintext[i:], decrypted)
		copy(prevPlain, decrypted)
		xorBytes(prevPlain, currentCipher)
		copy(prevCipher, prevPlain)
	}
	return plaintext
}

// CFB Mode
func (rc6 *RC6) encryptCFB(plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	feedback := make([]byte, rc6.blockSize)
	copy(feedback, iv)

	for i := 0; i < len(plaintext); i += rc6.blockSize {
		encrypted := rc6.EncryptBlock(feedback)
		size := min(rc6.blockSize, len(plaintext)-i)
		for j := 0; j < size; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ encrypted[j]
		}

		if size == rc6.blockSize {
			copy(feedback, ciphertext[i:i+size])
		} else {
			copy(feedback, ciphertext[i:i+size])
			copy(feedback[size:], encrypted[size:])
		}
	}
	return ciphertext
}

func (rc6 *RC6) decryptCFB(ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	feedback := make([]byte, rc6.blockSize)
	copy(feedback, iv)

	for i := 0; i < len(ciphertext); i += rc6.blockSize {
		encrypted := rc6.EncryptBlock(feedback)
		size := min(rc6.blockSize, len(ciphertext)-i)
		for j := 0; j < size; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ encrypted[j]
		}

		if size == rc6.blockSize {
			copy(feedback, ciphertext[i:i+size])
		} else {
			copy(feedback, ciphertext[i:i+size])
			copy(feedback[size:], encrypted[size:])
		}
	}
	return plaintext
}

// OFB Mode
func (rc6 *RC6) encryptOFB(plaintext, iv []byte) []byte {
	return rc6.ofbXOR(plaintext, iv)
}

func (rc6 *RC6) decryptOFB(ciphertext, iv []byte) []byte {
	return rc6.ofbXOR(ciphertext, iv)
}

func (rc6 *RC6) ofbXOR(data, iv []byte) []byte {
	result := make([]byte, len(data))
	feedback := make([]byte, rc6.blockSize)
	copy(feedback, iv)

	for i := 0; i < len(data); i += rc6.blockSize {
		encrypted := rc6.EncryptBlock(feedback)
		copy(feedback, encrypted)
		size := min(rc6.blockSize, len(data)-i)
		for j := 0; j < size; j++ {
			result[i+j] = data[i+j] ^ encrypted[j]
		}
	}
	return result
}

// CTR Mode
func (rc6 *RC6) encryptCTR(plaintext, nonce []byte) []byte {
	return rc6.ctrXOR(plaintext, nonce)
}

func (rc6 *RC6) decryptCTR(ciphertext, nonce []byte) []byte {
	return rc6.ctrXOR(ciphertext, nonce)
}

func (rc6 *RC6) ctrXOR(data, nonce []byte) []byte {
	result := make([]byte, len(data))
	counter := make([]byte, rc6.blockSize)
	copy(counter, nonce)

	for i := 0; i < len(data); i += rc6.blockSize {
		encrypted := rc6.EncryptBlock(counter)
		size := min(rc6.blockSize, len(data)-i)
		for j := 0; j < size; j++ {
			result[i+j] = data[i+j] ^ encrypted[j]
		}
		incrementCounter(counter)
	}
	return result
}

// Random Delta Mode
func (rc6 *RC6) encryptRandomDelta(plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	delta := make([]byte, rc6.blockSize)
	copy(delta, iv)

	for i := 0; i < len(plaintext); i += rc6.blockSize {
		block := make([]byte, rc6.blockSize)
		copy(block, plaintext[i:i+rc6.blockSize])
		xorBytes(block, delta)
		encrypted := rc6.EncryptBlock(block)
		copy(ciphertext[i:], encrypted)
		delta = rc6.EncryptBlock(delta)
	}
	return ciphertext
}

func (rc6 *RC6) decryptRandomDelta(ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	delta := make([]byte, rc6.blockSize)
	copy(delta, iv)

	for i := 0; i < len(ciphertext); i += rc6.blockSize {
		decrypted := rc6.DecryptBlock(ciphertext[i : i+rc6.blockSize])
		xorBytes(decrypted, delta)
		copy(plaintext[i:], decrypted)
		delta = rc6.EncryptBlock(delta)
	}
	return plaintext
}

// Padding modes
type PaddingMode int

const (
	Zeros PaddingMode = iota
	ANSIX923
	PKCS7
	ISO10126
)

func (p PaddingMode) String() string {
	names := []string{"Zeros", "ANSI X9.23", "PKCS7", "ISO 10126"}
	if int(p) < len(names) {
		return names[p]
	}
	return "Unknown"
}

func Pad(data []byte, blockSize int, mode PaddingMode) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	padded := make([]byte, len(data)+padding)
	copy(padded, data)

	switch mode {
	case Zeros:
	case ANSIX923:
		padded[len(padded)-1] = byte(padding)
	case PKCS7:
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(padding)
		}
	case ISO10126:
		rand.Read(padded[len(data) : len(padded)-1])
		padded[len(padded)-1] = byte(padding)
	}

	return padded
}

func Unpad(data []byte, blockSize int, mode PaddingMode) []byte {
	if len(data) == 0 {
		return data
	}

	switch mode {
	case Zeros:
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] != 0 {
				return data[:i+1]
			}
		}
		return []byte{}
	case ANSIX923, PKCS7, ISO10126:
		padding := int(data[len(data)-1])
		if padding > len(data) || padding == 0 || padding > blockSize {
			return data
		}
		return data[:len(data)-padding]
	}

	return data
}

// Параллельная обработка файлов
func (rc6 *RC6) EncryptFileParallel(inputPath, outputPath string, mode CipherMode, padding PaddingMode, numWorkers int) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}

	paddedData := Pad(data, rc6.blockSize, padding)
	iv := make([]byte, rc6.blockSize)
	rand.Read(iv)

	var encrypted []byte
	if mode == ECB || mode == CTR {
		encrypted = rc6.encryptParallel(paddedData, mode, iv, numWorkers)
	} else {
		encrypted = rc6.EncryptMode(paddedData, mode, iv)
	}

	output := append(iv, encrypted...)
	return os.WriteFile(outputPath, output, 0644)
}

func (rc6 *RC6) DecryptFileParallel(inputPath, outputPath string, mode CipherMode, padding PaddingMode, numWorkers int) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}

	if len(data) < rc6.blockSize {
		return fmt.Errorf("файл слишком мал")
	}

	iv := data[:rc6.blockSize]
	ciphertext := data[rc6.blockSize:]

	var decrypted []byte
	if mode == ECB || mode == CTR {
		decrypted = rc6.decryptParallel(ciphertext, mode, iv, numWorkers)
	} else {
		decrypted = rc6.DecryptMode(ciphertext, mode, iv)
	}

	plaintext := Unpad(decrypted, rc6.blockSize, padding)
	return os.WriteFile(outputPath, plaintext, 0644)
}

func (rc6 *RC6) encryptParallel(data []byte, mode CipherMode, iv []byte, numWorkers int) []byte {
	numBlocks := len(data) / rc6.blockSize
	result := make([]byte, len(data))
	var wg sync.WaitGroup
	blocksChan := make(chan int, numBlocks)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockIdx := range blocksChan {
				offset := blockIdx * rc6.blockSize
				block := data[offset : offset+rc6.blockSize]

				var encrypted []byte
				if mode == ECB {
					encrypted = rc6.EncryptBlock(block)
				} else if mode == CTR {
					counter := make([]byte, rc6.blockSize)
					copy(counter, iv)
					for i := 0; i < blockIdx; i++ {
						incrementCounter(counter)
					}
					keystream := rc6.EncryptBlock(counter)
					encrypted = make([]byte, rc6.blockSize)
					copy(encrypted, block)
					xorBytes(encrypted, keystream)
				}

				copy(result[offset:], encrypted)
			}
		}()
	}

	for i := 0; i < numBlocks; i++ {
		blocksChan <- i
	}
	close(blocksChan)

	wg.Wait()
	return result
}

func (rc6 *RC6) decryptParallel(data []byte, mode CipherMode, iv []byte, numWorkers int) []byte {
	numBlocks := len(data) / rc6.blockSize
	result := make([]byte, len(data))
	var wg sync.WaitGroup
	blocksChan := make(chan int, numBlocks)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockIdx := range blocksChan {
				offset := blockIdx * rc6.blockSize
				block := data[offset : offset+rc6.blockSize]

				var decrypted []byte
				if mode == ECB {
					decrypted = rc6.DecryptBlock(block)
				} else if mode == CTR {
					counter := make([]byte, rc6.blockSize)
					copy(counter, iv)
					for i := 0; i < blockIdx; i++ {
						incrementCounter(counter)
					}
					keystream := rc6.EncryptBlock(counter)
					decrypted = make([]byte, rc6.blockSize)
					copy(decrypted, block)
					xorBytes(decrypted, keystream)
				}

				copy(result[offset:], decrypted)
			}
		}()
	}

	for i := 0; i < numBlocks; i++ {
		blocksChan <- i
	}
	close(blocksChan)

	wg.Wait()
	return result
}

// Вспомогательные функции
func xorBytes(a, b []byte) {
	for i := range a {
		if i < len(b) {
			a[i] ^= b[i]
		}
	}
}

func incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Демонстрации
func main() {

	demo1DifferentWordSizes()
	demo2AllCipherModes()
	demo3AllPaddingModes()

}

func demo1DifferentWordSizes() {
	fmt.Println("\nDEMO 1: Работа с разными размерами слов (w) и log₂(w)")
	wordSizes := []int{16, 32, 64}

	for _, w := range wordSizes {
		key := make([]byte, 16)
		rand.Read(key)
		rc6, err := NewRC6(w, 20, 16, key)
		if err != nil {
			fmt.Printf("Ошибка создания RC6-%d: %v\n", w, err)
			continue
		}

		blockSize := rc6.BlockSize()
		plaintext := make([]byte, blockSize)
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		encrypted := rc6.EncryptBlock(plaintext)
		decrypted := rc6.DecryptBlock(encrypted)

		fmt.Printf("RC6-%d/20/16:\n", w)
		fmt.Printf("  Размер блока: %d байт\n", blockSize)
		fmt.Printf("  log₂(%d) = %d (используется для t и u сдвигов)\n", w, rc6.lgw)
		fmt.Printf("  Результат: ")
		if string(decrypted) == string(plaintext) {
			fmt.Println("OK")
		} else {
			fmt.Println("FAILED")
		}
		fmt.Println()
	}
}

func demo2AllCipherModes() {
	fmt.Println("\nDEMO 2: Все режимы шифрования")
	key := make([]byte, 16)
	rand.Read(key)
	rc6, _ := NewRC6(32, 20, 16, key)

	plaintext := []byte("Hello, RC6! This is a comprehensive test of all cipher modes.")
	paddedPlaintext := Pad(plaintext, rc6.BlockSize(), PKCS7)

	iv := make([]byte, rc6.BlockSize())
	rand.Read(iv)

	modes := []CipherMode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta}

	for _, mode := range modes {
		encrypted := rc6.EncryptMode(paddedPlaintext, mode, iv)
		decrypted := rc6.DecryptMode(encrypted, mode, iv)
		unpadded := Unpad(decrypted, rc6.BlockSize(), PKCS7)

		fmt.Printf("Режим %-12s: ", mode)
		if string(unpadded) == string(plaintext) {
			fmt.Println("OK")
		} else {
			fmt.Printf("FAILED\n")
		}
	}
}

func demo3AllPaddingModes() {
	fmt.Println("\nDEMO 3: Все режимы padding")
	key := make([]byte, 16)
	rand.Read(key)
	rc6, _ := NewRC6(32, 20, 16, key)

	plaintext := []byte("Short text for padding test")
	iv := make([]byte, rc6.BlockSize())
	rand.Read(iv)

	paddingModes := []PaddingMode{PKCS7, ANSIX923, ISO10126}

	for _, padding := range paddingModes {
		padded := Pad(plaintext, rc6.BlockSize(), padding)
		encrypted := rc6.EncryptMode(padded, CBC, iv)
		decrypted := rc6.DecryptMode(encrypted, CBC, iv)
		unpadded := Unpad(decrypted, rc6.BlockSize(), padding)

		fmt.Printf("Padding %-12s: ", padding)
		if string(unpadded) == string(plaintext) {
			fmt.Printf("OK (padded: %d -> %d bytes)\n", len(plaintext), len(padded))
		} else {
			fmt.Printf("FAILED\n")
		}
	}
}
