package main

import (
	"crypto/rand"
	"fmt"
)

// Начальная перестановка (IP)

var initialPermutation = []int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

// Финальная перестановка (FP)
var finalPermutation = []int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

// Расширяющая перестановка (E)
var expansionTable = []int{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

// P-блок перестановка
var pBox = []int{
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25,
}

// S-блоки
var sBoxes = [8][4][16]int{
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

// PC-1
var pc1 = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

// PC-2
var pc2 = []int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

// Количество левых сдвигов для каждого раунда
var shiftTable = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

// rotateLeft28 выполняет циклический левый сдвиг 28-битного числа на shifts позиций
func rotateLeft28(n uint32, shifts uint) uint32 {
	shifts = shifts % 28
	mask := uint32((1 << 28) - 1) // 0x0FFFFFFF
	return ((n << shifts) | (n >> (28 - shifts))) & mask
}

// bitsToUint32 преобразует массив битов в uint32
func bitsToUint32(bits []int) uint32 {
	var result uint32
	for i := 0; i < len(bits) && i < 32; i++ {
		if bits[i] != 0 {
			result |= 1 << uint(len(bits)-1-i)
		}
	}
	return result
}

// uint32ToBits преобразует uint32 в массив битов указанной длины
func uint32ToBits(n uint32, bitCount int) []int {
	bits := make([]int, bitCount)
	for i := 0; i < bitCount; i++ {
		bits[bitCount-1-i] = int((n >> uint(i)) & 1)
	}
	return bits
}

// DESKeyExpansion реализация расширения ключа для DES
type DESKeyExpansion struct{}

// ExpandKey генерирует 16 раундовых ключей из 64-битного ключа
func (ke *DESKeyExpansion) ExpandKey(key []byte) [][]byte {
	if len(key) != 8 {
		panic(fmt.Sprintf("ключ DES должен быть 64 бита (8 байт), получено %d", len(key)))
	}

	// Применяем PC-1 к ключу
	pc1Key := BitPermutation(key, pc1, false, 1)
	var pc1Bits []int
	for _, b := range pc1Key {
		for i := 7; i >= 0; i-- {
			pc1Bits = append(pc1Bits, int((b>>i)&1))
		}
	}
	if len(pc1Bits) > 56 {
		pc1Bits = pc1Bits[:56]
	}

	// Преобразуем левую и правую половины в uint32 для битовых операций
	leftBits := pc1Bits[:28]
	rightBits := pc1Bits[28:56]

	leftHalf := bitsToUint32(leftBits)
	rightHalf := bitsToUint32(rightBits)

	var roundKeys [][]byte
	for roundNum := 0; roundNum < 16; roundNum++ {
		// Циклические сдвиги через битовые операции
		shiftCount := uint(shiftTable[roundNum])
		leftHalf = rotateLeft28(leftHalf, shiftCount)
		rightHalf = rotateLeft28(rightHalf, shiftCount)

		// Преобразуем обратно в биты и объединяем
		leftBitsRotated := uint32ToBits(leftHalf, 28)
		rightBitsRotated := uint32ToBits(rightHalf, 28)
		combined := append(leftBitsRotated, rightBitsRotated...)

		var combinedBytes []byte
		for i := 0; i < len(combined); i += 8 {
			var byteValue byte
			for j := 0; j < 8 && i+j < len(combined); j++ {
				byteValue |= byte(combined[i+j] << (7 - j))
			}
			combinedBytes = append(combinedBytes, byteValue)
		}

		// Применяем PC-2 для получения раундового ключа
		rk := BitPermutation(combinedBytes, pc2, false, 1)
		if len(rk) > 6 {
			rk = rk[:6]
		}
		roundKeys = append(roundKeys, rk)
	}

	return roundKeys
}

// DESRoundFunction реализация раундовой функции DES
type DESRoundFunction struct{}

// Apply применяет раундовую функцию DES к 32-битному блоку
func (rf *DESRoundFunction) Apply(block []byte, roundKey []byte) []byte {
	if len(block) != 4 {
		panic(fmt.Sprintf("блок должен быть 32 бита (4 байта), получено %d", len(block)))
	}

	if len(roundKey) != 6 {
		panic(fmt.Sprintf("раундовый ключ должен быть 48 бит (6 байт), получено %d", len(roundKey)))
	}

	// Расширение E
	expanded := BitPermutation(block, expansionTable, false, 1)
	if len(expanded) > 6 {
		expanded = expanded[:6]
	}

	// XOR с раундовым ключом
	xored := make([]byte, len(expanded))
	for i := 0; i < len(expanded) && i < len(roundKey); i++ {
		xored[i] = expanded[i] ^ roundKey[i]
	}

	// Преобразование в биты
	var xoredBits []int
	for _, b := range xored {
		for i := 7; i >= 0; i-- {
			xoredBits = append(xoredBits, int((b>>i)&1))
		}
	}
	if len(xoredBits) > 48 {
		xoredBits = xoredBits[:48]
	}

	// S-блоки
	var sboxOutput []int
	for i := 0; i < 8; i++ {
		start := i * 6
		end := start + 6
		if end > len(xoredBits) {
			end = len(xoredBits)
		}

		block6bit := make([]int, 6)
		copy(block6bit, xoredBits[start:end])
		for len(block6bit) < 6 {
			block6bit = append(block6bit, 0)
		}

		row := (block6bit[0] << 1) | block6bit[5]
		col := (block6bit[1] << 3) | (block6bit[2] << 2) | (block6bit[3] << 1) | block6bit[4]
		val := sBoxes[i][row][col]

		for j := 3; j >= 0; j-- {
			sboxOutput = append(sboxOutput, (val>>j)&1)
		}
	}

	// Преобразование обратно в байты
	var sboxBytes []byte
	for i := 0; i < 32; i += 8 {
		var byteValue byte
		for j := 0; j < 8 && i+j < len(sboxOutput); j++ {
			byteValue |= byte(sboxOutput[i+j] << (7 - j))
		}
		sboxBytes = append(sboxBytes, byteValue)
	}

	// P-блок
	finalResult := BitPermutation(sboxBytes, pBox, false, 1)
	if len(finalResult) > 4 {
		finalResult = finalResult[:4]
	}

	return finalResult
}

// DESCipher реализация алгоритма DES
type DESCipher struct {
	feistelNetwork *FeistelNetwork
}

// NewDESCipher создает новый шифр DES
func NewDESCipher() *DESCipher {
	keyExpansion := &DESKeyExpansion{}
	roundFunction := &DESRoundFunction{}
	feistelNetwork := NewFeistelNetwork(keyExpansion, roundFunction, 16)
	return &DESCipher{feistelNetwork: feistelNetwork}
}

func (des *DESCipher) SetupKeys(key []byte) error {
	return des.feistelNetwork.SetupKeys(key)
}

func (des *DESCipher) EncryptBlock(block []byte) []byte {
	afterIP := BitPermutation(block, initialPermutation, false, 1)
	afterFeistel := des.feistelNetwork.EncryptBlock(afterIP)
	finalResult := BitPermutation(afterFeistel, finalPermutation, false, 1)
	return finalResult
}

func (des *DESCipher) DecryptBlock(block []byte) []byte {
	afterIP := BitPermutation(block, initialPermutation, false, 1)
	afterFeistel := des.feistelNetwork.DecryptBlock(afterIP)
	finalResult := BitPermutation(afterFeistel, finalPermutation, false, 1)
	return finalResult
}

// GenerateDESKey генерирует случайный 64-битный ключ для DES
func GenerateDESKey() ([]byte, error) {
	key := make([]byte, 8)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации случайного ключа DES: %w", err)
	}
	return key, nil
}
