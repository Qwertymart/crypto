package rijndael

import (
	"lab_3/gf"
	"errors"
	"fmt"
)

type BlockSize int

const (
	Block128 BlockSize = 16
	Block192 BlockSize = 24
	Block256 BlockSize = 32
)

type KeySize int

const (
	Key128 KeySize = 16
	Key192 KeySize = 24
	Key256 KeySize = 32
)

type Rijndael struct {
	blockSize BlockSize
	keySize   KeySize
	modulus   byte
	gf        *gf.GF256Service
	sBox      [256]byte
	invSBox   [256]byte
	roundKeys [][]byte
	nb        int
	nk        int
	nr        int
	sBoxInit  bool
}

func NewRijndael(blockSize BlockSize, keySize KeySize, modulus byte) (*Rijndael, error) {
	gfService := gf.NewGF256Service()

	if !gfService.IsIrreducible(modulus) {
		return nil, fmt.Errorf("модуль 0x%02X (0x1%02X) не является неприводимым", modulus, modulus)
	}

	r := &Rijndael{
		blockSize: blockSize,
		keySize:   keySize,
		modulus:   modulus,
		gf:        gfService,
		nb:        int(blockSize) / 4,
		nk:        int(keySize) / 4,
	}

	r.nr = r.calculateRounds()
	return r, nil
}

func (r *Rijndael) BlockSize() int {
	return int(r.blockSize)
}

func (r *Rijndael) calculateRounds() int {
	maxNbNk := r.nb
	if r.nk > maxNbNk {
		maxNbNk = r.nk
	}
	return maxNbNk + 6
}

func (r *Rijndael) SetKey(key []byte) error {
	if len(key) != int(r.keySize) {
		return fmt.Errorf("неверная длина ключа: ожидается %d, получено %d", r.keySize, len(key))
	}

	if !r.sBoxInit {
		r.initializeSBox()
		r.sBoxInit = true
	}

	r.roundKeys = r.keyExpansion(key)
	return nil
}

func (r *Rijndael) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) != int(r.blockSize) {
		return nil, fmt.Errorf("неверный размер блока: ожидается %d, получено %d", r.blockSize, len(plaintext))
	}

	if r.roundKeys == nil {
		return nil, errors.New("ключ не установлен")
	}

	state := r.bytesToState(plaintext)
	r.addRoundKey(state, 0)

	for round := 1; round < r.nr; round++ {
		r.subBytes(state)
		r.shiftRows(state)
		r.mixColumns(state)
		r.addRoundKey(state, round)
	}

	r.subBytes(state)
	r.shiftRows(state)
	r.addRoundKey(state, r.nr)

	return r.stateToBytes(state), nil
}

func (r *Rijndael) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != int(r.blockSize) {
		return nil, fmt.Errorf("неверный размер блока: ожидается %d, получено %d", r.blockSize, len(ciphertext))
	}

	if r.roundKeys == nil {
		return nil, errors.New("ключ не установлен")
	}

	state := r.bytesToState(ciphertext)
	r.addRoundKey(state, r.nr)

	for round := r.nr - 1; round > 0; round-- {
		r.invShiftRows(state)
		r.invSubBytes(state)
		r.addRoundKey(state, round)
		r.invMixColumns(state)
	}

	r.invShiftRows(state)
	r.invSubBytes(state)
	r.addRoundKey(state, 0)

	return r.stateToBytes(state), nil
}

func (r *Rijndael) initializeSBox() {
	// Прямая S-box
	for i := 0; i < 256; i++ {
		val := byte(i)

		// Находим обратный элемент
		if val != 0 {
			inv, err := r.gf.Inverse(val, r.modulus)
			if err == nil {
				val = inv
			}
		}

		// Аффинное преобразование
		val = r.affineTransform(val)
		r.sBox[i] = val
	}

	// Обратная S-box - строим через обратное аффинное преобразование
	for i := 0; i < 256; i++ {
		val := byte(i)

		// Сначала обратное аффинное преобразование
		val = r.invAffineTransform(val)

		// Потом обратный элемент в GF(2^8)
		if val != 0 {
			inv, err := r.gf.Inverse(val, r.modulus)
			if err == nil {
				val = inv
			}
		}

		r.invSBox[i] = val
	}
}

func (r *Rijndael) affineTransform(b byte) byte {
	result := byte(0)

	for i := 0; i < 8; i++ {
		bit := byte(0)
		bit ^= (b >> i) & 1
		bit ^= (b >> ((i + 4) % 8)) & 1
		bit ^= (b >> ((i + 5) % 8)) & 1
		bit ^= (b >> ((i + 6) % 8)) & 1
		bit ^= (b >> ((i + 7) % 8)) & 1

		result |= bit << i
	}

	return result ^ 0x63
}

func (r *Rijndael) invAffineTransform(b byte) byte {
	result := byte(0)

	for i := 0; i < 8; i++ {
		bit := byte(0)
		bit ^= (b >> ((i + 2) % 8)) & 1
		bit ^= (b >> ((i + 5) % 8)) & 1
		bit ^= (b >> ((i + 7) % 8)) & 1

		result |= bit << i
	}

	return result ^ 0x05
}

func (r *Rijndael) subBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < r.nb; j++ {
			state[i][j] = r.sBox[state[i][j]]
		}
	}
}

func (r *Rijndael) invSubBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < r.nb; j++ {
			state[i][j] = r.invSBox[state[i][j]]
		}
	}
}

func (r *Rijndael) shiftRows(state [][]byte) {
	for row := 1; row < 4; row++ {
		shift := r.getShift(row)
		r.rotateLeft(state[row], shift)
	}
}

func (r *Rijndael) invShiftRows(state [][]byte) {
	for row := 1; row < 4; row++ {
		shift := r.getShift(row)
		r.rotateRight(state[row], shift)
	}
}

func (r *Rijndael) getShift(row int) int {
	shifts := map[int]map[int]int{
		4: {1: 1, 2: 2, 3: 3},
		6: {1: 1, 2: 2, 3: 3},
		8: {1: 1, 2: 3, 3: 4},
	}
	return shifts[r.nb][row]
}

func (r *Rijndael) mixColumns(state [][]byte) {
	for col := 0; col < r.nb; col++ {
		r.mixColumn(state, col)
	}
}

func (r *Rijndael) mixColumn(state [][]byte, col int) {
	a := make([]byte, 4)
	copy(a, []byte{state[0][col], state[1][col], state[2][col], state[3][col]})

	state[0][col] = r.gfMul(0x02, a[0]) ^ r.gfMul(0x03, a[1]) ^ a[2] ^ a[3]
	state[1][col] = a[0] ^ r.gfMul(0x02, a[1]) ^ r.gfMul(0x03, a[2]) ^ a[3]
	state[2][col] = a[0] ^ a[1] ^ r.gfMul(0x02, a[2]) ^ r.gfMul(0x03, a[3])
	state[3][col] = r.gfMul(0x03, a[0]) ^ a[1] ^ a[2] ^ r.gfMul(0x02, a[3])
}

func (r *Rijndael) invMixColumns(state [][]byte) {
	for col := 0; col < r.nb; col++ {
		r.invMixColumn(state, col)
	}
}

func (r *Rijndael) invMixColumn(state [][]byte, col int) {
	a := make([]byte, 4)
	copy(a, []byte{state[0][col], state[1][col], state[2][col], state[3][col]})

	state[0][col] = r.gfMul(0x0E, a[0]) ^ r.gfMul(0x0B, a[1]) ^ r.gfMul(0x0D, a[2]) ^ r.gfMul(0x09, a[3])
	state[1][col] = r.gfMul(0x09, a[0]) ^ r.gfMul(0x0E, a[1]) ^ r.gfMul(0x0B, a[2]) ^ r.gfMul(0x0D, a[3])
	state[2][col] = r.gfMul(0x0D, a[0]) ^ r.gfMul(0x09, a[1]) ^ r.gfMul(0x0E, a[2]) ^ r.gfMul(0x0B, a[3])
	state[3][col] = r.gfMul(0x0B, a[0]) ^ r.gfMul(0x0D, a[1]) ^ r.gfMul(0x09, a[2]) ^ r.gfMul(0x0E, a[3])
}

func (r *Rijndael) gfMul(a, b byte) byte {
	result, _ := r.gf.Multiply(a, b, r.modulus)
	return result
}

func (r *Rijndael) addRoundKey(state [][]byte, round int) {
	for col := 0; col < r.nb; col++ {
		for row := 0; row < 4; row++ {
			state[row][col] ^= r.roundKeys[round][row+col*4]
		}
	}
}

func (r *Rijndael) keyExpansion(key []byte) [][]byte {
	totalWords := r.nb * (r.nr + 1)
	w := make([][]byte, totalWords)

	for i := 0; i < r.nk; i++ {
		w[i] = make([]byte, 4)
		copy(w[i], key[i*4:(i+1)*4])
	}

	for i := r.nk; i < totalWords; i++ {
		temp := make([]byte, 4)
		copy(temp, w[i-1])

		if i%r.nk == 0 {
			temp = r.subWord(r.rotWord(temp))
			temp[0] ^= r.rcon(i / r.nk)
		} else if r.nk > 6 && i%r.nk == 4 {
			temp = r.subWord(temp)
		}

		w[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			w[i][j] = w[i-r.nk][j] ^ temp[j]
		}
	}

	roundKeys := make([][]byte, r.nr+1)
	for round := 0; round <= r.nr; round++ {
		roundKeys[round] = make([]byte, r.nb*4)
		for col := 0; col < r.nb; col++ {
			for row := 0; row < 4; row++ {
				roundKeys[round][row+col*4] = w[round*r.nb+col][row]
			}
		}
	}

	return roundKeys
}

func (r *Rijndael) rotWord(word []byte) []byte {
	return []byte{word[1], word[2], word[3], word[0]}
}

func (r *Rijndael) subWord(word []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = r.sBox[word[i]]
	}
	return result
}

func (r *Rijndael) rcon(i int) byte {
	rc := byte(1)
	for j := 1; j < i; j++ {
		rc = r.gfMul(rc, 0x02)
	}
	return rc
}

func (r *Rijndael) bytesToState(data []byte) [][]byte {
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, r.nb)
		for j := 0; j < r.nb; j++ {
			state[i][j] = data[i+j*4]
		}
	}
	return state
}

func (r *Rijndael) stateToBytes(state [][]byte) []byte {
	data := make([]byte, r.nb*4)
	for i := 0; i < 4; i++ {
		for j := 0; j < r.nb; j++ {
			data[i+j*4] = state[i][j]
		}
	}
	return data
}

func (r *Rijndael) rotateLeft(slice []byte, n int) {
	n = n % len(slice)
	temp := make([]byte, len(slice))
	copy(temp, slice[n:])
	copy(temp[len(slice)-n:], slice[:n])
	copy(slice, temp)
}

func (r *Rijndael) rotateRight(slice []byte, n int) {
	n = n % len(slice)
	temp := make([]byte, len(slice))
	copy(temp, slice[len(slice)-n:])
	copy(temp[n:], slice[:len(slice)-n])
	copy(slice, temp)
}
