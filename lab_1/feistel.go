package main

import "fmt"

type FeistelNetwork struct {
	keyExpansion  KeyExpansion
	roundFunction RoundFunction
	numRounds     int
	roundKeys     [][]byte
}

func NewFeistelNetwork(keyExpansion KeyExpansion, roundFunction RoundFunction, numRounds int) *FeistelNetwork {
	return &FeistelNetwork{
		keyExpansion:  keyExpansion,
		roundFunction: roundFunction,
		numRounds:     numRounds,
	}
}

func (fn *FeistelNetwork) SetupKeys(key []byte) error {
	fn.roundKeys = fn.keyExpansion.ExpandKey(key)
	if len(fn.roundKeys) != fn.numRounds {
		return fmt.Errorf("ожидается %d раундовых ключей, получено %d", fn.numRounds, len(fn.roundKeys))
	}
	return nil
}

func (fn *FeistelNetwork) EncryptBlock(block []byte) []byte {
	if len(block) != 8 {
		panic(fmt.Sprintf("блок должен быть 64 бита (8 байт), получено %d", len(block)))
	}

	L := make([]byte, 4)
	R := make([]byte, 4)
	copy(L, block[:4])
	copy(R, block[4:])

	for i := 0; i < fn.numRounds; i++ {
		tempR := fn.xorBytes(L, fn.roundFunction.Apply(R, fn.roundKeys[i]))
		L = R
		R = tempR
	}

	result := make([]byte, 8)
	copy(result[:4], R)
	copy(result[4:], L)
	return result
}

func (fn *FeistelNetwork) DecryptBlock(block []byte) []byte {
	if len(block) != 8 {
		panic(fmt.Sprintf("блок должен быть 64 бита (8 байт), получено %d", len(block)))
	}

	L := make([]byte, 4)
	R := make([]byte, 4)
	copy(L, block[:4])
	copy(R, block[4:])

	for i := fn.numRounds - 1; i >= 0; i-- {
		tempR := fn.xorBytes(L, fn.roundFunction.Apply(R, fn.roundKeys[i]))
		L = R
		R = tempR
	}

	result := make([]byte, 8)
	copy(result[:4], R)
	copy(result[4:], L)
	return result
}

func (fn *FeistelNetwork) xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a) && i < len(b); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
