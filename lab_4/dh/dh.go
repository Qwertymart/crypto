package dh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type DHParameters struct {
	Prime     *big.Int
	Generator *big.Int
	BitSize   int
}

type KeyPair struct {
	PrivateKey *big.Int
	PublicKey  *big.Int
}

type Party struct {
	Name       string
	Params     *DHParameters
	Keys       *KeyPair
	SharedKey  *big.Int
}

func GenerateSafePrime(bits int) (*big.Int, error) {
	if bits < 256 {
		return nil, errors.New("размер ключа должен быть не менее 256 бит")
	}

	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации простого числа: %w", err)
		}

		q := new(big.Int).Sub(p, big.NewInt(1))
		q.Div(q, big.NewInt(2))

		if q.ProbablyPrime(20) {
			return p, nil
		}
	}
}

func FindGenerator(prime *big.Int) (*big.Int, error) {
	g := big.NewInt(2)
	
	pMinus1 := new(big.Int).Sub(prime, big.NewInt(1))
	exp := new(big.Int).Div(pMinus1, big.NewInt(2))
	result := new(big.Int).Exp(g, exp, prime)
	
	if result.Cmp(big.NewInt(1)) != 0 {
		return g, nil
	}

	for i := int64(3); i < 100; i++ {
		g = big.NewInt(i)
		result = new(big.Int).Exp(g, exp, prime)
		if result.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}

	return nil, errors.New("не удалось найти генератор")
}

func NewDHParameters(bits int) (*DHParameters, error) {
	prime, err := GenerateSafePrime(bits)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации простого числа: %w", err)
	}

	generator, err := FindGenerator(prime)
	if err != nil {
		return nil, fmt.Errorf("ошибка поиска генератора: %w", err)
	}

	return &DHParameters{
		Prime:     prime,
		Generator: generator,
		BitSize:   bits,
	}, nil
}

func (params *DHParameters) GeneratePrivateKey() (*big.Int, error) {
	max := new(big.Int).Sub(params.Prime, big.NewInt(2))
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации приватного ключа: %w", err)
	}

	privateKey.Add(privateKey, big.NewInt(2))
	return privateKey, nil
}

func (params *DHParameters) ComputePublicKey(privateKey *big.Int) *big.Int {
	return new(big.Int).Exp(params.Generator, privateKey, params.Prime)
}

func (params *DHParameters) ComputeSharedSecret(myPrivateKey, otherPublicKey *big.Int) (*big.Int, error) {
	if otherPublicKey.Cmp(big.NewInt(1)) <= 0 || 
	   otherPublicKey.Cmp(new(big.Int).Sub(params.Prime, big.NewInt(1))) >= 0 {
		return nil, errors.New("некорректный публичный ключ")
	}

	return new(big.Int).Exp(otherPublicKey, myPrivateKey, params.Prime), nil
}

func NewParty(name string, params *DHParameters) (*Party, error) {
	privateKey, err := params.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("ошибка создания участника: %w", err)
	}

	publicKey := params.ComputePublicKey(privateKey)

	return &Party{
		Name:   name,
		Params: params,
		Keys: &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
	}, nil
}

func (party *Party) ExchangeKeys(otherPublicKey *big.Int) error {
	sharedSecret, err := party.Params.ComputeSharedSecret(
		party.Keys.PrivateKey,
		otherPublicKey,
	)
	if err != nil {
		return fmt.Errorf("ошибка вычисления общего секрета: %w", err)
	}

	party.SharedKey = sharedSecret
	return nil
}

func (party *Party) GetSharedKeyBytes(length int) []byte {
	if party.SharedKey == nil {
		return nil
	}

	keyBytes := party.SharedKey.Bytes()
	result := make([]byte, length)
	
	if len(keyBytes) < length {
		copy(result[length-len(keyBytes):], keyBytes)
	} else {
		copy(result, keyBytes[:length])
	}

	return result
}
