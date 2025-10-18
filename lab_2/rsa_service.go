package main

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type PrimalityTestType int

const (
	TestFermat PrimalityTestType = iota
	TestSolovayStrassen
	TestMillerRabin
)

type RSAKeyGenerator struct {
	mathService    *MathService
	primalityTest  PrimalityTest
	minProbability float64
	bitLength      int
}

func NewRSAKeyGenerator(testType PrimalityTestType, minProbability float64, bitLength int, ms *MathService) *RSAKeyGenerator {
	var test PrimalityTest

	switch testType {
	case TestFermat:
		test = NewFermatTest(ms)
	case TestSolovayStrassen:
		test = NewSolovayStrassenTest(ms)
	case TestMillerRabin:
		test = NewMillerRabinTest(ms)
	default:
		test = NewMillerRabinTest(ms)
	}

	return &RSAKeyGenerator{
		mathService:    ms,
		primalityTest:  test,
		minProbability: minProbability,
		bitLength:      bitLength,
	}
}

func (kg *RSAKeyGenerator) generatePrime() (*big.Int, error) {
	for {
		candidate, err := rand.Prime(rand.Reader, kg.bitLength) // дает вероятно простое
		if err != nil {
			return nil, err
		}

		if kg.primalityTest.IsProbablyPrime(candidate, kg.minProbability) {
			return candidate, nil
		}
	}
}

func (kg *RSAKeyGenerator) GenerateKeyPair() (*RSAPublicKey, *RSAPrivateKey, error) {
	for {
		p, err := kg.generatePrime()
		if err != nil {
			return nil, nil, err
		}

		q, err := kg.generatePrime()
		if err != nil {
			return nil, nil, err
		}

		// Защита от атаки Ферма: |p - q| должно быть достаточно большим
		diff := new(big.Int).Sub(p, q)
		diff.Abs(diff)
		minDiff := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(kg.bitLength/2-100)), nil)
		// для защиты можно генерить новую пару, если не прошло условие

		if diff.Cmp(minDiff) < 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)

		// φ(n) = (p-1)(q-1)
		phi := new(big.Int).Mul(
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(q, big.NewInt(1)),
		)

		// Выбираем e = 65537 (стандартное значение)
		e := big.NewInt(65537)

		// Вычисляем d
		gcd, d, _ := kg.mathService.ExtendedGCD(e, phi)
		if gcd.Cmp(big.NewInt(1)) != 0 {
			continue
		}

		if d.Sign() < 0 {
			d.Add(d, phi)
		}

		// Защита от атаки Винера: d должно быть > n^0.25
		// Проверяем: d > n^0.25
		nSqrtSqrt := new(big.Int).Sqrt(new(big.Int).Sqrt(n))
		if d.Cmp(nSqrtSqrt) <= 0 {
			continue
		}

		publicKey := &RSAPublicKey{N: n, E: e}
		privateKey := &RSAPrivateKey{
			PublicKey: publicKey,
			D:         d,
			P:         p,
			Q:         q,
		}

		return publicKey, privateKey, nil
	}
}

type RSAPublicKey struct {
	N *big.Int
	E *big.Int
}

type RSAPrivateKey struct {
	PublicKey *RSAPublicKey
	D         *big.Int
	P         *big.Int
	Q         *big.Int
}

type RSAService struct {
	keyGenerator *RSAKeyGenerator
	mathService  *MathService
	publicKey    *RSAPublicKey
	privateKey   *RSAPrivateKey
}

func NewRSAService(testType PrimalityTestType, minProbability float64, bitLength int) *RSAService {
	ms := NewMathService()
	kg := NewRSAKeyGenerator(testType, minProbability, bitLength, ms)

	return &RSAService{
		keyGenerator: kg,
		mathService:  ms,
	}
}

func (rs *RSAService) GenerateKeys() error {
	pubKey, privKey, err := rs.keyGenerator.GenerateKeyPair()
	if err != nil {
		return err
	}

	rs.publicKey = pubKey
	rs.privateKey = privKey
	return nil
}

func (rs *RSAService) GetPublicKey() *RSAPublicKey {
	return rs.publicKey
}

func (rs *RSAService) GetPrivateKey() *RSAPrivateKey {
	return rs.privateKey
}

func (rs *RSAService) Encrypt(message *big.Int) (*big.Int, error) {
	if rs.publicKey == nil {
		return nil, errors.New("keys not generated")
	}

	if message.Cmp(rs.publicKey.N) >= 0 {
		return nil, errors.New("message too large")
	}

	ciphertext := rs.mathService.ModPow(message, rs.publicKey.E, rs.publicKey.N)
	return ciphertext, nil
}

func (rs *RSAService) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if rs.privateKey == nil {
		return nil, errors.New("keys not generated")
	}

	message := rs.mathService.ModPow(ciphertext, rs.privateKey.D, rs.publicKey.N)
	return message, nil
}
