package main

import (
	"crypto/rand"
	"math"
	"math/big"
)

type PrimalityTest interface {
	IsProbablyPrime(n *big.Int, minProbability float64) bool
}

type BasePrimalityTest struct {
	mathService *MathService
	testName    string
}

func NewBasePrimalityTest(ms *MathService, name string) *BasePrimalityTest {
	return &BasePrimalityTest{mathService: ms, testName: name}
}

func (bpt *BasePrimalityTest) calculateRounds(minProbability float64) int {
	if minProbability >= 1.0 || minProbability < 0.5 {
		minProbability = 0.99999
	}
	errorProb := 1.0 - minProbability
	rounds := int(math.Ceil(math.Log(errorProb) / math.Log(0.5)))
	if rounds < 1 {
		rounds = 1
	}
	return rounds
}

func (bpt *BasePrimalityTest) performTest(n *big.Int, minProbability float64,
	iterationFunc func(*big.Int, *big.Int) bool) bool {

	if n.Cmp(big.NewInt(2)) == 0 {
		return true
	}
	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	rounds := bpt.calculateRounds(minProbability)

	for i := 0; i < rounds; i++ {
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		if err != nil {
			return false
		}
		a.Add(a, big.NewInt(2))

		if !iterationFunc(n, a) {
			return false
		}
	}
	return true
}

// FermatTest тест простоты Ферма
type FermatTest struct {
	*BasePrimalityTest
}

func NewFermatTest(ms *MathService) *FermatTest {
	return &FermatTest{BasePrimalityTest: NewBasePrimalityTest(ms, "Fermat")}
}

func (ft *FermatTest) IsProbablyPrime(n *big.Int, minProbability float64) bool {
	return ft.performTest(n, minProbability, func(n, a *big.Int) bool {
		exp := new(big.Int).Sub(n, big.NewInt(1))
		result := ft.mathService.ModPow(a, exp, n)
		return result.Cmp(big.NewInt(1)) == 0
	})
}

// SolovayStrassenTest тест простоты Соловея-Штрассена
type SolovayStrassenTest struct {
	*BasePrimalityTest
}

func NewSolovayStrassenTest(ms *MathService) *SolovayStrassenTest {
	return &SolovayStrassenTest{BasePrimalityTest: NewBasePrimalityTest(ms, "Solovay-Strassen")}
}

func (sst *SolovayStrassenTest) IsProbablyPrime(n *big.Int, minProbability float64) bool {
	return sst.performTest(n, minProbability, func(n, a *big.Int) bool {
		jacobi := sst.mathService.JacobiSymbol(a, n)
		exp := new(big.Int).Sub(n, big.NewInt(1))
		exp.Div(exp, big.NewInt(2))
		result := sst.mathService.ModPow(a, exp, n)

		jacobiMod := big.NewInt(int64(jacobi))
		if jacobiMod.Sign() < 0 {
			jacobiMod.Add(jacobiMod, n)
		}
		return result.Cmp(jacobiMod) == 0
	})
}

// MillerRabinTest тест простоты Миллера-Рабина
type MillerRabinTest struct {
	*BasePrimalityTest
}

func NewMillerRabinTest(ms *MathService) *MillerRabinTest {
	return &MillerRabinTest{BasePrimalityTest: NewBasePrimalityTest(ms, "Miller-Rabin")}
}

func (mrt *MillerRabinTest) IsProbablyPrime(n *big.Int, minProbability float64) bool {
	return mrt.performTest(n, minProbability, func(n, a *big.Int) bool {
		nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
		s := 0
		d := new(big.Int).Set(nMinus1)

		for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			s++
			d.Div(d, big.NewInt(2))
		}

		x := mrt.mathService.ModPow(a, d, n)

		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(nMinus1) == 0 {
			return true
		}

		for i := 0; i < s-1; i++ {
			x = mrt.mathService.ModPow(x, big.NewInt(2), n)
			if x.Cmp(nMinus1) == 0 {
				return true
			}
		}
		return false
	})
}
