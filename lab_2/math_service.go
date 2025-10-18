package main

import "math/big"

type MathService struct{}

func NewMathService() *MathService {
	return &MathService{}
}

// LegendreSymbol вычисляет символ Лежандра (a/p)
func (ms *MathService) LegendreSymbol(a, p *big.Int) int {
	if a.Sign() == 0 {
		return 0
	}
	exp := new(big.Int).Sub(p, big.NewInt(1)) // p - 1
	exp.Div(exp, big.NewInt(2))               // /2
	result := new(big.Int).Exp(a, exp, p)     // возводим в степень mod(p)

	if result.Cmp(big.NewInt(0)) == 0 {
		return 0
	}
	if result.Cmp(big.NewInt(1)) == 0 {
		return 1
	}
	return -1
}

// JacobiSymbol вычисляет символ Якоби (a/n)
func (ms *MathService) JacobiSymbol(a, n *big.Int) int {
	if n.Cmp(big.NewInt(1)) == 0 {
		return 1
	}
	if a.Sign() == 0 {
		return 0
	}

	aTemp := new(big.Int).Set(a)
	nTemp := new(big.Int).Set(n)
	result := 1

	for aTemp.Sign() != 0 {
		//выделяем степени 2
		for new(big.Int).Mod(aTemp, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			aTemp.Div(aTemp, big.NewInt(2))
			//правила двойки
			nMod8 := new(big.Int).Mod(nTemp, big.NewInt(8))
			if nMod8.Cmp(big.NewInt(3)) == 0 || nMod8.Cmp(big.NewInt(5)) == 0 {
				result = -result
			}
		}

		aTemp, nTemp = nTemp, aTemp

		//св-во 3
		if new(big.Int).Mod(aTemp, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 &&
			new(big.Int).Mod(nTemp, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
			result = -result
		}

		//4 св-во
		aTemp.Mod(aTemp, nTemp)
	}

	if nTemp.Cmp(big.NewInt(1)) == 0 {
		return result
	}
	return 0
}

// GCD вычисляет НОД алгоритмом Евклида
func (ms *MathService) GCD(a, b *big.Int) *big.Int {
	x := new(big.Int).Set(a)
	y := new(big.Int).Set(b)

	for y.Sign() != 0 {
		x, y = y, new(big.Int).Mod(x, y)
	}
	return x
}

// ExtendedGCD решает уравнение Безу: ax + by = gcd(a,b)
func (ms *MathService) ExtendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Sign() == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}

	oldR, r := new(big.Int).Set(a), new(big.Int).Set(b)
	oldS, s := big.NewInt(1), big.NewInt(0)
	oldT, t := big.NewInt(0), big.NewInt(1)

	// r - остаток
	// s - коэф a
	// t - коэф b

	for r.Sign() != 0 {
		quotient := new(big.Int).Div(oldR, r)
		oldR, r = r, new(big.Int).Sub(oldR, new(big.Int).Mul(quotient, r)) // остаток от деления
		oldS, s = s, new(big.Int).Sub(oldS, new(big.Int).Mul(quotient, s)) // аналогично для коэффов
		oldT, t = t, new(big.Int).Sub(oldT, new(big.Int).Mul(quotient, t))

	}

	return oldR, oldS, oldT
}

// ModPow выполняет возведение в степень по модулю
func (ms *MathService) ModPow(base, exp, m *big.Int) *big.Int {
	result := big.NewInt(1)
	base = new(big.Int).Mod(base, m)
	e := new(big.Int).Set(exp)
	b := new(big.Int).Set(base)

	for e.Sign() > 0 {
		if new(big.Int).Mod(e, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
			result.Mul(result, b)
			result.Mod(result, m)
		}
		e.Div(e, big.NewInt(2))
		b.Mul(b, b)
		b.Mod(b, m)
	}
	return result
}
