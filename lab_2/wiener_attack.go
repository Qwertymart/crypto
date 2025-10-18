package main

import "math/big"

type ContinuedFraction struct {
	Numerator   *big.Int // k
	Denominator *big.Int // d
}

type WienerAttackResult struct {
	D                  *big.Int
	Phi                *big.Int
	ContinuedFractions []ContinuedFraction // подходящие дроби
	Success            bool
}

type WienerAttackService struct {
	mathService *MathService
}

func NewWienerAttackService() *WienerAttackService {
	return &WienerAttackService{
		mathService: NewMathService(),
	}
}

// цепная дробь
func (was *WienerAttackService) continuedFractionExpansion(e, n *big.Int) []ContinuedFraction {
	a := new(big.Int).Set(e)
	b := new(big.Int).Set(n)

	var convergents []ContinuedFraction

	h0, h1 := big.NewInt(1), big.NewInt(0)
	k0, k1 := big.NewInt(0), big.NewInt(1)

	for b.Sign() != 0 {
		q := new(big.Int).Div(a, b)

		h := new(big.Int).Add(new(big.Int).Mul(q, h0), h1)
		k := new(big.Int).Add(new(big.Int).Mul(q, k0), k1)

		convergents = append(convergents, ContinuedFraction{
			Numerator:   new(big.Int).Set(h),
			Denominator: new(big.Int).Set(k),
		})

		h1, h0 = h0, h
		k1, k0 = k0, k

		a, b = b, new(big.Int).Mod(a, b)
	}

	return convergents
}

func (was *WienerAttackService) Attack(publicKey *RSAPublicKey) *WienerAttackResult {
	result := &WienerAttackResult{
		Success: false,
	}

	convergents := was.continuedFractionExpansion(publicKey.E, publicKey.N)
	result.ContinuedFractions = convergents

	for _, cf := range convergents {
		k := cf.Numerator
		d := cf.Denominator

		if k.Sign() == 0 {
			continue
		}

		numerator := new(big.Int).Mul(publicKey.E, d)
		numerator.Sub(numerator, big.NewInt(1))

		if new(big.Int).Mod(numerator, k).Sign() != 0 {
			continue
		}

		phi := new(big.Int).Div(numerator, k)

		b := new(big.Int).Sub(publicKey.N, phi) // p+q
		b.Add(b, big.NewInt(1))

		discriminant := new(big.Int).Mul(b, b)
		discriminant.Sub(discriminant, new(big.Int).Mul(big.NewInt(4), publicKey.N))

		if discriminant.Sign() < 0 {
			continue
		}

		sqrtD := new(big.Int).Sqrt(discriminant)

		if new(big.Int).Mul(sqrtD, sqrtD).Cmp(discriminant) != 0 { //корень не целый
			continue
		}

		p := new(big.Int).Add(b, sqrtD)
		p.Div(p, big.NewInt(2))

		q := new(big.Int).Sub(b, sqrtD)
		q.Div(q, big.NewInt(2))

		if new(big.Int).Mul(p, q).Cmp(publicKey.N) == 0 {
			result.D = d
			result.Phi = phi
			result.Success = true
			return result
		}
	}

	return result
}
