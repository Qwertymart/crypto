package main

import (
	"fmt"
	"math/big"
)

func main() {

	// 1: Демонстрация MathService
	fmt.Println("MathService")
	ms := NewMathService()

	a := big.NewInt(3)
	p := big.NewInt(7)
	fmt.Printf("Символ Лежандра (3/7) = %d\n", ms.LegendreSymbol(a, p))

	a = big.NewInt(5)
	n := big.NewInt(21)
	fmt.Printf("Символ Якоби (5/21) = %d\n", ms.JacobiSymbol(a, n))

	a = big.NewInt(48)
	b := big.NewInt(18)
	fmt.Printf("НОД(48, 18) = %s\n", ms.GCD(a, b))

	gcd, x, y := ms.ExtendedGCD(a, b)
	fmt.Printf("Расширенный Евклид: gcd=%s, x=%s, y=%s\n", gcd, x, y)

	base := big.NewInt(3)
	exp := big.NewInt(5)
	mod := big.NewInt(13)
	fmt.Printf("ModPow: 3^5 mod 13 = %s\n\n", ms.ModPow(base, exp, mod))

	// 2: Демонстрация тестов простоты
	fmt.Println("Тесты простоты")
	testNum := big.NewInt(97)

	fermat := NewFermatTest(ms)
	fmt.Printf("Тест Ферма для %s: %v\n", testNum, fermat.IsProbablyPrime(testNum, 0.999))

	solovay := NewSolovayStrassenTest(ms)
	fmt.Printf("Тест Соловея-Штрассена для %s: %v\n", testNum, solovay.IsProbablyPrime(testNum, 0.999))

	miller := NewMillerRabinTest(ms)
	fmt.Printf("Тест Миллера-Рабина для %s: %v\n\n", testNum, miller.IsProbablyPrime(testNum, 0.999))

	// 3: Демонстрация RSA
	fmt.Println("RSA шифрование")
	rsaService := NewRSAService(TestMillerRabin, 0.9999, 512)

	fmt.Println("Генерация ключей...")
	err := rsaService.GenerateKeys()
	if err != nil {
		fmt.Printf("Ошибка генерации ключей: %v\n", err)
		return
	}

	pubKey := rsaService.GetPublicKey()
	fmt.Printf("Открытый ключ:\n  N = %s\n  E = %s\n", pubKey.N, pubKey.E)

	message := big.NewInt(42)
	fmt.Printf("\nИсходное сообщение: %s\n", message)

	ciphertext, err := rsaService.Encrypt(message)
	if err != nil {
		fmt.Printf("Ошибка шифрования: %v\n", err)
		return
	}
	fmt.Printf("Зашифрованное: %s\n", ciphertext)

	decrypted, err := rsaService.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("Ошибка дешифрования: %v\n", err)
		return
	}
	fmt.Printf("Расшифрованное: %s\n\n", decrypted)

	/// 4: Демонстрация атаки Винера
	fmt.Println("Атака Винера")
	fmt.Println("Создание уязвимого ключа для демонстрации атаки...")

	// Используем малые простые числа для демонстрации
	vulnerableP := big.NewInt(857)
	vulnerableQ := big.NewInt(1009)
	vulnerableN := new(big.Int).Mul(vulnerableP, vulnerableQ)
	vulnerablePhi := new(big.Int).Mul(
		new(big.Int).Sub(vulnerableP, big.NewInt(1)),
		new(big.Int).Sub(vulnerableQ, big.NewInt(1)),
	)

	// Выбираем МАЛОЕ d для уязвимости к атаке Винера
	vulnerableD := big.NewInt(5) // Маленькое d!

	// Вычисляем e = d^(-1) mod φ(n)
	gcd, vulnerableE, _ := ms.ExtendedGCD(vulnerableD, vulnerablePhi)
	if vulnerableE.Sign() < 0 {
		vulnerableE.Add(vulnerableE, vulnerablePhi)
	}

	// Проверяем, что получили корректный ключ
	if gcd.Cmp(big.NewInt(1)) != 0 {
		fmt.Println("Ошибка: не удалось создать уязвимый ключ")
		return
	}

	vulnerableKey := &RSAPublicKey{N: vulnerableN, E: vulnerableE}
	fmt.Printf("Уязвимый открытый ключ:\n")
	fmt.Printf("  N = %s\n", vulnerableKey.N)
	fmt.Printf("  E = %s\n", vulnerableKey.E)
	fmt.Printf("  d = %s (секретный, для проверки)\n", vulnerableD)

	// Проверяем условие уязвимости
	nFourth := new(big.Float).SetInt(vulnerableN)
	nFourth.Sqrt(nFourth)
	nFourth.Sqrt(nFourth) // N^(1/4)
	limit := new(big.Float).Quo(nFourth, big.NewFloat(3.0))
	dFloat := new(big.Float).SetInt(vulnerableD)

	fmt.Printf("\nУсловие атаки Винера: d < N^(1/4) / 3\n")
	fmt.Printf("  d = %s\n", vulnerableD)
	fmt.Printf("  N^(1/4) / 3 ≈ %.2f\n", limit)

	if dFloat.Cmp(limit) < 0 {
		fmt.Println("Условие выполнено — ключ УЯЗВИМ")
	} else {
		fmt.Println("Условие не выполнено")
	}

	// Запускаем атаку
	wienerService := NewWienerAttackService()
	attackResult := wienerService.Attack(vulnerableKey)

	fmt.Println()
	if attackResult.Success {
		fmt.Printf("  Атака успешна!\n")
		fmt.Printf("  Найденная экспонента d = %s\n", attackResult.D)
		fmt.Printf("  Правильная экспонента d = %s\n", vulnerableD)
		fmt.Printf("  Совпадают: %v\n", attackResult.D.Cmp(vulnerableD) == 0)
		if attackResult.Phi != nil {
			fmt.Printf("  Функция Эйлера φ(n) = %s\n", attackResult.Phi)
		}
	} else {
		fmt.Println("  Атака не удалась")
		fmt.Println("  (возможно, нужно улучшить алгоритм атаки)")
	}

}
