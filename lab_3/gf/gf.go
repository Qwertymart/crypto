package gf

import (
	"errors"
	"fmt"
)

// ReducibleModulusError возникает при использовании приводимого модуля
type ReducibleModulusError struct {
	Modulus byte
}

func (e *ReducibleModulusError) Error() string {
	return fmt.Sprintf("модуль 0x%02X (0x1%02X) является приводимым над GF(2^8)", e.Modulus, e.Modulus)
}

// GF256Service предоставляет операции над полем Галуа GF(2^8)
type GF256Service struct{}

// NewGF256Service создает новый экземпляр сервиса
func NewGF256Service() *GF256Service {
	return &GF256Service{}
}

// Add выполняет сложение элементов в GF(2^8)
func (s *GF256Service) Add(a, b byte) byte {
	return a ^ b
}

// Multiply выполняет умножение элементов в GF(2^8) по модулю
// modulus хранится без старшего бита (x^8 подразумевается)
func (s *GF256Service) Multiply(a, b byte, modulus byte) (byte, error) {
	if !s.IsIrreducible(modulus) {
		return 0, &ReducibleModulusError{Modulus: modulus}
	}

	var result byte
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			result ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= modulus // Используем младшие 8 бит модуля
		}
		b >>= 1
	}
	return result, nil
}

// Inverse находит обратный элемент в GF(2^8) по модулю
func (s *GF256Service) Inverse(a byte, modulus byte) (byte, error) {
	if !s.IsIrreducible(modulus) {
		return 0, &ReducibleModulusError{Modulus: modulus}
	}

	if a == 0 {
		return 0, errors.New("обратный элемент для 0 не существует")
	}

	// Расширенный алгоритм Евклида
	// Добавляем неявный бит x^8 для модуля
	fullModulus := uint16(modulus) | 0x100
	r0, r1 := fullModulus, uint16(a)
	t0, t1 := uint16(0), uint16(1)

	for r1 != 0 {
		q := s.polyDiv(r0, r1)
		r0, r1 = r1, s.polyMod(r0, r1)
		t0, t1 = t1, s.polyXor(t0, s.polyMult8(q, t1))
	}

	if r0 != 1 {
		return 0, errors.New("элемент не обратим")
	}

	return byte(t0), nil
}

// IsIrreducible проверяет неприводимость полинома степени 8
// modulus передается без старшего бита (x^8 подразумевается)
func (s *GF256Service) IsIrreducible(modulus byte) bool {
	// Добавляем неявный бит x^8 для проверки
	poly := uint16(modulus) | 0x100

	if poly < 0x100 || poly > 0x1FF {
		return false
	}

	deg := s.degree(poly)
	if deg != 8 {
		return false
	}

	// Проверяем делимость на все возможные неприводимые полиномы степеней 1-4
	for testDeg := 1; testDeg <= 4; testDeg++ {
		testPolys := s.getAllIrreduciblesOfDegree(testDeg)
		for _, div := range testPolys {
			if s.polyMod(poly, div) == 0 {
				return false
			}
		}
	}

	return true
}

// getAllIrreduciblesOfDegree возвращает все неприводимые полиномы заданной степени
func (s *GF256Service) getAllIrreduciblesOfDegree(degree int) []uint16 {
	if degree == 1 {
		return []uint16{0x02, 0x03}
	}
	if degree == 2 {
		return []uint16{0x07}
	}
	if degree == 3 {
		return []uint16{0x0B, 0x0D}
	}
	if degree == 4 {
		// Полный список неприводимых полиномов степени 4
		return []uint16{0x13, 0x19, 0x1F}
	}

	// Для других степеней генерируем
	var result []uint16
	start := uint16(1 << degree)
	end := uint16(1 << (degree + 1))

	for poly := start; poly < end; poly++ {
		if s.isIrreducibleSimple(poly, degree) {
			result = append(result, poly)
		}
	}

	return result
}

// isIrreducibleSimple упрощенная проверка неприводимости
func (s *GF256Service) isIrreducibleSimple(poly uint16, degree int) bool {
	if degree <= 0 {
		return false
	}

	// Проверяем делимость на все неприводимые полиномы меньших степеней
	for d := 1; d <= degree/2; d++ {
		divisors := s.getAllIrreduciblesOfDegree(d)
		for _, div := range divisors {
			if s.polyMod(poly, div) == 0 {
				return false
			}
		}
	}

	return true
}

// GetAllIrreducible возвращает все неприводимые полиномы степени 8
// Возвращает как byte (без старшего бита x^8)
func (s *GF256Service) GetAllIrreducible() []byte {
	var result []byte
	for poly := uint16(0x100); poly <= 0x1FF; poly++ {
		modulus := byte(poly & 0xFF) // Берем только младшие 8 бит
		if s.IsIrreducible(modulus) {
			result = append(result, modulus)
		}
	}
	return result
}

// Factorize разлагает полином на неприводимые множители
// Возвращает полиномы с неявным старшим битом для степени 8
func (s *GF256Service) Factorize(poly byte) []byte {
	// Добавляем неявный бит x^8
	fullPoly := uint16(poly) | 0x100

	if fullPoly == 0x100 || fullPoly == 0x101 {
		return []byte{poly}
	}

	var factors []byte
	maxDegree := s.degree(fullPoly)
	irreducibles := s.getAllIrreduciblesUpTo(maxDegree)

	current := fullPoly
	for _, irr := range irreducibles {
		for current != 0 && s.polyMod(current, irr) == 0 {
			if s.degree(irr) == 8 {
				factors = append(factors, byte(irr&0xFF))
			} else {
				factors = append(factors, byte(irr))
			}
			current = s.polyDiv(current, irr)
		}
	}

	if current > 1 {
		if s.degree(current) == 8 {
			factors = append(factors, byte(current&0xFF))
		} else {
			factors = append(factors, byte(current))
		}
	}

	if len(factors) == 0 {
		factors = append(factors, poly)
	}

	return factors
}

// Вспомогательные функции

func (s *GF256Service) degree(poly uint16) int {
	if poly == 0 {
		return -1
	}
	deg := 0
	for poly > 0 {
		poly >>= 1
		deg++
	}
	return deg - 1
}

func (s *GF256Service) polyXor(a, b uint16) uint16 {
	return a ^ b
}

func (s *GF256Service) polyMult8(a, b uint16) uint16 {
	var result uint16
	for b != 0 {
		if b&1 == 1 {
			result ^= a
		}
		a <<= 1
		b >>= 1
	}
	return result
}

func (s *GF256Service) polyDiv(a, b uint16) uint16 {
	if b == 0 {
		return 0
	}

	degA := s.degree(a)
	degB := s.degree(b)

	if degA < degB {
		return 0
	}

	var quotient uint16
	for degA >= degB {
		shift := degA - degB
		quotient ^= 1 << shift
		a ^= b << shift
		degA = s.degree(a)
	}

	return quotient
}

func (s *GF256Service) polyMod(a, b uint16) uint16 {
	if b == 0 {
		return a
	}

	degA := s.degree(a)
	degB := s.degree(b)

	for degA >= degB && a != 0 {
		shift := degA - degB
		a ^= b << shift
		degA = s.degree(a)
	}

	return a
}

func (s *GF256Service) getAllIrreduciblesUpTo(maxDegree int) []uint16 {
	var result []uint16

	irreducibles := []uint16{
		0x02, 0x03, // степень 1
		0x07,       // степень 2
		0x0B, 0x0D, // степень 3
		0x13, 0x19, 0x1F, // степень 4
	}

	for _, irr := range irreducibles {
		if s.degree(irr) <= maxDegree {
			result = append(result, irr)
		}
	}

	for deg := 5; deg <= maxDegree; deg++ {
		start := uint16(1 << deg)
		end := uint16(1 << (deg + 1))
		for poly := start; poly < end; poly++ {
			if s.isIrreducibleGeneral(poly) {
				result = append(result, poly)
			}
		}
	}

	return result
}

func (s *GF256Service) isIrreducibleGeneral(poly uint16) bool {
	deg := s.degree(poly)
	if deg < 1 {
		return false
	}

	for testDeg := 1; testDeg <= deg/2; testDeg++ {
		start := uint16(1 << testDeg)
		end := uint16(1 << (testDeg + 1))
		for div := start; div < end; div++ {
			if s.isIrreducibleGeneral(div) && s.polyMod(poly, div) == 0 {
				return false
			}
		}
	}

	return true
}
