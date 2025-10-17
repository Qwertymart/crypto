package main

import (
	"crypto/des"
	"crypto/rand"
	"fmt"
	"os"
	_ "os"
	"strings"
)

func main() {

	// Демонстрация функции перестановки битов
	demonstrateBitPermutation()

	// Демонстрация DES
	demonstrateDES()

	// Демонстрация DEAL
	demonstrateDEAL()

	// Демонстрация режимов набивки
	demonstratePaddingModes()

	encryptDES_ECB()
	testStandardDES()

	demonstrateMyFileEncryption()

	decryptFiles()

}

func demonstrateBitPermutation() {
	fmt.Println("=== ФУНКЦИЯ ПЕРЕСТАНОВКИ БИТ ===")

	data := []byte{0xAB, 0xCD} // 10101011 11001101
	fmt.Printf("Исходные данные: %08b %08b\n", data[0], data[1])

	permTable := []int{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	result := BitPermutation(data, permTable, false, 1)
	fmt.Printf("После перестановки: %08b %08b\n", result[0], result[1])

	reverseTable := []int{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	restored := BitPermutation(result, reverseTable, false, 1)
	fmt.Printf("Восстановленные: %08b %08b\n", restored[0], restored[1])

	fmt.Printf("Корректность: %v\n\n", string(data) == string(restored))
}

func demonstrateDES() {
	fmt.Println("=== ДЕМОНСТРАЦИЯ РАБОТЫ DES ===")

	desCipher := NewDESCipher()
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1} // 64-битный ключ

	fmt.Printf("Ключ: %X\n", key)

	plaintext := []byte("Hello!!!") // ровно 8 байт
	fmt.Printf("Исходный текст: %s\n", plaintext)
	fmt.Printf("Исходный текст (hex): %X\n", plaintext)

	if err := desCipher.SetupKeys(key); err != nil {
		fmt.Printf("Ошибка настройки ключей: %v\n", err)
		return
	}
	fmt.Println("✓ Ключи настроены")

	ciphertext := desCipher.EncryptBlock(plaintext)
	fmt.Printf("Зашифрованный текст (hex): %X\n", ciphertext)

	decrypted := desCipher.DecryptBlock(ciphertext)
	fmt.Printf("Расшифрованный текст: %s\n", decrypted)
	fmt.Printf("Расшифрованный текст (hex): %X\n", decrypted)

	fmt.Printf("Корректность: %v\n\n", string(plaintext) == string(decrypted))

	fmt.Println("=== ТЕСТИРОВАНИЕ РАЗЛИЧНЫХ РЕЖИМОВ ШИФРОВАНИЯ ===")

	modes := []CipherMode{ECB, CBC, CFB, OFB, CTR}
	testData := []byte("This is a longer test message that requires multiple blocks for encryption testing purposes!")
	fmt.Printf("Тестовые данные: %s\n", testData)
	fmt.Printf("Длина данных: %d байт\n", len(testData))

	for _, mode := range modes {
		fmt.Printf("\n--- Режим: %s, Набивка: %s ---\n", mode, PKCS7)

		iv := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
		ctx, err := NewCipherContext(desCipher, key, mode, PKCS7, iv, 8)
		if err != nil {
			fmt.Printf("Ошибка создания контекста: %v\n", err)
			continue
		}

		enc, err := ctx.Encrypt(testData)
		if err != nil {
			fmt.Printf("Ошибка шифрования: %v\n", err)
			continue
		}
		fmt.Printf("Зашифровано: %d байт\n", len(enc))

		dec, err := ctx.Decrypt(enc)
		if err != nil {
			fmt.Printf("Ошибка дешифрования: %v\n", err)
			continue
		}
		fmt.Printf("Дешифровано: %d байт\n", len(dec))
		fmt.Printf("Корректность: %v\n", string(testData) == string(dec))
	}
	fmt.Println()
}

func demonstrateDEAL() {
	fmt.Println("=== ДЕМОНСТРАЦИЯ РАБОТЫ DEAL ===")

	dealCipher := NewDEALCipher()
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10} // 128-битный ключ
	fmt.Printf("Ключ DEAL: %X\n", key)

	plaintext := []byte("This is 16 byte!") // 16 байт
	fmt.Printf("Исходный текст: %s\n", plaintext)
	fmt.Printf("Исходный текст (hex): %X\n", plaintext)

	if err := dealCipher.SetupKeys(key); err != nil {
		fmt.Printf("Ошибка настройки ключей DEAL: %v\n", err)
		return
	}
	fmt.Println("✓ Ключи DEAL настроены")

	ciphertext := dealCipher.EncryptBlock(plaintext)
	fmt.Printf("Зашифрованный текст (hex): %X\n", ciphertext)

	decrypted := dealCipher.DecryptBlock(ciphertext)
	fmt.Printf("Расшифрованный текст: %s\n", decrypted)
	fmt.Printf("Расшифрованный текст (hex): %X\n", decrypted)
	fmt.Printf("Корректность: %v\n\n", string(plaintext) == string(decrypted))

	fmt.Println("=== ТЕСТИРОВАНИЕ DEAL С РАЗЛИЧНЫМИ РЕЖИМАМИ ===")

	modes := []CipherMode{ECB, CBC, CFB, OFB, CTR}
	testData := []byte("This is a comprehensive test of the DEAL cipher implementation with multiple blocks and various encryption modes to verify correctness!")
	fmt.Printf("Тестовые данные: %s\n", testData)
	fmt.Printf("Длина данных: %d байт\n", len(testData))

	for _, mode := range modes {
		fmt.Printf("\n--- DEAL Режим: %s ---\n", mode)

		iv := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21}
		dealCtx := NewDEALCipherContext(key, mode, PKCS7, iv)

		enc, err := dealCtx.Encrypt(testData)
		if err != nil {
			fmt.Printf("Ошибка шифрования DEAL: %v\n", err)
			continue
		}
		fmt.Printf("Зашифровано: %d байт\n", len(enc))

		dec, err := dealCtx.Decrypt(enc)
		if err != nil {
			fmt.Printf("Ошибка дешифрования DEAL: %v\n", err)
			continue
		}
		fmt.Printf("Дешифровано: %d байт\n", len(dec))
		fmt.Printf("Корректность: %v\n", string(testData) == string(dec))
	}
	fmt.Println()
}

func demonstratePaddingModes() {
	fmt.Println("=== ДЕМОНСТРАЦИЯ РЕЖИМОВ НАБИВКИ ===")

	testCases := [][]byte{
		[]byte("Short"),                    // 5 байт
		[]byte("Medium length"),            // 13 байт
		[]byte("This is a longer message"), // 24 байта
		[]byte("Exact 8!"),                 // ровно 8 байт
	}
	paddingModes := []PaddingMode{PKCS7, ANSIX923, ISO10126, Zeros}

	desKey := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	desCipher := NewDESCipher()

	for i, data := range testCases {
		fmt.Printf("\nТест %d: '%s' (%d байт)\n", i+1, data, len(data))

		for _, padding := range paddingModes {
			fmt.Printf("  Режим набивки: %s\n", padding)

			ctx, err := NewCipherContext(desCipher, desKey, ECB, padding, nil, 8)
			if err != nil {
				fmt.Printf("    ✗ Ошибка создания контекста: %v\n", err)
				continue
			}

			enc, err := ctx.Encrypt(data)
			if err != nil {
				fmt.Printf("    ✗ Ошибка шифрования: %v\n", err)
				continue
			}
			fmt.Printf("    Зашифровано: %d байт\n", len(enc))

			dec, err := ctx.Decrypt(enc)
			if err != nil {
				fmt.Printf("    ✗ Ошибка дешифрования: %v\n", err)
				continue
			}
			fmt.Printf("    Дешифровано: %d байт\n", len(dec))
			fmt.Printf("    Результат: %v\n", string(data) == string(dec))
		}
	}

	fmt.Println()
}

func boolToCheckmark(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}

func generateRandomData(size int) []byte {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		for i := range data {
			data[i] = byte(i % 256)
		}
	}
	return data
}

func repeatBytes(src []byte, count int) []byte {
	var result []byte
	for i := 0; i < count; i++ {
		result = append(result, src...)
	}
	return result
}

// === Функция для шифрования данных в режиме ECB ===
func encryptDES_ECB() {
	fmt.Println("=== ШИФРОВАНИЕ DES В РЕЖИМЕ ECB ===\n")

	// Ключ (64 бита = 8 байт)
	key := []byte{
		0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
	}

	// Открытый текст (64 бита = 8 байт)
	plaintext := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	}

	fmt.Printf("Ключ (hex):       %X\n", key)
	fmt.Printf("Открытый текст:   %X\n", plaintext)
	fmt.Printf("Открытый текст (bin): ")
	for _, b := range plaintext {
		fmt.Printf("%08b ", b)
	}
	fmt.Printf("\n\n")

	desCipher := NewDESCipher()

	if err := desCipher.SetupKeys(key); err != nil {
		fmt.Printf("Ошибка настройки ключей: %v\n", err)
		return
	}

	ciphertext := desCipher.EncryptBlock(plaintext)

	fmt.Println("--- РЕЗУЛЬТАТ ШИФРОВАНИЯ ---")
	fmt.Printf("Шифротекст (hex): %X\n", ciphertext)
	fmt.Printf("Шифротекст (bin): ")
	for _, b := range ciphertext {
		fmt.Printf("%08b ", b)
	}
	fmt.Printf("\n\n")

	decrypted := desCipher.DecryptBlock(ciphertext)
	fmt.Println("--- ПРОВЕРКА РАСШИФРОВАНИЯ ---")
	fmt.Printf("Расшифровано:     %X\n", decrypted)
	fmt.Printf("Корректность:     %v\n", string(plaintext) == string(decrypted))
}

func demonstrateMyFileEncryption() {
	fmt.Println("=== ДЕМОНСТРАЦИЯ ШИФРОВАНИЯ ФАЙЛОВ ===")

	pdfFiles := []string{
		"test/photo_2025-09-15_19-04-32.jpg",
		"test/ляля",
		"test/IMG_4496.MP4",
	}

	// DEAL с 128-битным ключом
	dealKey := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	iv := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21,
	}

	dealCipher := NewDEALCipher()
	modes := []CipherMode{CBC, CTR}

	for _, mode := range modes {
		fmt.Printf("\n--- Режим: %s ---\n", mode)

		ctx, _ := NewCipherContext(dealCipher, dealKey, mode, PKCS7, iv, 16)

		for _, filename := range pdfFiles {
			fmt.Printf("\n%s: ", filename)

			info, err := os.Stat(filename)
			if err != nil {
				fmt.Printf("✗ Не найден\n")
				continue
			}

			fmt.Printf("%.2f MB → ", float64(info.Size())/(1024*1024))

			encPath := filename + ".deal_" + mode.String() + "_encrypted"
			decPath := filename + ".deal_" + mode.String() + "_decrypted"

			if err := ctx.EncryptFile(filename, encPath); err != nil {
				fmt.Printf("✗ Ошибка шифрования\n")
				continue
			}

			if err := ctx.DecryptFile(encPath, decPath); err != nil {
				fmt.Printf("✗ Ошибка расшифрования\n")
				continue
			}

			// Проверка целостности
			orig, _ := os.ReadFile(filename)
			dec, _ := os.ReadFile(decPath)

			if string(orig) == string(dec) {
				fmt.Printf("✓ Зашифровано и проверено\n")
			} else {
				fmt.Printf("✗ Ошибка проверки\n")
			}

			os.Remove(decPath) // Удаляем тестовый файл
		}
	}
}

func decryptFiles() {
	fmt.Println("\n=== РАСШИФРОВКА ФАЙЛОВ ===")

	dealKey := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	iv := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21,
	}

	dealCipher := NewDEALCipher()

	baseFiles := []string{
		"test/photo_2025-09-15_19-04-32.jpg",
		"test/ляля",
		"test/IMG_4496.MP4",
	}

	modes := []struct {
		mode CipherMode
		ext  string
	}{
		{CBC, "CBC"},
		{CTR, "CTR"},
	}

	for _, mode := range modes {
		ctx, _ := NewCipherContext(dealCipher, dealKey, mode.mode, PKCS7, iv, 16)

		for _, baseFile := range baseFiles {
			encPath := baseFile + ".deal_" + mode.ext + "_encrypted"

			ext := ""
			baseName := baseFile
			if idx := strings.LastIndex(baseFile, "."); idx != -1 {
				ext = baseFile[idx:]
				baseName = baseFile[:idx]
			}

			decPath := baseName + "_decrypted_" + mode.ext + ext

			if err := ctx.DecryptFile(encPath, decPath); err != nil {
				fmt.Printf("✗ Ошибка: %s\n", encPath)
			} else {
				fmt.Printf("✓ %s → %s\n", encPath, decPath)
			}
		}
	}

	fmt.Println("Расшифровка завершена!")
}

func testStandardDES() {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	block, _ := des.NewCipher(key)
	ciphertext := make([]byte, 8)
	block.Encrypt(ciphertext, plaintext)

	fmt.Printf("Стандартная Go: %X\n", ciphertext)
}
