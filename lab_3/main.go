package main

import (
	"lab_3/cipher"
	"lab_3/gf"
	"lab_3/padding"
	"lab_3/rijndael"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	demonstrateGF256()
	demonstrateRijndael()
	demonstrateFileEncryption()
}

func demonstrateGF256() {

	gfService := gf.NewGF256Service()

	a, b := byte(0x57), byte(0x83)
	sum := gfService.Add(a, b)
	fmt.Printf("Сложение: 0x%02X + 0x%02X = 0x%02X\n", a, b, sum)

	modulus := byte(0x1B) // 0x11B без старшего бита
	product, err := gfService.Multiply(a, b, modulus)
	if err != nil {
		log.Printf("Ошибка умножения: %v\n", err)
	} else {
		fmt.Printf("Умножение: 0x%02X * 0x%02X (mod 0x1%02X) = 0x%02X\n", a, b, modulus, product)
	}

	inv, err := gfService.Inverse(a, modulus)
	if err != nil {
		log.Printf("Ошибка нахождения обратного: %v\n", err)
	} else {
		fmt.Printf("Обратный элемент: inv(0x%02X) (mod 0x1%02X) = 0x%02X\n", a, modulus, inv)
	}

	isIrr := gfService.IsIrreducible(modulus)
	fmt.Printf("Проверка неприводимости: 0x1%02X - %v\n", modulus, isIrr)

	irreducibles := gfService.GetAllIrreducible()
	fmt.Printf("Всего неприводимых полиномов степени 8: %d\n", len(irreducibles))
	fmt.Print("Первые 10: ")
	for i := 0; i < 10 && i < len(irreducibles); i++ {
		fmt.Printf("0x1%02X ", irreducibles[i])
	}
}

func demonstrateRijndael() {
	fmt.Println()
	fmt.Println()
	fmt.Println("Шифрование Rijndael")
	
	plaintext := []byte("Hello, Rijndael! This is a test message for encryption.")
	key := []byte("ThisIsA128BitKey")
	
	configs := []struct {
		blockSize rijndael.BlockSize
		keySize   rijndael.KeySize
		modulus   byte
		mode      cipher.Mode
		padding   padding.Padding
	}{
		{rijndael.Block128, rijndael.Key128, 0x1B, cipher.ECB, &padding.PKCS7Padding{}},
		{rijndael.Block128, rijndael.Key128, 0x1B, cipher.CBC, &padding.PKCS7Padding{}},
		{rijndael.Block128, rijndael.Key128, 0x1B, cipher.CFB, &padding.PKCS7Padding{}},
		{rijndael.Block128, rijndael.Key128, 0x1B, cipher.OFB, &padding.PKCS7Padding{}},
		{rijndael.Block128, rijndael.Key128, 0x1B, cipher.CTR, &padding.PKCS7Padding{}},
	}

	modeNames := []string{"ECB", "CBC", "CFB", "OFB", "CTR"}

	for i, config := range configs {
		fmt.Printf("\nКонфигурация %d: Режим %s\n", i+1, modeNames[i])

		r, err := rijndael.NewRijndael(config.blockSize, config.keySize, config.modulus)
		if err != nil {
			log.Printf("Ошибка создания Rijndael: %v\n", err)
			continue
		}

		err = r.SetKey(key)
		if err != nil {
			log.Printf("Ошибка установки ключа: %v\n", err)
			continue
		}

		c := cipher.NewCipher(r, config.mode, config.padding)

		iv, err := cipher.GenerateIV(int(config.blockSize))
		if err != nil {
			log.Printf("Ошибка генерации IV: %v\n", err)
			continue
		}

		ciphertext, err := c.Encrypt(plaintext, iv)
		if err != nil {
			log.Printf("Ошибка шифрования: %v\n", err)
			continue
		}

		decrypted, err := c.Decrypt(ciphertext, iv)
		if err != nil {
			log.Printf("Ошибка дешифрования: %v\n", err)
			continue
		}

		if string(decrypted) == string(plaintext) {
			fmt.Println("  Шифрование и дешифрование успешны")
			fmt.Printf("  Исходный текст: %s...\n", plaintext[:30])
			fmt.Printf("  Зашифрованный размер: %d байт\n", len(ciphertext))
		} else {
			fmt.Println("  Ошибка: расшифрованный текст не совпадает с исходным")
			fmt.Printf("  Ожидалось: %s\n", plaintext)
			fmt.Printf("  Получено: %s\n", decrypted)
		}
	}

	fmt.Println()
}

func demonstrateFileEncryption() {
	fmt.Println("Демонстрация работы с файлами")

	data, err := ioutil.ReadFile("test_input.txt")
	if err != nil {
		log.Printf("Ошибка чтения файла: %v\n", err)
		return
	}

	r, err := rijndael.NewRijndael(rijndael.Block128, rijndael.Key128, 0x1B)
	if err != nil {
		log.Printf("Ошибка создания Rijndael: %v\n", err)
		return
	}

	key := []byte("FileEncryptKey16")
	err = r.SetKey(key)
	if err != nil {
		log.Printf("Ошибка установки ключа: %v\n", err)
		return
	}

	c := cipher.NewCipher(r, cipher.CBC, &padding.PKCS7Padding{})
	iv, _ := cipher.GenerateIV(16)

	encrypted, err := c.Encrypt(data, iv)
	if err != nil {
		log.Printf("Ошибка шифрования файла: %v\n", err)
		return
	}

	err = ioutil.WriteFile("test_encrypted.bin", encrypted, 0644)
	if err != nil {
		log.Printf("Ошибка сохранения зашифрованного файла: %v\n", err)
		return
	}

	decrypted, err := c.Decrypt(encrypted, iv)
	if err != nil {
		log.Printf("Ошибка дешифрования файла: %v\n", err)
		return
	}

	err = ioutil.WriteFile("test_decrypted.txt", decrypted, 0644)
	if err != nil {
		log.Printf("Ошибка сохранения расшифрованного файла: %v\n", err)
		return
	}

	fmt.Println("  Файл успешно зашифрован и расшифрован")
	fmt.Printf("  Исходный размер: %d байт\n", len(data))
	fmt.Printf("  Зашифрованный размер: %d байт\n", len(encrypted))
	fmt.Printf("  Файлы: test_input.txt, test_encrypted.bin, test_decrypted.txt\n")
}
