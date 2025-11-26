package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"lab_4/crypto"
	"lab_4/dh"
)

func main() {

	params, err := dh.NewDHParameters(512)
	if err != nil {
		log.Fatalf("Ошибка генерации параметров: %v", err)
	}

	fmt.Printf("Простое число p: %s\n", formatBigInt(params.Prime, 60))
	fmt.Printf("Генератор g: %s\n\n", params.Generator.String())

	alice, err := dh.NewParty("Алиса", params)
	if err != nil {
		log.Fatalf("Ошибка создания Алисы: %v", err)
	}

	bob, err := dh.NewParty("Боб", params)
	if err != nil {
		log.Fatalf("Ошибка создания Боба: %v", err)
	}

	fmt.Printf("Алиса - приватный ключ: %s\n", formatBigInt(alice.Keys.PrivateKey, 60))
	fmt.Printf("Алиса - публичный ключ: %s\n", formatBigInt(alice.Keys.PublicKey, 60))
	fmt.Printf("Боб - приватный ключ: %s\n", formatBigInt(bob.Keys.PrivateKey, 60))
	fmt.Printf("Боб - публичный ключ: %s\n\n", formatBigInt(bob.Keys.PublicKey, 60))

	if err := alice.ExchangeKeys(bob.Keys.PublicKey); err != nil {
		log.Fatalf("Ошибка обмена ключами (Алиса): %v", err)
	}

	if err := bob.ExchangeKeys(alice.Keys.PublicKey); err != nil {
		log.Fatalf("Ошибка обмена ключами (Боб): %v", err)
	}

	if alice.SharedKey.Cmp(bob.SharedKey) == 0 {
		fmt.Println("Общий секрет успешно установлен")
		fmt.Printf("Общий секрет: %s\n\n", formatBigInt(alice.SharedKey, 60))
	} else {
		log.Fatal("Ошибка: общие секреты не совпадают")
	}

	sharedSecretBytes := alice.GetSharedKeyBytes(32)
	aesKey := crypto.DeriveAESKey(sharedSecretBytes, 32)

	fmt.Printf("AES-256 ключ: %s\n\n", hex.EncodeToString(aesKey))

	originalMessage := "Секретное сообщение для демонстрации симметричного шифрования"
	fmt.Printf("Исходное сообщение: %s\n", originalMessage)

	ciphertext, err := crypto.EncryptAES([]byte(originalMessage), aesKey)
	if err != nil {
		log.Fatalf("Ошибка шифрования: %v", err)
	}

	fmt.Printf("Зашифрованное: %s\n", hex.EncodeToString(ciphertext))

	decrypted, err := crypto.DecryptAES(ciphertext, aesKey)
	if err != nil {
		log.Fatalf("Ошибка расшифровки: %v", err)
	}

	fmt.Printf("Расшифрованное: %s\n", string(decrypted))

	if string(decrypted) == originalMessage {
		fmt.Println("\nРасшифровка успешна")
	}
}

func formatBigInt(num *big.Int, maxLen int) string {
	str := num.String()
	if len(str) > maxLen {
		return str[:maxLen/2] + "..." + str[len(str)-maxLen/2:]
	}
	return str
}
