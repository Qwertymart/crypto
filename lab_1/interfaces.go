package main

// KeyExpansion интерфейс для расширения ключа (генерации раундовых ключей)
type KeyExpansion interface {
	// ExpandKey генерирует раундовые ключи из основного ключа
	ExpandKey(key []byte) [][]byte
}

// RoundFunction интерфейс для выполнения шифрующего преобразования
type RoundFunction interface {
	// Apply выполняет шифрующее преобразование блока с раундовым ключом
	Apply(block []byte, roundKey []byte) []byte
}

// SymmetricCipher интерфейс для симметричного шифрования и дешифрования
type SymmetricCipher interface {
	// SetupKeys настраивает раундовые ключи
	SetupKeys(key []byte) error

	// EncryptBlock шифрует блок данных
	EncryptBlock(block []byte) []byte

	// DecryptBlock дешифрует блок данных
	DecryptBlock(block []byte) []byte
}
