package main

// BitPermutation выполняет перестановку битов в соответствии с P-блоком
func BitPermutation(data []byte, permutationTable []int, bitIndexingFromLSB bool, startBitIndex int) []byte {
	var bits []int
	for _, b := range data {
		for i := 0; i < 8; i++ {
			if bitIndexingFromLSB {
				bits = append(bits, int((b>>i)&1)) // байты записываем побитно в нужном порядке
			} else {
				bits = append(bits, int((b>>(7-i))&1))
			}
		}
	}

	permutedBits := make([]int, len(permutationTable))
	for i, pos := range permutationTable {
		sourceIndex := pos - startBitIndex
		if sourceIndex >= 0 && sourceIndex < len(bits) {
			permutedBits[i] = bits[sourceIndex]
		}
	}

	// Конвертируем обратно в байты
	var result []byte
	for i := 0; i < len(permutedBits); i += 8 {
		end := i + 8
		if end > len(permutedBits) {
			end = len(permutedBits)
		}
		byteBits := permutedBits[i:end]

		// Дополняем нулями если необходимо
		for len(byteBits) < 8 {
			byteBits = append(byteBits, 0)
		}

		var byteValue byte
		for j, bit := range byteBits {
			if bitIndexingFromLSB {
				byteValue |= byte(bit << j)
			} else {
				byteValue |= byte(bit << (7 - j))
			}
		}
		result = append(result, byteValue)
	}
	return result
}
