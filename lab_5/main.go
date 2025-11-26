package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// RC4 структура для работы с алгоритмом RC4
type RC4 struct {
	s    [256]byte
	i, j byte
}

// NewRC4 создает новый экземпляр RC4 с заданным ключом
func NewRC4(key []byte) *RC4 {
	rc4 := &RC4{}
	rc4.KSA(key)
	return rc4
}

// KSA - Key Scheduling Algorithm
func (r *RC4) KSA(key []byte) {
	keyLen := len(key)
	
	// Инициализация массива S значениями от 0 до 255
	for i := 0; i < 256; i++ {
		r.s[i] = byte(i)
	}
	
	// Перемешивание массива S на основе ключа
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(r.s[i]) + int(key[i%keyLen])) % 256
		r.s[i], r.s[j] = r.s[j], r.s[i]
	}
	
	r.i = 0
	r.j = 0
}

// PRGA - Pseudo-Random Generation Algorithm
// Генерирует один байт ключевого потока
func (r *RC4) PRGAByte() byte {
	r.i = byte((int(r.i) + 1) % 256)
	r.j = byte((int(r.j) + int(r.s[r.i])) % 256)
	
	r.s[r.i], r.s[r.j] = r.s[r.j], r.s[r.i]
	
	t := byte((int(r.s[r.i]) + int(r.s[r.j])) % 256)
	return r.s[t]
}
// GenerateKeystream генерирует ключевой поток заданной длины
func (r *RC4) GenerateKeystream(length int) []byte {
	keystream := make([]byte, length)
	for i := 0; i < length; i++ {
		keystream[i] = r.PRGAByte()
	}
	return keystream
}

// XORChunk выполняет XOR операцию над чанком данных
func XORChunk(data []byte, keystream []byte, offset int) {
	for i := 0; i < len(data); i++ {
		data[i] ^= keystream[offset+i]
	}
}

// ProcessFileParallel обрабатывает файл конкурентно несколькими горутинами
func ProcessFileParallel(inputPath, outputPath string, key []byte, numWorkers int) error {
	// Читаем весь файл
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	fileSize := len(data)
	
	// Генерируем ключевой поток нужной длины
	rc4 := NewRC4(key)
	keystream := rc4.GenerateKeystream(fileSize)
	
	// Вычисляем размер чанка для каждого воркера
	chunkSize := fileSize / numWorkers
	if chunkSize == 0 {
		chunkSize = fileSize
		numWorkers = 1
	}
	
	var wg sync.WaitGroup
	
	// Запускаем горутины для обработки каждого чанка
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		
		start := w * chunkSize
		end := start + chunkSize
		
		// Последний воркер обрабатывает остаток
		if w == numWorkers-1 {
			end = fileSize
		}
		
		go func(startIdx, endIdx int) {
			defer wg.Done()
			XORChunk(data[startIdx:endIdx], keystream, startIdx)
		}(start, end)
	}
	
	wg.Wait()
	
	// Записываем результат
	err = os.WriteFile(outputPath, data, 0644)
	if err != nil {
		return fmt.Errorf("ошибка записи файла: %w", err)
	}
	
	return nil
}

// ProcessFileStream обрабатывает файл потоково с конкурентной обработкой чанков
func ProcessFileStream(inputPath, outputPath string, key []byte, numWorkers int) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer inputFile.Close()
	
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("ошибка создания файла: %w", err)
	}
	defer outputFile.Close()
	
	// Получаем размер файла
	stat, err := inputFile.Stat()
	if err != nil {
		return err
	}
	fileSize := stat.Size()
	
	// Генерируем ключевой поток
	rc4 := NewRC4(key)
	keystream := rc4.GenerateKeystream(int(fileSize))
	
	// Размер чанка для обработки
	chunkSize := 64 * 1024 // 64KB
	if int(fileSize) < chunkSize*numWorkers {
		chunkSize = int(fileSize) / numWorkers
		if chunkSize == 0 {
			chunkSize = int(fileSize)
		}
	}
	
	type chunk struct {
		data   []byte
		offset int
	}
	
	inputChan := make(chan chunk, numWorkers)
	outputChan := make(chan chunk, numWorkers)
	
	var wg sync.WaitGroup
	
	// Запускаем воркеры
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ch := range inputChan {
				XORChunk(ch.data, keystream, ch.offset)
				outputChan <- ch
			}
		}()
	}
	
	// Горутина для записи результатов
	done := make(chan bool)
	nextOffset := 0
	pendingChunks := make(map[int][]byte)
	
	go func() {
		for ch := range outputChan {
			pendingChunks[ch.offset] = ch.data
			
			// Записываем чанки по порядку
			for {
				if data, ok := pendingChunks[nextOffset]; ok {
					outputFile.Write(data)
					delete(pendingChunks, nextOffset)
					nextOffset += len(data)
				} else {
					break
				}
			}
		}
		done <- true
	}()
	
	// Читаем и отправляем чанки на обработку
	offset := 0
	for {
		buffer := make([]byte, chunkSize)
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		
		inputChan <- chunk{
			data:   buffer[:n],
			offset: offset,
		}
		offset += n
	}
	
	close(inputChan)
	wg.Wait()
	close(outputChan)
	<-done
	
	return nil
}

// шифрование одного файла
func demo1BasicEncryption() {

	testData := []byte("сиси писи")
	
	os.WriteFile("test_input.txt", testData, 0644)
	defer os.Remove("test_input.txt")
	defer os.Remove("test_encrypted.txt")
	defer os.Remove("test_decrypted.txt")
	
	fmt.Printf("\nИсходный файл создан, размер: %d байт\n", len(testData))
	fmt.Println("Содержимое:", string(testData))
	
	key := []byte("SecretKey123")
	fmt.Printf("\nКлюч шифрования: %s (длина: %d байт)\n", string(key), len(key))
	
	// Шифрование
	fmt.Println("\nШифрование файла с 4 воркерами...")
	start := time.Now()
	err := ProcessFileParallel("test_input.txt", "test_encrypted.txt", key, 4)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}
	fmt.Printf("Время шифрования: %v\n", time.Since(start))
	
	encData, _ := os.ReadFile("test_encrypted.txt")
	fmt.Printf("Зашифрованные данные: %x\n", encData[:min(50, len(encData))])
	
	// Дешифрование
	fmt.Println("\nДешифрование файла с 4 воркерами...")
	start = time.Now()
	err = ProcessFileParallel("test_encrypted.txt", "test_decrypted.txt", key, 4)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}
	fmt.Printf("Время дешифрования: %v\n", time.Since(start))
	
	decData, _ := os.ReadFile("test_decrypted.txt")
	fmt.Println("Расшифрованное содержимое:", string(decData))
	
	if string(testData) == string(decData) {
		fmt.Println("\nРезультат: Данные полностью совпадают")
	} else {
		fmt.Println("\nРезультат: ОШИБКА - данные не совпадают")
	}
}

// Обработка большого файла
func demo2LargeFile() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Обработка большого файла разным количеством воркеров")
	
	// Создаем файл 5 MB
	fileSize := 5 * 1024 * 1024
	largeData := make([]byte, fileSize)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	
	os.WriteFile("large_file.bin", largeData, 0644)
	defer os.Remove("large_file.bin")
	
	fmt.Printf("\nСоздан тестовый файл размером: %.2f MB\n", float64(fileSize)/(1024*1024))
	
	key := []byte("LargeFileKey")
	
	workers := []int{1, 2, 4, 8, 16}
	
	fmt.Println("\nСравнение производительности:")
	fmt.Println(strings.Repeat("-", 70))
	
	for _, w := range workers {
		outFile := fmt.Sprintf("large_encrypted_%d.bin", w)
		
		start := time.Now()
		ProcessFileParallel("large_file.bin", outFile, key, w)
		duration := time.Since(start)
		
		speed := float64(fileSize) / (1024 * 1024) / duration.Seconds()
		
		fmt.Printf("Воркеров: %2d | Время: %8v | Скорость: %6.2f MB/s\n", 
			w, duration, speed)
		
		os.Remove(outFile)
	}
}

// Демонстрация 3: Потоковая обработка
func demo3StreamProcessing() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Потоковая обработка с параллельными воркерами")
	
	// Создаем файл 10 MB
	fileSize := 10 * 1024 * 1024
	streamData := make([]byte, fileSize)
	for i := range streamData {
		streamData[i] = byte((i * 7) % 256)
	}
	
	os.WriteFile("stream_input.bin", streamData, 0644)
	defer os.Remove("stream_input.bin")
	defer os.Remove("stream_encrypted.bin")
	defer os.Remove("stream_decrypted.bin")
	
	fmt.Printf("\nФайл для обработки: %.2f MB\n", float64(fileSize)/(1024*1024))
	
	key := []byte("StreamKey")
	numWorkers := 8
	
	fmt.Printf("Количество воркеров: %d\n", numWorkers)
	
	// Шифрование
	fmt.Println("\nПотоковое шифрование...")
	start := time.Now()
	err := ProcessFileStream("stream_input.bin", "stream_encrypted.bin", key, numWorkers)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}
	encTime := time.Since(start)
	
	// Дешифрование
	fmt.Println("Потоковое дешифрование...")
	start = time.Now()
	err = ProcessFileStream("stream_encrypted.bin", "stream_decrypted.bin", key, numWorkers)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}
	decTime := time.Since(start)
	
	// Проверка
	decData, _ := os.ReadFile("stream_decrypted.bin")

	match := string(streamData) == string(decData)
	
	fmt.Println("\nРезультаты:")
	fmt.Printf("Время шифрования:   %v (%.2f MB/s)\n", 
		encTime, float64(fileSize)/(1024*1024)/encTime.Seconds())
	fmt.Printf("Время дешифрования: %v (%.2f MB/s)\n", 
		decTime, float64(fileSize)/(1024*1024)/decTime.Seconds())
	fmt.Printf("Проверка данных:    ")
	if match {
		fmt.Println("Успешно")
	} else {
		fmt.Println("Ошибка")
	}
}

//Разные типы файлов
func demo4DifferentFileTypes() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Шифрование разных типов файлов")
	
	key := []byte("UniversalKey")
	
	// Текстовый файл
	textData := []byte("Текстовый файл с кириллицей и латиницей\nMultiple lines\nWith various data")
	os.WriteFile("test_text.txt", textData, 0644)
	defer os.Remove("test_text.txt")
	defer os.Remove("test_text.enc")
	
	// Бинарный файл
	binaryData := make([]byte, 1024)
	for i := range binaryData {
		binaryData[i] = byte((i * i) % 256)
	}
	os.WriteFile("test_binary.bin", binaryData, 0644)
	defer os.Remove("test_binary.bin")
	defer os.Remove("test_binary.enc")
	
	// JSON-подобные данные
	jsonData := []byte(`{"name":"test","value":123,"array":[1,2,3],"nested":{"key":"value"}}`)
	os.WriteFile("test_json.json", jsonData, 0644)
	defer os.Remove("test_json.json")
	defer os.Remove("test_json..enc")
	
	files := []struct {
		name string
		size int
	}{
		{"test_text.txt", len(textData)},
		{"test_binary.bin", len(binaryData)},
		{"test_json.json", len(jsonData)},
	}
	
	fmt.Println("\nОбработка файлов:")
	for _, f := range files {
		start := time.Now()
		ProcessFileParallel(f.name, f.name[:len(f.name)-4]+".enc", key, 4)
		duration := time.Since(start)
		
		fmt.Printf("Файл: %-20s | Размер: %6d байт | Время: %v\n", 
			f.name, f.size, duration)
	}
	
	fmt.Println("\nВсе типы файлов успешно обработаны")
}

// Тест корректности параллельной обработки
func demo5CorrectnessTest() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Тест корректности при разном количестве воркеров")
	
	testData := []byte(strings.Repeat("Test data for correctness verification. ", 1000))
	os.WriteFile("correctness_test.txt", testData, 0644)
	defer os.Remove("correctness_test.txt")
	
	key := []byte("CorrectnessKey")
	
	fmt.Println("\nПроверка с разным количеством воркеров:")
	
	var firstResult []byte
	allMatch := true
	
	for w := 1; w <= 16; w *= 2 {
		encFile := fmt.Sprintf("corr_enc_%d.bin", w)
		decFile := fmt.Sprintf("corr_dec_%d.bin", w)
		
		// Шифруем
		ProcessFileParallel("correctness_test.txt", encFile, key, w)
		// Дешифруем
		ProcessFileParallel(encFile, decFile, key, w)
		
		decData, _ := os.ReadFile(decFile)
		
		if w == 1 {
			firstResult = decData
		} else {
			if string(firstResult) != string(decData) {
				allMatch = false
				fmt.Printf("Воркеров: %2d | Результат: ОШИБКА - не совпадает\n", w)
			}
		}
		
		// Проверка с исходными данными
		match := string(testData) == string(decData)
		status := "OK"
		if !match {
			status = "ОШИБКА"
			allMatch = false
		}
		
		fmt.Printf("Воркеров: %2d | Результат: %s\n", w, status)
		
		os.Remove(encFile)
		os.Remove(decFile)
	}
	
	if allMatch {
		fmt.Println("\nВсе тесты пройдены успешно")
	} else {
		fmt.Println("\nОбнаружены ошибки")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	demo1BasicEncryption()
	demo2LargeFile()
	demo3StreamProcessing()
	demo4DifferentFileTypes()
	demo5CorrectnessTest()
}
