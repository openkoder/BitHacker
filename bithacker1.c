// Compile with:
// gcc -O2 -I secp256k1-0.3.0/src/ -I secp256k1-0.3.0/ -lgmp -lcrypto -lsecp256k1  bithacker1.c -o bithacker1

#include <stdio.h>
#include <stdbool.h>

#include "secp256k1-0.3.0/include/secp256k1.h"
#include "secp256k1-0.3.0/include/secp256k1_ecdh.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <string.h>


#define MAX_ADDRESSES 100 // Максимальное количество адресов для поиска
#define MAX_ADDRESS_SIZE 40 // Примерное значение для сжатого адреса (P2PKH)
// Количество генераций
#define COUNTGEN 20


typedef unsigned char byte;

static secp256k1_context *ctx = NULL;


/* See https://en.wikipedia.org/wiki/Positional_notation#Base_conversion */
char* base58(byte *s, int s_size, byte *out, int out_size) {
	static const char *base_chars = "123456789"
		"ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";

	byte s_cp[s_size];
	memcpy(s_cp, s, s_size);

	int c, i, n;

	out[n = out_size] = 0;
	while (n--) {
		for (c = i = 0; i < s_size; i++) {
			c = c * 256 + s_cp[i];
			s_cp[i] = c / 58;
			c %= 58;
		}
		out[n] = base_chars[c];
	}

	return out;
}


int generateRandomPrivateKey(unsigned char* seckey) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    /* Load private key (seckey) from random bytes */
    /* Загрузим закрытый ключ (seckey) из случайных байтов */
    FILE* finput = fopen("/dev/urandom", "r");
    
    /* Check if the file was opened successfully */
    if (!finput) {
        printf("Failed to open /dev/urandom\n");
        return -1;
    }
    
    /* Read 32 bytes from finput */
    /* Читаем 32 байта из finput */
    size_t bytesRead = fread(seckey, 32, 1, finput);
    
    /* Check if reading was successful */
    if (bytesRead != 1) {
        printf("Failed to read random bytes\n");
        fclose(finput);
        return -1;
    }
    
    /* Close the file */
    /* Закрываем этот файл */
    fclose(finput);
    
    if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
        printf("Invalid secret key\n");
        return -1;
    }
    

    return 0;
}

int generatePublicKey(const unsigned char* seckey, unsigned char* pubkey)
{
	secp256k1_pubkey secp_pubkey;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	
	int result = secp256k1_ec_pubkey_create(ctx, &secp_pubkey, seckey);
	if (result != 1) {
		printf("Failed to generate public key\n");
		return 1;
	}
	
	size_t pubkey_len = 65;

	/* Serialize Public Key */
	/* Сериализация открытого ключа */
	result = secp256k1_ec_pubkey_serialize(
		ctx,
		pubkey,
		&pubkey_len,
		&secp_pubkey,
		SECP256K1_EC_UNCOMPRESSED
		);
	
	if (result != 1) {
		printf("Failed to serialize public key\n");
		return -1;
	}
	
	return 0;
}

int generateCompressedPublicKey(const unsigned char* seckey, unsigned char* pubkey)
{
	secp256k1_pubkey secp_pubkey;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	
	int result = secp256k1_ec_pubkey_create(ctx, &secp_pubkey, seckey);
	if (result != 1) {
		printf("Failed to generate compressed public key\n");
		return 1;
	}
	
	size_t pubkey_len = 33; // Compressed public key size is 33 bytes

	/* Serialize Public Key */
	/* Сериализация открытого ключа */
	result = secp256k1_ec_pubkey_serialize(
		ctx,
		pubkey,
		&pubkey_len,
		&secp_pubkey,
		SECP256K1_EC_COMPRESSED
		);
	
	if (result != 1) {
		printf("Failed to serialize public key\n");
		return -1;
	}
	
	
	return 0;
}


void generateAddress(const unsigned char* pk_bytes, size_t pubkey_size, char* address) {
    unsigned char s[pubkey_size];
    unsigned char rmd[21 + SHA256_DIGEST_LENGTH];
    
    int j;
    for (j = 0; j < pubkey_size; j++) {
        s[j] = pk_bytes[j];
    }
    
    // Set 0x00 byte for main net
    /* Устанавливаем 0x00 байт для основной версии биткоин адреса */
    rmd[0] = 0;
    
    // Perform SHA-256 hashing
    SHA256(s, pubkey_size, rmd + 1);
    
    // Create the EVP_MD_CTX structure
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    // Initialize the EVP_MD_CTX structure with the RIPEMD160 algorithm
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL);
    
    // Update the EVP_MD_CTX with the SHA-256 hash
    EVP_DigestUpdate(ctx, rmd + 1, SHA256_DIGEST_LENGTH);
    
    // Finalize the RIPEMD160 hash
    unsigned int rmdLen;
    EVP_DigestFinal_ex(ctx, rmd + 1, &rmdLen);
    
    // Cleanup the EVP_MD_CTX structure
    EVP_MD_CTX_free(ctx);
    
    // Perform double SHA-256 hashing
    SHA256(SHA256(rmd, 21, NULL), SHA256_DIGEST_LENGTH, rmd + 21);
    
    // Copy the last 4 bytes of the double SHA-256 hash to rmd
    memcpy(rmd + 21, SHA256(SHA256(rmd, 21, NULL), SHA256_DIGEST_LENGTH, NULL), 4);
        
    base58(rmd, 25, address, 34);
    
    // Count the number of extra 1s at the beginning of the address
    /* Подсчитываем количество лишних 1 в начале адреса */
    int k;
    for (k = 1; address[k] == '1'; k++);

    // Count the number of extra leading 0x00 bytes
    /* Подсчитываем количество лишних начальных байтов 0x00 */
    int n;
    for (n = 1; rmd[n] == 0x00; n++);

    // Remove k-n leading 1's from the address
    /* Удаляем k-n ведущих единиц из адреса */
    memmove(address, address + (k - n), 34 - (k - n));
    address[34 - (k - n)] = '\0';
}

unsigned char* generateWIF(const unsigned char* privateKey, unsigned char* base58WIF) {
	// Шаг 1: Инициализация переменных
    unsigned char extendedPrivateKey[37]; // 1 + 32 + 4
    size_t privateKeyLength = 32;
    extendedPrivateKey[0] = 0x80;
    memcpy(extendedPrivateKey + 1, privateKey, privateKeyLength);

    // Шаг 2: Расчет хэша SHA256
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(extendedPrivateKey, privateKeyLength + 1, hash1);

    // Шаг 3: Повторный расчет хэша SHA256
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    // Шаг 4: Получение контрольной суммы (первые 4 байта хэша)
    unsigned char checksum[4];
    memcpy(checksum, hash2, 4);

    // Шаг 5: Добавление контрольной суммы в конец расширенного закрытого ключа
    memcpy(extendedPrivateKey + privateKeyLength + 1, checksum, 4);

	/*
	printf("extendedPrivateKey: ");
    for (size_t i = 0; i < 37; i++) {
        printf("%02X ", extendedPrivateKey[i]);
    }
    printf("\n");
    */
    
    // Шаг 6: Преобразование в base58
    base58(extendedPrivateKey, privateKeyLength + 5, base58WIF, 52);
    
    // Count the number of extra 1s at the beginning of the address
    /* Подсчитываем количество лишних 1 в начале адреса */
    int k;
    for (k = 0; base58WIF[k] == '1'; k++);

    // Remove k leading 1's from the base58WIF
    /* Удаляем k ведущих единиц из base58WIF */
    memmove(base58WIF, base58WIF + k, 52 - k);
    base58WIF[52 - k] = '\0';
    

    return base58WIF;
}

unsigned char* generateWIFcomp(const unsigned char* privateKey, unsigned char* base58WIF) {
	// Шаг 1: Инициализация переменных
    unsigned char extendedPrivateKey[38]; // 1 + 32 + 1 + 4
    size_t privateKeyLength = 32;
    extendedPrivateKey[0] = 0x80;
    memcpy(extendedPrivateKey + 1, privateKey, privateKeyLength);

	// Шаг 2: Добавление флага '01' в конец полученного 
	// расширенного приватного ключа для обозначения того, что нам надо
	// импортировать сжатый адрес
	extendedPrivateKey[privateKeyLength + 1] = 0x01;

    // Шаг 3: Расчет хэша SHA256
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(extendedPrivateKey, privateKeyLength + 2, hash1);

    // Шаг 4: Повторный расчет хэша SHA256
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
	
    // Шаг 5: Получение контрольной суммы (первые 4 байта хэша)
    unsigned char checksum[4];
    memcpy(checksum, hash2, 4);

    // Шаг 6: Добавление контрольной суммы в конец расширенного закрытого ключа
    memcpy(extendedPrivateKey + privateKeyLength + 2, checksum, 4);
    
    // Шаг 7: Преобразование в base58
    base58(extendedPrivateKey, privateKeyLength + 1 + 1 + 4, base58WIF, 52);
    
    // Count the number of extra 1s at the beginning of the address
    /* Подсчитываем количество лишних 1 в начале адреса */
    int k;
    for (k = 0; base58WIF[k] == '1'; k++);

    // Remove k leading 1's from the base58WIF
    /* Удаляем k ведущих единиц из base58WIF */
    memmove(base58WIF, base58WIF + k, 52 - k);
    base58WIF[52 - k] = '\0';
    

    return base58WIF;
}


// Функция для записи адреса и WIF в файл
void writeBingo(const char* address, const char* wif) {
    FILE* file = fopen("bingo.txt", "a");
    if (file == NULL) {
        printf("Ошибка при открытии файла bingo.txt\n");
        return;
    }
    
    fprintf(file, "Адрес:\n %s\n", address);
    fprintf(file, "WIF:\n %s\n\n", wif);
    
    fclose(file);
}



int main(int argc, char *argv[]) {

//----------------------------------------------------------------------
// настраиваем параметры программы
//----------------------------------------------------------------------

bool arg_nl = false;

// Проверяем наличие аргументов командной строки
for (int i = 1; i < argc; i++) {
	// Сравниваем текущий аргумент с "-nl"
	if (strcmp(argv[i], "-nl") == 0) {
		// Если аргумент совпадает, выполняем нужные действия
		arg_nl = true;
		
		break;  // Выходим из цикла, если нужен только первый найденный параметр -nl
	}
}


//----------------------------------------------------------------------
// читаем файл с адресами для поиска
//----------------------------------------------------------------------
FILE *file;
unsigned char addresses[MAX_ADDRESSES][64]; // Массив для хранения адресов, предполагается, что каждый адрес имеет не более 63 символов
int numAddresses = 0; // Количество считанных адресов

// Открытие файла для чтения
file = fopen("addresses.txt", "r");
if (file == NULL) {
	printf("Ошибка при открытии файла.\n");
	return 1;
}

// Чтение адресов из файла
unsigned char line[64];
while (fgets(line, sizeof(line), file) != NULL && numAddresses < MAX_ADDRESSES) {
	// Удаление символа новой строки, если он присутствует
	if (line[strlen(line) - 1] == '\n') {
		line[strlen(line) - 1] = '\0';
	}

	// Копирование адреса в массив
	strcpy(addresses[numAddresses], line);
	numAddresses++;
}

// Закрытие файла
fclose(file);


// Вывод проверяемых адресов
printf("Считанные адреса для проверки:\n");
for (int i = 0; i < numAddresses; i++) {
	printf("%s\n", addresses[i]);
}
printf("Всего проверяемых адресов: %d\n", numAddresses);

printf("Нажмите любую клавишу для продолжения...\n");
getchar(); // Ожидание нажатия клавиши
printf("Продолжение работы...\n");


// итераций поиска ключей
int count_gen;
    
printf("Введите количество итераций поиска ключей:\n");
scanf("%d", &count_gen);

float percent = 0;


//----------------------------------------------------------------------

FILE *outputFile = fopen("output.txt", "w");  // Открытие файла для записи


for (int i = 1; i <= count_gen; i++) {
	// Step 1. Create random Private Key
	
	/* Declare the private variable as a 32 byte unsigned char */
	/* Объявляем приватную переменную размером в 32-байта с типом символ без знака */
	unsigned char seckey[32];
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	generateRandomPrivateKey(seckey);
	
	// Step 2. Generate WIF
	unsigned char wif[52]; // Максимальная длина WIF равна 52 символам (включая завершающий нуль-символ)
	generateWIF(seckey, wif);
	
	// Step 3. Generate WIF for compressed address
	unsigned char wifcomp[52]; // Максимальная длина WIF равна 52 символам (включая завершающий нуль-символ)
	generateWIFcomp(seckey, wifcomp);
	
	// Step 4. Generate Public Key
	unsigned char pubkey[65];
	size_t pubkey_len = sizeof(pubkey);
	generatePublicKey(seckey, pubkey);
	
	// Step 5. Generate Address
	unsigned char address[34];
	generateAddress(pubkey, pubkey_len, address);
	
	// Step 6. Generate Compress Public Key
	unsigned char comppubkey[33];
	size_t comppubkey_len = sizeof(comppubkey);
	generateCompressedPublicKey(seckey, comppubkey);
	
	// Step 7. Generate Compressed Address
	unsigned char compaddress[34];
	generateAddress(comppubkey, comppubkey_len, compaddress);


	// Если при запуске программы не испольовался параметр -nl (no log),
	// то выводим информацию в консоль
	if(!arg_nl) {
		// Step. Print the results to console
		percent = (float)i / count_gen * 100;
		printf("%.2f%% #: %d\n", percent, i);

		/* Loop through and print each byte of the private key, */
		/* Перебираем в цикле и печатаем каждый байт закрытого ключа, */
		printf("Private Key: ");
		for(int i = 0; i < 32; i++) {
			printf("%02X", seckey[i]);
		}
		printf("\n");
		
		// Выводим WIF
		printf("WIF Private Key (wallet import format):\n %s\n", wif);
		
		// Выводим WIF for compressed public key
		printf("WIF Private Key (for compressed address):\n %s\n\n", wifcomp);


		/* Loop through and print each byte of the public key, */
		/* Перебираем в цикле и печатаем каждый байт открытого ключа, */
		printf("Public Key: ");
		for(int i = 0; i < pubkey_len; i++) {
			printf("%02X", pubkey[i]);
		}
		printf("\n");
		
		printf("Address: %s\n\n", address);
		
		
		/* Loop through and print each byte of the compressed public key, */
		/* Перебираем в цикле и печатаем каждый байт сжатого открытого ключа, */
		printf("Compressed Public Key: ");
		for(int i = 0; i < comppubkey_len; i++) {
			printf("%02X", comppubkey[i]);
		}
		printf("\n");

		printf("Compressed Address: %s\n\n", compaddress);
	}
		

	// Если при запуске программы не испольовался параметр -nl (no log),
	// то выводим информацию в файл
	if(!arg_nl) {
		// Выводим информацию в файл
		if (outputFile == NULL) {
			printf("Failed to open the output file.\n");
			return 1;
		}

		// Вывод значения целочисленной переменной i в файл
		fprintf(outputFile, "#: %d\n", i);

		// Вывод закрытого ключа в файл
		fprintf(outputFile, "Private Key: ");
		for (int j = 0; j < 32; j++) {
			fprintf(outputFile, "%02X", seckey[j]);
		}
		fprintf(outputFile, "\n");

		// Выводим WIF
		fprintf(outputFile, "WIF Private Key (wallet import format):\n %s\n", wif);

		// Выводим WIF for compressed public key
		fprintf(outputFile, "WIF Private Key (for compressed address):\n %s\n\n", wifcomp);
		
		/*
		fprintf(outputFile, "WIF (Hex): ");
		for (size_t i = 0; i < 52; i++) {
			fprintf(outputFile, "%02X ", wif[i]);
		}
		fprintf(outputFile, "\n");
		*/

		// Вывод открытого ключа в файл
		fprintf(outputFile, "Public Key: ");
		for (int j = 0; j < pubkey_len; j++) {
			fprintf(outputFile, "%02X", pubkey[j]);
		}
		fprintf(outputFile, "\n");

		// Вывод адреса в файл
		fprintf(outputFile, "Address: %s\n\n", address);

		// Вывод сжатого открытого ключа в файл
		fprintf(outputFile, "Compressed Public Key: ");
		for (int j = 0; j < comppubkey_len; j++) {
			fprintf(outputFile, "%02X", comppubkey[j]);
		}
		fprintf(outputFile, "\n");

		// Вывод сжатого адреса в файл
		fprintf(outputFile, "Compressed Address: %s\n\n", compaddress);
	}


	// Поиск совпадений адресов из файла addresses.txt и запись в файл bingo.txt
    for (int i = 0; i < numAddresses; i++) {
        if (strcmp(addresses[i], address) == 0) {
            printf("Поздравляю! Найдено совпадение с адресом: %s\n", addresses[i]);

            // Вызов функции для записи в файл bingo.txt
            writeBingo(addresses[i], wif);
        }
        if (strcmp(addresses[i], compaddress) == 0) {
			printf("Поздравляю! Найдено совпадение с адресом: %s\n", addresses[i]);

            // Вызов функции для записи в файл bingo.txt
            writeBingo(addresses[i], wifcomp);
		}
    }
}
	
// Закрытие файла
fclose(outputFile);


return 0;
}
