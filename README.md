# BitHacker

**BitHacker v1** is a program to solve the Bitcoin puzzle with a prize of 1000 $BTC

**You can read more about the Bitcoin puzzle with a prize of 1000 $BTC coins here:**

[Unsolved #Bitcoin Puzzle of the 1000 $BTC Transaction Since 2015: Can You Solve It? / #bitcoinchallenge #bitcoinpuzzle](https://steemit.com/bitcoin/@topkripto/unsolved-bitcoin-puzzle-of-the-1000-usdbtc-transaction-since-2015-can-you-solve-it-bitcoinchallenge-bitcoinpuzzle)

[Неразгаданная загадка #Bitcoin транзакции на 1000 $BTC с 2015 года: сможете ли Вы её решить? / #bitcoinchallenge #bitcoinpuzzle](https://steemit.com/bitcoinchallenge/@topkripto/nerazgadannaya-zagadka-bitcoin-tranzakcii-na-1000-usdbtc-s-2015-goda-smozhete-li-vy-eyo-reshit-bitcoinchallenge-bitcoinpuzzle)

Post: [https://bitcointalk.org/index.php?topic=5322040.0](https://bitcointalk.org/index.php?topic=5322040.0)

-----------

# BitHacker v1

**BitHacker v1** is a C-based tool designed to hunt for private keys in the famous **Bitcoin Puzzle Transaction** — a cryptographic challenge with a prize pool of **1000 BTC** that has remained unsolved since 2015.

The program generates random Bitcoin private keys, derives both compressed and uncompressed public keys and addresses, and checks them against a target list. If a match is found, the corresponding private key (in WIF format) is saved to `bingo.txt`.

> 📺 **Video tutorials & demonstrations the BitHacker v2 program:**
> - [Generating 100,000 Bitcoin Private Keys to Solve the 1000 $BTC #Bitcoin Challenge [Bitcoin Puzzle]](https://youtu.be/SRn-NKSqyqI)
> - [Operation of the BitHacker v2 program](https://odysee.com/@topcrypto:d/bithacker:a?r=6p9MVErKG75MkBnDtWe5aProPuc3tycG)

> 💬 **Community & Support:**
> - **Telegram:** [Crypto XXS Chat / Крипто XXS чат](#) — consultations and training on working with cryptocurrency

---

## 🔍 About the Bitcoin Puzzle

The Bitcoin Puzzle is a special transaction created in 2015 that splits **1000 BTC** across 166 Bitcoin addresses. Each address contains a private key within a known range:

- Puzzle #1: key in range `[1, 1]`
- Puzzle #2: key in range `[2, 3]`
- Puzzle #20: key in range `[2^19, 2^20 - 1]`
- Puzzle #66: key in range `[2^65, 2^66 - 1]`
- ...and so on up to Puzzle #166

The challenge is to find the private keys for the remaining unsolved addresses. As of now, puzzles up to approximately #85 have been solved by the community using increasingly powerful hardware and optimized algorithms.

**Read more:**
- [Unsolved #Bitcoin Puzzle of the 1000 $BTC Transaction Since 2015: Can You Solve It?](https://steemit.com/bitcoin/@topkripto/unsolved-bitcoin-puzzle-of-the-1000-usdbtc-transaction-since-2015-can-you-solve-it-bitcoinchallenge-bitcoinpuzzle)
- [Неразгаданная загадка #Bitcoin транзакции на 1000 $BTC с 2015 года: сможете ли Вы её решить?](https://steemit.com/bitcoinchallenge/@topkripto/nerazgadannaya-zagadka-bitcoin-tranzakcii-na-1000-usdbtc-s-2015-goda-smozhete-li-vy-eyo-reshit-bitcoinchallenge-bitcoinpuzzle)

---

## ⚙️ Features

- ✅ Generates cryptographically secure random private keys using `/dev/urandom`
- ✅ Derives both **compressed** and **uncompressed** public keys
- ✅ Generates corresponding Bitcoin addresses (P2PKH, Base58Check)
- ✅ Produces **WIF (Wallet Import Format)** keys for both compressed and uncompressed variants
- ✅ Compares generated addresses against a target list from `addresses.txt`
- ✅ Saves found matches (address + WIF) to `bingo.txt`
- ✅ Progress indicator with percentage completion
- ✅ Optional silent mode (`-nl`) for background operation
- ✅ Uses industry-standard libraries: `libsecp256k1`, `OpenSSL`, `GMP`

---

## 📋 Requirements

### System
- Linux / Unix-like system (uses `/dev/urandom`)
- GCC compiler
- Basic development tools

### Libraries
- `libsecp256k1` (version 0.3.0 recommended)
- `libssl` (OpenSSL)
- `libgmp` (GNU Multiple Precision Arithmetic Library)

---

## 🛠️ Installation

### On Debian / Ubuntu

```bash
sudo apt update
sudo apt install build-essential libssl-dev libgmp-dev git -y
```

### Download and prepare libsecp256k1

```bash
# Clone the secp256k1 library (version 0.3.0)
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
git checkout v0.3.0

# Build and install
./autogen.sh
./configure --enable-module-ecdh
make
sudo make install
sudo ldconfig
```

---

## 🔨 Compilation

Place `bithacker1.c` in the same directory as the `secp256k1-0.3.0` source folder, then compile with:

```bash
gcc -O2 -I secp256k1-0.3.0/src/ -I secp256k1-0.3.0/ -lgmp -lcrypto -lsecp256k1 bithacker1.c -o bithacker1
```

**Compilation flags explained:**
- `-O2` — optimization level 2 for better performance
- `-I secp256k1-0.3.0/src/` — include path for secp256k1 headers
- `-I secp256k1-0.3.0/` — include path for secp256k1 root
- `-lgmp` — link GNU Multiple Precision library
- `-lcrypto` — link OpenSSL crypto library
- `-lsecp256k1` — link secp256k1 library

---

## 🚀 Usage

### 1. Prepare the target addresses file

Create a file named `addresses.txt` in the same directory as the executable. Add one Bitcoin address per line:

```
1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA
```

### 2. Run the program

```bash
./bithacker1
```

The program will:
1. Display all loaded target addresses
2. Wait for a key press to continue
3. Ask for the number of iterations
4. Start generating and checking keys

### 3. Silent mode (no console output)

For long-running background sessions, use the `-nl` (no log) flag:

```bash
./bithacker1 -nl
```

In this mode, the program will not print generated keys to the console, but will still write matches to `bingo.txt`.

---

## 📁 Output Files

### `output.txt`
Contains the full log of all generated keys (only when running without `-nl`):
- Private key (hex)
- WIF (compressed and uncompressed)
- Public key (compressed and uncompressed)
- Bitcoin address (compressed and uncompressed)

### `bingo.txt`
Created automatically when a match is found. Contains:
```
Адрес:
 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
WIF:
 KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
```

---

## 💻 Example Output

```
Считанные адреса для проверки:
1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
Всего проверяемых адресов: 2

Нажмите любую клавишу для продолжения...

Продолжение работы...
Введите количество итераций поиска ключей:
100000

0.01% #: 1
Private Key: 3A552F4E8C7D9B0A1F2E3D4C5B6A79880F1E2D3C4B5A69788796A5B4C3D2E1F0
WIF Private Key (wallet import format):
 KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
WIF Private Key (for compressed address):
 L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ

Public Key: 043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0...
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH

Compressed Public Key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Compressed Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

---

## Important Notes

### ⚡ Performance Expectations

This is a **CPU-based random search** tool. It's excellent for learning and experimenting with small puzzles (#1-40), but please understand the math:

| Puzzle | Key Space Size | Expected Time (1 MKeys/s) |
|--------|----------------|---------------------------|
| #40 | ~1 trillion | ~13 days |
| #60 | ~1 quintillion | ~35,000 years |
| #66 | ~73 quintillion | ~2.3 million years |
| #100+ | Astronomical | Longer than the age of the universe |


### 🔐 Cryptographic Security

- Private keys are generated from `/dev/urandom` (cryptographically secure on Linux)
- Each key is verified with `secp256k1_ec_seckey_verify()` to ensure validity
- The program correctly handles both compressed and uncompressed address formats

---

## 💖 Support the Project

If this tool helped you learn about Bitcoin cryptography or you'd like to support further development, donations are greatly appreciated:

**Bitcoin:** bc1qchfnkugdcazwf6mhq9ke5tj32hrc4cd5v9f80z

**Unified ZCash address:**
u1q4rruex38eefgx22x264tc9hthnm0hd5qhyaxxv80fq7v0mt78wrv035zk9qwqp489jepgc7quq3cdawqcfge8adp0f4s8hdnsqjgh5g

**Transparent ZCash address:** t1XJXAYuJmXV4aVJ3pDSiRoujbPrD7dT55t

**Litecoin:** ltc1qe0jwmpq92vu63r3hl9m29n2x4gej2scaa2tekw

**Bitcoin Cash:** qqd5kmzjrzcp4dv3y577d8clq3adkc5c4q92ecafdh 

**Ethereum:** 0xD4E6f5Dade9E5C4f081174aBbC0e7EE05CD6fC3C

**BNB (BEP20):** 0xD4E6f5Dade9E5C4f081174aBbC0e7EE05CD6fC3C

**Doge:** DDujAyHmcCESigEUbXVWkGuvexj5nQHBMt

**Dash:** XhJiqvda1ZWkbSdSAgpifHGz5dcmKhtSES

**PIVX:** D86yDj8n4jjrSVMcgtW9tD7EMooAUCb4XR

**USDT (trc20):** TMFGJTqZCBvuQCDtWLkdAAu3yW8rrFS8UV


---

## 📞 Contact

- **Telegram:** [Crypto XXS Chat / Крипто XXS чат](#) — consultations and training on cryptocurrency

---

## ⚖️ Disclaimer

**This software is provided for educational and research purposes only.**

- The Bitcoin Puzzle is a public cryptographic challenge. Respect its rules and the community spirit.
- The author is not responsible for any misuse of this software.
- Do not use this tool to attempt to access wallets that do not belong to you.
- Finding keys for puzzles above #70 with a CPU-based random search is mathematically impractical.

**Use responsibly. Stay within the puzzles.**

---

## 📄 License

This project is free and open-source. See the source code for licensing details.

---

## 🙏 Acknowledgments

Thanks to the entire Bitcoin Puzzle hunting community for:
- Creating and maintaining the puzzle
- Developing optimized tools (Kangaroo, BitCrack, keyhunt)
- Sharing knowledge and pushing the boundaries of what's possible

**Good luck, and happy hunting! 🎯**

---

*If you find a bug or have a feature request, please open an issue on GitHub.*


