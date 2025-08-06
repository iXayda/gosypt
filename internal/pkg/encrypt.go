package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/ixayda/gosypt/pkg/algorithm"
	"github.com/ixayda/gosypt/pkg/crypt"
	"golang.org/x/crypto/pbkdf2"
)

func JasyptEncrypt(plaintext, password string, alg crypt.Algorithm) (string, error) {
	var saltSize, ivSize, keySize int
	var blockSize int
	var hashFunc func() hash.Hash

	// 根据算法选择参数
	switch alg {
	// DES系列算法
	case algorithm.PBEWITHMD5ANDDES:
		saltSize = saltSizeDES
		ivSize = ivSizeDES
		keySize = keySizeDES
		blockSize = blockSizeDES
		hashFunc = md5.New
	case algorithm.PBEWITHMD5ANDTRIPLEDES, algorithm.PBEWITHSHA1ANDDESEDE:
		saltSize = saltSizeDES
		ivSize = ivSizeDES
		keySize = keySize3DES
		blockSize = blockSizeDES
		if alg == algorithm.PBEWITHMD5ANDTRIPLEDES {
			hashFunc = md5.New
		} else {
			hashFunc = sha1.New
		}

	// RC2系列算法
	case algorithm.PBEWITHSHA1ANDRC2_40, algorithm.PBEWITHSHA1ANDRC2_128:
		saltSize = saltSizeRC2
		ivSize = 8    // RC2 IV大小
		blockSize = 8 // RC2块大小
		hashFunc = sha1.New
		if alg == algorithm.PBEWITHSHA1ANDRC2_40 {
			keySize = keySizeRC2_40
		} else {
			keySize = keySizeRC2_128
		}

	// RC4系列算法
	case algorithm.PBEWITHSHA1ANDRC4_40, algorithm.PBEWITHSHA1ANDRC4_128:
		saltSize = saltSizeRC4
		ivSize = 0    // RC4不需要IV
		blockSize = 1 // RC4是流密码，没有块大小
		hashFunc = sha1.New
		if alg == algorithm.PBEWITHSHA1ANDRC4_40 {
			keySize = keySizeRC4_40
		} else {
			keySize = keySizeRC4_128
		}

	// AES系列算法 - HMAC-SHA1
	case algorithm.PBEWITHHMACSHA1ANDAES_128, algorithm.PBEWITHHMACSHA1ANDAES_256:
		saltSize = saltSizeAES
		ivSize = ivSizeAES
		blockSize = blockSizeAES
		hashFunc = sha1.New
		if alg == algorithm.PBEWITHHMACSHA1ANDAES_128 {
			keySize = keySizeAES128
		} else {
			keySize = keySizeAES256
		}

	// AES系列算法 - HMAC-SHA224
	case algorithm.PBEWITHHMACSHA224ANDAES_128, algorithm.PBEWITHHMACSHA224ANDAES_256:
		saltSize = saltSizeAES
		ivSize = ivSizeAES
		blockSize = blockSizeAES
		hashFunc = sha256.New224
		if alg == algorithm.PBEWITHHMACSHA224ANDAES_128 {
			keySize = keySizeAES128
		} else {
			keySize = keySizeAES256
		}

	// AES系列算法 - HMAC-SHA256
	case algorithm.PBEWITHHMACSHA256ANDAES_128, algorithm.PBEWITHHMACSHA256ANDAES_256:
		saltSize = saltSizeAES
		ivSize = ivSizeAES
		blockSize = blockSizeAES
		hashFunc = sha256.New
		if alg == algorithm.PBEWITHHMACSHA256ANDAES_128 {
			keySize = keySizeAES128
		} else {
			keySize = keySizeAES256
		}

	// AES系列算法 - HMAC-SHA384
	case algorithm.PBEWITHHMACSHA384ANDAES_128, algorithm.PBEWITHHMACSHA384ANDAES_256:
		saltSize = saltSizeAES
		ivSize = ivSizeAES
		blockSize = blockSizeAES
		hashFunc = sha512.New384
		if alg == algorithm.PBEWITHHMACSHA384ANDAES_128 {
			keySize = keySizeAES128
		} else {
			keySize = keySizeAES256
		}

	// AES系列算法 - HMAC-SHA512
	case algorithm.PBEWITHHMACSHA512ANDAES_128, algorithm.PBEWITHHMACSHA512ANDAES_256:
		saltSize = saltSizeAES
		ivSize = ivSizeAES
		blockSize = blockSizeAES
		hashFunc = sha512.New
		if alg == algorithm.PBEWITHHMACSHA512ANDAES_128 {
			keySize = keySizeAES128
		} else {
			keySize = keySizeAES256
		}
	// AES-GCM系列算法 - HMAC-SHA512
	case algorithm.PBEWITHHMACSHA512ANDAES_256_GCM:
		saltSize = saltSizeAES
		ivSize = 12 // GCM推荐使用12字节IV
		blockSize = blockSizeAES
		keySize = keySizeAES256
		hashFunc = sha512.New

	default:
		return "", fmt.Errorf("不支持的算法: %s", alg)
	}

	// 1. 生成随机盐
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成盐失败: %v", err)
	}

	// 2. 生成随机IV (如果需要)
	var iv []byte
	if ivSize > 0 {
		iv = make([]byte, ivSize)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("生成IV失败: %v", err)
		}
	}

	// 3. 派生密钥
	key := pbkdf2.Key(
		[]byte(password),
		salt,
		iterations,
		keySize,
		hashFunc,
	)

	// 4. 数据处理和加密
	var ciphertext []byte

	switch alg {
	// DES系列算法
	case algorithm.PBEWITHMD5ANDDES, algorithm.PBEWITHMD5ANDTRIPLEDES, algorithm.PBEWITHSHA1ANDDESEDE:
		// PKCS#5填充
		paddedPlaintext, err := pkcs5Pad([]byte(plaintext), blockSize)
		if err != nil {
			return "", fmt.Errorf("数据填充失败: %v", err)
		}

		// 加密
		if alg == algorithm.PBEWITHMD5ANDDES {
			block, err := des.NewCipher(key)
			if err != nil {
				return "", fmt.Errorf("DES初始化失败: %v", err)
			}
			mode := cipher.NewCBCEncrypter(block, iv)
			ciphertext = make([]byte, len(paddedPlaintext))
			mode.CryptBlocks(ciphertext, paddedPlaintext)
		} else {
			block, err := des.NewTripleDESCipher(key)
			if err != nil {
				return "", fmt.Errorf("3DES初始化失败: %v", err)
			}
			mode := cipher.NewCBCEncrypter(block, iv)
			ciphertext = make([]byte, len(paddedPlaintext))
			mode.CryptBlocks(ciphertext, paddedPlaintext)
		}

	// RC2系列算法
	case algorithm.PBEWITHSHA1ANDRC2_40, algorithm.PBEWITHSHA1ANDRC2_128:
		// PKCS#5填充
		_, err := pkcs5Pad([]byte(plaintext), blockSize)
		if err != nil {
			return "", fmt.Errorf("数据填充失败: %v", err)
		}

		// 注意: Go标准库没有直接支持RC2, 这里使用模拟实现
		// 实际应用中可能需要使用第三方库
		return "", fmt.Errorf("RC2算法尚未实现")

	// RC4系列算法
	case algorithm.PBEWITHSHA1ANDRC4_40, algorithm.PBEWITHSHA1ANDRC4_128:
		// RC4不需要填充
		ciphertext = make([]byte, len(plaintext))
		cipher, err := rc4.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("RC4初始化失败: %v", err)
		}
		cipher.XORKeyStream(ciphertext, []byte(plaintext))

	// AES系列算法 - CBC模式
	case algorithm.PBEWITHHMACSHA1ANDAES_128, algorithm.PBEWITHHMACSHA1ANDAES_256,
		algorithm.PBEWITHHMACSHA224ANDAES_128, algorithm.PBEWITHHMACSHA224ANDAES_256,
		algorithm.PBEWITHHMACSHA256ANDAES_128, algorithm.PBEWITHHMACSHA256ANDAES_256,
		algorithm.PBEWITHHMACSHA384ANDAES_128, algorithm.PBEWITHHMACSHA384ANDAES_256,
		algorithm.PBEWITHHMACSHA512ANDAES_128, algorithm.PBEWITHHMACSHA512ANDAES_256:
		// PKCS#5填充
		paddedPlaintext, err := pkcs5Pad([]byte(plaintext), blockSize)
		if err != nil {
			return "", fmt.Errorf("数据填充失败: %v", err)
		}

		// 加密
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("AES初始化失败: %v", err)
		}
		mode := cipher.NewCBCEncrypter(block, iv)
		ciphertext = make([]byte, len(paddedPlaintext))
		mode.CryptBlocks(ciphertext, paddedPlaintext)

	// AES系列算法 - GCM模式
	case algorithm.PBEWITHHMACSHA512ANDAES_256_GCM:
		// GCM模式不需要填充
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("AES初始化失败: %v", err)
		}

		// 创建GCM模式
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("GCM初始化失败: %v", err)
		}

		// 加密并生成认证标签
		// 注意: GCM的nonce就是我们这里的iv
		ciphertext = gcm.Seal(nil, iv, []byte(plaintext), nil)
	}

	// 5. 组合盐、IV和密文
	data := append(salt, iv...)
	data = append(data, ciphertext...)

	// 6. Base64编码
	return base64.StdEncoding.EncodeToString(data), nil
}
