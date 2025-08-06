package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
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

func JasyptDecrypt(ciphertextBase64, password string, alg crypt.Algorithm) (string, error) {
	var saltSize, ivSize, keySize int
	var blockSize int
	var minDataLen int
	var hashFunc func() hash.Hash

	// 根据算法选择参数
	switch alg {
	// DES系列算法
	case algorithm.PBEWITHMD5ANDDES:
		saltSize = saltSizeDES
		ivSize = ivSizeDES
		keySize = keySizeDES
		blockSize = blockSizeDES
		minDataLen = minDataLenDES
		hashFunc = md5.New
	case algorithm.PBEWITHMD5ANDTRIPLEDES, algorithm.PBEWITHSHA1ANDDESEDE:
		saltSize = saltSizeDES
		ivSize = ivSizeDES
		keySize = keySize3DES
		blockSize = blockSizeDES
		minDataLen = minDataLenDES
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
		minDataLen = saltSize + ivSize
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
		minDataLen = saltSize
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
		minDataLen = minDataLenAES
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
		minDataLen = minDataLenAES
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
		minDataLen = minDataLenAES
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
		minDataLen = minDataLenAES
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
		minDataLen = minDataLenAES
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
		minDataLen = saltSize + ivSize
		keySize = keySizeAES256
		hashFunc = sha512.New

	default:
		return "", fmt.Errorf("不支持的算法: %s", alg)
	}

	// 1. Base64解码（使用标准解码器，处理填充符）
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("Base64解码失败（可能格式错误）: %v", err)
	}

	// 2. 校验总长度（至少盐+IV的长度）
	if len(data) < minDataLen {
		return "", fmt.Errorf("密文格式错误: 总长度%d字节，不足最小要求%d字节（盐+IV）", len(data), minDataLen)
	}

	// 2.1 检查是否至少有一个密文块（如果需要）
	if blockSize > 1 && len(data) < saltSize+ivSize+blockSize {
		return "", fmt.Errorf("密文太短: 总长度%d字节，至少需要%d字节（盐+IV+一个密文块）", len(data), saltSize+ivSize+blockSize)
	}

	// 3. 拆分盐、IV、密文（严格按Jasypt的顺序）
	salt := data[:saltSize]
	var iv []byte
	var ciphertext []byte

	if ivSize > 0 {
		iv = data[saltSize : saltSize+ivSize]
		ciphertext = data[saltSize+ivSize:]
	} else {
		// RC4不需要IV
		ciphertext = data[saltSize:]
	}

	// 校验盐和IV的长度（防止拆分错误）
	if len(salt) != saltSize {
		return "", fmt.Errorf("盐长度错误: 实际%d字节，预期%d字节", len(salt), saltSize)
	}
	if ivSize > 0 && len(iv) != ivSize {
		return "", fmt.Errorf("IV长度错误: 实际%d字节，预期%d字节", len(iv), ivSize)
	}

	// 4. 校验密文长度（必须是块大小的整数倍，除了流密码和GCM模式）
	if blockSize > 1 && len(ciphertext)%blockSize != 0 {
		// 检查是否为GCM模式
		isGCM := alg == algorithm.PBEWITHHMACSHA512ANDAES_256_GCM
		if !isGCM {
			return "", fmt.Errorf("密文长度错误: 实际%d字节，不是%d的整数倍", len(ciphertext), blockSize)
		}
	}

	// 5. 派生密钥
	key := pbkdf2.Key(
		[]byte(password),
		salt,
		iterations,
		keySize,
		hashFunc,
	)

	// 6. 解密
	var plaintext []byte
	var plaintextPadded []byte

	switch alg {
	// DES系列算法
	case algorithm.PBEWITHMD5ANDDES, algorithm.PBEWITHMD5ANDTRIPLEDES, algorithm.PBEWITHSHA1ANDDESEDE:
		plaintextPadded = make([]byte, len(ciphertext))
		if alg == algorithm.PBEWITHMD5ANDDES {
			block, err := des.NewCipher(key)
			if err != nil {
				return "", fmt.Errorf("DES初始化失败: %v", err)
			}
			mode := cipher.NewCBCDecrypter(block, iv)
			mode.CryptBlocks(plaintextPadded, ciphertext)
		} else {
			block, err := des.NewTripleDESCipher(key)
			if err != nil {
				return "", fmt.Errorf("3DES初始化失败: %v", err)
			}
			mode := cipher.NewCBCDecrypter(block, iv)
			mode.CryptBlocks(plaintextPadded, ciphertext)
		}

		// 去除填充
		plaintext, err = pkcs5Unpad(plaintextPadded, blockSize)
		if err != nil {
			return "", fmt.Errorf("填充验证失败（可能密码错误）: %v", err)
		}

	// RC2系列算法
	case algorithm.PBEWITHSHA1ANDRC2_40, algorithm.PBEWITHSHA1ANDRC2_128:
		// 注意: Go标准库没有直接支持RC2, 这里使用模拟实现
		// 实际应用中可能需要使用第三方库
		return "", fmt.Errorf("RC2算法尚未实现")

	// RC4系列算法
	case algorithm.PBEWITHSHA1ANDRC4_40, algorithm.PBEWITHSHA1ANDRC4_128:
		plaintext = make([]byte, len(ciphertext))
		cipher, err := rc4.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("RC4初始化失败: %v", err)
		}
		cipher.XORKeyStream(plaintext, ciphertext)

	// AES系列算法 - CBC模式
	case algorithm.PBEWITHHMACSHA1ANDAES_128, algorithm.PBEWITHHMACSHA1ANDAES_256,
		algorithm.PBEWITHHMACSHA224ANDAES_128, algorithm.PBEWITHHMACSHA224ANDAES_256,
		algorithm.PBEWITHHMACSHA256ANDAES_128, algorithm.PBEWITHHMACSHA256ANDAES_256,
		algorithm.PBEWITHHMACSHA384ANDAES_128, algorithm.PBEWITHHMACSHA384ANDAES_256,
		algorithm.PBEWITHHMACSHA512ANDAES_128, algorithm.PBEWITHHMACSHA512ANDAES_256:
		plaintextPadded = make([]byte, len(ciphertext))
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("AES初始化失败: %v", err)
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintextPadded, ciphertext)

		// 去除填充
		plaintext, err = pkcs5Unpad(plaintextPadded, blockSize)
		if err != nil {
			return "", fmt.Errorf("填充验证失败（可能密码错误）: %v", err)
		}

	// AES系列算法 - GCM模式
	case algorithm.PBEWITHHMACSHA512ANDAES_256_GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("AES初始化失败: %v", err)
		}

		// 创建GCM模式
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("GCM初始化失败: %v", err)
		}

		// 解密并验证认证标签
		plaintext, err = gcm.Open(nil, iv, ciphertext, nil)
		if err != nil {
			return "", fmt.Errorf("GCM解密失败（可能密文被篡改或密码错误）: %v", err)
		}
	}

	return string(plaintext), nil
}
