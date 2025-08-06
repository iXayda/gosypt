package gosypt

import (
	"testing"

	"github.com/ixayda/gosypt/pkg/algorithm"
	"github.com/ixayda/gosypt/pkg/crypt"
)

// 测试所有加密算法的加密和解密功能
func TestAllAlgorithms(t *testing.T) {
	// 测试数据
	plaintext := "这是一个测试文本，用于验证加密算法的正确性"
	password := "testPassword123"

	// 定义所有要测试的算法
	algorithms := []crypt.Algorithm{
		// DES系列算法
		algorithm.PBEWITHMD5ANDDES,
		algorithm.PBEWITHMD5ANDTRIPLEDES,
		algorithm.PBEWITHSHA1ANDDESEDE,

		// RC2系列算法 (暂未实现)
		algorithm.PBEWITHSHA1ANDRC2_40,
		algorithm.PBEWITHSHA1ANDRC2_128,

		// RC4系列算法
		algorithm.PBEWITHSHA1ANDRC4_40,
		algorithm.PBEWITHSHA1ANDRC4_128,

		// AES系列算法 - HMAC-SHA1
		algorithm.PBEWITHHMACSHA1ANDAES_128,
		algorithm.PBEWITHHMACSHA1ANDAES_256,

		// AES系列算法 - HMAC-SHA224
		algorithm.PBEWITHHMACSHA224ANDAES_128,
		algorithm.PBEWITHHMACSHA224ANDAES_256,

		// AES系列算法 - HMAC-SHA256
		algorithm.PBEWITHHMACSHA256ANDAES_128,
		algorithm.PBEWITHHMACSHA256ANDAES_256,

		// AES系列算法 - HMAC-SHA384
		algorithm.PBEWITHHMACSHA384ANDAES_128,
		algorithm.PBEWITHHMACSHA384ANDAES_256,

		// AES系列算法 - HMAC-SHA512
		algorithm.PBEWITHHMACSHA512ANDAES_128,
		algorithm.PBEWITHHMACSHA512ANDAES_256,
		algorithm.PBEWITHHMACSHA512ANDAES_256_GCM,
	}

	// 为每种算法运行测试
	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// 创建加密解析器
			crypto := New
			crypto.Algorithm(algorithm)

			// 加密文本
			ciphertext, err := crypto.Encrypt(plaintext, password)
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}

			// 解密文本
			decryptedText, err := crypto.Decrypt(ciphertext, password)
			if err != nil {
				t.Fatalf("解密失败: %v", err)
			}

			// 验证解密结果
			if decryptedText != plaintext {
				t.Errorf("解密结果不匹配: 期望 '%s', 得到 '%s'", plaintext, decryptedText)
			}
		})
	}
}
