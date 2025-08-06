package main

import (
	"fmt"
	"log"

	"github.com/ixayda/gosypt"
	"github.com/ixayda/gosypt/pkg/algorithm"
	"github.com/ixayda/gosypt/pkg/crypt"
)

func main() {
	// 创建加密解析器
	resolver := gosypt.New

	// 设置要加密的文本和密码
	plaintext := "这是一个使用高级配置的加密示例"
	password := "mySuperSecurePassword456"

	// 定义所有可用的加密算法
	algorithms := []crypt.Algorithm{
		// DES系列算法
		algorithm.PBEWITHMD5ANDDES,
		algorithm.PBEWITHMD5ANDTRIPLEDES,
		algorithm.PBEWITHSHA1ANDDESEDE,

		// RC2系列算法
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

	// 测试不同的前缀和后缀
	prefixes := []string{"ENC~[", "CRYPT(", "SECURE{"}
	suffixes := []string{"]", ")", "}"}

	for _, algorithm := range algorithms {
		// 设置当前算法
		resolver.Algorithm(algorithm)

		// 循环使用不同的前缀和后缀
		for j := range prefixes {
			resolver.Prefix(prefixes[j])
			resolver.Suffix(suffixes[j])

			fmt.Printf("\n===== 测试算法: %s, 前缀: %s, 后缀: %s =====\n", algorithm, prefixes[j], suffixes[j])
			fmt.Printf("原始文本: %s\n", plaintext)

			// 加密文本
			ciphertext, err := resolver.Encrypt(plaintext, password)
			if err != nil {
				log.Printf("加密失败: %v", err)
				continue
			}

			fmt.Printf("加密结果: %s\n", ciphertext)

			// 解密文本
			decryptedText, err := resolver.Decrypt(ciphertext, password)
			if err != nil {
				log.Printf("解密失败: %v", err)
				continue
			}

			fmt.Printf("解密结果: %s\n", decryptedText)

			// 验证解密结果
			if decryptedText == plaintext {
				fmt.Println("验证成功: 解密文本与原始文本一致")
			} else {
				fmt.Println("验证失败: 解密文本与原始文本不一致")
			}
		}
	}
	fmt.Println("\n=============================")
}
