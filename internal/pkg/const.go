package pkg

import (
	"crypto/aes"
	"crypto/des"
)

// Jasypt配置常量
const (
	// 通用参数
	iterations = 1000 // Jasypt默认迭代次数

	// DES系列参数
	saltSizeDES   = 8  // DES盐大小
	ivSizeDES     = 8  // DES IV大小
	keySizeDES    = 8  // DES密钥长度
	keySize3DES   = 24 // 3DES密钥长度
	blockSizeDES  = des.BlockSize
	minDataLenDES = saltSizeDES + ivSizeDES // DES最小数据长度

	// AES系列参数
	saltSizeAES   = 16 // AES盐大小（Jasypt强制）
	ivSizeAES     = 16 // AES IV大小（Jasypt强制）
	keySizeAES128 = 16 // AES-128密钥长度
	keySizeAES256 = 32 // AES-256密钥长度
	blockSizeAES  = aes.BlockSize
	minDataLenAES = saltSizeAES + ivSizeAES // AES最小数据长度

	// RC2系列参数
	saltSizeRC2    = 8  // RC2盐大小
	keySizeRC2_40  = 5  // RC2-40密钥长度 (5字节 = 40位)
	keySizeRC2_128 = 16 // RC2-128密钥长度

	// RC4系列参数
	saltSizeRC4    = 8  // RC4盐大小
	keySizeRC4_40  = 5  // RC4-40密钥长度
	keySizeRC4_128 = 16 // RC4-128密钥长度
)
