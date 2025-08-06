package pkg

import (
	"errors"
	"fmt"
)

// pkcs5Pad 严格匹配Jasypt的填充逻辑
func pkcs5Pad(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize // Jasypt特殊处理：长度为块大小倍数时仍填充
	}
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...), nil
}

// pkcs5Unpad 严格匹配Jasypt的填充验证逻辑
func pkcs5Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("数据为空")
	}
	padding := int(data[len(data)-1])
	// Jasypt会严格校验填充范围
	if padding < 1 || padding > blockSize || padding > len(data) {
		return nil, fmt.Errorf("填充长度无效: %d（必须1-%d）", padding, blockSize)
	}
	// 校验所有填充字节是否一致
	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, errors.New("填充字节不一致")
		}
	}
	return data[:len(data)-padding], nil
}
