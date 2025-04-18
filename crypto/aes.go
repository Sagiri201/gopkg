package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AesEncryptCBC 使用 AES-CBC 加密（带 PKCS7 填充）
func AesEncryptCBC(plainText, key []byte) (string, error) {
	// 创建 AES 块
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES 块失败: %w", err)
	}

	blockSize := block.BlockSize()

	// 填充数据
	plainText = pkcs7Pad(plainText, blockSize)

	// IV（初始化向量）和密文一起输出
	cipherText := make([]byte, blockSize+len(plainText))
	iv := cipherText[:blockSize]

	// 随机生成 IV
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("生成 IV 失败: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], plainText)

	// Base64 输出
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// AesDecryptCBC 使用 AES-CBC 解密（带 PKCS7 去填充）
func AesDecryptCBC(cipherBase64 string, key []byte) (string, error) {
	// Base64 解码
	cipherText, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %w", err)
	}

	// 创建 AES 块
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES 块失败: %w", err)
	}
	blockSize := block.BlockSize()

	if len(cipherText) < blockSize {
		return "", fmt.Errorf("密文太短")
	}

	iv := cipherText[:blockSize]
	cipherText = cipherText[blockSize:]

	if len(cipherText)%blockSize != 0 {
		return "", fmt.Errorf("密文长度不是块大小的倍数")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	// 去填充
	plainText, err := pkcs7Unpad(cipherText, blockSize)
	if err != nil {
		return "", fmt.Errorf("去填充失败: %w", err)
	}

	return string(plainText), nil
}

// pkcs7Pad 填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// pkcs7Unpad 去填充
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("无效填充")
	}

	padLen := int(data[length-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("无效填充长度")
	}

	for _, v := range data[length-padLen:] {
		if int(v) != padLen {
			return nil, fmt.Errorf("填充内容错误")
		}
	}

	return data[:length-padLen], nil
}
