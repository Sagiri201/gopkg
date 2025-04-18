package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// RsaGenerateKey 生成Rsa公钥私钥(2048)
func RsaGenerateKey() (_ *rsa.PrivateKey, _ error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// RsaGenerateKeyToBase64 生成PKCS1的Rsa公钥私钥再进行Base64
func RsaGenerateKeyToBase64() (privBase64 string, pubBase64 string, err error) {
	var (
		privKey *rsa.PrivateKey
	)
	if privKey, err = RsaGenerateKey(); err != nil {
		return "", "", fmt.Errorf("生成Rsa公私钥失败: %w", err)
	}
	privBase64 = RsaPrivateKeyToPKCS1Base64(privKey)
	if pubBase64, err = RsaPublicKeyToBase64(&privKey.PublicKey); err != nil {
		return "", "", fmt.Errorf("Rsa公钥转Base64失败: %w", err)
	}
	return
}

// RsaPrivateKeyToPKCS1Base64 将PKCS1私钥转Base64
func RsaPrivateKeyToPKCS1Base64(privKey *rsa.PrivateKey) (_ string) {
	var (
		privBytes []byte
		privPEM   []byte
	)
	privBytes = x509.MarshalPKCS1PrivateKey(privKey)
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	return base64.StdEncoding.EncodeToString(privPEM)
}

// RsaPrivateKeyToPKCS8Base64 将PKCS8私钥转Base64
func RsaPrivateKeyToPKCS8Base64(privKey *rsa.PrivateKey) (_ string, err error) {
	var (
		privBytes []byte
		privPEM   []byte
	)
	if privBytes, err = x509.MarshalPKCS8PrivateKey(privKey); err != nil {
		return "", fmt.Errorf("生成x509标准私钥失败: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	return base64.StdEncoding.EncodeToString(privPEM), nil
}

// RsaPublicKeyToBase64 将PublicKey转Base64
func RsaPublicKeyToBase64(pubKey *rsa.PublicKey) (_ string, err error) {
	var (
		pubBytes []byte
		pubPEM   []byte
	)
	if pubBytes, err = x509.MarshalPKIXPublicKey(pubKey); err != nil {
		return "", fmt.Errorf("生成x509标准公钥失败: %w", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return base64.StdEncoding.EncodeToString(pubPEM), nil
}

// RsaPrivateKeyFromBase64 将Base64转私钥
func RsaPrivateKeyFromBase64(privBase64 string) (privKey *rsa.PrivateKey, err error) {
	var (
		privPEM   []byte
		privBlock *pem.Block
	)
	if privPEM, err = base64.StdEncoding.DecodeString(privBase64); err != nil {
		return nil, fmt.Errorf("Base64无法解析: %w", err)
	}

	if privBlock, _ = pem.Decode(privPEM); privBlock == nil {
		return nil, fmt.Errorf("PEM 解码失败或类型错误, block是nil")
	}

	switch privBlock.Type {
	case "RSA PRIVATE KEY": // PKCS1
		if privKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes); err != nil {
			return nil, fmt.Errorf("x509 PKCS1 解析失败, block: %v", privBlock)
		}
	case "PRIVATE KEY": // PKCS8
		var privKeyAny any
		if privKeyAny, err = x509.ParsePKCS8PrivateKey(privBlock.Bytes); err != nil {
			return nil, fmt.Errorf("x509 PKCS8 解析失败, block: %v", privBlock)
		}
		var ok bool
		if privKey, ok = privKeyAny.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("解析到的不是 rsa.PrivateKey 类型")
		}
	default:
		return nil, fmt.Errorf("未知的私钥类型: %s", privBlock.Type)
	}

	return
}

// RsaPublicKeyFromBase64 将base64转公钥
func RsaPublicKeyFromBase64(pubBase64 string) (pubKey *rsa.PublicKey, err error) {
	var (
		pubPEM   []byte
		pubBlock *pem.Block
		pubAny   any
		ok       bool
	)
	if pubPEM, err = base64.StdEncoding.DecodeString(pubBase64); err != nil {
		return nil, fmt.Errorf("Base64解码失败: %w", err)
	}
	if pubBlock, _ = pem.Decode(pubPEM); pubBlock == nil {
		return nil, fmt.Errorf("PEM解码失败")
	}
	if pubAny, err = x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		return nil, fmt.Errorf("公钥解析失败: %w", err)
	}
	if pubKey, ok = pubAny.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("解析到的不是 rsa.PublicKey 类型")
	}
	return
}

// RsaSign 使用私钥签名
func RsaSign(data string, privKey *rsa.PrivateKey) (_ string, err error) {
	// Hash 数据
	var (
		hashed    = sha256.Sum256([]byte(data))
		signature []byte
	)
	// 使用私钥进行签名
	if signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:]); err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}

	// 返回 base64 编码后的签名
	return base64.StdEncoding.EncodeToString(signature), nil
}

// RsaVerify 使用公钥验证签名
func RsaVerify(data, base64Signature string, pubKey *rsa.PublicKey) (err error) {
	var signature []byte
	// 解码 base64 签名
	if signature, err = base64.StdEncoding.DecodeString(base64Signature); err != nil {
		return fmt.Errorf("签名解码失败: %w", err)
	}

	// Hash 数据
	hashed := sha256.Sum256([]byte(data))

	// 验证签名
	if err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature); err != nil {
		return fmt.Errorf("签名验证失败: %w", err)
	}

	return
}

// RsaEncryptOAEP OAEP公钥加密
func RsaEncryptOAEP(data string, pubKey *rsa.PublicKey) (_ string, err error) {
	var ciphertext []byte
	if ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(data), nil); err != nil {
		return "", fmt.Errorf("加密失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// RsaDecryptOAEP OAEP私钥解密
func RsaDecryptOAEP(cipherBase64 string, privKey *rsa.PrivateKey) (_ string, err error) {
	var ciphertext []byte
	if ciphertext, err = base64.StdEncoding.DecodeString(cipherBase64); err != nil {
		return "", fmt.Errorf("Base64解码失败: %w", err)
	}

	var plaintext []byte
	if plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil); err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}

	return string(plaintext), nil
}

// RsaEncryptPKCS1v15 PKCS1v15公钥加密
func RsaEncryptPKCS1v15(data string, pubKey *rsa.PublicKey) (_ string, err error) {
	var ciphertext []byte
	if ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(data)); err != nil {
		return "", fmt.Errorf("加密失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// RsaDecryptPKCS1v15 PKCS1v15私钥解密
func RsaDecryptPKCS1v15(cipherBase64 string, privKey *rsa.PrivateKey) (_ string, err error) {
	var ciphertext []byte
	if ciphertext, err = base64.StdEncoding.DecodeString(cipherBase64); err != nil {
		return "", fmt.Errorf("Base64解码失败: %w", err)
	}

	var plaintext []byte
	if plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext); err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}
	return string(plaintext), nil
}
