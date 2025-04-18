package crypto

import (
	"crypto/md5"
	"encoding/hex"
)

// Md5Hash Md5哈希加密
func Md5Hash(plain string) string {
	hash := md5.Sum([]byte(plain))
	return hex.EncodeToString(hash[:])
}

// Md5HashWithSalt Md5哈希加盐
func Md5HashWithSalt(plain string, salt string) string {
	hash := md5.Sum([]byte(plain + salt))
	return hex.EncodeToString(hash[:])
}
