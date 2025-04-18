package crypto

import (
	"log/slog"

	"golang.org/x/crypto/bcrypt"
)

// BcryptHash Bcryp哈希加密
func BcryptHash(plain string) string {
	var (
		hash []byte
		err  error
	)
	if hash, err = bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost); err != nil {
		slog.Warn("Bcrypt哈希加密失败",
			slog.String("plain", plain),
			slog.Any("err", err),
		)
		return ""
	}
	return string(hash)
}

// BcryptVerify Bcryp验证
func BcryptVerify(plain, hashed string) bool {
	var err error
	if err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)); err != nil {
		slog.Warn("Bcrypt验证失败",
			slog.String("plain", plain),
			slog.String("hashed", hashed),
			slog.Any("err", err),
		)
		return false
	}
	return true
}
