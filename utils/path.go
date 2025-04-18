package utils

import (
	"log/slog"
	"os"
	"path/filepath"
)

// ExecPath 获取当前可执行文件的路径
func ExecPath() string {
	execPath, err := os.Executable()
	if err != nil {
		slog.Error("获取可执行文件路径失败", "err", err)
		return ""
	}
	return filepath.Dir(execPath)
}

// ExecPath 获取当前Home目录的路径
func HomePath() string {
	homePath, err := os.UserHomeDir()
	if err != nil {
		slog.Error("获取用户Home路径错误", "err", err)
		return ""
	}
	return homePath
}
