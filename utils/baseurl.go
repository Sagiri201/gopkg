package utils

import (
	"log/slog"
	"net/url"
)

type BaseURL string

// GenerateURL 基于BaseURL生成url
func (b *BaseURL) GenerateURL(urls ...string) string {
	var (
		baseURL *url.URL
		err     error
	)
	if baseURL, err = b.parse(); err != nil {
		slog.Error("解析url失败", "err", err, "baseURL", *b, "urls", urls)
		return string(*b)
	}
	return baseURL.JoinPath(urls...).String()
}

// parse 解析BaseURL为*url.URL
func (b *BaseURL) parse() (*url.URL, error) {
	return url.Parse(string(*b))
}

// CheckOut 检查是不是url链接
func (b *BaseURL) CheckOut() bool {
	var err error
	_, err = b.parse()
	return err != nil
}
