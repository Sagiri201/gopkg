package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"github.com/Sagiri201/gopkg/utils"

	"gopkg.in/natefinch/lumberjack.v2"
)

var defaultLog = NewLogHandler()

func init() {
	defaultLog.SetDefaultLog()
}

type LogHandler struct {
	slog.Handler
	level *slog.LevelVar
	w     io.Writer
	opts  *slog.HandlerOptions
	mu    sync.Mutex
}

// NewLogHandler 创建日志处理器
func NewLogHandler(opts ...LogHandlerOption) (l *LogHandler) {
	l = new(LogHandler)
	l.w = os.Stdout
	l.level = new(slog.LevelVar)
	l.level.Set(slog.LevelInfo)
	l.opts = &slog.HandlerOptions{
		AddSource: true,
		Level:     l.level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok {
					a.Value = slog.StringValue(fmt.Sprintf("%s:%d", source.Function, source.Line))
				}
			}
			return a
		},
	}

	for _, opt := range opts {
		opt(l)
	}

	l.Handler = slog.NewTextHandler(l.w, l.opts)
	return
}

// Handle 重写Handle方法, 添加错误调用堆栈信息
func (l *LogHandler) Handle(ctx context.Context, r slog.Record) (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if traceId, ok := ctx.Value("traceId").(string); ok {
		r.AddAttrs(slog.String("traceId", traceId))
	}
	if r.Level == slog.LevelError {
		r.AddAttrs(slog.Any("stack", getStackTrace(4, 3)))
	}
	return l.Handler.Handle(ctx, r)
}

// SetLevel 设置日志等级
func (l *LogHandler) SetLevel(level slog.Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level.Set(level)
}

func (l *LogHandler) SetDefaultLog() {
	slog.SetDefault(slog.New(l))
}

/*
 * LogHandler 选项配置
 */

type LogHandlerOption func(*LogHandler)

// LogHandlerWithIoWriter 修改配置io写入
func LogHandlerWithIoWriter(w io.Writer) LogHandlerOption {
	return func(l *LogHandler) {
		l.w = w
	}
}

// LogHandlerWithLevel 设置日志等级
func LogHandlerWithLevel(level slog.Level) LogHandlerOption {
	return func(l *LogHandler) {
		l.level.Set(level)
	}
}

// LogHandlerWithHandlerOptions 设置处理器配置
func LogHandlerWithHandlerOptions(opts *slog.HandlerOptions) LogHandlerOption {
	return func(l *LogHandler) {
		l.opts = opts
	}
}

/*
 * 日志切割配置
 */
func LogHandlerWithLumberjack(lumberjackLog *lumberjack.Logger) LogHandlerOption {
	return func(l *LogHandler) {
		l.w = io.MultiWriter(l.w, lumberjackLog)
	}
}

func LogHandlerWithLumberjackDefault() LogHandlerOption {
	return func(l *LogHandler) {
		l.w = io.MultiWriter(l.w, &lumberjack.Logger{
			Filename:   filepath.Join(utils.ExecPath(), "logs", "app.log"),
			MaxSize:    100,
			MaxBackups: 0,
			MaxAge:     0,
			Compress:   true,
			LocalTime:  true,
		})
	}
}

/*
 * 辅助方法
 */

// getStackTrace 获得堆栈跟踪
func getStackTrace(skip, maxDepth int) []string {
	pcs := make([]uintptr, maxDepth)
	n := runtime.Callers(skip, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	stack := make([]string, 0, n) // 预分配容量
	for {
		frame, more := frames.Next()
		stack = append(stack, frame.Function+":"+strconv.Itoa(frame.Line))
		if !more {
			break
		}
	}
	return stack
}
