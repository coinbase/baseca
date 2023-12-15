package logger

import (
	"context"
	"time"

	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
)

type Extractor func(resp interface{}, err error, code codes.Code) string

type Error struct {
	UserError     error
	InternalError error
}

func (e *Error) Error() string {
	return e.UserError.Error()
}

func RpcError(user, internal error) *Error {
	return &Error{
		UserError:     user,
		InternalError: internal,
	}
}

func RpcLogger(extractor Extractor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		currentTime := time.Now().UTC()
		result, err := handler(ctx, req)
		duration := time.Since(currentTime)

		var event *zerolog.Event
		if err != nil {
			event = log.Error().Err(err)
		} else {
			event = log.Info()
		}

		statusCode := extractStatusCode(err)
		clientIP := extractClientIP(ctx)

		event.Str("protocol", "grpc").
			Str("method", info.FullMethod).
			Int("status_code", int(statusCode)).
			Str("ip_address", clientIP).
			Dur("duration", duration)

		provisioner, ok := ctx.Value(types.ProvisionerAuthenticationContextKey).(string)
		if ok {
			event.Str("provisioner_account_uuid", provisioner)
		}

		service, ok := ctx.Value(types.ServiceAuthenticationContextKey).(string)
		if ok {
			event.Str("service_account_uuid", service)
		}

		event.Msg(extractor(result, err, statusCode))
		return result, err
	}
}

func extractClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

func extractStatusCode(err error) codes.Code {
	if st, ok := status.FromError(err); ok {
		return st.Code()
	} else if customErr, ok := err.(*Error); ok {
		return status.Code(customErr.UserError)
	}
	return codes.Unknown
}

type Logger interface {
	AddFields(fields ...zap.Field)

	Panic(msg string, fields ...zap.Field)
	Fatal(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Debug(msg string, fields ...zap.Field)
}

var DefaultLogger = NewLogger(
	zap.NewExample().WithOptions(zap.Development()).With(zap.Bool("default", true)),
)

func NewLogger(logger *zap.Logger, logFields ...zap.Field) *ContextLogger {
	logger = logger.WithOptions(
		zap.AddCallerSkip(1),
		zap.AddCaller(),
		zap.Fields(append(logFields,
			zap.String("logger", "observability.ContextLogger"),
		)...,
		),
	)
	return NewContextLogger(logWrapper{logger})
}

type logKey struct{}

type ContextLogger struct {
	Logger Logger
	Fields []zap.Field
}

func NewContextLogger(logger Logger, fields ...zap.Field) *ContextLogger {
	if ctxLogger, ok := logger.(*ContextLogger); ok {
		return NewContextLogger(ctxLogger.Logger, append(fields, ctxLogger.Fields...)...)
	}
	return &ContextLogger{
		Logger: logger,
		Fields: fields,
	}
}

func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, logKey{}, NewContextLogger(logger))
}

func Log(ctx context.Context) Logger {
	if l := extractLogger(ctx); l != nil {
		return l
	}
	l := NewContextLogger(DefaultLogger)
	l.AddFields(zap.Any("context", ctx))
	l.Warn("Log called but context not set up.")
	return l
}

func AddLogFields(ctx context.Context, fields ...zap.Field) {
	if logger := extractLogger(ctx); logger != nil {
		logger.AddFields(fields...)
	} else {
		Log(ctx).Warn("AddLogFields called but context not set up.", fields...)
	}
}

func extractLogger(ctx context.Context) Logger {
	logger := ctx.Value(logKey{})
	if logger == nil {
		return nil
	}
	return logger.(Logger)
}

func (ctxLogger *ContextLogger) AddFields(fields ...zap.Field) {
	ctxLogger.Fields = append(ctxLogger.Fields, fields...)
}

func (ctxLogger *ContextLogger) fields(fields []zap.Field) []zap.Field {
	return append(fields, ctxLogger.Fields...)
}

func (ctxLogger *ContextLogger) stackFields(fields []zap.Field) []zap.Field {
	return append(ctxLogger.fields(fields))
}

func (ctxLogger *ContextLogger) Panic(msg string, fields ...zap.Field) {
	ctxLogger.Logger.Panic(msg, ctxLogger.stackFields(fields)...)
}
func (ctxLogger *ContextLogger) Fatal(msg string, fields ...zap.Field) {
	ctxLogger.Logger.Fatal(msg, ctxLogger.stackFields(fields)...)
}
func (ctxLogger *ContextLogger) Error(msg string, fields ...zap.Field) {
	ctxLogger.Logger.Error(msg, ctxLogger.stackFields(fields)...)
}
func (ctxLogger *ContextLogger) Warn(msg string, fields ...zap.Field) {
	ctxLogger.Logger.Warn(msg, ctxLogger.fields(fields)...)
}
func (ctxLogger *ContextLogger) Info(msg string, fields ...zap.Field) {
	ctxLogger.Logger.Info(msg, ctxLogger.fields(fields)...)
}
func (ctxLogger *ContextLogger) Debug(msg string, fields ...zap.Field) {
	ctxLogger.Logger.Debug(msg, ctxLogger.fields(fields)...)
}

// logWrapper adds a nop AddFields to a zap Logger client to implement the Logger interface
type logWrapper struct {
	*zap.Logger
}

func (logWrapper) AddFields(_ ...zap.Field) {}

func AppendField(zapFields []zapcore.Field, key string, value string) []zapcore.Field {
	return append(zapFields, zap.String(key, value))
}

func AppendZapField(zapFields []zapcore.Field, field zapcore.Field) []zapcore.Field {
	return append(zapFields, field)
}
