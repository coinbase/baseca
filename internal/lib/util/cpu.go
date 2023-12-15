package util

import (
	"time"

	"github.com/coinbase/baseca/internal/logger"
	"github.com/gogo/status"
	"github.com/shirou/gopsutil/cpu"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

var (
	_default_cpu_interval  = time.Second * 5
	_default_cpu_threshold = 70.0

	_backoff_duration = time.Second * 5
	_backoff_timeout  = time.Minute * 1

	CPU_HIGH = false
)

func UpdateCPULoad() {
	ticker := time.NewTicker(_default_cpu_interval)
	defer ticker.Stop()

	for range ticker.C {
		cpu, err := cpu.Percent(0, false)
		if err != nil {
			logger.DefaultLogger.Error("error retrieving cpu utilization", zap.Error(err))
			continue
		}
		CPU_HIGH = cpu[0] > _default_cpu_threshold
	}
}

// Backoff Authentication [middleware/authentication.go]
var ProcessBackoff = func() error {
	timeout := time.NewTimer(_backoff_timeout)
	defer timeout.Stop()

	select {
	case <-time.After(_backoff_duration):
		logger.DefaultLogger.Warn("cpu load high") // TODO: Additional Context
		return nil
	case <-timeout.C:
		return logger.RpcError(status.Error(codes.Internal, "queue processinging signing requests at capacity"), nil)
	}
}
