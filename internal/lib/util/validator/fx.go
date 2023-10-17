package validator

import "go.uber.org/fx"

var Module = fx.Options(
	fx.Invoke(
		SupportedConfig,
		SupportedEnvironments,
		SetBaseDirectory,
	),
)
