package types

type EnvironmentKey uint

const (
	// Environments
	Production EnvironmentKey = iota
	PreProduction
	Staging
	Development
	Sandbox
	Local
	Corporate
)

func (u EnvironmentKey) String() string {
	return [...]string{
		"production",
		"pre_production",
		"staging",
		"development",
		"sandbox",
		"local",
		"corporate",
	}[u]
}
