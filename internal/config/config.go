package config

type SubordinateCertificate struct {
	Region      string `mapstructure:"region"`
	CaArn       string `mapstructure:"ca_arn"`
	CaActiveDay int    `mapstructure:"ca_active_day"`
	AssumeRole  bool   `mapstructure:"assume_role"`
	RoleArn     string `mapstructure:"role_arn"`
	RootCa      bool   `mapstructure:"root_ca"`
}

type SubordinateCertificateAuthority struct {
	BaseDirectory    string `mapstructure:"directory"`
	Country          string `mapstructure:"country"`
	Province         string `mapstructure:"province"`
	Locality         string `mapstructure:"locality"`
	Organization     string `mapstructure:"organization"`
	OrganizationUnit string `mapstructure:"organization_unit"`
	Email            string `mapstructure:"email"`
	SigningAlgorithm string `mapstructure:"signing_algorithm"`
	KeyAlgorithm     string `mapstructure:"key_algorithm"`
	KeySize          int    `mapstructure:"key_size"`
}

type DatabaseConfig struct {
	Driver         string `mapstructure:"database_driver"`
	Table          string `mapstructure:"database_table"`
	Endpoint       string `mapstructure:"database_endpoint"`
	ReaderEndpoint string `mapstructure:"database_reader_endpoint"`
	User           string `mapstructure:"database_user"`
	Port           int    `mapstructure:"database_port"`
	Region         string `mapstructure:"region"`
	SSLMode        string `mapstructure:"ssl_mode"`
}

type RedisConfig struct {
	Endpoint  string `mapstructure:"cluster_endpoint"`
	Port      string `mapstructure:"port"`
	Duration  int    `mapstructure:"duration"`
	Period    int    `mapstructure:"period"`
	RateLimit int    `mapstructure:"rate_limit"`
}

type FirehoseConfig struct {
	Stream string `mapstructure:"stream"`
	Region string `mapstructure:"region"`
}

type KMSConfig struct {
	KeyId            string `mapstructure:"key_id"`
	SigningAlgorithm string `mapstructure:"signing_algorithm"`
	Region           string `mapstructure:"region"`
	AuthValidity     int    `mapstructure:"auth_validity"`
}

type SecretsManagerConfig struct {
	SecretId string `mapstructure:"secret_id"`
	Region   string `mapstructure:"region"`
}

type Environment struct {
	Local         []string `mapstructure:"local"`
	Sandbox       []string `mapstructure:"sandbox"`
	Development   []string `mapstructure:"development"`
	Staging       []string `mapstructure:"staging"`
	PreProduction []string `mapstructure:"pre_production"`
	Production    []string `mapstructure:"production"`
	Corporate     []string `mapstructure:"corporate"`
}

type Config struct {
	GRPCServerAddress   string                            `mapstructure:"grpc_server_address"`
	OCSPServer          []string                          `mapstructure:"ocsp_server"`
	Database            DatabaseConfig                    `mapstructure:"database"`
	Redis               RedisConfig                       `mapstructure:"redis"`
	KMS                 KMSConfig                         `mapstructure:"kms"`
	Firehose            FirehoseConfig                    `mapstructure:"firehose"`
	Domains             []string                          `mapstructure:"domains"`
	ACMPCA              map[string]SubordinateCertificate `mapstructure:"acm_pca"`
	SecretsManager      SecretsManagerConfig              `mapstructure:"secrets_manager"`
	SubordinateMetadata SubordinateCertificateAuthority   `mapstructure:"subordinate_ca_metadata"`
	Environment         Environment                       `mapstructure:"certificate_authority"`
}
