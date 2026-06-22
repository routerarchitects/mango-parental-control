package config

import (
	"github.com/caarlos0/env/v11"
	subsystem "github.com/routerarchitects/ow-common-mods/fiber/system-routes"
	"github.com/routerarchitects/ow-common-mods/servicediscovery"
	"github.com/routerarchitects/ra-common-mods/kafka"
	"github.com/routerarchitects/ra-common-mods/logger"
)

type ServerConfig struct {
	HTTPPort    int    `env:"HTTP_PORT" envDefault:"16008"`
	PrivatePort int    `env:"PRIVATE_HTTP_PORT" envDefault:"17008"`
	TLS_CERT    string `env:"INTERNAL_RESTAPI_HOST_CERT"`
	TLS_KEY     string `env:"INTERNAL_RESTAPI_HOST_KEY"`
	TLS_ROOTCA  string `env:"INTERNAL_RESTAPI_HOST_ROOTCA"`
}

type PostgresConfig struct {
	StorageType string `env:"STORAGE_TYPE" envDefault:"postgresql"`
	Host        string `env:"STORAGE_TYPE_POSTGRESQL_HOST" envDefault:"localhost"`
	Port        int    `env:"STORAGE_TYPE_POSTGRESQL_PORT" envDefault:"5432"`
	Username    string `env:"STORAGE_TYPE_POSTGRESQL_USERNAME" envDefault:"postgres"`
	Password    string `env:"STORAGE_TYPE_POSTGRESQL_PASSWORD" envDefault:"postgres"`
	Database    string `env:"STORAGE_TYPE_POSTGRESQL_DATABASE" envDefault:"postgres"`
	SSLMode     string `env:"STORAGE_TYPE_POSTGRESQL_SSLMODE" envDefault:"disable"`
}

type DiscoveryConfig struct {
	Enabled bool `env:"DISCOVERY_ENABLED" envDefault:"true"`
	servicediscovery.Config
}

type RPCConfig struct {
	Enabled bool `env:"SERVICE_RPC_ENABLED" envDefault:"true"`
}

type AuthConfig struct {
	Enabled bool `env:"AUTH_ENABLED" envDefault:"true"`
}

type Config struct {
	Server    ServerConfig
	Database  PostgresConfig
	Kafka     kafka.Config
	Discovery DiscoveryConfig
	RPC       RPCConfig
	Auth      AuthConfig
	Logger    logger.Config
	Subsystem subsystem.Config
}

// Load parses environment variables into the Config struct.
func Load() (*Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
