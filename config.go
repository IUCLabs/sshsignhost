package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath = "/opt/sshsignhost/config.yaml"
	defaultTTL        = "87600h"
	defaultJWTPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101
	defaultTimeout    = 15 * time.Second

	authAppRole    = "approle"
	authKubernetes = "kubernetes"
)

type configFile struct {
	Vault vaultConfig `yaml:"vault"`
}

type vaultConfig struct {
	Addr          string `yaml:"addr"`
	AuthMethod    string `yaml:"auth_method"`
	MountPoint    string `yaml:"mount_point"`
	RoleName      string `yaml:"role_name"`
	RoleID        string `yaml:"role_id"`
	AppRolePath   string `yaml:"approle_path"`
	K8sMount      string `yaml:"k8s_mount"`
	K8sRole       string `yaml:"k8s_role"`
	JWTPath       string `yaml:"jwt_path"`
	TLSSkipVerify *bool  `yaml:"tls_skip_verify"`
	Timeout       string `yaml:"timeout"`
}

func loadConfig(path string) (vaultConfig, error) {
	raw, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return vaultConfig{}, fmt.Errorf("reading config %q: %w", path, err)
	}

	var parsed configFile
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return vaultConfig{}, fmt.Errorf("parsing config %q: %w", path, err)
	}

	cfg := parsed.Vault
	if cfg.AuthMethod == "" {
		cfg.AuthMethod = authAppRole
	}
	if cfg.JWTPath == "" {
		cfg.JWTPath = defaultJWTPath
	}

	if err := cfg.validate(); err != nil {
		return vaultConfig{}, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

func (c vaultConfig) validate() error {
	required := []struct {
		key   string
		value string
	}{
		{"addr", c.Addr},
		{"mount_point", c.MountPoint},
		{"role_name", c.RoleName},
	}
	for _, field := range required {
		if field.value == "" {
			return fmt.Errorf("vault.%s is required", field.key)
		}
	}

	switch c.AuthMethod {
	case authAppRole:
		if c.RoleID == "" {
			return fmt.Errorf("vault.role_id is required for auth_method %q", authAppRole)
		}
		if c.AppRolePath == "" {
			return fmt.Errorf("vault.approle_path is required for auth_method %q", authAppRole)
		}
	case authKubernetes:
		if c.K8sMount == "" {
			return fmt.Errorf("vault.k8s_mount is required for auth_method %q", authKubernetes)
		}
		if c.K8sRole == "" {
			return fmt.Errorf("vault.k8s_role is required for auth_method %q", authKubernetes)
		}
	default:
		return fmt.Errorf("unsupported auth_method %q: expected %q or %q", c.AuthMethod, authAppRole, authKubernetes)
	}

	if _, err := c.requestTimeout(); err != nil {
		return err
	}
	return nil
}

// TLS verification stays off by default because the estate's Vault listeners
// are not yet covered by trusted certificates; set tls_skip_verify: false once
// they are.
func (c vaultConfig) skipTLSVerify() bool {
	return c.TLSSkipVerify == nil || *c.TLSSkipVerify
}

func (c vaultConfig) requestTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return defaultTimeout, nil
	}
	timeout, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 0, fmt.Errorf("vault.timeout %q is not a duration: %w", c.Timeout, err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("vault.timeout %q must be positive", c.Timeout)
	}
	return timeout, nil
}
