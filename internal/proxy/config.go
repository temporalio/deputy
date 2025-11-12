package proxy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config describes one or more listeners exposed by the proxy server.
type Config struct {
	Listeners []ListenerConfig `yaml:"listeners"`
}

// ListenerConfig configures a single HTTP listener bound to an ecosystem adapter.
type ListenerConfig struct {
	Name       string   `yaml:"name"`
	Bind       string   `yaml:"bind"`
	Ecosystems []string `yaml:"ecosystems"`
	Upstream   string   `yaml:"upstream"`
	Policies   []string `yaml:"policies"`
}

// LoadConfig loads YAML/JSON configuration from the provided path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if len(cfg.Listeners) == 0 {
		return Config{}, fmt.Errorf("config must define at least one listener")
	}
	return cfg, nil
}

// MarshalTemplate renders a starter configuration for the specified ecosystem.
func MarshalTemplate(ecosystem string) (string, error) {
	var cfg Config
	switch ecosystem {
	case "", "go":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "go-proxy",
					Bind:       ":8080",
					Ecosystems: []string{"go"},
					Upstream:   "https://proxy.golang.org",
					Policies:   []string{"policy/go-proxy.cel"},
				},
			},
		}
	case "pypi":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "pypi-proxy",
					Bind:       ":8081",
					Ecosystems: []string{"pypi"},
					Upstream:   "https://pypi.org",
					Policies:   []string{"policy/pypi.cel"},
				},
			},
		}
	case "npm":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "npm-proxy",
					Bind:       ":8082",
					Ecosystems: []string{"npm"},
					Upstream:   "https://registry.npmjs.org",
					Policies:   []string{"policy/npm.cel"},
				},
			},
		}
	case "rubygems":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "rubygems-proxy",
					Bind:       ":8083",
					Ecosystems: []string{"rubygems"},
					Upstream:   "https://rubygems.org",
					Policies:   []string{"policy/rubygems.cel"},
				},
			},
		}
	default:
		return "", fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
