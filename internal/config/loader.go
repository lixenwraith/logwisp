package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/lixenwraith/logwisp/internal/core"

	lconfig "github.com/lixenwraith/config"
)

// ErrConfigNotFound identifies an explicitly requested missing configuration file.
var ErrConfigNotFound = lconfig.ErrConfigNotFound

// Manager owns the configuration sources and watcher for one application instance.
// Its snapshots are detached from each other and from the running service.
type Manager struct {
	config   *lconfig.Config
	path     string
	explicit bool
	read     bool           // the file was loaded once
	specs    []pipelineSpec // command-line or environment pipelines, kept across reloads
}

// Args is a parsed command line; cmd/lw owns its grammar.
type Args struct {
	File      string   // -c: the configuration file, "" for the environment or discovery
	Specs     []Spec   // pipeline flags, in order
	Overrides []string // --path=value settings and bare switches, for lixenwraith/config
}

// Settings maps each --path setting Load takes to whether it is a switch, which
// takes no separate value; the parser must not leave config to guess.
func Settings() map[string]bool {
	settings := map[string]bool{}
	for _, k := range SettingKeys() {
		settings[k.Name] = k.Kind == "bool"
	}
	return settings
}

// Load reads the startup sources and validates the initial configuration.
// Watching starts only when Watch is called after successful service startup.
func Load(args Args) (*Manager, error) {
	configPath, isExplicit := resolveConfigPath(args.File)
	specs, err := cliSpecs(args.Specs)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		specs = envPipelineSpecs()
	}
	if _, err := buildPipelines(specs, HostIsDir); err != nil {
		return nil, err
	}
	m := &Manager{path: configPath, explicit: isExplicit, specs: specs}
	initial := defaults()
	if _, err := os.Stat(configPath); errors.Is(err, fs.ErrNotExist) {
		// Without a file lw is a command-line tool: warnings and errors only
		initial.Logging.Level = "warn"
		initial.StatusReporter = false
	}
	cfg, err := lconfig.NewBuilder().
		WithTarget(initial).
		WithEnvPrefix("LOGWISP_").
		WithArgs(args.Overrides).
		WithFile(configPath).
		WithTypedValidator(func(cfg *Config) error {
			effective := *cfg // the builder keeps cfg; only the copy is replaced
			if err := m.usePipelines(&effective); err != nil {
				return err
			}
			return ValidateConfig(&effective)
		}).
		WithSecurityOptions(lconfig.SecurityOptions{
			PreventPathTraversal: true,
			MaxFileSize:          10 * 1024 * 1024,
		}).
		Build()
	if err != nil {
		if !errors.Is(err, lconfig.ErrConfigNotFound) {
			return nil, fmt.Errorf("failed to load or validate config: %w", err)
		}
		if isExplicit {
			return nil, fmt.Errorf("config file %q: %w", configPath, err)
		}
		// A missing discovered default still permits valid CLI/env/default values.
	}
	m.read = err == nil
	m.config = cfg
	return m, nil
}

// BuiltIn reports whether the pipelines are lw's built-in pipe: no file, flag
// or variable defined one
func (m *Manager) BuiltIn() bool {
	_, inFile := m.config.GetSource("pipelines", lconfig.SourceFile)
	return !inFile && len(m.specs) == 0
}

// Snapshot validates a detached candidate before it is used to build a service.
// Builder validators only run during Load, so every reload needs this check too.
func (m *Manager) Snapshot() (*Config, error) {
	value, err := m.config.AsStruct()
	if err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	cfg := value.(*Config)
	cfg.ConfigFile = m.path
	if err := m.usePipelines(cfg); err != nil {
		return nil, err
	}
	// The top-level color is each console sink's default; the maps are fresh
	for _, p := range cfg.Pipelines {
		for i, s := range p.PluginSinks {
			if _, set := s.Config["color"]; s.Type == "console" && !set {
				if s.Config == nil {
					p.PluginSinks[i].Config = map[string]any{}
				}
				p.PluginSinks[i].Config["color"] = cfg.Color
			}
		}
	}
	if err := checkFileKeys(m.path); err != nil {
		return nil, fmt.Errorf("config file %q: %w", m.path, err)
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}

// Uninherit removes the color Snapshot gave each console sink, so a dump or a
// composition leaves it inherited
func Uninherit(pipelines []PipelineConfig, color string) {
	for _, p := range pipelines {
		for _, s := range p.PluginSinks {
			if s.Type == "console" && s.Config["color"] == color {
				delete(s.Config, "color")
			}
		}
	}
}

// usePipelines replaces the file's or default pipelines with the spec ones.
func (m *Manager) usePipelines(cfg *Config) error {
	if len(m.specs) == 0 {
		return nil
	}
	pipelines, err := buildPipelines(m.specs, HostIsDir)
	cfg.Pipelines = pipelines
	return err
}

// Reload rereads the selected file, retaining the startup CLI/environment sources.
// Signals must call this even when automatic watching is disabled.
func (m *Manager) Reload() (*Config, error) {
	// As at startup, a discovered default that does not exist is no error, so a
	// file-less instance still rebuilds and rotates its certificates. Once read,
	// its removal is one: the loader would keep the removed file's values.
	err := m.config.LoadFile(m.path)
	if err != nil && (m.explicit || m.read || !errors.Is(err, ErrConfigNotFound)) {
		return nil, fmt.Errorf("reload %q: %w", m.path, err)
	}
	m.read = m.read || err == nil
	return m.Snapshot()
}

// Watch subscribes with logwisp's polling and debounce settings.
func (m *Manager) Watch() <-chan string {
	opts := lconfig.DefaultWatchOptions()
	opts.PollInterval = core.ReloadWatchPollInterval
	opts.Debounce = core.ReloadWatchDebounce
	opts.ReloadTimeout = core.ReloadWatchTimeout
	return m.config.WatchWithOptions(opts)
}

func (m *Manager) Close() { m.config.StopAutoUpdate() }

// defaults provides the default configuration values for the application.
// Data goes to stdout, so lw's own log goes to stderr.
func defaults() *Config {
	return &Config{
		StatusReporter: true,
		Color:          "auto",
		Logging: &LogConfig{
			Output: "stderr",
			Level:  "info",
			Format: "txt",
			File: &LogFileConfig{
				Directory:      "./log",
				Name:           "logwisp",
				MaxSizeMB:      100,
				MaxTotalSizeMB: 1000,
				RetentionHours: 168, // 7 days
			},
			Console: &LogConsoleConfig{
				Target: "stderr",
			},
		},
		Pipelines: []PipelineConfig{pipeDefault("pipe")},
	}
}

// pipeDefault is a filter in the Unix sense: stdin to stdout, line for line
func pipeDefault(name string) PipelineConfig {
	return PipelineConfig{
		Name:          name,
		Flow:          &FlowConfig{Format: &FormatConfig{Type: "raw"}},
		PluginSources: []PluginSourceConfig{{ID: "stdin", Type: "console", Config: map[string]any{}}},
		PluginSinks:   []PluginSinkConfig{{ID: "stdout", Type: "console", Config: map[string]any{}}},
	}
}

// resolveConfigPath picks the file: -c, then LOGWISP_CONFIG_FILE and
// LOGWISP_CONFIG_DIR, then the first of the user's and the working directory's
// logwisp.toml. Only the discovered default may be missing.
func resolveConfigPath(file string) (path string, isExplicit bool) {
	if file != "" {
		return file, true
	}
	if configFile := os.Getenv("LOGWISP_CONFIG_FILE"); configFile != "" {
		path = configFile
		if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
			path = filepath.Join(configDir, configFile)
		}
		return path, true
	}
	if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
		return filepath.Join(configDir, "logwisp.toml"), true
	}
	if path, err := UserFile(); err == nil {
		if _, err := os.Stat(path); err == nil {
			return path, false
		}
	}
	return "logwisp.toml", false
}

// DefaultPath is the file lw reads without -c
func DefaultPath() string {
	path, _ := resolveConfigPath("")
	return path
}

// UserFile is ~/.config/logwisp/logwisp.toml, the file lw reads first without -c
func UserFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "logwisp", "logwisp.toml"), nil
}
