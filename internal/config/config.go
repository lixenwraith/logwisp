package config

// --- LogWisp Configuration Options ---

// Config is the top-level configuration structure for the LogWisp application
type Config struct {
	Quiet bool `toml:"quiet" help:"silence lw's own log and notices; pipeline output still flows"`

	// "auto" is a terminal with NO_COLOR unset and TERM not dumb
	Color string `toml:"color" lw:"enum=auto|always|never" help:"level names in color on console sinks without their own"`

	StatusReporter   bool `toml:"status_reporter" help:"log pipeline statistics every 30 s at debug; without a file, off"`
	ConfigAutoReload bool `toml:"auto_reload" help:"reload when the file changes"`

	// Selected file path is runtime metadata, never a configurable override.
	ConfigFile string `toml:"-"`

	// Existing fields
	Logging   *LogConfig       `toml:"logging"`
	Pipelines []PipelineConfig `toml:"pipelines"`
}

// --- Logging Options ---

// LogConfig represents the logging configuration for the LogWisp application itself
type LogConfig struct {
	Output       string `toml:"output" lw:"enum=file|stdout|stderr|split|all|none" help:"where lw's own log goes; split: warn and error to stderr"`
	Level        string `toml:"level" lw:"enum=debug|info|warn|error" help:"lowest level logged; without a file, warn"`
	Format       string `toml:"format" lw:"enum=raw|txt|json,zero=the log default" help:"format of lw's own log"`
	Sanitization string `toml:"sanitization" lw:"enum=raw|json|txt|shell,zero=the log default" help:"how the console log escapes control characters"`

	// File output settings (when Output includes "file" or "all")
	File *LogFileConfig `toml:"file"`

	// Console output settings
	Console *LogConsoleConfig `toml:"console"`
}

// LogFileConfig defines settings for file-based application logging
type LogFileConfig struct {
	Directory      string  `toml:"directory" lw:"hint=dir" help:"where file and all write; the limits below delete old .log files in it"`
	Name           string  `toml:"name" help:"base name of the files"`
	MaxSizeMB      int64   `toml:"max_size_mb" help:"size at which a file rotates"`
	MaxTotalSizeMB int64   `toml:"max_total_size_mb" help:"size of all .log files there, beyond which the oldest go"`
	RetentionHours float64 `toml:"retention_hours" help:"hours a .log file is kept; 0 keeps them"`
}

// LogConsoleConfig defines settings for console-based application logging
type LogConsoleConfig struct {
	Target string `toml:"target" lw:"enum=stdout|stderr|split" help:"accepted without effect: logging.output chooses the console"`
}

// --- Pipeline ---

// PipelineConfig defines a complete data flow from sources to sinks
type PipelineConfig struct {
	Name string      `toml:"name"`
	Flow *FlowConfig `toml:"flow"`

	PluginSources []PluginSourceConfig `toml:"plugin_sources,omitempty"`
	PluginSinks   []PluginSinkConfig   `toml:"plugin_sinks,omitempty"`
}

// --- Flow ---

// FlowConfig holds the stages between sources and sinks, in the order entries
// pass them; the heartbeat runs beside them
type FlowConfig struct {
	RateLimit *RateLimitConfig `toml:"rate_limit"`
	Filters   []FilterConfig   `toml:"filters,omitempty"`
	Format    *FormatConfig    `toml:"format"`
	Heartbeat *HeartbeatConfig `toml:"heartbeat"`
}

// --- Flow stages ---

// HeartbeatConfig defines settings for periodic keep-alive or status messages
type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled" help:"send heartbeats"`
	IntervalMS       int64  `toml:"interval_ms" default:"1000" lw:"min=100" help:"milliseconds between heartbeats"`
	IncludeTimestamp bool   `toml:"include_timestamp" help:"stamp each heartbeat with its time"`
	IncludeStats     bool   `toml:"include_stats" help:"add the pipeline's counters"`
	Format           string `toml:"format" default:"txt" lw:"enum=txt|json|raw" help:"heartbeat format"`
}

// FormatConfig is how a pipeline writes its entries
type FormatConfig struct {
	Type            string `toml:"type" default:"raw" lw:"enum=raw|txt|text|json" help:"entry format; text is txt"`
	Flags           int64  `toml:"flags,omitempty" lw:"zero=by type" help:"formatter flags"`
	TimestampFormat string `toml:"timestamp_format,omitempty" lw:"zero=RFC 3339" help:"Go time layout of timestamps"`
	SanitizerPolicy string `toml:"sanitizer_policy,omitempty" lw:"enum=raw|json|txt|shell,zero=by type" help:"how control characters are escaped"`
}

// RateLimitPolicy defines the action to take when a rate limit is exceeded
type RateLimitPolicy int

const (
	// PolicyPass allows all logs through, effectively disabling the limiter
	PolicyPass RateLimitPolicy = iota
	// PolicyDrop drops logs that exceed the rate limit
	PolicyDrop
)

// RateLimitConfig defines the configuration for pipeline-level rate limiting
type RateLimitConfig struct {
	Rate              float64 `toml:"rate" lw:"min=0,zero=off" help:"entries a second"`
	Burst             float64 `toml:"burst" lw:"min=0,zero=the rate" help:"entries at once"`
	Policy            string  `toml:"policy" default:"pass" lw:"enum=pass|drop" help:"drop entries over the rate, or pass them"`
	MaxEntrySizeBytes int64   `toml:"max_entry_size_bytes" lw:"min=0,zero=unlimited" help:"drop larger entries"`
}

// FilterType represents the filter's behavior (include or exclude)
type FilterType string

const (
	// FilterTypeInclude specifies that only matching logs will pass
	FilterTypeInclude FilterType = "include"
	// FilterTypeExclude specifies that matching logs will be dropped
	FilterTypeExclude FilterType = "exclude"
)

// FilterLogic represents how multiple filter patterns are combined
type FilterLogic string

const (
	// FilterLogicOr specifies that a match on any pattern is sufficient
	FilterLogicOr FilterLogic = "or"
	// FilterLogicAnd specifies that all patterns must match
	FilterLogicAnd FilterLogic = "and"
)

// FilterConfig represents the configuration for a single filter
type FilterConfig struct {
	Type     FilterType  `toml:"type" default:"include" lw:"enum=include|exclude" help:"pass only matching entries, or drop them"`
	Logic    FilterLogic `toml:"logic" default:"or" lw:"enum=or|and" help:"match any pattern, or all"`
	Patterns []string    `toml:"patterns,omitempty" lw:"hint=regex" help:"RE2 patterns"`
}

// --- Sources ---

// PluginSourceConfig represents a source plugin instance configuration
type PluginSourceConfig struct {
	ID         string         `toml:"id"`
	Type       string         `toml:"type"`
	Config     map[string]any `toml:"config"`
	ConfigFile string         `toml:"config_file,omitempty"` // TODO: support for include/source mechanism for nested config
}

// NullSourceOptions defines settings for a null source (no configuration needed)
type NullSourceOptions struct{}

// RandomSourceOptions defines settings for a random log generator source
type RandomSourceOptions struct {
	IntervalMS int64  `toml:"interval_ms" default:"500" lw:"min=1" help:"milliseconds between entries"`
	JitterMS   int64  `toml:"jitter_ms" lw:"min=0,zero=none" help:"random milliseconds added to the interval, at most the interval"`
	Format     string `toml:"format" default:"txt" lw:"enum=raw|txt|json" help:"entry format"`
	Length     int64  `toml:"length" default:"20" lw:"min=1" help:"message characters"`
	Special    bool   `toml:"special" help:"mix in control characters"`
}

// FileSourceOptions defines settings for a file-based source
type FileSourceOptions struct {
	Directory       string `toml:"directory" lw:"required,hint=dir" help:"directory whose files are followed"`
	Pattern         string `toml:"pattern" default:"*" lw:"hint=glob" help:"glob the file names match"`
	CheckIntervalMS int64  `toml:"check_interval_ms" default:"100" lw:"min=10" help:"milliseconds between scans for files"`
	Raw             bool   `toml:"raw" help:"keep the whole line as the message, never parse it"`
	From            string `toml:"from" default:"end" lw:"enum=start|end" help:"where reading a newly found file starts"`
}

// ConsoleSourceOptions defines settings for a stdin-based source
type ConsoleSourceOptions struct {
	BufferSize int64 `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
}

// TCPChainSourceOptions defines settings for a stdlib TCP listener ingesting
// NDJSON entries from upstream logwisp tcp_chain sinks
type TCPChainSourceOptions struct {
	TLS            *TLSOptions  `toml:"tls"`
	Host           string       `toml:"host" default:"0.0.0.0" lw:"hint=host" help:"address to listen on; :: for IPv6"`
	Port           int64        `toml:"port" lw:"required,min=1,max=65535" help:"port to listen on"`
	BufferSize     int64        `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
	MaxConnections int64        `toml:"max_connections" lw:"min=0,zero=unlimited" help:"connections at once"`
	ReadTimeoutMS  int64        `toml:"read_timeout_ms" lw:"min=0,zero=none" help:"milliseconds a connection may idle"`
	HelloTimeoutMS int64        `toml:"hello_timeout_ms" default:"10000" lw:"min=1" help:"milliseconds for a peer's hello"`
	TrustNode      bool         `toml:"trust_node" default:"true" help:"keep the node label a peer declares; off, the label is its address"`
	Auth           *AuthOptions `toml:"auth"`
	ACL            *ACLOptions  `toml:"acl"`
}

// HTTPChainSourceOptions defines settings for a stdlib HTTP listener ingesting
// NDJSON batches from upstream logwisp http_chain sinks
type HTTPChainSourceOptions struct {
	TLS           *TLSOptions  `toml:"tls"`
	Host          string       `toml:"host" default:"0.0.0.0" lw:"hint=host" help:"address to listen on; :: for IPv6"`
	Port          int64        `toml:"port" lw:"required,min=1,max=65535" help:"port to listen on"`
	IngestPath    string       `toml:"ingest_path" default:"/ingest" lw:"hint=path" help:"path batches are posted to"`
	BufferSize    int64        `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
	MaxBodyBytes  int64        `toml:"max_body_bytes" default:"8388608" lw:"min=1" help:"largest batch accepted"`
	ReadTimeoutMS int64        `toml:"read_timeout_ms" default:"30000" lw:"min=1" help:"milliseconds to read a request"`
	TrustNode     bool         `toml:"trust_node" default:"true" help:"keep the node label a peer declares; off, the label is its address"`
	Auth          *AuthOptions `toml:"auth"`
	ACL           *ACLOptions  `toml:"acl"`
}

// --- Sinks ---

// PluginSinkConfig represents a sink plugin instance configuration
type PluginSinkConfig struct {
	ID         string         `toml:"id"`
	Type       string         `toml:"type"`
	Config     map[string]any `toml:"config"`
	ConfigFile string         `toml:"config_file,omitempty"` // TODO: support for include/source mechanism for nested config
}

// NullSinkOptions defines settings for a null sink (no configuration needed)
type NullSinkOptions struct{}

// ConsoleSinkOptions defines settings for a console-based sink
type ConsoleSinkOptions struct {
	Target     string `toml:"target" default:"stdout" lw:"enum=stdout|stderr" help:"stream written to"`
	BufferSize int64  `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
	Escape     string `toml:"escape" default:"auto" lw:"enum=auto|always|never" help:"write control characters as <hex>; auto on a terminal"`
	Color      string `toml:"color" default:"auto" lw:"enum=auto|always|never" help:"level names in color; unset, the top-level color"`
}

// FileSinkOptions defines settings for a file-based sink
type FileSinkOptions struct {
	Directory       string  `toml:"directory" lw:"required,hint=dir" help:"directory written to"`
	Name            string  `toml:"name" lw:"required" help:"base name of the files"`
	MaxSizeMB       int64   `toml:"max_size_mb" default:"100" lw:"min=1" help:"size at which a file rotates"`
	MaxTotalSizeMB  int64   `toml:"max_total_size_mb" default:"1000" lw:"min=1" help:"size of all files, beyond which the oldest go"`
	MinDiskFreeMB   int64   `toml:"min_disk_free_mb" lw:"zero=none" help:"free space kept on the disk; negative means 100"`
	RetentionHours  float64 `toml:"retention_hours" default:"168" lw:"min=0" help:"hours a file is kept"`
	BufferSize      int64   `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
	FlushIntervalMs int64   `toml:"flush_interval_ms" default:"100" lw:"min=1" help:"milliseconds between flushes"`
}

// TCPSinkOptions defines settings for a TCP server sink
type TCPSinkOptions struct {
	TLS               *TLSOptions  `toml:"tls"`
	Host              string       `toml:"host" default:"0.0.0.0" lw:"hint=host" help:"address to listen on; :: for IPv6"`
	Port              int64        `toml:"port" lw:"required,min=1,max=65535" help:"port to listen on"`
	BufferSize        int64        `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued for all clients"`
	ClientBufferSize  int64        `toml:"client_buffer_size" default:"256" lw:"min=1" help:"entries queued per client"`
	WriteTimeoutMS    int64        `toml:"write_timeout_ms" default:"5000" lw:"min=1" help:"milliseconds a write may take before the client is dropped"`
	KeepAlive         bool         `toml:"keep_alive" default:"true" help:"TCP keep-alive"`
	KeepAlivePeriodMS int64        `toml:"keep_alive_period_ms" default:"30000" lw:"min=1" help:"milliseconds idle before a keep-alive probe"`
	MaxConnections    int64        `toml:"max_connections" lw:"min=0,zero=unlimited" help:"clients at once"`
	Auth              *AuthOptions `toml:"auth"`
	ACL               *ACLOptions  `toml:"acl"`
}

// HTTPSinkOptions defines settings for an HTTP SSE server sink
type HTTPSinkOptions struct {
	TLS              *TLSOptions  `toml:"tls"`
	Host             string       `toml:"host" default:"0.0.0.0" lw:"hint=host" help:"address to listen on; :: for IPv6"`
	Port             int64        `toml:"port" lw:"required,min=1,max=65535" help:"port to listen on"`
	StreamPath       string       `toml:"stream_path" default:"/stream" lw:"hint=path" help:"path of the event stream"`
	StatusPath       string       `toml:"status_path" default:"/status" lw:"hint=path" help:"path of the status document"`
	BufferSize       int64        `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued for all clients"`
	ClientBufferSize int64        `toml:"client_buffer_size" default:"256" lw:"min=1" help:"entries queued per client"`
	WriteTimeoutMS   int64        `toml:"write_timeout_ms" lw:"min=0,zero=none" help:"milliseconds an event write may take"`
	MaxConnections   int64        `toml:"max_connections" lw:"min=0,zero=unlimited" help:"clients at once"`
	ReplayLines      int64        `toml:"replay_lines" lw:"min=0,zero=none" help:"recent entries a new stream gets first"`
	LoginPage        bool         `toml:"login_page" help:"serve the login page; scram behind auth.trusted_proxies"`
	ViewerPage       bool         `toml:"viewer_page" help:"serve the viewer to users logged in; needs login_page"`
	Auth             *AuthOptions `toml:"auth"`
	ACL              *ACLOptions  `toml:"acl"`
}

// TCPChainSinkOptions defines settings for a stdlib TCP client forwarding
// entries to a downstream logwisp tcp_chain source
type TCPChainSinkOptions struct {
	TLS               *TLSOptions  `toml:"tls"`
	Node              string       `toml:"node" lw:"zero=the host name" help:"origin label of the entries"`
	Host              string       `toml:"host" lw:"required,hint=host" help:"host of the tcp_chain source"`
	Port              int64        `toml:"port" lw:"required,min=1,max=65535" help:"port of the tcp_chain source"`
	BufferSize        int64        `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
	DialTimeoutMS     int64        `toml:"dial_timeout_ms" default:"5000" lw:"min=1" help:"milliseconds to connect"`
	WriteTimeoutMS    int64        `toml:"write_timeout_ms" default:"5000" lw:"min=1" help:"milliseconds a write may take"`
	BackoffMinMS      int64        `toml:"backoff_min_ms" default:"500" lw:"min=1" help:"first wait before reconnecting"`
	BackoffMaxMS      int64        `toml:"backoff_max_ms" default:"30000" lw:"min=1" help:"longest wait before reconnecting; below the first, the default"`
	KeepAlivePeriodMS int64        `toml:"keep_alive_period_ms" default:"30000" lw:"min=1" help:"milliseconds idle before a keep-alive probe"`
	KeepAlive         bool         `toml:"keep_alive" default:"true" help:"TCP keep-alive"`
	Auth              *AuthOptions `toml:"auth"`
}

// HTTPChainSinkOptions defines settings for a stdlib HTTP client posting
// NDJSON batches to a downstream logwisp http_chain source
type HTTPChainSinkOptions struct {
	TLS              *TLSOptions  `toml:"tls"`
	Node             string       `toml:"node" lw:"zero=the host name" help:"origin label of the entries"`
	Host             string       `toml:"host" lw:"required,hint=host" help:"host of the http_chain source"`
	Port             int64        `toml:"port" lw:"required,min=1,max=65535" help:"port of the http_chain source"`
	IngestPath       string       `toml:"ingest_path" default:"/ingest" lw:"hint=path" help:"path batches are posted to"`
	BufferSize       int64        `toml:"buffer_size" default:"1000" lw:"min=1" help:"entries queued"`
	MaxBatchCount    int64        `toml:"max_batch_count" default:"100" lw:"min=1" help:"entries in a batch"`
	MaxBatchBytes    int64        `toml:"max_batch_bytes" default:"1048576" lw:"min=1" help:"bytes in a batch"`
	FlushIntervalMS  int64        `toml:"flush_interval_ms" default:"1000" lw:"min=1" help:"milliseconds before a partial batch is sent"`
	RequestTimeoutMS int64        `toml:"request_timeout_ms" default:"10000" lw:"min=1" help:"milliseconds for a request: dial, write and response"`
	BackoffMinMS     int64        `toml:"backoff_min_ms" default:"500" lw:"min=1" help:"first wait before retrying"`
	BackoffMaxMS     int64        `toml:"backoff_max_ms" default:"30000" lw:"min=1" help:"longest wait before retrying; below the first, the default"`
	Auth             *AuthOptions `toml:"auth"`
}

// --- Auth Options ---

// AuthOptions selects how a network plugin authenticates its peer. It sits
// beside `tls`: TLS answers "is this channel private", auth answers "may this
// peer do this". Listeners verify (mtls: certificate identity; scram: password
// via credentials_file); dialers prove themselves (scram) or pin the server
// (mtls). AuthOptions.Check holds the rules of each side.
type AuthOptions struct {
	Type            string   `toml:"type" default:"none" lw:"enum=none|mtls|scram" help:"how peers authenticate"`
	Identity        string   `toml:"identity" lw:"enum=cn|san_dns|san_uri|san_email,zero=cn under mtls; no binding under scram" help:"certificate field naming the peer; under scram it must equal the user"`
	Allow           []string `toml:"allow" help:"mtls: identities admitted; with allow_patterns empty, any the CA issued"`
	AllowPatterns   []string `toml:"allow_patterns" lw:"hint=regex" help:"mtls: RE2 patterns of identities admitted; anchor them"`
	NodeBinding     string   `toml:"node_binding" lw:"listener,enum=none|assert|force,zero=force" help:"chain sources: how a peer's identity binds its node label; overrides trust_node"`
	CredentialsFile string   `toml:"credentials_file" lw:"listener,hint=file" help:"scram: verifiers, from lw auth add-user"`
	// exp has whole seconds, a sub-second expires_in reads as unknown, and 10 s
	// leaves room for renewal ahead of expiry
	TokenLifetimeMS int64    `toml:"token_lifetime_ms" lw:"listener,min=10000,max=86400000,zero=15 minutes" help:"scram on HTTP: bearer token lifetime"`
	TrustedProxies  []string `toml:"trusted_proxies" lw:"listener,hint=cidr" help:"scram on the http sink: proxies ending the browsers' TLS; logins are then unbound"`
	Username        string   `toml:"username" lw:"dialer" help:"scram: the user this dialer logs in as"`
	PasswordFile    string   `toml:"password_file" lw:"dialer,hint=file" help:"scram: file holding the user's password"`
}

// ACLOptions is a listener's address rules, entries being addresses or CIDRs:
// deny wins, then a set allow list admits only its entries. proxy_from lists
// the L4 proxies whose PROXY header names the client the rules then see; the
// per-client limits count that client. ACLOptions.Check holds the rules.
type ACLOptions struct {
	Allow                      []string `toml:"allow" lw:"hint=cidr" help:"addresses admitted; empty, all deny does not list"`
	Deny                       []string `toml:"deny" lw:"hint=cidr" help:"addresses refused"`
	ProxyProtocol              string   `toml:"proxy_protocol" default:"off" lw:"enum=off|optional|required" help:"read a PROXY header from proxy_from"`
	ProxyFrom                  []string `toml:"proxy_from" lw:"hint=cidr" help:"proxies that may send a PROXY header"`
	MaxConnectionsPerClient    int64    `toml:"max_connections_per_client" lw:"min=0,zero=unlimited" help:"connections a client may hold"`
	RequestsPerSecondPerClient float64  `toml:"requests_per_second_per_client" lw:"min=0,zero=unlimited" help:"HTTP: requests a client may make each second"`
}

// --- TLS Options ---

// TLSOptions is one shape for both roles. Listeners present cert_file and
// key_file, or a certificate issued at startup (self_signed, or from the
// issuer files), and verify clients with client_auth and client_ca_file;
// dialers verify the server with ca_file and server_name, or pin_sha256, and
// may present cert_file and key_file.
type TLSOptions struct {
	Enabled            bool     `toml:"enabled" help:"use TLS"`
	CertFile           string   `toml:"cert_file" lw:"hint=file" help:"certificate presented; a dialer's for mTLS"`
	KeyFile            string   `toml:"key_file" lw:"hint=file" help:"key of cert_file"`
	SelfSigned         bool     `toml:"self_signed" lw:"listener" help:"a self-signed certificate on a key made at startup"`
	IssuerCertFile     string   `toml:"issuer_cert_file" lw:"listener,hint=file" help:"CA certificate (lw tls ca) that issues the listener's at startup"`
	IssuerKeyFile      string   `toml:"issuer_key_file" lw:"listener,hint=file" help:"key of issuer_cert_file"`
	Hosts              []string `toml:"hosts" lw:"listener" help:"names and addresses a made certificate carries beyond host, this machine's and loopback"`
	ClientAuth         bool     `toml:"client_auth" lw:"listener" help:"require and verify client certificates"`
	ClientCAFile       string   `toml:"client_ca_file" lw:"listener,hint=file" help:"CA bundle verifying client certificates"`
	CAFile             string   `toml:"ca_file" lw:"dialer,hint=file,zero=the system roots" help:"CA bundle verifying the server"`
	ServerName         string   `toml:"server_name" lw:"dialer,zero=the host" help:"name the server's certificate must carry"`
	InsecureSkipVerify bool     `toml:"insecure_skip_verify" lw:"dialer" help:"verify nothing of the server; never in production"`
	PinSHA256          string   `toml:"pin_sha256" lw:"dialer" help:"sha256//BASE64 of the server's key, ';' between several; replaces ca_file"`
	MinVersion         string   `toml:"min_version" default:"1.3" lw:"enum=1.2|1.3" help:"lowest TLS version"`
}
