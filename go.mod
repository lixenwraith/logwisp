module logwisp

go 1.25.1

require (
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/lixenwraith/config v0.0.0-20250908085506-537a4d49d2c3
	github.com/lixenwraith/log v0.0.0-20250929084748-210374d95b3e
	github.com/panjf2000/gnet/v2 v2.9.4
	github.com/valyala/fasthttp v1.66.0
	golang.org/x/crypto v0.42.0
	golang.org/x/term v0.35.0
	golang.org/x/time v0.13.0
)

require (
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/panjf2000/ants/v2 v2.11.3 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mitchellh/mapstructure => github.com/go-viper/mapstructure v1.6.0
