package http

import (
	"bytes"
	"context"
	"embed"
	"html"
	"net/http"
	"path"
	"strings"

	"logwisp/internal/authz"
	"logwisp/internal/chain"
	"logwisp/internal/config"
)

//go:embed web/*.js web/*.html web/*.css
var webFiles embed.FS

// pageCSP confines the pages to their own scripts and styles: no inline code,
// no other origin, no framing
const pageCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

var webTypes = map[string]string{
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".html": "text/html; charset=utf-8",
}

func loginOn(o *config.HTTPSinkOptions) bool  { return o.LoginPage }
func viewerOn(o *config.HTTPSinkOptions) bool { return o.ViewerPage }

// webRoutes are served under /auth/ in proxy mode: the client library always,
// so a site can load it, and the pages when enabled
var webRoutes = []struct {
	name, file string
	on         func(*config.HTTPSinkOptions) bool
}{
	{"scram.js", "scram.js", func(*config.HTTPSinkOptions) bool { return true }},
	{"style.css", "style.css", loginOn},
	{"login", "login.html", loginOn},
	{"login.js", "login.js", loginOn},
	{"view", "view.html", viewerOn},
	{"view.js", "view.js", viewerOn},
}

// webHandlers maps each enabled GET path to its file. The viewer learns a
// custom status path from a meta tag, as the CSP allows no inline script.
func webHandlers(o *config.HTTPSinkOptions) (map[string]http.Handler, error) {
	handlers := make(map[string]http.Handler)
	for _, r := range webRoutes {
		if !r.on(o) {
			continue
		}
		data, err := webFiles.ReadFile("web/" + r.file)
		if err != nil {
			return nil, err
		}
		if r.file == "view.html" {
			status := html.EscapeString(strings.TrimPrefix(o.StatusPath, "/"))
			data = bytes.Replace(data, []byte(`content="status"`), []byte(`content="`+status+`"`), 1)
		}
		handlers[chain.AuthPath+"/"+r.name] = serveWebFile(data, webTypes[path.Ext(r.file)])
	}
	return handlers, nil
}

func serveWebFile(data []byte, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hd := w.Header()
		hd.Set("Content-Type", contentType)
		hd.Set("Content-Security-Policy", pageCSP)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-cache")
		w.Write(data)
	})
}

// clientKey carries the forwarded client address from proxyGate
type clientKey struct{}

// proxyGate admits only the trusted proxies, and records the client they
// forward for logs and sessions. ServeAuth and AuthorizeRequest check again.
func (h *HTTPSink) proxyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := h.auth.ClientAddr(r)
		if err != nil {
			h.logger.Warn("msg", "Request refused: not through a trusted proxy over https",
				"component", "http_sink",
				"instance_id", h.id,
				"remote_addr", r.RemoteAddr,
				"path", r.URL.Path,
				"error", err)
			authz.Refuse(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, addr)))
	})
}

// clientAddr names the client in logs and sessions: the forwarded client in
// proxy mode, else the socket peer
func clientAddr(r *http.Request) string {
	if addr, ok := r.Context().Value(clientKey{}).(string); ok {
		return addr
	}
	return r.RemoteAddr
}
