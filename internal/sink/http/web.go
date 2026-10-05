package http

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"path"
	"strings"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/netacl"
)

//go:embed web/*.js web/*.html web/*.css web/*.svg
var webFiles embed.FS

// pageCSP confines the pages to their own scripts, styles and icon: no inline
// code, no other origin, no framing
const pageCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; " +
	"img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

var webTypes = map[string]string{
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".html": "text/html; charset=utf-8",
	".svg":  "image/svg+xml",
}

// webRoutes are the browser files under /auth/, each with the page that needs
// it; "" marks a shared file, served with any page and always in proxy mode,
// where a site may load the client library on its own
var webRoutes = []struct {
	name, file, page string
}{
	{"scram.js", "scram.js", ""},
	{"style.css", "style.css", ""},
	{"favicon.svg", "favicon.svg", ""},
	{"login", "login.html", "login"},
	{"login.js", "login.js", "login"},
	{"view", "view.html", "view"},
	{"view.js", "view.js", "view"},
}

// webHandlers maps each GET path a browser uses to its handler. Without a
// login (no auth, or mtls: the certificate is the login) the viewer is always
// served; under scram the pages need proxy mode. The viewer learns the status
// path, whether it logs in and the level table from meta tags, as the CSP
// allows no inline script.
func webHandlers(o *config.HTTPSinkOptions, p *authz.Policy) (map[string]http.Handler, error) {
	open := !p.NeedsLogin()
	on := map[string]bool{"": open || p.BehindProxy(), "login": o.LoginPage, "view": open || o.ViewerPage}
	handlers := make(map[string]http.Handler)
	for _, r := range webRoutes {
		if !on[r.page] {
			continue
		}
		data, err := webFiles.ReadFile("web/" + r.file)
		if err != nil {
			return nil, err
		}
		if r.file == "view.html" {
			status := html.EscapeString(strings.TrimPrefix(o.StatusPath, "/"))
			data = bytes.Replace(data, []byte(`name="logwisp-status" content="status"`), []byte(`name="logwisp-status" content="`+status+`"`), 1)
			if open {
				data = bytes.Replace(data, []byte(`name="logwisp-login" content="scram"`), []byte(`name="logwisp-login" content="none"`), 1)
			}
			levels, _ := json.Marshal(core.Levels)
			data = bytes.Replace(data, []byte(`name="logwisp-levels" content=""`), []byte(`name="logwisp-levels" content="`+html.EscapeString(string(levels))+`"`), 1)
		}
		handlers[chain.AuthPath+"/"+r.name] = serveWebFile(data, webTypes[path.Ext(r.file)])
	}
	switch {
	case o.StreamPath == "/" || o.StatusPath == "/": // the endpoint owns the root
	case on["view"]:
		handlers["/{$}"] = seeOther("auth/view")
	case on["login"]:
		handlers["/{$}"] = seeOther("auth/login")
	}
	return handlers, nil
}

// seeOther redirects to a relative target, which a proxy prefix keeps intact;
// http.Redirect would resolve it against the backend's path
func seeOther(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusSeeOther)
	})
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

// proxyGate admits only the trusted proxies, forwarding a client the acl
// rules admit, and records that client for logs, sessions and the request
// rate. ServeAuth and AuthorizeRequest check again.
func (h *HTTPSink) proxyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := h.auth.ClientAddr(r)
		if err != nil {
			if !errors.Is(err, netacl.ErrDenied) { // reported by netacl, once a minute
				h.logger.Warn("msg", "Request refused: not through a trusted proxy over https",
					"component", "http_sink",
					"instance_id", h.id,
					"remote_addr", r.RemoteAddr,
					"path", r.URL.Path,
					"error", err)
			}
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
