package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultPort = "8080"
	DataFolder  = "/app/data"
	ConfigFile  = "/app/data/settings.json"
	CookieName  = "bermuda_session"
	SaltKey     = "BERMUDA1998_MONOCHROME_SALT_V4"

	WSSecretPath    = "/ws-cazar-gate"
	XHTTPSecretPath = "/xh-cazar-gate"
)

type Settings struct {
	UserHash    string `json:"user_hash"`
	PassHash    string `json:"pass_hash"`
	IsDefault   bool   `json:"is_default"`
	Domain      string `json:"domain"`
	City        string `json:"city"`
	CountryFlag string `json:"country_flag"`
	SessionKey  string `json:"session_key"`
}

var (
	configLock        sync.RWMutex
	rateLimitLock     sync.Mutex
	failedLoginEvents = make(map[string]*rateLimitRecord)
)

type rateLimitRecord struct {
	count     int
	blockedTo time.Time
}

func getInitialHash() string {
	raw := string([]byte{67, 97, 122, 97, 114, 115, 101, 110, 115, 101, 49, 50, 51, 52}) // "Cazarsense1234"
	return hashString(raw)
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s + ":" + SaltKey))
	return hex.EncodeToString(h[:])
}

func generateSecureToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func getSettings() Settings {
	configLock.RLock()
	defer configLock.RUnlock()

	initH := getInitialHash()
	s := Settings{
		UserHash:    initH,
		PassHash:    initH,
		IsDefault:   true,
		City:        "Amsterdam",
		CountryFlag: "🇳🇱",
	}

	b, err := os.ReadFile(ConfigFile)
	if err == nil {
		_ = json.Unmarshal(b, &s)
		if s.UserHash == "" || s.PassHash == "" {
			s.UserHash = initH
			s.PassHash = initH
			s.IsDefault = true
		}
		if s.City == "" {
			s.City = "Amsterdam"
			s.CountryFlag = "🇳🇱"
		}
	}
	return s
}

func saveSettings(s Settings) {
	configLock.Lock()
	defer configLock.Unlock()

	_ = os.MkdirAll(DataFolder, 0755)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(ConfigFile, b, 0644)
}

func checkAuth(r *http.Request, s Settings) bool {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" || s.SessionKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.SessionKey)) == 1
}

func setAuthCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return r.RemoteAddr
}

func isRateLimited(ip string) bool {
	rateLimitLock.Lock()
	defer rateLimitLock.Unlock()

	rec, exists := failedLoginEvents[ip]
	if !exists {
		return false
	}
	if time.Now().Before(rec.blockedTo) {
		return true
	}
	if time.Now().After(rec.blockedTo) && rec.count >= 5 {
		delete(failedLoginEvents, ip)
	}
	return false
}

func recordFailedLogin(ip string) {
	rateLimitLock.Lock()
	defer rateLimitLock.Unlock()

	rec, exists := failedLoginEvents[ip]
	if !exists {
		rec = &rateLimitRecord{}
		failedLoginEvents[ip] = rec
	}
	rec.count++
	if rec.count >= 5 {
		rec.blockedTo = time.Now().Add(10 * time.Minute)
	}
}

func resetRateLimit(ip string) {
	rateLimitLock.Lock()
	defer rateLimitLock.Unlock()
	delete(failedLoginEvents, ip)
}

func sanitizeDomain(input string) string {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "tcp://")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}
	return strings.ToLower(s)
}

func startXraySupervisor(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			log.Println("[Xray Supervisor] Spawning Xray-core daemon...")
			cmd := exec.Command("/usr/local/bin/xray", "run", "-config", "/app/config.json")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if err := cmd.Start(); err != nil {
				log.Printf("[Xray Supervisor] Launch error: %v. Retrying in 3s...", err)
				time.Sleep(3 * time.Second)
				continue
			}

			waitChan := make(chan error, 1)
			go func() {
				waitChan <- cmd.Wait()
			}()

			select {
			case <-ctx.Done():
				log.Println("[Xray Supervisor] Signal received. Stopping Xray...")
				if cmd.Process != nil {
					_ = cmd.Process.Signal(syscall.SIGTERM)
					time.Sleep(500 * time.Millisecond)
					_ = cmd.Process.Kill()
				}
				return
			case err := <-waitChan:
				log.Printf("[Xray Supervisor] Process exited: %v. Re-spawning in 2s...", err)
				time.Sleep(2 * time.Second)
			}
		}
	}()
}

func main() {
	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()

	_ = getSettings()
	startXraySupervisor(appCtx)

	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}

	wsBackend, _ := url.Parse("http://127.0.0.1:8081")
	xhBackend, _ := url.Parse("http://127.0.0.1:8082")

	proxyTransport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}

	wsProxy := httputil.NewSingleHostReverseProxy(wsBackend)
	wsProxy.Transport = proxyTransport

	xhProxy := httputil.NewSingleHostReverseProxy(xhBackend)
	xhProxy.Transport = proxyTransport
	xhProxy.FlushInterval = 20 * time.Millisecond

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqPath := r.URL.Path

		if reqPath == "/healthz" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}

		if strings.HasPrefix(reqPath, WSSecretPath) {
			wsProxy.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(reqPath, XHTTPSecretPath) {
			xhProxy.ServeHTTP(w, r)
			return
		}

		switch reqPath {
		case "/login":
			handleLogin(w, r)
		case "/onboarding":
			handleOnboarding(w, r)
		case "/logout":
			handleLogout(w, r)
		case "/":
			handleDashboard(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	server := &http.Server{
		Addr:    "0.0.0.0:" + port,
		Handler: handler,
	}

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Println("[Server] Shutting down...")
		cancelApp()
		_ = server.Shutdown(context.Background())
	}()

	log.Printf("[Server] BERMUDA1998 Active Gateway on :%s\n", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[Server] Fatal: %v\n", err)
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	current := getSettings()
	if !checkAuth(r, current) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if current.IsDefault {
		http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "save_domain" {
			d := sanitizeDomain(r.FormValue("domain"))
			city := strings.TrimSpace(r.FormValue("city"))
			flag := strings.TrimSpace(r.FormValue("country_flag"))

			if d != "" {
				current.Domain = d
			}
			if city != "" && flag != "" {
				current.City = city
				current.CountryFlag = flag
			}
			saveSettings(current)
		} else if action == "save_security" {
			newU := strings.TrimSpace(r.FormValue("new_username"))
			newP := strings.TrimSpace(r.FormValue("new_password"))
			if newU != "" && newP != "" {
				current.UserHash = hashString(newU)
				current.PassHash = hashString(newP)
				current.IsDefault = false
				token := generateSecureToken()
				current.SessionKey = token
				saveSettings(current)
				setAuthCookie(w, token)
			}
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	html := strings.ReplaceAll(dashboardHTML, "{{DOMAIN}}", current.Domain)
	html = strings.ReplaceAll(html, "{{CITY}}", current.City)
	html = strings.ReplaceAll(html, "{{COUNTRY_FLAG}}", current.CountryFlag)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	current := getSettings()

	if r.Method == http.MethodPost {
		if isRateLimited(clientIP) {
			http.Redirect(w, r, "/login?error=blocked", http.StatusSeeOther)
			return
		}

		user := strings.TrimSpace(r.FormValue("username"))
		pass := strings.TrimSpace(r.FormValue("password"))

		uMatch := subtle.ConstantTimeCompare([]byte(hashString(user)), []byte(current.UserHash)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(hashString(pass)), []byte(current.PassHash)) == 1

		if uMatch && pMatch {
			resetRateLimit(clientIP)
			token := generateSecureToken()
			current.SessionKey = token
			saveSettings(current)
			setAuthCookie(w, token)

			if current.IsDefault {
				http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		recordFailedLogin(clientIP)
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
		return
	}

	errNotice := ""
	if r.URL.Query().Get("error") == "blocked" {
		errNotice = `<div class="error-msg">Too many failed attempts. Locked for 10 minutes.</div>`
	} else if r.URL.Query().Get("error") == "invalid" {
		errNotice = `<div class="error-msg">Invalid credentials. Access denied.</div>`
	}

	html := strings.ReplaceAll(loginHTML, "{{ERROR}}", errNotice)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func handleOnboarding(w http.ResponseWriter, r *http.Request) {
	current := getSettings()
	if !checkAuth(r, current) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if !current.IsDefault {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		newU := strings.TrimSpace(r.FormValue("new_username"))
		newP := strings.TrimSpace(r.FormValue("new_password"))
		initH := getInitialHash()

		if newU != "" && newP != "" && (hashString(newU) != initH || hashString(newP) != initH) {
			current.UserHash = hashString(newU)
			current.PassHash = hashString(newP)
			current.IsDefault = false
			token := generateSecureToken()
			current.SessionKey = token
			saveSettings(current)
			setAuthCookie(w, token)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/onboarding?error=1", http.StatusSeeOther)
		return
	}

	errNotice := ""
	if r.URL.Query().Get("error") == "1" {
		errNotice = `<div class="error-msg">New credentials cannot match default factory values.</div>`
	}

	html := strings.ReplaceAll(onboardingHTML, "{{ERROR}}", errNotice)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	current := getSettings()
	current.SessionKey = ""
	saveSettings(current)
	clearAuthCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ------------------- قالب‌های مونوکروم (Monochrome UI) -------------------

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In — BERMUDA1998</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #000000; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1.5rem; }
  .card { background: #09090b; padding: 2.2rem; border-radius: 0.75rem; width: 100%; max-width: 360px; border: 1px solid #27272a; box-shadow: 0 20px 40px rgba(0,0,0,0.9); }
  h2 { font-size: 1.15rem; font-weight: 700; letter-spacing: -0.03em; margin-bottom: 0.3rem; text-align: center; color: #ffffff; }
  .sub { font-size: 0.75rem; color: #71717a; text-align: center; margin-bottom: 1.6rem; text-transform: uppercase; letter-spacing: 0.08em; }
  .error-msg { background: #18181b; border: 1px solid #52525b; color: #e4e4e7; font-size: 0.75rem; padding: 0.6rem; border-radius: 0.35rem; margin-bottom: 1.2rem; text-align: center; }
  label { display: block; font-size: 0.75rem; margin-bottom: 0.4rem; color: #a1a1aa; font-weight: 500; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 1.2rem; border-radius: 0.4rem; border: 1px solid #27272a; background: #000000; color: #ffffff; font-family: monospace; font-size: 0.85rem; }
  input:focus { border-color: #71717a; outline: none; }
  button { width: 100%; padding: 0.8rem; border-radius: 0.4rem; border: none; background: #ffffff; color: #000000; font-weight: 700; cursor: pointer; font-size: 0.85rem; letter-spacing: -0.01em; transition: 0.15s; }
  button:hover { background: #e4e4e7; }
</style>
</head>
<body>
<div class="card">
  <h2>BERMUDA1998</h2>
  <div class="sub">Production Access Gate</div>
  {{ERROR}}
  <form method="POST">
    <label>USERNAME</label>
    <input type="text" name="username" required autofocus autocomplete="off">
    <label>PASSWORD</label>
    <input type="password" name="password" required>
    <button type="submit">AUTHENTICATE</button>
  </form>
</div>
</body>
</html>`

const onboardingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Setup — BERMUDA1998</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #000000; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1.5rem; }
  .card { background: #09090b; padding: 2.2rem; border-radius: 0.75rem; width: 100%; max-width: 380px; border: 1px solid #27272a; box-shadow: 0 20px 40px rgba(0,0,0,0.9); }
  h2 { font-size: 1.15rem; font-weight: 700; letter-spacing: -0.03em; margin-bottom: 0.4rem; text-align: center; }
  p { font-size: 0.78rem; color: #71717a; text-align: center; margin-bottom: 1.4rem; line-height: 1.45; }
  .error-msg { background: #18181b; border: 1px solid #52525b; color: #e4e4e7; font-size: 0.75rem; padding: 0.6rem; border-radius: 0.35rem; margin-bottom: 1.2rem; text-align: center; }
  label { display: block; font-size: 0.75rem; margin-bottom: 0.4rem; color: #a1a1aa; font-weight: 500; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 1.2rem; border-radius: 0.4rem; border: 1px solid #27272a; background: #000000; color: #ffffff; font-family: monospace; font-size: 0.85rem; }
  input:focus { border-color: #71717a; outline: none; }
  button { width: 100%; padding: 0.8rem; border-radius: 0.4rem; border: none; background: #ffffff; color: #000000; font-weight: 700; cursor: pointer; font-size: 0.85rem; transition: 0.15s; }
  button:hover { background: #e4e4e7; }
</style>
</head>
<body>
<div class="card">
  <h2>Initialize Security</h2>
  <p>Default credentials must be updated before accessing this cluster.</p>
  {{ERROR}}
  <form method="POST">
    <label>NEW USERNAME</label>
    <input type="text" name="new_username" required autofocus autocomplete="off">
    <label>NEW PASSWORD</label>
    <input type="password" name="new_password" required>
    <button type="submit">COMMIT CREDENTIALS</button>
  </form>
</div>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BERMUDA1998 Control Terminal</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #000000; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif; padding: 2rem 1rem; display: flex; justify-content: center; }
  .box { width: 100%; max-width: 490px; background: #09090b; padding: 2rem; border-radius: 0.85rem; border: 1px solid #27272a; box-shadow: 0 25px 50px rgba(0,0,0,0.9); }
  
  .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.8rem; border-bottom: 1px solid #18181b; padding-bottom: 1rem; }
  .top-bar h1 { font-size: 1.05rem; font-weight: 700; letter-spacing: -0.02em; }
  .status-badge { font-size: 0.68rem; color: #a1a1aa; border: 1px solid #27272a; padding: 0.25rem 0.5rem; border-radius: 0.3rem; text-transform: uppercase; font-family: monospace; }
  .exit { color: #a1a1aa; text-decoration: none; font-size: 0.75rem; border: 1px solid #27272a; padding: 0.3rem 0.65rem; border-radius: 0.35rem; transition: 0.15s; }
  .exit:hover { background: #ffffff; color: #000000; border-color: #ffffff; }

  .section-label { display: block; font-size: 0.72rem; margin-bottom: 0.5rem; color: #71717a; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 0.7rem; border-radius: 0.4rem; border: 1px solid #27272a; background: #000000; color: #ffffff; font-family: monospace; font-size: 0.85rem; }
  input:focus { border-color: #71717a; outline: none; }

  .country-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.45rem; margin-bottom: 1rem; }
  .country-btn { background: #000000; border: 1px solid #27272a; padding: 0.65rem 0.6rem; border-radius: 0.4rem; font-size: 0.78rem; font-weight: 600; color: #a1a1aa; cursor: pointer; text-align: left; display: flex; align-items: center; gap: 0.45rem; transition: 0.15s; }
  .country-btn:hover { border-color: #52525b; color: #ffffff; }
  .country-btn.active { background: #ffffff; color: #000000; border-color: #ffffff; }

  .btn-action { width: 100%; padding: 0.75rem; border-radius: 0.4rem; border: 1px solid #27272a; background: #18181b; color: #ffffff; font-weight: 600; cursor: pointer; font-size: 0.82rem; margin-bottom: 1.6rem; transition: 0.15s; }
  .btn-action:hover { background: #27272a; border-color: #3f3f46; }

  .toggle-group { display: flex; gap: 0.4rem; background: #000000; border: 1px solid #18181b; border-radius: 0.5rem; padding: 0.3rem; margin-bottom: 1.5rem; }
  .toggle-btn { flex: 1; text-align: center; padding: 0.65rem 0.4rem; font-size: 0.78rem; font-weight: 600; border-radius: 0.35rem; cursor: pointer; color: #71717a; transition: 0.15s; }
  .toggle-btn.active { background: #ffffff; color: #000000; }

  .qr-frame { background: #ffffff; padding: 0.8rem; border-radius: 0.5rem; width: fit-content; margin: 0 auto 1.2rem auto; display: flex; justify-content: center; }
  
  .link-box { background: #000000; border: 1px solid #27272a; border-radius: 0.4rem; padding: 0.75rem; font-family: monospace; font-size: 0.72rem; word-break: break-all; color: #a1a1aa; margin-bottom: 0.8rem; max-height: 80px; overflow-y: auto; }

  .btn-primary { width: 100%; padding: 0.85rem; border-radius: 0.4rem; border: none; background: #ffffff; color: #000000; font-weight: 700; font-size: 0.85rem; cursor: pointer; margin-bottom: 1.8rem; transition: 0.15s; }
  .btn-primary:hover { background: #e4e4e7; }

  .divider { border-top: 1px solid #18181b; margin: 1.8rem 0 1.4rem 0; }
  .sec-title { font-size: 0.82rem; font-weight: 600; color: #ffffff; margin-bottom: 0.9rem; letter-spacing: -0.01em; }
</style>
</head>
<body>
<div class="box">
  <div class="top-bar">
    <div>
      <h1>BERMUDA1998</h1>
    </div>
    <div style="display:flex;gap:0.5rem;align-items:center;">
      <span class="status-badge">Edge 443</span>
      <a href="/logout" class="exit">Exit</a>
    </div>
  </div>

  <form method="POST">
    <input type="hidden" name="action" value="save_domain">
    <input type="hidden" name="city" id="cityInput" value="{{CITY}}">
    <input type="hidden" name="country_flag" id="countryFlagInput" value="{{COUNTRY_FLAG}}">

    <label class="section-label">1. Railway Edge Region</label>
    <div class="country-grid">
      <div class="country-btn" onclick="selectCity('Amsterdam', '🇳🇱', this)">
        <span>🇳🇱</span> Amsterdam
      </div>
      <div class="country-btn" onclick="selectCity('Virginia', '🇺🇸', this)">
        <span>🇺🇸</span> Virginia
      </div>
      <div class="country-btn" onclick="selectCity('Singapore', '🇸🇬', this)">
        <span>🇸🇬</span> Singapore
      </div>
      <div class="country-btn" onclick="selectCity('California', '🇺🇸', this)">
        <span>🇺🇸</span> California
      </div>
    </div>

    <label class="section-label">2. Target Domain / Hostname</label>
    <input type="text" name="domain" value="{{DOMAIN}}" placeholder="e.g. your-app.up.railway.app" required autocomplete="off">
    <button type="submit" class="btn-action">Commit Network & Region</button>
  </form>

  <label class="section-label">3. Transport Protocol</label>
  <div class="toggle-group">
    <div class="toggle-btn active" id="btnProtoXHTTP" onclick="setProtocol('xhttp')">XHTTP (Anti-DPI)</div>
    <div class="toggle-btn" id="btnProtoWS" onclick="setProtocol('ws')">WebSocket</div>
  </div>

  <label class="section-label">4. Outbound Routing Profile</label>
  <div class="toggle-group">
    <div class="toggle-btn active" id="btnModeNormal" onclick="setMode('normal')">Standard (IPv4)</div>
    <div class="toggle-btn" id="btnModeAI" onclick="setMode('ai')">AI Dedicated (IPv6)</div>
  </div>

  <div class="qr-frame" id="qrcode"></div>
  <div class="link-box" id="uriBox"></div>
  <button class="btn-primary" onclick="copyURI()">Copy Config Link</button>

  <div class="divider"></div>
  <div class="sec-title">Cluster Authentication</div>
  <form method="POST">
    <input type="hidden" name="action" value="save_security">
    <label class="section-label">Update Username</label>
    <input type="text" name="new_username" placeholder="Username" required autocomplete="off">
    <label class="section-label">Update Password</label>
    <input type="password" name="new_password" placeholder="Password" required>
    <button type="submit" class="btn-action" style="margin-bottom:0;">Commit Credentials</button>
  </form>
</div>

<script>
  let currentProto = 'xhttp';
  let currentMode = 'normal';

  const idNormal = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d";
  const idAI     = "f9e8d7c6-b5a4-3210-fedc-ba9876543210";
  const domain   = "{{DOMAIN}}".trim();

  let activeCity = "{{CITY}}" || "Amsterdam";
  let activeFlag = "{{COUNTRY_FLAG}}" || "🇳🇱";

  let generatedURI = "";

  function initLocationUI() {
    const buttons = document.querySelectorAll('.country-btn');
    buttons.forEach(btn => {
      if (btn.innerText.includes(activeCity)) {
        btn.classList.add('active');
      }
    });
  }

  function selectCity(city, flag, elem) {
    document.querySelectorAll('.country-btn').forEach(b => b.classList.remove('active'));
    elem.classList.add('active');
    
    document.getElementById('cityInput').value = city;
    document.getElementById('countryFlagInput').value = flag;

    activeCity = city;
    activeFlag = flag;

    render();
  }

  function setProtocol(proto) {
    currentProto = proto;
    document.getElementById('btnProtoXHTTP').classList.toggle('active', proto === 'xhttp');
    document.getElementById('btnProtoWS').classList.toggle('active', proto === 'ws');
    render();
  }

  function setMode(mode) {
    currentMode = mode;
    document.getElementById('btnModeNormal').classList.toggle('active', mode === 'normal');
    document.getElementById('btnModeAI').classList.toggle('active', mode === 'ai');
    render();
  }

  function render() {
    const qrElem = document.getElementById('qrcode');
    const boxElem = document.getElementById('uriBox');

    if (!domain) {
      qrElem.innerHTML = '<span style="color:#000;font-size:11px;padding:20px;display:block">Save target domain above</span>';
      boxElem.innerText = "No domain configured.";
      generatedURI = "";
      return;
    }

    const uid = (currentMode === 'ai') ? idAI : idNormal;
    const modeTag = (currentMode === 'ai') ? 'AI' : 'Standard';
    const locTag = activeFlag + ' ' + activeCity;

    if (currentProto === 'xhttp') {
      const tag = locTag + ' | XHTTP | ' + modeTag;
      // استاندارد و کاملا سازگار با معماری لبه Railway، کلاینت Throne و NPV Tunnel
      generatedURI = 'vless://' + uid + '@' + domain + ':443?encryption=none&security=tls&sni=' + domain + '&alpn=h2%2Chttp%2F1.1&fp=chrome&type=xhttp&host=' + domain + '&path=%2Fxh-cazar-gate&mode=packet-up#' + encodeURIComponent(tag);
    } else {
      const tag = locTag + ' | WS | ' + modeTag;
      generatedURI = 'vless://' + uid + '@' + domain + ':443?encryption=none&security=tls&sni=' + domain + '&fp=chrome&type=ws&host=' + domain + '&path=%2Fws-cazar-gate#' + encodeURIComponent(tag);
    }

    boxElem.innerText = generatedURI;
    qrElem.innerHTML = '';
    new QRCode(qrElem, { text: generatedURI, width: 170, height: 170 });
  }

  function copyURI() {
    if (!generatedURI) return alert('Configure target domain first.');
    navigator.clipboard.writeText(generatedURI);
    alert('Config copied to clipboard.');
  }

  initLocationUI();
  render();
</script>
</body>
</html>`
