package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"homepki/internal/storage"
)

var basePage = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} - HomePKI</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { margin: 0; background: #f5f7fa; color: #17202a; }
    main { width: min(42rem, calc(100% - 2rem)); margin: 3rem auto; }
    section { background: white; padding: 1.5rem; border-radius: .75rem; box-shadow: 0 1px 8px #0002; margin-bottom: 1rem; }
    h1,h2 { margin-top: 0; }
    label { display: block; margin: 1rem 0 .3rem; font-weight: 600; }
    input,button { box-sizing: border-box; width: 100%; padding: .75rem; font: inherit; }
    button { margin-top: 1rem; cursor: pointer; background: #155eef; color: white; border: 0; border-radius: .4rem; }
    .danger { background: #b42318; }
    .error { color: #b42318; }
    nav a, nav button { display: inline-block; width: auto; margin-right: .5rem; }
    table { width: 100%; border-collapse: collapse; }
    th,td { padding: .6rem; text-align: left; border-bottom: 1px solid #ddd; }
    code { overflow-wrap: anywhere; }
    @media (prefers-color-scheme: dark) {
      body { background: #111827; color: #f9fafb; }
      section { background: #1f2937; }
      input { background: #111827; color: white; border: 1px solid #667085; }
      th,td { border-color: #475467; }
    }
  </style>
</head>
<body><main>{{.Body}}</main></body>
</html>`))

var setupPage = template.Must(template.New("setup").Parse(`
<section>
  <h1>Set up HomePKI</h1>
  <p>Create the single administrator account. After this, the setup wizard checks the CA prerequisites and provisions the certificate authority.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="post" action="/setup/admin">
    <label for="username">Administrator username</label>
    <input id="username" name="username" autocomplete="username" required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="new-password" minlength="12" required>
    <button type="submit">Create administrator</button>
  </form>
</section>`))

var loginPage = template.Must(template.New("login").Parse(`
<section>
  <h1>Sign in</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="post" action="/login">
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="username" required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</section>`))

var caSetupPage = template.Must(template.New("ca").Parse(`
<section>
  <h1>Provision the certificate authority</h1>
  <p>HomePKI will now check the configured hardware and run the Step CA provisioning command. Keep the YubiKey connected and be ready for any required touch confirmation.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  {{if .Reason}}<p><strong>Previous failure:</strong> {{.Reason}}</p>{{end}}
  <form method="post" action="/setup/ca">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label for="root_name">Root CA name</label>
    <input id="root_name" name="root_name" value="HomePKI Root CA" required>
    <label for="intermediate_name">Intermediate CA name</label>
    <input id="intermediate_name" name="intermediate_name" value="HomePKI Intermediate CA" required>
    {{if .RequiresYubiKey}}
    <label for="yubikey_pin">YubiKey PIN</label>
    <input id="yubikey_pin" name="yubikey_pin" type="password" autocomplete="current-password" required>
    {{end}}
    <button type="submit">Check prerequisites and provision CA</button>
  </form>
</section>`))

var dashboardPage = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"formatTime": func(value time.Time) string { return value.Format("2006-01-02 15:04 UTC") },
}).Parse(`
<section>
  <h1>HomePKI</h1>
  <p>Setup state: <strong>{{.SetupState}}</strong></p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <nav>
    <a href="/trust-guidance">Trust guidance</a>
    <form method="post" action="/logout" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
      <button type="submit">Sign out</button>
    </form>
  </nav>
</section>
<section>
  <h2>Issue a certificate</h2>
  <form method="post" action="/certificates">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label for="common_name">Common name</label>
    <input id="common_name" name="common_name" placeholder="service.home.example" required>
    <label for="dns_names">Additional DNS names, one per line</label>
    <textarea id="dns_names" name="dns_names" style="width:100%;min-height:5rem"></textarea>
    <label for="ttl_hours">Lifetime in hours</label>
    <input id="ttl_hours" name="ttl_hours" type="number" min="1" max="9528" value="24" required>
    <button type="submit">Issue certificate</button>
  </form>
</section>
<section>
  <h2>Certificate inventory</h2>
  {{if .Certificates}}
  <table>
    <thead><tr><th>Name</th><th>Serial</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody>
    {{range .Certificates}}
      <tr>
        <td>{{.CommonName}}</td>
        <td><code>{{.SerialNumber}}</code></td>
        <td>{{.Status}}</td>
        <td>{{formatTime .NotAfter}}</td>
        <td>
          {{if eq .Status "active"}}
          <form method="post" action="/certificates/{{.SerialNumber}}/revoke">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="confirm" value="REVOKE">
            <button type="submit">Revoke</button>
          </form>
          {{else}}
          <form method="post" action="/certificates/{{.SerialNumber}}/delete">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="confirm" value="DELETE">
            <button class="danger" type="submit">Delete</button>
          </form>
          {{end}}
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <p>No certificates have been issued.</p>
  {{end}}
</section>`))

var trustPage = template.Must(template.New("trust").Parse(`
<section>
  <h1>Trust HomePKI</h1>
  <p>Install the CA certificate only from a backup or source you control.</p>
  <h2>Linux</h2>
  <ol>
    <li>Copy the CA certificate to <code>/usr/local/share/ca-certificates/homepki.crt</code>.</li>
    <li>Run <code>sudo update-ca-certificates</code>.</li>
  </ol>
  <h2>macOS</h2>
  <ol>
    <li>Open Keychain Access and import the HomePKI CA certificate.</li>
    <li>Set the certificate to Always Trust for SSL.</li>
    <li>Restart browsers that cached trust settings.</li>
  </ol>
  <p><a href="/">Back to HomePKI</a></p>
</section>`))

type pageModel struct {
	Title           string
	Body            template.HTML
	Error           string
	Reason          string
	CSRFToken       string
	SetupState      storage.SetupState
	Certificates    []storage.Certificate
	RequiresYubiKey bool
}

func renderPage(w http.ResponseWriter, status int, content *template.Template, model pageModel) {
	var contentBuffer bytes.Buffer
	if err := content.Execute(&contentBuffer, model); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("render page: %v", err))
		return
	}

	model.Body = template.HTML(contentBuffer.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = basePage.Execute(w, model)
}

func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return r.Method == http.MethodGet && (accept == "" || accept == "text/html" || len(accept) >= 9 && accept[:9] == "text/html")
}
