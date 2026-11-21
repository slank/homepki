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
    small { display: block; margin-top: .35rem; color: #475467; }
    select { box-sizing: border-box; width: 100%; padding: .75rem; font: inherit; }
    .hint { margin: .5rem 0 0; font-size: .95rem; color: #475467; }
    .notice { border-left: .3rem solid #155eef; padding: .75rem 1rem; background: #eef4ff; border-radius: .4rem; margin: 1rem 0; }
    .inline-button { width: auto; margin-top: .5rem; }
    dialog { border: 0; border-radius: .7rem; padding: 1.2rem; width: min(32rem, calc(100% - 2rem)); box-shadow: 0 12px 30px #0005; }
    dialog::backdrop { background: #0008; }
    .dialog-actions { display: flex; gap: .75rem; justify-content: flex-end; margin-top: 1rem; }
    .dialog-actions button { width: auto; margin-top: 0; }
    code { overflow-wrap: anywhere; }
    @media (prefers-color-scheme: dark) {
      body { background: #111827; color: #f9fafb; }
      section { background: #1f2937; }
      small, .hint { color: #d0d5dd; }
      .notice { background: #1d2939; border-left-color: #84adff; }
      dialog { background: #1f2937; color: #f9fafb; }
      input { background: #111827; color: white; border: 1px solid #667085; }
      select, textarea { background: #111827; color: white; border: 1px solid #667085; }
      th,td { border-color: #475467; }
    }
  </style>
  <script>
    function toggleSecretField(fieldId, buttonId) {
      const field = document.getElementById(fieldId);
      const button = document.getElementById(buttonId);
      if (!field || !button) return;
      const show = field.type === "password";
      field.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
      button.setAttribute("aria-pressed", show ? "true" : "false");
    }

    function confirmCATouchAwareness(event) {
      const form = document.getElementById("ca_setup_form");
      const modal = document.getElementById("ca_touch_confirm_modal");
      if (!form || !modal) return true;
      if (form.dataset.confirmed === "true") {
        form.dataset.confirmed = "";
        return true;
      }
      event.preventDefault();
      if (typeof modal.showModal === "function") {
        modal.showModal();
      } else {
        const confirmed = confirm("During provisioning, you will need to touch the YubiKey multiple times. Continue now?");
        if (confirmed) {
          form.dataset.confirmed = "true";
          form.requestSubmit();
        }
      }
      return false;
    }

    function proceedWithCAProvisioning() {
      const form = document.getElementById("ca_setup_form");
      const modal = document.getElementById("ca_touch_confirm_modal");
      if (modal && typeof modal.close === "function") modal.close();
      if (!form) return;
      form.dataset.confirmed = "true";
      form.requestSubmit();
    }

    function confirmCertificateIssue(event) {
      const form = document.getElementById("issue_certificate_form");
      const modal = document.getElementById("issue_cert_touch_confirm_modal");
      if (!form || !modal) return true;
      event.preventDefault();
      if (!form.reportValidity()) return false;
      if (typeof modal.showModal === "function") {
        modal.showModal();
      } else {
        const confirmed = confirm("Issuing a certificate requires YubiKey touch confirmation. Continue now?");
        if (confirmed) issueCertificateWithRefresh();
      }
      return false;
    }

    function closeCertificateIssueModal() {
      const modal = document.getElementById("issue_cert_touch_confirm_modal");
      if (modal && typeof modal.close === "function") modal.close();
    }

    async function issueCertificateWithRefresh() {
      const form = document.getElementById("issue_certificate_form");
      const modal = document.getElementById("issue_cert_touch_confirm_modal");
      if (modal && typeof modal.close === "function") modal.close();
      if (!form) return;
      const feedback = document.getElementById("issue_certificate_feedback");
      if (feedback) {
        feedback.hidden = true;
        feedback.textContent = "";
      }

      const submitButton = document.getElementById("issue_certificate_submit");
      if (submitButton) submitButton.disabled = true;

      try {
        const params = new URLSearchParams(new FormData(form));
        const response = await fetch(form.action, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          },
          body: params.toString(),
          credentials: "same-origin",
        });
        if (!response.ok) {
          let message = "Certificate issuance failed (" + response.status + ").";
          try {
            const errorPayload = await response.json();
            if (errorPayload && typeof errorPayload.error === "string") {
              message = errorPayload.error;
            }
          } catch (_ignored) {
          }
          if (feedback) {
            feedback.hidden = false;
            feedback.textContent = message;
          } else {
            alert(message);
          }
          return;
        }

        const blob = await response.blob();
        let filename = "homepki-certificate.zip";
        const disposition = response.headers.get("Content-Disposition") || "";
        const match = disposition.match(/filename="([^"]+)"/i);
        if (match && match[1]) filename = match[1];

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        window.location.reload();
      } catch (_err) {
        if (feedback) {
          feedback.hidden = false;
          feedback.textContent = "Certificate issuance request failed before completion.";
        } else {
          alert("Certificate issuance request failed before completion.");
        }
      } finally {
        if (submitButton) submitButton.disabled = false;
      }
    }
  </script>
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
    <small>This is the single local admin account for this appliance.</small>
    <input id="username" name="username" autocomplete="username" required>
    <label for="password">Password</label>
    <small>Use at least 12 characters. A long passphrase is best.</small>
    <input id="password" name="password" type="password" autocomplete="new-password" minlength="12" required>
    <button class="inline-button" id="password-toggle" type="button" aria-pressed="false" onclick="toggleSecretField('password', 'password-toggle')">Show</button>
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
    <button class="inline-button" id="login-password-toggle" type="button" aria-pressed="false" onclick="toggleSecretField('password', 'login-password-toggle')">Show</button>
    <button type="submit">Sign in</button>
  </form>
</section>`))

var caSetupPage = template.Must(template.New("ca").Parse(`
<section>
  <h1>Provision the certificate authority</h1>
  <p>HomePKI will now check the configured hardware and run the Step CA provisioning command.</p>
  <p class="hint">Existing private keys already present in YubiKey slots 82 and 83 are reused, not overwritten.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  {{if .Reason}}<p><strong>Previous failure:</strong> {{.Reason}}</p>{{end}}
  <form id="ca_setup_form" method="post" action="/setup/ca" onsubmit="return confirmCATouchAwareness(event)">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label for="root_name">Root CA name</label>
    <small>Recommended: keep this as a stable long-lived name, for example "HomePKI Root CA".</small>
    <input id="root_name" name="root_name" value="HomePKI Root CA" required>
    <label for="intermediate_name">Intermediate CA name</label>
    <small>This signs service certificates. Keep it clearly related to the root.</small>
    <input id="intermediate_name" name="intermediate_name" value="HomePKI Intermediate CA" required>
    {{if .RequiresYubiKey}}
    <label for="yubikey_pin">YubiKey PIN</label>
    <small>Choose a 6-8 digit PIN that is not reused elsewhere. Store the PIN and PUK separately in a secure password manager.</small>
    <input id="yubikey_pin" name="yubikey_pin" type="password" autocomplete="current-password" required>
    <button class="inline-button" id="yubikey-pin-toggle" type="button" aria-pressed="false" onclick="toggleSecretField('yubikey_pin', 'yubikey-pin-toggle')">Show</button>
    {{end}}
    <button type="submit">Check prerequisites and provision CA</button>
  </form>
  <dialog id="ca_touch_confirm_modal">
    <h2>Confirm YubiKey touch prompts</h2>
    <p>This setup operation will require multiple physical YubiKey touches while root/intermediate keys and certificates are prepared.</p>
    <div class="dialog-actions">
      <form method="dialog">
        <button type="submit" class="danger">Cancel</button>
      </form>
      <button type="button" onclick="proceedWithCAProvisioning()">Continue setup</button>
    </div>
  </dialog>
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
  <form id="issue_certificate_form" method="post" action="/certificates" onsubmit="return confirmCertificateIssue(event)">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label for="common_name">Common name</label>
    <small>HomePKI validates DNS syntax only. You must verify you control each name before issuing.</small>
    <input id="common_name" name="common_name" placeholder="service.home.example" required>
    <label for="dns_names">Additional DNS names, one per line</label>
    <textarea id="dns_names" name="dns_names" style="width:100%;min-height:5rem"></textarea>
    <label for="ttl_hours">Certificate lifetime</label>
    <select id="ttl_hours" name="ttl_hours" required>
      <option value="24">24 hours</option>
      <option value="1008">6 weeks</option>
      <option value="2160" selected>3 months (recommended)</option>
      <option value="4320">6 months</option>
      <option value="6480">9 months</option>
      <option value="8760">1 year</option>
      <option value="17520">2 years</option>
    </select>
    <button id="issue_certificate_submit" type="submit">Issue certificate</button>
  </form>
  <p id="issue_certificate_feedback" class="error" hidden></p>
  <dialog id="issue_cert_touch_confirm_modal">
    <h2>Confirm YubiKey touch prompts</h2>
    <p>Issuing this certificate requires one or more physical YubiKey touches. Continue now?</p>
    <div class="dialog-actions">
      <button type="button" class="danger" onclick="closeCertificateIssueModal()">Cancel</button>
      <button type="button" onclick="issueCertificateWithRefresh()">Continue issuing</button>
    </div>
  </dialog>
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
  <h2>Download certificates</h2>
  <ol>
    <li><a href="{{.RootCertificateDownloadPath}}">Download root CA certificate (PEM)</a></li>
    <li><a href="{{.IntermediateCertificateDownloadPath}}">Download intermediate CA certificate (PEM)</a></li>
  </ol>
  <p><strong>Root SHA-256 fingerprint:</strong> <code>{{.RootCertificateFingerprint}}</code></p>
  <p><strong>Intermediate SHA-256 fingerprint:</strong> <code>{{.IntermediateCertificateFingerprint}}</code></p>
  <p>Verify fingerprints before trusting:</p>
  <pre><code>openssl x509 -in root_ca.crt -noout -fingerprint -sha256
openssl x509 -in intermediate_ca.crt -noout -fingerprint -sha256</code></pre>
  <h2>Linux</h2>
  <ol>
    <li>Copy the <strong>root CA certificate</strong> to <code>/usr/local/share/ca-certificates/homepki.crt</code>.</li>
    <li>Run <code>sudo update-ca-certificates</code>.</li>
  </ol>
  <h2>macOS</h2>
  <ol>
    <li>Open Keychain Access and import the <strong>root CA certificate</strong>.</li>
    <li>Set the certificate to Always Trust for SSL.</li>
    <li>Restart browsers that cached trust settings.</li>
  </ol>
  <p><a href="/">Back to HomePKI</a></p>
</section>`))

type pageModel struct {
	Title                               string
	Body                                template.HTML
	Error                               string
	Reason                              string
	CSRFToken                           string
	SetupState                          storage.SetupState
	Certificates                        []storage.Certificate
	RequiresYubiKey                     bool
	RootCertificateDownloadPath         string
	IntermediateCertificateDownloadPath string
	RootCertificateFingerprint          string
	IntermediateCertificateFingerprint  string
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
