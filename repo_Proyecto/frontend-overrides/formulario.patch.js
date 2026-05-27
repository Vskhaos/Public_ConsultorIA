/**
 * formulario.patch.js  (v2 – fix tunnel panel + date format)
 *
 * Cambios respecto a la versión anterior:
 *   - Eliminado cloneNode() que destruía los listeners del script inline
 *     (túnel, IPs, consentimiento…).  Ahora se usa removeEventListener
 *     via AbortController para sustituir sólo el listener "submit".
 *   - Campo fecha reemplazado por input type="text" con formato dd/mm/yyyy
 *     para mostrar día antes que mes.
 *
 * INSTRUCCIONES:
 *   Mantén <script src="formulario.patch.js"></script> justo antes de </body>
 *   en formulario.html (después del script inline existente).
 */

(function () {
  "use strict";

  // Mismo origen: el proxy reverso enruta /api/* al backend.
  const API_URL = "/api/audit-request";

  /* ── 1. Reemplazar el campo de fecha ────────────────────────────────────
     El <input type="date"> nativo muestra mm/dd/yyyy en muchos navegadores.
     Lo sustituimos por type="text" con validación manual dd/mm/yyyy.
  ───────────────────────────────────────────────────────────────────────── */
  const originalDate = document.querySelector('input[name="audit_date"]');
  if (originalDate) {
    const textDate = document.createElement("input");
    textDate.type        = "text";
    textDate.name        = "audit_date";
    textDate.placeholder = "dd/mm/aaaa";
    textDate.autocomplete = "off";
    textDate.style.cssText = originalDate.style.cssText;
    textDate.className   = originalDate.className;

    // Máscara automática  →  escribe "21" y aparece "21/"
    textDate.addEventListener("input", function () {
      let v = this.value.replace(/\D/g, "").slice(0, 8);
      if (v.length >= 3) v = v.slice(0, 2) + "/" + v.slice(2);
      if (v.length >= 6) v = v.slice(0, 5) + "/" + v.slice(5);
      this.value = v;
    });

    originalDate.parentNode.replaceChild(textDate, originalDate);
  }

  /* ── 2. Función para parsear la fecha dd/mm/yyyy → Date ─────────────── */
  function parseDateDMY(str) {
    const m = str.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (!m) return null;
    const d = new Date(`${m[3]}-${m[2]}-${m[1]}`);
    return isNaN(d.getTime()) ? null : d;
  }

  /* ── 3. Interceptar el submit SIN clonar el formulario ──────────────────
     Usamos AbortController para poder cancelar el listener original
     si el script inline ya lo registró, y añadir el nuestro en su lugar.
     Pero como el script inline usa addEventListener sin signal, la forma
     más limpia es añadir el nuestro con capture=true (se ejecuta primero)
     y llamar stopImmediatePropagation para que el inline no llegue a correr.
  ───────────────────────────────────────────────────────────────────────── */
  const form = document.getElementById("auditForm");

  // ── Login overlay (mismo estilo que admin panel) ────────────────────────
  const TOKEN_KEY = "consultor_admin_token";
  function getToken()   { return sessionStorage.getItem(TOKEN_KEY); }
  function setToken(t)  { sessionStorage.setItem(TOKEN_KEY, t); }
  function clearToken() { sessionStorage.removeItem(TOKEN_KEY); }

  function injectLoginStyles() {
    if (document.getElementById("audit-login-style")) return;
    const s = document.createElement("style");
    s.id = "audit-login-style";
    s.textContent = `
      .audit-login-overlay {
        position: fixed; inset: 0; z-index: 100000;
        background: #04080f; display: flex; align-items: center; justify-content: center;
        font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace;
      }
      .audit-login-overlay.hidden { display: none; }
      .audit-login-box {
        background: #080e1a; border: 1px solid #1e3a5f; border-radius: 8px;
        padding: 40px; width: 100%; max-width: 380px;
        box-shadow: 0 0 40px rgba(0,212,255,0.06);
      }
      .audit-login-logo { text-align: center; margin-bottom: 28px; }
      .audit-login-logo h1 {
        font-family: 'Syne', system-ui, sans-serif; font-size: 22px; font-weight: 800;
        color: #00d4ff; letter-spacing: 0.05em; margin: 0;
      }
      .audit-login-logo p {
        font-size: 10px; color: #6b8aad; letter-spacing: 0.15em;
        text-transform: uppercase; margin-top: 6px;
      }
      .audit-login-field { margin-bottom: 14px; }
      .audit-login-field label {
        display: block; font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase;
        color: #6b8aad; margin-bottom: 6px;
      }
      .audit-login-field input {
        width: 100%; background: #0d1625; border: 1px solid #1a2a40;
        border-radius: 4px; color: #e8f2ff; font-family: inherit; font-size: 13px;
        padding: 10px 12px; outline: none; transition: border-color 0.2s;
      }
      .audit-login-field input:focus { border-color: #00d4ff; }
      .audit-login-pass-wrap { position: relative; }
      .audit-login-pass-wrap input { padding-right: 40px; }
      .audit-login-pass-toggle {
        position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
        background: transparent; border: 0; cursor: pointer; color: #6b8aad;
        padding: 4px 8px; font-size: 16px; line-height: 1; user-select: none;
      }
      .audit-login-pass-toggle:hover { color: #e8f2ff; }
      .audit-login-error {
        font-size: 11px; color: #e74c3c; min-height: 18px; margin-bottom: 10px;
      }
      .audit-login-info {
        font-size: 11px; color: #6b8aad; line-height: 1.5; margin-bottom: 16px;
        padding: 10px 12px; background: #0d1625; border-left: 2px solid #00d4ff;
        border-radius: 2px;
      }
      .audit-login-info a { color: #00d4ff; text-decoration: none; }
      .audit-login-btn {
        width: 100%; background: #0066cc; color: #fff; border: 0; border-radius: 4px;
        font-family: inherit; font-size: 12px; font-weight: 600; letter-spacing: 0.1em;
        text-transform: uppercase; padding: 12px; cursor: pointer; transition: background 0.2s;
      }
      .audit-login-btn:hover:not(:disabled) { background: #0077ee; }
      .audit-login-btn:disabled { opacity: 0.5; cursor: default; }
      .audit-login-close {
        position: absolute; top: 12px; right: 14px; background: transparent; border: 0;
        color: #6b8aad; font-size: 22px; cursor: pointer; line-height: 1;
      }
      .audit-login-close:hover { color: #e8f2ff; }
    `;
    document.head.appendChild(s);
  }

  function buildLoginOverlay() {
    if (document.getElementById("auditLoginOverlay")) return;
    injectLoginStyles();
    const o = document.createElement("div");
    o.id = "auditLoginOverlay";
    o.className = "audit-login-overlay";
    o.innerHTML = `
      <div class="audit-login-box" style="position:relative">
        <button type="button" class="audit-login-close" id="auditLoginClose" aria-label="Cerrar">×</button>
        <div class="audit-login-logo">
          <h1>ConsultorIA</h1>
          <p>Acceso autorizado</p>
        </div>
        <div class="audit-login-info">
          🚧 Estamos en pre-lanzamiento. Si tienes credenciales, inicia sesión para enviar la solicitud.<br>
          Si aún no las tienes, escríbenos a <a href="mailto:contacto@laconsultoria.cat">contacto@laconsultoria.cat</a> y te avisaremos cuando se abra al público.
        </div>
        <form id="auditLoginForm" autocomplete="on" novalidate>
          <div class="audit-login-field">
            <label for="auditLoginUser">Usuario</label>
            <input type="text" id="auditLoginUser" autocomplete="username" spellcheck="false" required>
          </div>
          <div class="audit-login-field">
            <label for="auditLoginPass">Contraseña</label>
            <div class="audit-login-pass-wrap">
              <input type="password" id="auditLoginPass" autocomplete="current-password" required>
              <button type="button" class="audit-login-pass-toggle" id="auditLoginPassToggle"
                aria-label="Mostrar / ocultar contraseña" title="Mostrar / ocultar contraseña">👁</button>
            </div>
          </div>
          <div class="audit-login-error" id="auditLoginError"></div>
          <button type="submit" class="audit-login-btn" id="auditLoginBtn">Acceder y enviar →</button>
        </form>
      </div>
    `;
    document.body.appendChild(o);

    document.getElementById("auditLoginClose").addEventListener("click", () => o.remove());
    o.addEventListener("click", (ev) => { if (ev.target === o) o.remove(); });

    document.getElementById("auditLoginPassToggle").addEventListener("click", () => {
      const i = document.getElementById("auditLoginPass");
      const b = document.getElementById("auditLoginPassToggle");
      if (i.type === "password") { i.type = "text"; b.textContent = "🙈"; }
      else { i.type = "password"; b.textContent = "👁"; }
    });

    const lf = document.getElementById("auditLoginForm");
    const lerr = document.getElementById("auditLoginError");
    const lbtn = document.getElementById("auditLoginBtn");
    lf.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      lerr.textContent = "";
      lbtn.disabled = true;
      lbtn.textContent = "Verificando…";
      try {
        const r = await fetch("/api/admin/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: document.getElementById("auditLoginUser").value,
            password: document.getElementById("auditLoginPass").value,
          }),
        });
        if (!r.ok) {
          lerr.textContent = r.status === 401
            ? "Credenciales incorrectas."
            : `Error de servidor (${r.status}).`;
          lbtn.disabled = false;
          lbtn.textContent = "Acceder y enviar →";
          return;
        }
        const j = await r.json();
        setToken(j.access_token);
        o.remove();
        // Reintenta el envío del formulario tras login exitoso
        form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
      } catch (err) {
        lerr.textContent = "Error de red. Reintenta.";
        lbtn.disabled = false;
        lbtn.textContent = "Acceder y enviar →";
      }
    });
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    e.stopImmediatePropagation();   // evita que el listener inline original se ejecute

    // Modo soft-launch: sin token → panel de login.
    if (!getToken()) {
      buildLoginOverlay();
      return;
    }

    /* Reutiliza las funciones del script inline */
    if (!validateForm()) {
      showToast("Por favor, revisa los campos marcados en rojo", "error");
      return;
    }

    const btnSubmit    = document.getElementById("btnSubmit");
    const refId        = document.getElementById("refId");
    const consentCheck = document.getElementById("consentCheck");

    btnSubmit.disabled    = true;
    btnSubmit.textContent = "Enviando…";

    /* Construir payload JSON */
    const fd = new FormData(form);
    const scopes = [...document.querySelectorAll('input[name="scope"]:checked')]
      .map((c) => c.value);

    /* Convertir fecha dd/mm/yyyy → yyyy-mm-dd para el backend */
    const rawDate  = (fd.get("audit_date") || "").trim();
    const parsed   = parseDateDMY(rawDate);
    const isoDate  = parsed ? parsed.toISOString().split("T")[0] : rawDate;

    /* Franja horaria: combinar hora_inicio y hora_fin en "HH:MM-HH:MM" */
    const horaInicio = fd.get("hora_inicio") || "";
    const horaFin    = fd.get("hora_fin")    || "";
    const horarioPref = horaInicio && horaFin ? `${horaInicio}-${horaFin}` : null;

    const payload = {
      ref:               refId.textContent,
      company:           fd.get("company"),
      sector:            fd.get("sector"),
      domain:            fd.get("domain") || "",
      contact:           fd.get("contact"),
      role:              fd.get("role"),
      department:        fd.get("department") || "",
      email:             fd.get("email"),
      phone:             fd.get("phone") || "",
      ips:               window.ips || [],
      scope:             scopes,
      tunnel: document.getElementById("tunnelPanel").classList.contains("visible")
        ? (document.querySelector('input[name="tunnel"]:checked')?.value || null)
        : null,
      scope_notes:       fd.get("scope_notes") || "",
      audit_date:        isoDate,
      duration:          fd.get("duration") || "",
      horario_preferido: horarioPref,
      priority:          fd.get("priority"),
      submitted_at:      new Date().toISOString(),
    };

    /* Construir multipart */
    const body = new FormData();
    body.append("data", JSON.stringify(payload));

    const wgConfInput = document.getElementById("fileWgConf");
    const sshKeyInput = document.getElementById("fileSshKey");
    if (wgConfInput?.files?.[0]) body.append("wg_conf", wgConfInput.files[0]);
    if (sshKeyInput?.files?.[0]) body.append("ssh_key",  sshKeyInput.files[0]);

    /* Enviar (con JWT del login si existe) */
    const _headers = {};
    const _token = getToken();
    if (_token) _headers["Authorization"] = "Bearer " + _token;
    try {
      const res = await fetch(API_URL, { method: "POST", body, headers: _headers });

      if (res.ok || res.status === 207) {
        const json = await res.json();
        showToast(
          `✓ Solicitud ${json.ref} registrada. Recibirás confirmación por email.`,
          "success"
        );
        form.reset();
        (window.ips || []).length = 0;
        if (window.renderIPs) window.renderIPs();
        window.consentGiven = false;
        consentCheck.classList.remove("checked");
        refId.textContent = "AUD-" + Date.now().toString(36).toUpperCase().slice(-6);
      } else {
        const err = await res.json().catch(() => ({}));
        const msg =
          err?.detail?.validation_errors
            ? err.detail.validation_errors.map((e) => `${e.field}: ${e.msg}`).join(" · ")
            : err?.detail || `Error del servidor (${res.status})`;
        showToast("✗ " + msg, "error");
      }
    } catch (networkErr) {
      console.error("Error de red:", networkErr);
      showToast("✗ Error de red. Reintenta en un momento.", "error");
    } finally {
      btnSubmit.disabled    = false;
      btnSubmit.textContent = "Enviar solicitud →";
    }
  }, true /* capture=true → se ejecuta antes que el listener inline */);

  /* ── 4. Parchear validateForm para la nueva fecha ───────────────────── */
  const _originalValidate = window.validateForm;
  window.validateForm = function () {
    /* Ejecuta la validación original (comprueba empresa, email, etc.) */
    let valid = _originalValidate ? _originalValidate() : true;

    /* Revalida el campo de fecha con el nuevo formato */
    const dateField = document.getElementById("f-date");
    const dateInput = document.querySelector('input[name="audit_date"]');
    if (dateInput && dateField) {
      const val    = (dateInput.value || "").trim();
      const parsed = parseDateDMY(val);
      const today  = new Date(); today.setHours(0, 0, 0, 0);

      if (!val || !parsed) {
        dateField.classList.add("error");
        const errEl = dateField.querySelector(".field-error");
        if (errEl) errEl.textContent = "Introduce una fecha válida (dd/mm/aaaa)";
        valid = false;
      } else if (parsed < today) {
        dateField.classList.add("error");
        const errEl = dateField.querySelector(".field-error");
        if (errEl) errEl.textContent = "La fecha no puede ser pasada";
        valid = false;
      } else {
        dateField.classList.remove("error");
        // El original pudo marcar valid=false por la comparación de fecha incorrecta
        // (compara "dd/mm/yyyy" < "yyyy-mm-dd" como string, siempre true).
        // Recalculamos: válido si no quedan campos con error ni el consentimiento pendiente.
        if (!valid) {
          const remainingErrors = document.querySelectorAll(".field.error").length;
          const consentErr      = document.getElementById("consentError");
          const consentPending  = consentErr && consentErr.style.display !== "none";
          valid = remainingErrors === 0 && !consentPending;
        }
      }
    }

    return valid;
  };

})();