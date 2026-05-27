/**
 * formulario.patch.js
 *
 * Reemplaza el bloque "Submit" del formulario original para que envíe
 * multipart/form-data a la API FastAPI en lugar de JSON puro.
 *
 * INSTRUCCIONES:
 *   1. Añade este <script src="formulario.patch.js"></script> ANTES del </body>
 *      en formulario.html (después del script inline existente).
 *   2. Ajusta API_URL si la API corre en otro host/puerto.
 *
 * El script sobreescribe el listener 'submit' del formulario.
 */

(function () {
  const API_URL = "http://localhost:8000/api/audit-request";

  // Elimina el listener anterior (que usaba fetch con JSON)
  const form = document.getElementById("auditForm");
  const newForm = form.cloneNode(true);
  form.parentNode.replaceChild(newForm, form);

  // Referencias que el listener original usaba como closures
  // (las re-obtenemos del DOM clonado)
  const refId       = document.getElementById("refId");
  const btnSubmit   = document.getElementById("btnSubmit");
  const consentCheck = document.getElementById("consentCheck");

  newForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    // Reutiliza la función de validación del script inline
    if (!validateForm()) {
      showToast("Por favor, revisa los campos marcados en rojo", "error");
      return;
    }

    btnSubmit.disabled = true;
    btnSubmit.textContent = "Enviando…";

    // ── Construir el payload JSON (igual que antes) ────────────────────────
    const fd = new FormData(newForm);
    const scopes = [...document.querySelectorAll('input[name="scope"]:checked')]
      .map((c) => c.value);

    const payload = {
      ref:         refId.textContent,
      company:     fd.get("company"),
      sector:      fd.get("sector"),
      domain:      fd.get("domain") || "",
      contact:     fd.get("contact"),
      role:        fd.get("role"),
      department:  fd.get("department") || "",
      email:       fd.get("email"),
      phone:       fd.get("phone") || "",
      ips:         window.ips || [],           // array del script inline
      scope:       scopes,
      tunnel: document.getElementById("tunnelPanel").classList.contains("visible")
        ? document.querySelector('input[name="tunnel"]:checked')?.value || null
        : null,
      scope_notes: fd.get("scope_notes") || "",
      audit_date:  fd.get("audit_date"),
      duration:    fd.get("duration") || "",
      priority:    fd.get("priority"),
      submitted_at: new Date().toISOString(),
    };

    // ── Construir el multipart ─────────────────────────────────────────────
    const body = new FormData();

    // Campo "data": el JSON como string
    body.append("data", JSON.stringify(payload));

    // Archivos opcionales
    const wgConfInput  = document.getElementById("fileWgConf");
    const sshKeyInput  = document.getElementById("fileSshKey");

    if (wgConfInput?.files?.[0])  body.append("wg_conf",  wgConfInput.files[0]);
    if (sshKeyInput?.files?.[0])  body.append("ssh_key",  sshKeyInput.files[0]);

    // ── Enviar a la API ────────────────────────────────────────────────────
    try {
      const res = await fetch(API_URL, { method: "POST", body });

      if (res.ok || res.status === 207) {
        const json = await res.json();
        showToast(
          `✓ Solicitud ${json.ref} registrada. Recibirás confirmación por email.`,
          "success"
        );
        // Reset
        newForm.reset();
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
      showToast("✗ No se pudo conectar con la API. ¿Está corriendo en el puerto 8000?", "error");
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.textContent = "Enviar solicitud →";
    }
  });
})();
