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

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    e.stopImmediatePropagation();   // evita que el listener inline original se ejecute

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

    /* Enviar */
    try {
      const res = await fetch(API_URL, { method: "POST", body });

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