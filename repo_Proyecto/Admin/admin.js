'use strict';

const USER_KEY  = 'consultor_user';
const API = '';   // mismo host (relativa)
// A2: JWT vive en cookie HttpOnly `consultor_token` que setea el servidor en
// login/signup. El JS no la lee. Para CSRF usamos la cookie pública
// `consultor_csrf` y la reenviamos como header `X-CSRF-Token` en POST/PUT/etc.

// ── CSRF ──────────────────────────────────────────────────────────────────
function getCsrf() {
  const m = document.cookie.match(/(?:^|; )consultor_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

// ── Almacenamiento (solo perfil no sensible, NO token) ────────────────────
function getUser()   { try { return JSON.parse(sessionStorage.getItem(USER_KEY)); } catch { return null; } }
function setUser(u)  { sessionStorage.setItem(USER_KEY, JSON.stringify(u)); }
function clearUser() { sessionStorage.removeItem(USER_KEY); }

// ── Helpers fetch ──────────────────────────────────────────────────────────
async function api(method, path, body, _withAuth /* legacy, ignorado */) {
  const headers = { 'Content-Type': 'application/json' };
  const m = (method || 'GET').toUpperCase();
  if (m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS') {
    const csrf = getCsrf();
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }
  const opts = { method: m, headers, credentials: 'include' };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(API + path, opts);
  if (r.status === 401) { clearUser(); showLogin(); throw new Error('UNAUTH'); }
  return r;
}

// ── UI: mostrar / ocultar vistas ───────────────────────────────────────────
function showLogin() {
  document.getElementById('loginOverlay').classList.remove('hidden');
  document.getElementById('appHeader').style.display = 'none';
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
}
function hideLogin() {
  document.getElementById('loginOverlay').classList.add('hidden');
  document.getElementById('appHeader').style.display = 'flex';
}
function showAdminView() {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('viewAdmin').classList.add('active');
  document.getElementById('headerTitle').textContent = 'CALENDARIO DE AUDITORÍAS';
  document.getElementById('headerRolBadge').textContent = 'Admin';
}
function showClientView() {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('viewClient').classList.add('active');
  document.getElementById('headerTitle').textContent = 'CONSULTORIA';
  document.getElementById('headerRolBadge').textContent = 'Cliente';
}

async function logout() {
  try {
    await fetch(API + '/api/auth/logout', {
      method: 'POST', credentials: 'include',
      headers: { 'X-CSRF-Token': getCsrf() },
    });
  } catch {}
  clearUser();
  if (window._calendar) { window._calendar.destroy(); window._calendar = null; }
  document.getElementById('eventDetail').classList.remove('visible');
  document.getElementById('upcomingList').innerHTML = '<span class="empty">—</span>';
  document.getElementById('auditsList').innerHTML = '';
  showLogin();
}

// ── Tabs login/signup ──────────────────────────────────────────────────────
document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.auth-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.pane).classList.add('active');
  });
});

// ── Login (email O username) ───────────────────────────────────────────────
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('loginBtn');
  const errEl = document.getElementById('loginError');
  errEl.textContent = '';
  btn.disabled = true; btn.textContent = 'Verificando…';
  const userInput = document.getElementById('loginUser').value.trim();
  const password  = document.getElementById('loginPass').value;
  const turnstile_token = await getTurnstileToken('login');
  if (!turnstile_token) {
    errEl.textContent = 'Resuelve primero el captcha de abajo.';
    btn.disabled = false; btn.textContent = 'Acceder →';
    return;
  }
  try {
    let r, body;
    if (userInput.includes('@')) {
      r = await fetch(API + '/api/auth/login', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: userInput, password, turnstile_token }),
      });
      if (r.ok) body = await r.json();
    }
    if (!r || !r.ok) {
      // fallback al endpoint legacy que acepta username además de email
      r = await fetch(API + '/api/admin/login', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: userInput, password, turnstile_token }),
      });
      if (r.ok) {
        // /api/admin/login no devuelve user — la cookie ya está puesta,
        // pedimos /me usando la propia cookie.
        const meRes = await fetch(API + '/api/auth/me', { credentials: 'include' });
        const meUser = meRes.ok ? await meRes.json() : { id: 0, email: userInput, rol: 'admin', nombre: userInput, empresas: [] };
        body = { user: meUser };
      }
    }
    if (r.status === 403) { errEl.textContent = 'Verificación anti-bot fallida. Recarga e inténtalo otra vez.'; return; }
    if (r.status === 429) { errEl.textContent = 'Demasiados intentos. Espera un momento.'; return; }
    if (!r.ok)            { errEl.textContent = 'Credenciales incorrectas.'; return; }

    setUser(body.user);
    hideLogin();
    routeAfterLogin();
  } catch {
    errEl.textContent = 'Error de conexión.';
  } finally {
    btn.disabled = false; btn.textContent = 'Acceder →';
    resetTurnstile('login');
  }
});

// ── Signup ─────────────────────────────────────────────────────────────────
function renderEmpresasRow(idx) {
  const div = document.createElement('div');
  div.className = 'empresa-row';
  div.dataset.idx = idx;
  div.innerHTML = `
    <div class="row-line">
      <input type="text" class="emp-nombre" placeholder="Nombre de la empresa" required>
      <button type="button" class="remove-row-btn" title="Quitar">✕</button>
    </div>
    <div class="row-line" style="margin-top:6px">
      <input type="text" class="emp-sectores" placeholder="Sectores (separados por coma): Tecnología, Pharma">
    </div>
    <div class="sectores-help">Puedes poner uno o varios. Ej: Tecnología, Healthcare</div>
  `;
  div.querySelector('.remove-row-btn').onclick = () => div.remove();
  return div;
}
let empIdx = 0;
function addEmpresaRow() {
  document.getElementById('empresasList').appendChild(renderEmpresasRow(empIdx++));
}
document.getElementById('addEmpresaBtn').onclick = addEmpresaRow;
addEmpresaRow();   // inicial

// ── Turnstile visible (login + signup) ───────────────────────────────────
// Dos widgets visibles, uno por form. El usuario resuelve el desafío antes
// de pulsar submit. Los tokens se guardan en _tsTokens y se resetean tras
// cada submit (los tokens expiran a 5 min).
const _tsTokens = { login: null, signup: null };
window.onTSLogin     = (t) => { _tsTokens.login  = t; };
window.onTSLoginErr  = ()  => { _tsTokens.login  = null; };
window.onTSSignup    = (t) => { _tsTokens.signup = t; };
window.onTSSignupErr = ()  => { _tsTokens.signup = null; };

function getTurnstileToken(formKey = 'login') {
  return Promise.resolve(_tsTokens[formKey] || null);
}
function resetTurnstile(formKey) {
  if (typeof turnstile === 'undefined') return;
  const id = formKey === 'signup' ? '#tsSignupWidget' : '#tsLoginWidget';
  try { turnstile.reset(id); } catch {}
  _tsTokens[formKey] = null;
}

document.getElementById('signupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('signupBtn');
  const errEl = document.getElementById('signupError');
  const infoEl = document.getElementById('signupInfo');
  errEl.textContent = ''; infoEl.textContent = '';
  const email = document.getElementById('signupEmail').value.trim();
  const nombre = document.getElementById('signupName').value.trim();
  const password = document.getElementById('signupPass').value;
  const password2 = document.getElementById('signupPass2').value;
  if (password !== password2) { errEl.textContent = 'Las contraseñas no coinciden.'; return; }
  if (password.length < 8) { errEl.textContent = 'Mínimo 8 caracteres.'; return; }
  const empresas = [...document.querySelectorAll('.empresa-row')].map(row => {
    const nombre = row.querySelector('.emp-nombre').value.trim();
    const sectores = row.querySelector('.emp-sectores').value
      .split(',').map(s => s.trim()).filter(Boolean);
    return { nombre, sectores };
  }).filter(e => e.nombre);
  if (!empresas.length) { errEl.textContent = 'Añade al menos una empresa.'; return; }

  btn.disabled = true; btn.textContent = 'Verificando…';
  const turnstile_token = await getTurnstileToken('signup');
  if (!turnstile_token) {
    errEl.textContent = 'Resuelve primero el captcha de abajo.';
    btn.disabled = false; btn.textContent = 'Crear cuenta →';
    return;
  }
  btn.textContent = 'Creando cuenta…';
  try {
    const r = await fetch(API + '/api/auth/signup', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, nombre: nombre || null, empresas, turnstile_token }),
    });
    if (r.status === 403) { errEl.textContent = 'Verificación anti-bot fallida. Recarga e inténtalo otra vez.'; return; }
    if (r.status === 409) { errEl.textContent = 'Ese email ya está registrado.'; return; }
    if (r.status === 429) { errEl.textContent = 'Demasiados intentos. Espera un momento.'; return; }
    if (!r.ok)            { errEl.textContent = 'No se ha podido crear la cuenta.'; return; }
    const body = await r.json();
    setUser(body.user);
    infoEl.textContent = '¡Cuenta creada! Entrando…';
    setTimeout(() => { hideLogin(); routeAfterLogin(); }, 600);
  } catch {
    errEl.textContent = 'Error de conexión.';
  } finally {
    btn.disabled = false; btn.textContent = 'Crear cuenta →';
    resetTurnstile('signup');
  }
});

// ── Routing por rol ────────────────────────────────────────────────────────
function routeAfterLogin() {
  const u = getUser();
  document.getElementById('headerEmail').textContent = u?.email || '';
  if (u?.rol === 'admin') { showAdminView(); loadCalendar(); }
  else                    { showClientView(); loadMyAudits(); }
}

// ── Calendar admin ─────────────────────────────────────────────────────────
const fmtDate = d => d
  ? new Date(d + 'T00:00:00').toLocaleDateString('es-ES', { day:'2-digit', month:'short', year:'numeric' })
  : '—';

function showAdminEventDetail(event) {
  const p = event.extendedProps;
  document.getElementById('detailTitle').textContent    = event.title;
  document.getElementById('detailSector').textContent   = p.sector   || '—';
  document.getElementById('detailEmail').textContent    = p.email    || '—';
  document.getElementById('detailTunnel').textContent   = p.tunnel   || 'No especificado';
  document.getElementById('detailSchedule').textContent = p.schedule || '—';
  const startStr = event.startStr;
  let endStr = event.endStr;
  if (endStr) {
    const d = new Date(endStr); d.setDate(d.getDate() - 1);
    endStr = d.toISOString().split('T')[0];
  }
  document.getElementById('detailDates').textContent =
    startStr === endStr || !endStr ? fmtDate(startStr) : `${fmtDate(startStr)} → ${fmtDate(endStr)}`;
  const prio = p.priority || 'low';
  const labels = { high: 'Alta', medium: 'Media', low: 'Normal' };
  document.getElementById('detailPriority').innerHTML =
    `<span class="badge badge-${safeKey(prio)}">${escapeHtml(labels[prio] || prio)}</span>`;
  const est = p.estado || 'pendiente';
  document.getElementById('detailEstado').innerHTML =
    `<span class="badge badge-${safeKey(est)}">${escapeHtml(est)}</span>`;
  const dl = document.getElementById('detailDownloads');
  if (est === 'completada' && p.ref) {
    dl.querySelector('#detailDownloadEjecutivo').dataset.ref = p.ref;
    dl.querySelector('#detailDownloadTecnico').dataset.ref = p.ref;
    dl.hidden = false;
  } else {
    dl.hidden = true;
  }
  document.getElementById('eventDetail').classList.add('visible');
}

function renderUpcoming(events) {
  const today = new Date(); today.setHours(0,0,0,0);
  const upcoming = events
    .filter(e => e.start && new Date(e.start) >= today)
    .sort((a, b) => new Date(a.start) - new Date(b.start)).slice(0, 6);
  const list = document.getElementById('upcomingList');
  if (!upcoming.length) { list.innerHTML = '<span class="empty">Sin auditorías próximas</span>'; return; }
  list.innerHTML = upcoming.map(e => `
    <div class="upcoming-item" data-id="${escapeHtml(String(e.id ?? ''))}">
      <div class="upcoming-item-name">${escapeHtml(e.title || '')}</div>
      <div class="upcoming-item-date">${escapeHtml(fmtDate(e.start))}</div>
    </div>`).join('');
}

async function loadCalendar() {
  const r = await api('GET', '/api/admin/events', undefined, true);
  if (!r.ok) return;
  const allEvents = await r.json();
  if (window._calendar) window._calendar.destroy();
  const calendar = new FullCalendar.Calendar(document.getElementById('calendar'), {
    initialView: 'dayGridMonth', locale: 'es', firstDay: 1, height: 'auto',
    headerToolbar: { left: 'prev,next today', center: 'title', right: 'dayGridMonth,timeGridWeek,listMonth,all' },
    buttonText: { today: 'Hoy', month: 'Mes', week: 'Semana', list: 'Lista', all: 'Todas' },
    views: { listAll: { type: 'list', duration: { years: 20 }, buttonText: 'Todas' } },
    customButtons: { all: { text: 'Todas', click: () => calendar.changeView('listAll', new Date(2020, 0, 1)) } },
    events: allEvents,
    eventClick: info => showAdminEventDetail(info.event),
    eventDidMount: info => { info.el.title = info.event.title; },
  });
  window._calendar = calendar; calendar.render();
  renderUpcoming(allEvents);
  document.getElementById('upcomingList').addEventListener('click', e => {
    const item = e.target.closest('.upcoming-item');
    if (!item) return;
    const ev = allEvents.find(x => x.id === item.dataset.id);
    if (ev?.start) {
      calendar.gotoDate(ev.start);
      const fcEvent = calendar.getEventById(item.dataset.id);
      if (fcEvent) showAdminEventDetail(fcEvent);
    }
  });
}

// ── Dashboard cliente: mis peticiones ──────────────────────────────────────
async function loadMyAudits() {
  const list = document.getElementById('auditsList');
  list.innerHTML = '<div class="empty">Cargando…</div>';
  try {
    const r = await api('GET', '/api/me/audits', undefined, true);
    if (!r.ok) { list.innerHTML = '<div class="empty">Error al cargar.</div>'; return; }
    const audits = await r.json();
    if (!audits.length) {
      list.innerHTML = `<div class="empty">Aún no tienes peticiones. Pulsa <strong>+ Nueva petición</strong> para crear la primera.</div>`;
      return;
    }
    list.innerHTML = audits.map(a => renderAuditCard(a)).join('');
    list.querySelectorAll('.btn-cancel').forEach(b => b.addEventListener('click', onCancelAudit));
    list.querySelectorAll('.btn-firmar:not(.btn-pagar):not(.btn-informe)').forEach(b => b.addEventListener('click', onFirmarDescargo));
    list.querySelectorAll('.btn-pagar').forEach(b => b.addEventListener('click', onPagarAuditoria));
    list.querySelectorAll('.btn-informe').forEach(b => b.addEventListener('click', onDescargarInforme));
  } catch (err) {
    if (err.message !== 'UNAUTH') list.innerHTML = '<div class="empty">Error de conexión.</div>';
  }
}

function renderAuditCard(a) {
  const labelsScope = {
    pentest_ext: 'Pentesting externo', pentest_int: 'Pentesting interno',
    web_app: 'Web app', cloud: 'Cloud', compliance: 'Compliance',
    gdpr: 'GDPR', phishing: 'Phishing', wifi: 'Wi-Fi',
  };
  const scopeStr = (a.scope || []).map(s => labelsScope[s] || s).join(', ') || '—';
  const ipsStr   = (a.ips   || []).join(', ') || '—';
  const dom      = a.dominio || '—';
  const fechaStr = a.fecha_inicial ? fmtDate(a.fecha_inicial) : '—';
  const horario  = a.horario_preferido || '—';
  const estado   = a.estado || 'pendiente';
  const cancelable = estado === 'pendiente' || estado === 'pendiente_descargo' || estado === 'pendiente_pago';
  const estadoTerminal = ['cancelada','completada','expirada','en_curso'].includes(estado);
  const needsSign = estado === 'pendiente_descargo' && !a.descargo_id;
  const needsPay = estado === 'pendiente_pago';
  const estadoLabel = estado === 'pendiente_descargo' ? '🔒 falta firma'
                    : estado === 'pendiente_pago'    ? '💳 falta pago'
                    : estado;
  return `
    <div class="audit-card" data-id="${escapeHtml(String(a.id ?? ''))}">
      <div>
        <div class="audit-card-head">
          <span class="audit-card-ref">${escapeHtml(a.ref || '#' + a.id)}</span>
          <span class="audit-card-empresa">${escapeHtml(a.empresa_nombre || '')}</span>
          <span class="badge badge-${safeKey(estado)}">${escapeHtml(estadoLabel)}</span>
        </div>
        <div class="audit-card-meta">
          <span>📅 ${escapeHtml(fechaStr)}  ${escapeHtml(horario)}</span>
          <span>🌐 ${escapeHtml(dom)}</span>
          <span>🛡️ ${escapeHtml(scopeStr)}</span>
        </div>
        ${ipsStr !== '—' ? `<div class="audit-card-meta"><span>IPs: ${escapeHtml(ipsStr)}</span></div>` : ''}
      </div>
      <div class="audit-card-actions">
        ${needsSign ? `<button class="btn-firmar" data-ref="${escapeHtml(a.ref || '')}" data-empresa-id="${escapeHtml(String(a.empresa_id ?? ''))}">Firmar descargo</button>` : ''}
        ${needsPay ? `<button class="btn-firmar btn-pagar" data-ref="${escapeHtml(a.ref || '')}">💳 Pagar</button>` : ''}
        ${estado === 'completada' && a.ref ? `
          <button class="btn-firmar btn-informe" data-ref="${escapeHtml(a.ref)}" data-tipo="ejecutivo">📊 Resumen ejecutivo</button>
          <button class="btn-firmar btn-informe" data-ref="${escapeHtml(a.ref)}" data-tipo="tecnico">📄 Informe técnico</button>
        ` : ''}
        ${estadoTerminal ? '' : `
        <button class="btn-danger btn-cancel" data-id="${escapeHtml(String(a.id ?? ''))}" ${cancelable ? '' : 'disabled'}>
          ${cancelable ? 'Cancelar' : 'No cancelable'}
        </button>`}
      </div>
    </div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function safeKey(s) {
  return String(s).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
}

function onPagarAuditoria(e) {
  const ref = e.currentTarget.dataset.ref;
  if (!ref) return;
  modal.classList.add('visible');
  showPagoStep(ref);
}

function onFirmarDescargo(e) {
  const ref = e.currentTarget.dataset.ref;
  const empresaId = parseInt(e.currentTarget.dataset.empresaId, 10) || null;
  if (!ref) return;
  // Abrir modal directo en step-firma (sin reset del form, para no perder
  // datos si el usuario tenía el formulario relleno)
  modal.classList.add('visible');
  showFirmaStep(ref, empresaId);
}

async function onDescargarInforme(e) {
  const btn = e.currentTarget;
  const ref = btn.dataset.ref;
  const tipo = btn.dataset.tipo;
  const formato = btn.dataset.formato || 'pdf';
  if (!ref || !tipo) return;
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⌛ Descargando…';
  try {
    const r = await fetch(`${API}/api/me/audits/${encodeURIComponent(ref)}/informe/${tipo}?format=${formato}`, {
      credentials: 'include',
    });
    if (r.status === 401) { clearUser(); showLogin(); return; }
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: 'Error desconocido' }));
      alert(`No se pudo descargar el informe: ${err.detail || r.status}`);
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `informe_${tipo}_${ref}.${formato}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    console.error('Error descarga informe', err);
    alert('Error al descargar el informe.');
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

async function onCancelAudit(e) {
  const id = e.target.dataset.id;
  if (!confirm('¿Cancelar esta auditoría?\n\nNo se puede cancelar si quedan menos de 24h hasta el inicio.')) return;
  try {
    const r = await api('DELETE', `/api/me/audits/${id}`, undefined, true);
    if (r.ok) { await loadMyAudits(); return; }
    const err = await r.json().catch(() => ({}));
    if (r.status === 409 && err.detail?.code === 'cutoff_24h') {
      alert('Ya no se puede cancelar: el inicio está a menos de 24h.');
    } else {
      alert('No se ha podido cancelar.');
    }
  } catch (err) {
    if (err.message !== 'UNAUTH') alert('Error de conexión.');
  }
}

// ── Modal Nueva petición ───────────────────────────────────────────────────
const modal = document.getElementById('newAuditModal');
const TUNNEL_TRIGGERS = ['pentest_int', 'compliance', 'gdpr'];

function updateTunnelPanel() {
  const checked = [...document.querySelectorAll('#naScope input:checked')].map(c => c.value);
  const need = checked.some(v => TUNNEL_TRIGGERS.includes(v));
  document.getElementById('naTunnelPanel').style.display = need ? 'grid' : 'none';
}

document.querySelectorAll('#naScope input').forEach(c => c.addEventListener('change', updateTunnelPanel));

document.querySelectorAll('input[name="naTunnel"]').forEach(r => r.addEventListener('change', () => {
  const v = document.querySelector('input[name="naTunnel"]:checked')?.value;
  document.getElementById('naWgWrap').style.display  = v === 'wireguard' ? 'block' : 'none';
  document.getElementById('naSshWrap').style.display = v === 'ssh' ? 'block' : 'none';
}));

// File drop-zones — XHR upload con progress + verificación de hash
const uploadedKeys = { wg_conf: null, ssh_key: null };

async function sha256Hex(buf) {
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2,'0')).join('');
}

function setupFileDrop(inputId, dropId, kind) {
  const input = document.getElementById(inputId);
  const drop  = document.getElementById(dropId);
  if (!input || !drop) return;

  const fillBar = drop.querySelector('.fd-progress-fill');
  const pctEl   = drop.querySelector('.fd-progress-pct');
  const statusEl= drop.querySelector('.fd-progress-status');
  const upName  = drop.querySelector('.fd-uploading-name');
  const vName   = drop.querySelector('.fd-verified-name');
  const hLocal  = drop.querySelector('.fd-hash-local');
  const hServer = drop.querySelector('.fd-hash-server');
  const hStatus = drop.querySelector('.fd-hash-status');
  const replaceBtn = drop.querySelector('.fd-replace-btn');

  function reset() {
    drop.classList.remove('is-uploading','is-verified','is-error');
    input.value = ''; uploadedKeys[kind] = null;
    fillBar.style.width = '0%'; pctEl.textContent = '0%';
    hLocal.textContent = ''; hServer.textContent = '';
    hStatus.textContent = ''; hStatus.className = 'fd-hash-status';
  }

  replaceBtn.addEventListener('click', e => {
    e.preventDefault(); e.stopPropagation();
    reset();
    setTimeout(() => input.click(), 50);
  });

  ['dragenter','dragover'].forEach(ev => drop.addEventListener(ev, e => {
    if (drop.classList.contains('is-uploading') || drop.classList.contains('is-verified')) return;
    e.preventDefault(); drop.classList.add('is-dragover');
  }));
  ['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.remove('is-dragover');
  }));
  drop.addEventListener('drop', e => {
    if (drop.classList.contains('is-uploading') || drop.classList.contains('is-verified')) return;
    if (e.dataTransfer.files?.length) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event('change'));
    }
  });

  input.addEventListener('change', async () => {
    const file = input.files[0];
    if (!file) return;

    // 1) Cambia a estado "uploading" + calcula hash local en paralelo a la subida
    drop.classList.add('is-uploading');
    drop.classList.remove('is-error');
    upName.textContent = file.name + ` (${(file.size/1024).toFixed(1)} KB)`;
    fillBar.style.width = '0%'; pctEl.textContent = '0%';
    statusEl.textContent = 'Subiendo y calculando hash…';

    let hashLocal;
    try {
      hashLocal = await sha256Hex(await file.arrayBuffer());
    } catch (err) {
      statusEl.textContent = 'Error calculando hash local';
      drop.classList.remove('is-uploading'); drop.classList.add('is-error');
      return;
    }

    // 2) XHR upload con onprogress
    const fd = new FormData();
    fd.append('file', file); fd.append('kind', kind);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', API + '/api/me/uploads');
    xhr.withCredentials = true;
    const _csrfUp = getCsrf();
    if (_csrfUp) xhr.setRequestHeader('X-CSRF-Token', _csrfUp);
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        fillBar.style.width = pct + '%';
        pctEl.textContent = pct + '%';
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        let r;
        try { r = JSON.parse(xhr.responseText); } catch { return showErr('Respuesta inválida'); }
        const match = r.sha256 === hashLocal;
        uploadedKeys[kind] = match ? r.object_key : null;
        drop.classList.remove('is-uploading');
        drop.classList.add('is-verified');
        vName.textContent = r.filename + ` (${(r.size/1024).toFixed(1)} KB)`;
        hLocal.textContent = hashLocal;
        hServer.textContent = r.sha256;
        hStatus.className = 'fd-hash-status ' + (match ? 'ok' : 'fail');
        hStatus.textContent = match
          ? '✓ Hashes coinciden — archivo verificado'
          : '✗ Los hashes NO coinciden — vuelve a subir';
        if (!match) {
          drop.classList.add('is-error');
          drop.classList.remove('is-verified');
        }
      } else if (xhr.status === 401) {
        clearUser(); showLogin();
      } else {
        showErr('Error servidor (' + xhr.status + ')');
      }
    };
    xhr.onerror = () => showErr('Error de red');
    xhr.send(fd);

    function showErr(msg) {
      drop.classList.remove('is-uploading'); drop.classList.add('is-error');
      statusEl.textContent = msg;
    }
  });
}

setupFileDrop('naWgFile',  'naWgDrop',  'wg_conf');
setupFileDrop('naSshFile', 'naSshDrop', 'ssh_key');

document.getElementById('newAuditBtnHeader').addEventListener('click', async () => {
  const u = getUser();
  if (!u || !u.empresas?.length) {
    alert('Primero añade al menos una empresa a tu cuenta (en el registro).');
    return;
  }
  const sel = document.getElementById('naEmpresa');
  sel.innerHTML = u.empresas.map(e => `<option value="${escapeHtml(String(e.id ?? ''))}">${escapeHtml(e.nombre)}</option>`).join('');
  document.getElementById('newAuditForm').reset();
  document.querySelectorAll('#naScope input').forEach(c => c.checked = false);
  uploadedKeys.wg_conf = null; uploadedKeys.ssh_key = null;
  ['naWgDrop','naSshDrop'].forEach(id => {
    const d = document.getElementById(id);
    d.classList.remove('is-uploading','is-verified','is-error','is-dragover');
  });
  updateTunnelPanel();
  document.getElementById('naDate').min = new Date().toISOString().split('T')[0];
  document.getElementById('naContactName').value = u.nombre || '';
  document.getElementById('naError').textContent = '';
  // Asegurar que arrancamos en el step del form, no en residuos de firma/pago
  document.getElementById('newAuditForm').hidden = false;
  document.getElementById('naStepFirma').hidden = true;
  document.getElementById('naStepPago').hidden  = true;
  document.getElementById('naFirmaCloseBtn').hidden = true;
  // Toggle "saltar firma" solo para admin
  const adminRow = document.getElementById('naAdminSkipRow');
  adminRow.hidden = (u.rol !== 'admin');
  document.getElementById('naSkipDescargo').checked = false;
  // Reset duración custom
  document.getElementById('naDurationCustom').hidden = true;
  document.getElementById('naDurationCustom').value = '';
  // Generar ref UNA sola vez por modal-open. Reusar en cada submit evita
  // duplicados aunque el navegador haga retry.
  pendingRef = genRef();
  modal.classList.add('visible');
});

// Mostrar input de horas custom cuando se selecciona "Personalizada"
document.getElementById('naDuration').addEventListener('change', (e) => {
  const inp = document.getElementById('naDurationCustom');
  inp.hidden = (e.target.value !== 'custom');
  if (!inp.hidden) inp.focus();
});
document.getElementById('naCancelBtn').addEventListener('click', () => modal.classList.remove('visible'));

// `pendingRef` se setea al abrir el modal y se reutiliza en cada submit.
// Si el navegador hace retry, el segundo POST llega con la misma ref y
// la BD lo bloquea con 23505 (UNIQUE violation) → API 409 manejado abajo.
let pendingRef = null;
function genRef() {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = ''; for (let i = 0; i < 6; i++) s += c[Math.floor(Math.random()*c.length)];
  return 'AUD-' + s;
}

document.getElementById('newAuditForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('naError');
  errEl.textContent = '';
  const empresa_id = parseInt(document.getElementById('naEmpresa').value, 10);
  const scope = [...document.querySelectorAll('#naScope input:checked')].map(c => c.value);
  const dominios = document.getElementById('naDomains').value.split('\n').map(s => s.trim()).filter(Boolean);
  const ips = document.getElementById('naIps').value.split('\n').map(s => s.trim()).filter(Boolean);
  const audit_date = document.getElementById('naDate').value;
  const duration = document.getElementById('naDuration').value;
  const customHoursRaw = document.getElementById('naDurationCustom').value;
  const customHours = duration === 'custom'
    ? parseInt(customHoursRaw, 10) : null;
  if (duration === 'custom' && (!customHours || customHours < 1)) {
    errEl.textContent = 'Indica cuántas horas dura la auditoría.'; return;
  }
  const horario_preferido = document.getElementById('naSchedule').value.trim();
  const priority = document.getElementById('naPriority').value;
  const contact_name = document.getElementById('naContactName').value.trim();
  const contact_role = document.getElementById('naContactRole').value.trim();
  const scope_notes = document.getElementById('naNotes').value.trim();
  if (!empresa_id) { errEl.textContent = 'Selecciona empresa.'; return; }
  if (!scope.length) { errEl.textContent = 'Marca al menos un tipo de auditoría.'; return; }
  if (!dominios.length && !ips.length) { errEl.textContent = 'Indica al menos un dominio o una IP.'; return; }
  if (!audit_date) { errEl.textContent = 'Indica fecha de inicio.'; return; }
  if (!contact_name) { errEl.textContent = 'Indica tu nombre como representante.'; return; }

  const needsTunnel = scope.some(v => TUNNEL_TRIGGERS.includes(v));
  const tunnelKind  = needsTunnel ? document.querySelector('input[name="naTunnel"]:checked')?.value : null;
  const wgKey  = tunnelKind === 'wireguard' ? uploadedKeys.wg_conf : null;
  const sshKey = tunnelKind === 'ssh'       ? uploadedKeys.ssh_key : null;
  if (needsTunnel && !wgKey && !sshKey) {
    errEl.textContent = 'Sube y verifica el archivo de túnel antes de enviar.';
    return;
  }

  if (!pendingRef) pendingRef = genRef();
  // Si "Personalizada", codifico las horas en la string para persistencia
  // sin tocar schema: "custom_12h" → backend pricing lo parsea.
  const durationFinal = duration === 'custom' ? `custom_${customHours}h` : duration;
  const payload = {
    empresa_id,
    ref: pendingRef,
    dominio: dominios[0] || null,
    dominios_extra: dominios.slice(1),
    ips,
    scope,
    audit_date,
    duration: durationFinal,
    horario_preferido, priority,
    tunnel: tunnelKind,
    wg_object_key: wgKey,
    ssh_object_key: sshKey,
    scope_notes: scope_notes || null,
    contact: { nombre: contact_name, rol: contact_role || null },
    skip_descargo: !!document.getElementById('naSkipDescargo').checked,
  };

  const btn = document.getElementById('naSubmitBtn');
  btn.disabled = true; btn.textContent = 'Enviando…';
  try {
    const r = await api('POST', '/api/me/audits', payload, true);
    // 409: ref ya existe → idempotencia ok, seguimos al siguiente step
    if (r.status === 409) {
      const j = await r.json().catch(() => ({}));
      if (j.detail?.code !== 'duplicate_ref') {
        errEl.textContent = (typeof j.detail === 'string' ? j.detail : 'Conflicto.');
        return;
      }
    } else if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      errEl.textContent = (typeof j.detail === 'string' ? j.detail : null) || 'Error al enviar la petición.';
      return;
    }
    uploadedKeys.wg_conf = null; uploadedKeys.ssh_key = null;
    const empresaIdSel = parseInt(document.getElementById('naEmpresa').value, 10) || null;
    const refUsed = payload.ref;
    pendingRef = null;  // ref consumido — la próxima abierta del modal generará otro
    if (payload.skip_descargo && getUser()?.rol === 'admin') {
      showPagoStep(refUsed);
    } else {
      showFirmaStep(refUsed, empresaIdSel);
    }
  } catch (err) {
    if (err.message !== 'UNAUTH') errEl.textContent = 'Error de conexión.';
  } finally {
    btn.disabled = false; btn.textContent = 'Enviar petición';
  }
});

// ── Paso 4: firma del descargo ─────────────────────────────────────────────
const stepFirma = document.getElementById('naStepFirma');
const stepForm = document.getElementById('newAuditForm');
let firmaCtx = { ref: null, empresaId: null };

function showFirmaStep(ref, empresaId) {
  firmaCtx = { ref, empresaId };
  document.getElementById('naFirmaRef').textContent = ref;
  document.getElementById('naFirmaError').textContent = '';
  stepForm.hidden = true;
  stepFirma.hidden = false;
  resetDescargoDrop();
}

let descargoResetTimer = null;
function resetDescargoDrop() {
  if (descargoResetTimer) { clearTimeout(descargoResetTimer); descargoResetTimer = null; }
  const dz = document.getElementById('naDescargoDrop');
  dz.querySelector('.drop-zone-idle').hidden = false;
  dz.querySelector('.drop-zone-loading').hidden = true;
  dz.querySelector('.drop-zone-done').hidden = true;
  document.getElementById('naDescargoFile').value = '';
}

async function downloadDescargoPdf() {
  const errEl = document.getElementById('naFirmaError');
  errEl.textContent = '';
  document.getElementById('naCifBox').hidden = true;
  try {
    const r = await api('GET', `/api/me/audits/${encodeURIComponent(firmaCtx.ref)}/descargo/pdf`, undefined, true);
    if (r.status === 409) {
      const j = await r.json().catch(() => ({}));
      if (j.detail?.code === 'missing_cif') {
        document.getElementById('naCifBox').hidden = false;
        errEl.textContent = 'Antes de firmar, añade el CIF/NIF de tu empresa.';
        return;
      }
    }
    if (!r.ok) { errEl.textContent = 'No se pudo generar el descargo.'; return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `descargo_${firmaCtx.ref}.pdf`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (err) {
    if (err.message !== 'UNAUTH') errEl.textContent = 'Error de conexión.';
  }
}

async function saveCif() {
  const errEl = document.getElementById('naFirmaError');
  const cif = document.getElementById('naCifInput').value.trim();
  if (!cif || !firmaCtx.empresaId) return;
  try {
    const r = await api('PATCH', `/api/me/empresas/${firmaCtx.empresaId}`, { cif }, true);
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      errEl.textContent = (typeof j.detail === 'string' ? j.detail : 'CIF inválido.');
      return;
    }
    document.getElementById('naCifBox').hidden = true;
    errEl.textContent = '';
    await downloadDescargoPdf();
  } catch (err) {
    if (err.message !== 'UNAUTH') errEl.textContent = 'Error de conexión.';
  }
}

async function uploadSignedPdf(file) {
  if (descargoResetTimer) { clearTimeout(descargoResetTimer); descargoResetTimer = null; }
  const fileInputEl = document.getElementById('naDescargoFile');
  const errEl = document.getElementById('naFirmaError');
  errEl.textContent = '';
  if (!file || file.type !== 'application/pdf' && !/\.pdf$/i.test(file.name || '')) {
    errEl.textContent = 'El archivo debe ser un PDF.';
    fileInputEl.value = '';
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    errEl.textContent = 'El PDF supera 5 MB.';
    fileInputEl.value = '';
    return;
  }

  const dz = document.getElementById('naDescargoDrop');
  dz.querySelector('.drop-zone-idle').hidden = true;
  dz.querySelector('.drop-zone-done').hidden = true;
  dz.querySelector('.drop-zone-loading').hidden = false;
  const bar = document.getElementById('naDescargoBar');
  const status = document.getElementById('naDescargoStatus');
  bar.style.width = '0%'; status.textContent = 'Subiendo…';

  const fd = new FormData();
  fd.append('file', file, file.name || 'descargo.pdf');

  await new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', API + `/api/me/audits/${encodeURIComponent(firmaCtx.ref)}/descargo/firmar`);
    xhr.withCredentials = true;
    const _csrfFirma = getCsrf();
    if (_csrfFirma) xhr.setRequestHeader('X-CSRF-Token', _csrfFirma);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) bar.style.width = (e.loaded / e.total * 100).toFixed(0) + '%';
    };
    xhr.onload = () => {
      bar.style.width = '100%';
      let r = {};
      try { r = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status >= 200 && xhr.status < 300) {
        dz.querySelector('.drop-zone-loading').hidden = true;
        const doneEl = dz.querySelector('.drop-zone-done');
        doneEl.hidden = false;
        if (r.valid) {
          document.getElementById('naDescargoDoneText').textContent = '✅ Firma válida — pasamos al pago';
          document.getElementById('naDescargoSigner').textContent =
            `Firmante: ${r.signer_dn || 'desconocido'}` +
            (r.firmado_at ? ` · ${r.firmado_at}` : '');
          // Tras 1.5s, pasar al step-pago automáticamente
          setTimeout(() => showPagoStep(firmaCtx.ref), 1500);
        } else {
          document.getElementById('naDescargoDoneText').textContent = '❌ Firma inválida';
          document.getElementById('naDescargoSigner').textContent = r.error || 'No se pudo verificar la firma contra la cadena FNMT.';
          fileInputEl.value = '';
          descargoResetTimer = setTimeout(resetDescargoDrop, 3000);
        }
      } else {
        const msg = (r.detail && (r.detail.message || r.detail)) || 'Error al subir el PDF.';
        errEl.textContent = typeof msg === 'string' ? msg : 'Error al subir el PDF.';
        resetDescargoDrop();
      }
      resolve();
    };
    xhr.onerror = () => {
      errEl.textContent = 'Error de conexión.';
      resetDescargoDrop();
      resolve();
    };
    xhr.send(fd);
  });
}

document.getElementById('naDownloadDescargoBtn').addEventListener('click', (e) => {
  e.preventDefault(); downloadDescargoPdf();
});
document.getElementById('naCifSaveBtn').addEventListener('click', saveCif);

const dzDescargo = document.getElementById('naDescargoDrop');
const fileDescargo = document.getElementById('naDescargoFile');
dzDescargo.addEventListener('click', () => fileDescargo.click());
fileDescargo.addEventListener('change', () => {
  if (fileDescargo.files[0]) uploadSignedPdf(fileDescargo.files[0]);
});
['dragenter','dragover'].forEach(ev => dzDescargo.addEventListener(ev, e => {
  e.preventDefault(); dzDescargo.classList.add('drop-zone-active');
}));
['dragleave','drop'].forEach(ev => dzDescargo.addEventListener(ev, e => {
  e.preventDefault(); dzDescargo.classList.remove('drop-zone-active');
}));
dzDescargo.addEventListener('drop', e => {
  e.preventDefault();
  if (e.dataTransfer.files[0]) uploadSignedPdf(e.dataTransfer.files[0]);
});

document.getElementById('naFirmaSkipBtn').addEventListener('click', async () => {
  modal.classList.remove('visible');
  stepForm.hidden = false; stepFirma.hidden = true;
  await loadMyAudits();
});
document.getElementById('naFirmaCloseBtn').addEventListener('click', async () => {
  modal.classList.remove('visible');
  stepForm.hidden = false; stepFirma.hidden = true;
  document.getElementById('naFirmaCloseBtn').hidden = true;
  await loadMyAudits();
});

// ── Paso 5: pago de la auditoría ───────────────────────────────────────────
const stepPago = document.getElementById('naStepPago');
let pagoCtx = { ref: null, codigo: null, finalCents: null };

async function showPagoStep(ref) {
  pagoCtx = { ref, codigo: null, finalCents: null };
  document.getElementById('naPagoRef').textContent = ref;
  document.getElementById('naPagoError').textContent = '';
  document.getElementById('naPromoStatus').textContent = '';
  document.getElementById('naPromoInput').value = '';
  stepFirma.hidden = true;
  stepForm.hidden = true;
  stepPago.hidden = false;
  // Cargar precio preview
  try {
    const r = await api('GET', `/api/me/audits/${encodeURIComponent(ref)}/precio`, undefined, true);
    if (!r.ok) {
      document.getElementById('naPagoError').textContent = 'No se pudo calcular el precio.';
      return;
    }
    const p = await r.json();
    pintarPrecio(p, 0);
  } catch (err) {
    if (err.message !== 'UNAUTH') document.getElementById('naPagoError').textContent = 'Error de conexión.';
  }
}

function pintarPrecio(p, descuentoEur) {
  document.getElementById('naPrecioRate').textContent = `${p.rate_eur_hour.toFixed(0)} €/h (${p.tier})`;
  document.getElementById('naPrecioHoras').textContent = `${p.horas} h`;
  document.getElementById('naPrecioMultTipo').textContent = `×${p.mult_tipo.toFixed(2)}`;
  document.getElementById('naPrecioMultPrio').textContent = `×${p.mult_prio.toFixed(2)}`;
  const total = p.importe_eur - (descuentoEur || 0);
  document.getElementById('naPrecioTotal').textContent =
    descuentoEur > 0
      ? `${total.toFixed(2)} € (descuento ${descuentoEur.toFixed(2)} €)`
      : `${total.toFixed(2)} €`;
  pagoCtx.finalCents = Math.round(total * 100);
  // Cambia botón si total = 0
  const btnPagar = document.getElementById('naPagoBtn');
  btnPagar.textContent = total <= 0 ? 'Confirmar (gratis)' : 'Pagar con BTC';
}

document.getElementById('naPromoApplyBtn').addEventListener('click', async () => {
  const codigo = document.getElementById('naPromoInput').value.trim();
  const status = document.getElementById('naPromoStatus');
  const errEl = document.getElementById('naPagoError');
  errEl.textContent = '';
  if (!codigo) { status.textContent = ''; pagoCtx.codigo = null; return; }
  // Aplicación tentativa: hacemos un POST /pay con el código sólo si total
  // resultará 0 (caso bypass). Para el resto necesitamos preview... que la
  // API hoy no expone con código aplicado. Atajo: marcamos el código y se
  // resuelve al pulsar "Pagar". Damos feedback visual de que se aplicó.
  pagoCtx.codigo = codigo;
  status.style.color = '#4da6ff';
  status.textContent = `Código "${codigo}" se aplicará al pulsar Pagar.`;
});

document.getElementById('naPagoBtn').addEventListener('click', async () => {
  const errEl = document.getElementById('naPagoError');
  errEl.textContent = '';
  const btn = document.getElementById('naPagoBtn');
  btn.disabled = true; const origText = btn.textContent; btn.textContent = 'Procesando…';
  try {
    const body = pagoCtx.codigo ? { codigo_promo: pagoCtx.codigo } : {};
    const r = await api('POST', `/api/me/audits/${encodeURIComponent(pagoCtx.ref)}/pay`, body, true);
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      const msg = j.detail?.message || j.detail || `Error ${r.status} al iniciar el pago.`;
      errEl.textContent = typeof msg === 'string' ? msg : 'Error al iniciar el pago.';
      return;
    }
    const resp = await r.json();
    if (resp.paid) {
      document.getElementById('naPrecioTotal').textContent = `✅ Pagado (0,00 €)`;
      document.getElementById('naPagoBtn').textContent = '✅ Auditoría confirmada';
      document.getElementById('naPagoSkipBtn').textContent = 'Cerrar';
      setTimeout(async () => {
        modal.classList.remove('visible');
        stepPago.hidden = true; stepForm.hidden = false;
        await loadMyAudits();
      }, 1500);
    } else if (resp.btcpay_url) {
      // Redirección a BTCPay para hacer el pago real
      window.location.href = resp.btcpay_url;
    } else {
      errEl.textContent = 'Respuesta inesperada del servidor.';
    }
  } catch (err) {
    if (err.message !== 'UNAUTH') errEl.textContent = 'Error de conexión.';
  } finally {
    btn.disabled = false;
    if (btn.textContent === 'Procesando…') btn.textContent = origText;
  }
});

document.getElementById('naPagoSkipBtn').addEventListener('click', async () => {
  modal.classList.remove('visible');
  stepPago.hidden = true; stepForm.hidden = false;
  await loadMyAudits();
});

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('detailDownloadEjecutivo')
    ?.addEventListener('click', onDescargarInforme);
  document.getElementById('detailDownloadTecnico')
    ?.addEventListener('click', onDescargarInforme);
  // A2: ya no hay token en JS. Probamos /me con la cookie HttpOnly:
  // si vuelve 200 estamos logueados, si vuelve 401 mostramos login.
  try {
    const r = await fetch(API + '/api/auth/me', { credentials: 'include' });
    if (!r.ok) { clearUser(); showLogin(); return; }
    const u = await r.json();
    setUser(u);
    hideLogin();
    routeAfterLogin();
  } catch (err) {
    showLogin();
  }
});

// ── A2/M2 (CSP strict): bindings que reemplazan los onclick="..." inline ─────
// Ejecutamos en DOMContentLoaded para que los nodos ya existan.
document.addEventListener('DOMContentLoaded', () => {
  // Botón "Cerrar sesión" (sustituye al onclick="logout()" del HTML).
  const lo = document.getElementById('logoutBtn');
  if (lo) lo.addEventListener('click', logout);

  // Botones ojito mostrar/ocultar contraseña (sólo presentes en
  // admin-overrides/index.html). Cada uno trae data-pwd-target="<id-input>".
  document.querySelectorAll('.pwd-toggle[data-pwd-target]').forEach(btn => {
    btn.addEventListener('click', () => togglePwd(btn, btn.dataset.pwdTarget));
  });
});

// Toggle mostrar/ocultar contraseña (compartido login + signup).
// Emoji 👁 = visible (click muestra), 🙈 = oculta (click vuelve a ocultar).
// Permanece definido aunque la versión base del admin no la use — el
// override sí. Coste: ~12 líneas inertes.
window.togglePwd = function(btn, inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
    btn.setAttribute('aria-label', 'Ocultar contraseña');
  } else {
    input.type = 'password';
    btn.textContent = '👁';
    btn.setAttribute('aria-label', 'Mostrar contraseña');
  }
};
