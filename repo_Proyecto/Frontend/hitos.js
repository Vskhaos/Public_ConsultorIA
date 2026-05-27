'use strict';

// Paleta coherente con la landing
const PALETTE = ['#00d4ff', '#0066cc', '#4dffff', '#1e90ff', '#5ec9ff',
                 '#0090e0', '#3aafff', '#7dd3ff', '#005a99', '#9be7ff'];
const TEXT_DIM = '#8aaac8';
const BORDER   = '#1a2a40';

// Mapa interno → label legible
const TIPO_LABEL = {
  pentest_ext: 'Pentesting externo', pentest_int: 'Pentesting interno',
  web_app: 'Web/API', cloud: 'Cloud', compliance: 'Compliance',
  gdpr: 'RGPD/ENS', phishing: 'Phishing', wifi: 'Wi-Fi',
};
const labelTipo = (s) => TIPO_LABEL[s] || s;

// Defaults globales Chart.js
Chart.defaults.color = TEXT_DIM;
Chart.defaults.borderColor = BORDER;
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.labels.boxWidth = 12;

let charts = { tipo: null, sector: null, mes: null };

async function loadStats() {
  try {
    const r = await fetch('/api/public/stats', { headers: {'Accept':'application/json'} });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    pintarKPIs(data);
    pintarTipos(data.por_tipo || []);
    pintarSectores(data.por_sector || []);
    pintarMeses(data.por_mes || []);
  } catch (err) {
    document.getElementById('legalNote').innerHTML =
      '<strong>Datos no disponibles.</strong> El backend no responde ahora mismo. ' +
      'Vuelve en unos minutos.';
    console.error(err);
  }
}

function pintarKPIs(d) {
  document.getElementById('kpiCompletadas').textContent = d.total_completadas ?? 0;
  document.getElementById('kpiEnCurso').textContent     = d.total_en_curso ?? 0;
  document.getElementById('kpiEmpresas').textContent    = d.empresas_unicas ?? 0;
  const total = (d.total_completadas || 0) + (d.total_fallidas || 0);
  const tasa  = total > 0 ? Math.round(100 * d.total_completadas / total) + '%' : '—';
  document.getElementById('kpiTasaExito').textContent = tasa;
}

function pintarTipos(rows) {
  const ctx = document.getElementById('chartTipo');
  if (charts.tipo) charts.tipo.destroy();
  if (!rows.length) {
    ctx.parentElement.innerHTML = '<div class="empty">Sin datos suficientes (k-anonymity ≥ 3)</div>';
    return;
  }
  charts.tipo = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: rows.map(r => r.label === 'Otros' ? 'Otros' : labelTipo(r.label)),
      datasets: [{
        data: rows.map(r => r.n),
        backgroundColor: rows.map((_, i) => PALETTE[i % PALETTE.length]),
        borderColor: '#04080f',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right' },
        tooltip: { callbacks: { label: ctx => `${ctx.label}: ${ctx.parsed} auditoría(s)` } },
      },
    },
  });
}

function pintarSectores(rows) {
  const ctx = document.getElementById('chartSector');
  if (charts.sector) charts.sector.destroy();
  if (!rows.length) {
    ctx.parentElement.innerHTML = '<div class="empty">Sin datos suficientes (k-anonymity ≥ 3)</div>';
    return;
  }
  charts.sector = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: rows.map(r => r.label),
      datasets: [{
        data: rows.map(r => r.n),
        backgroundColor: '#00d4ff80',
        borderColor: '#00d4ff', borderWidth: 1,
      }],
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { stepSize: 1, precision: 0 }, grid: { color: BORDER } },
        y: { grid: { display: false } },
      },
    },
  });
}

function pintarMeses(rows) {
  const ctx = document.getElementById('chartMes');
  if (charts.mes) charts.mes.destroy();
  if (!rows.length) {
    ctx.parentElement.innerHTML = '<div class="empty">Sin auditorías en los últimos 12 meses</div>';
    return;
  }
  charts.mes = new Chart(ctx, {
    type: 'line',
    data: {
      labels: rows.map(r => r.mes),
      datasets: [{
        label: 'Auditorías',
        data: rows.map(r => r.n),
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.12)',
        fill: true, tension: 0.3,
        pointBackgroundColor: '#00d4ff', pointBorderColor: '#04080f', pointRadius: 4,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { stepSize: 1, precision: 0 }, grid: { color: BORDER } },
        x: { grid: { color: BORDER } },
      },
    },
  });
}

loadStats();
// Refresca cada 5 minutos
setInterval(loadStats, 5 * 60 * 1000);
