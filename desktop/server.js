'use strict';
// ReconARG Desktop - server.js
// Servidor Express portable con scanner + generación de PDFs
// Funciona 100% offline excepto las llamadas al scanner (necesita internet)

const express = require('express');
const path = require('path');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const PDFDocument = require('pdfkit');

const PORT = 3737;
const HIBP_KEY = '032a78c1720f4dadb2b86593991ce75b';

/* ─── Helper: fetch con timeout ─────────────────────────────────────────── */
function fetchJSON(url, ms, headers) {
  ms = ms || 6000;
  headers = headers || {};
  return new Promise(function(resolve, reject) {
    var req = https.get(url, { headers: Object.assign({'User-Agent':'ReconARG-Desktop/1.0'}, headers) }, function(res) {
      var body = '';
      res.on('data', function(c) { body += c; });
      res.on('end', function() {
        if (res.statusCode === 404) return resolve([]);
        if (res.statusCode === 401) return reject(new Error('hibp-unauth'));
        if (res.statusCode === 429) return reject(new Error('hibp-ratelimit'));
        try { resolve(JSON.parse(body)); }
        catch(e) { reject(new Error('JSON parse: ' + body.slice(0,60))); }
      });
    });
    req.setTimeout(ms, function() { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function dnsQ(name, type) {
  return fetchJSON('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type, 4000);
}

/* ─── SSL ────────────────────────────────────────────────────────────────── */
function checkSSL(domain) {
  var fallback = { valid: false, issuer: null, expires: null, days_remaining: null };
  return new Promise(function(resolve) {
    try {
      var s = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, function() {
        try {
          var c = s.getPeerCertificate(false);
          s.destroy();
          if (!c || !c.valid_to) return resolve(fallback);
          var exp = new Date(c.valid_to);
          var days = Math.floor((exp - Date.now()) / 86400000);
          resolve({
            valid: days > 0,
            issuer: c.issuer ? (c.issuer.O || c.issuer.CN || null) : null,
            subject: c.subject ? (c.subject.CN || null) : null,
            expires: exp.toISOString().split('T')[0],
            days_remaining: days
          });
        } catch(_) { resolve(fallback); }
      });
      s.setTimeout(5000, function() { s.destroy(); resolve(fallback); });
      s.on('error', function() { resolve(fallback); });
    } catch(_) { resolve(fallback); }
  });
}

/* ─── DNS: SPF, DMARC, MX ───────────────────────────────────────────────── */
async function checkDNS(domain) {
  var results = await Promise.allSettled([
    dnsQ(domain, 'TXT'),
    dnsQ('_dmarc.' + domain, 'TXT'),
    dnsQ(domain, 'MX')
  ]);
  var sR = results[0], dR = results[1], mR = results[2];
  var spf = sR.status === 'fulfilled' && Array.isArray(sR.value.Answer) &&
    sR.value.Answer.some(function(r) { return (r.data||'').includes('v=spf1'); });
  var dmarc = dR.status === 'fulfilled' && Array.isArray(dR.value.Answer) &&
    dR.value.Answer.some(function(r) { return (r.data||'').includes('v=DMARC1'); });
  var mx = null;
  if (mR.status === 'fulfilled' && mR.value.Answer && mR.value.Answer.length) {
    mx = (mR.value.Answer[0].data||'').replace(/^\d+\s+/,'').replace(/\.$/,'');
  }
  return { spf: !!spf, dmarc: !!dmarc, mx: mx };
}

/* ─── Ports: Shodan InternetDB ───────────────────────────────────────────── */
var SVC = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
  143:'IMAP',443:'HTTPS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',
  5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};

async function checkPorts(domain) {
  try {
    var addrs = await dns.resolve4(domain).catch(function() { return []; });
    if (!addrs || !addrs.length) return { status: 'ok', ip: null, ports: [] };
    var ip = addrs[0];
    var d = await fetchJSON('https://internetdb.shodan.io/' + ip, 6000);
    if (!d || d.detail || !Array.isArray(d.ports)) return { status: 'ok', ip: ip, ports: [] };
    return {
      status: 'ok',
      ip: ip,
      ports: d.ports.map(function(p) { return { port: p, service: SVC[p]||'unknown', status: 'open' }; }),
      vulns: d.vulns || []
    };
  } catch(_) {
    return { status: 'ok', ip: null, ports: [] };
  }
}

/* ─── Subdominios: crt.sh ────────────────────────────────────────────────── */
async function checkSubdomains(domain) {
  try {
    var rows = await fetchJSON('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json', 8000);
    if (!Array.isArray(rows)) return [];
    var set = new Set();
    rows.forEach(function(r) {
      (r.name_value||'').split('\n').forEach(function(n) {
        var c = n.trim().toLowerCase().replace(/^\*\./, '');
        if (c && c.endsWith(domain) && c !== domain) set.add(c);
      });
    });
    return Array.from(set).sort().slice(0, 25);
  } catch(_) { return []; }
}

/* ─── HIBP: filtraciones ─────────────────────────────────────────────────── */
async function checkBreaches(domain) {
  try {
    var data = await fetchJSON(
      'https://haveibeenpwned.com/api/v3/breacheddomain/' + encodeURIComponent(domain),
      8000, { 'hibp-api-key': HIBP_KEY }
    );
    if (!Array.isArray(data)) return { status: 'ok', breaches: [], count: 0 };
    return { status: 'ok', breaches: data.slice(0, 5), count: data.length };
  } catch(e) {
    return { status: 'error', error: e.message, breaches: [], count: 0 };
  }
}

/* ─── Scanner principal ──────────────────────────────────────────────────── */
async function scanDomain(domain) {
  domain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  var [ssl, dns_r, ports, subs, breaches] = await Promise.all([
    checkSSL(domain),
    checkDNS(domain),
    checkPorts(domain),
    checkSubdomains(domain),
    checkBreaches(domain)
  ]);
  return { domain, timestamp: new Date().toISOString(), ssl, dns: dns_r, ports, subdomains: subs, breaches };
}

/* ─── Express server ─────────────────────────────────────────────────────── */
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/scan', async function(req, res) {
  var domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  try {
    var result = await scanDomain(domain);
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

/* ─── PDF: Informe Ejecutivo ─────────────────────────────────────────────── */
app.post('/api/pdf/ejecutivo', function(req, res) {
  var data = req.body;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="informe-ejecutivo-' + data.domain + '.pdf"');
  
  var doc = new PDFDocument({ margin: 50, size: 'A4' });
  doc.pipe(res);
  
  // Header
  doc.rect(0, 0, 595, 100).fill('#0a0a1a');
  doc.fillColor('#e8c84a').fontSize(22).font('Helvetica-Bold')
     .text('DIAGNÓSTICO EXPRESS', 50, 30);
  doc.fillColor('#ffffff').fontSize(11).font('Helvetica')
     .text('ReconARG · Evaluación de Seguridad', 50, 58);
  doc.fillColor('#aaaaaa').fontSize(9)
     .text('Confidencial · Solo para uso interno', 50, 75);
  
  doc.moveDown(2);
  doc.fillColor('#000000');
  
  // Score de riesgo
  var score = calcRiskScore(data);
  var riskLabel = score <= 30 ? 'BAJO' : score <= 60 ? 'MEDIO' : 'ALTO';
  var riskColor = score <= 30 ? '#22c55e' : score <= 60 ? '#f59e0b' : '#ef4444';
  
  doc.rect(50, 120, 495, 70).fill('#f8f9fa').stroke('#e2e8f0');
  doc.fillColor('#000000').fontSize(11).font('Helvetica-Bold').text('Dominio analizado:', 70, 132);
  doc.fillColor('#1a1a2e').fontSize(16).text(data.domain, 70, 148);
  doc.fillColor('#666666').fontSize(9).font('Helvetica').text('Fecha: ' + new Date(data.timestamp).toLocaleDateString('es-AR', {day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}), 70, 170);
  
  // Score visual
  doc.rect(400, 125, 130, 60).fill(riskColor);
  doc.fillColor('#ffffff').fontSize(11).font('Helvetica-Bold').text('NIVEL DE RIESGO', 410, 133);
  doc.fontSize(22).text(riskLabel, 420, 148);
  
  doc.moveDown(4);
  
  // Resumen ejecutivo - tabla de hallazgos
  doc.fillColor('#000000').fontSize(13).font('Helvetica-Bold').text('RESUMEN DE HALLAZGOS', 50, 210);
  doc.moveTo(50, 228).lineTo(545, 228).stroke('#e8c84a');
  
  var items = [
    ['🔒 Certificado SSL', data.ssl && data.ssl.valid ? 'VÁLIDO - ' + data.ssl.days_remaining + ' días' : 'INVÁLIDO O AUSENTE', data.ssl && data.ssl.valid && data.ssl.days_remaining > 30 ? 'ok' : 'warn'],
    ['📧 Protección Email', (data.dns && data.dns.spf && data.dns.dmarc) ? 'SPF + DMARC configurados' : 'Configuración incompleta', (data.dns && data.dns.spf && data.dns.dmarc) ? 'ok' : 'warn'],
    ['🌐 Puertos expuestos', (data.ports && data.ports.ports ? data.ports.ports.length : 0) + ' puertos detectados', (data.ports && data.ports.ports && data.ports.ports.length > 10) ? 'warn' : 'ok'],
    ['🔍 Subdominios', (Array.isArray(data.subdomains) ? data.subdomains.length : 0) + ' subdominios encontrados', 'info'],
    ['💧 Filtraciones HIBP', data.breaches && data.breaches.count > 0 ? data.breaches.count + ' filtración(es) detectada(s)' : 'Sin filtraciones conocidas', data.breaches && data.breaches.count > 0 ? 'warn' : 'ok']
  ];
  
  var y = 240;
  items.forEach(function(item) {
    var bgColor = item[2] === 'ok' ? '#f0fdf4' : item[2] === 'warn' ? '#fff7ed' : '#eff6ff';
    var dotColor = item[2] === 'ok' ? '#22c55e' : item[2] === 'warn' ? '#f59e0b' : '#3b82f6';
    doc.rect(50, y, 495, 30).fill(bgColor).stroke('#e2e8f0');
    doc.circle(68, y + 15, 5).fill(dotColor);
    doc.fillColor('#000000').fontSize(10).font('Helvetica-Bold').text(item[0], 80, y + 8);
    doc.font('Helvetica').text(item[1], 230, y + 8);
    y += 35;
  });
  
  // Recomendaciones
  doc.moveDown(2);
  var recY = y + 20;
  doc.fillColor('#000000').fontSize(13).font('Helvetica-Bold').text('RECOMENDACIONES PRIORITARIAS', 50, recY);
  doc.moveTo(50, recY + 18).lineTo(545, recY + 18).stroke('#e8c84a');
  
  var recs = buildRecommendations(data);
  var recTextY = recY + 30;
  recs.forEach(function(rec, i) {
    doc.rect(50, recTextY, 8, 8).fill('#e8c84a');
    doc.fillColor('#000000').fontSize(10).font('Helvetica').text(rec, 65, recTextY - 1, { width: 480 });
    recTextY += 20;
  });
  
  // Footer
  doc.fillColor('#888888').fontSize(8).text('Generado por ReconARG · Diagnóstico Express · ' + new Date().toLocaleDateString('es-AR'), 50, 780);
  doc.text('Este informe es confidencial y de uso exclusivo del cliente.', 50, 792);
  
  doc.end();
});

/* ─── PDF: Informe Técnico ───────────────────────────────────────────────── */
app.post('/api/pdf/tecnico', function(req, res) {
  var data = req.body;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="informe-tecnico-' + data.domain + '.pdf"');
  
  var doc = new PDFDocument({ margin: 50, size: 'A4' });
  doc.pipe(res);
  
  // Header
  doc.rect(0, 0, 595, 100).fill('#0a0a1a');
  doc.fillColor('#e8c84a').fontSize(20).font('Helvetica-Bold')
     .text('INFORME TÉCNICO DE SEGURIDAD', 50, 30);
  doc.fillColor('#ffffff').fontSize(11).font('Helvetica')
     .text('ReconARG · Análisis de superficie de ataque', 50, 56);
  doc.fillColor('#aaaaaa').fontSize(9)
     .text('Clasificación: CONFIDENCIAL · TLP:AMBER', 50, 74);
  
  // Metadata
  doc.rect(50, 115, 495, 55).fill('#f8f9fa').stroke('#e2e8f0');
  doc.fillColor('#000000').fontSize(10).font('Helvetica-Bold').text('Objetivo:', 65, 125);
  doc.font('Helvetica').text(data.domain, 130, 125);
  doc.font('Helvetica-Bold').text('Análisis:', 65, 140);
  doc.font('Helvetica').text(new Date(data.timestamp).toLocaleString('es-AR'), 130, 140);
  doc.font('Helvetica-Bold').text('IP:', 65, 155);
  doc.font('Helvetica').text((data.ports && data.ports.ip) || 'No resuelto', 130, 155);
  doc.font('Helvetica-Bold').text('Score:', 350, 125);
  var score = calcRiskScore(data);
  doc.font('Helvetica').fillColor(score <= 30 ? '#22c55e' : score <= 60 ? '#f59e0b' : '#ef4444')
     .fontSize(16).text(score + '/100', 400, 120);
  
  var y = 185;
  
  // SSL Section
  y = addSection(doc, 'CERTIFICADO SSL/TLS', y);
  if (data.ssl) {
    var sslRows = [
      ['Estado', data.ssl.valid ? '✓ Válido' : '✗ Inválido o ausente'],
      ['Emisor', data.ssl.issuer || 'Desconocido'],
      ['Sujeto', data.ssl.subject || 'N/A'],
      ['Vencimiento', data.ssl.expires || 'N/A'],
      ['Días restantes', data.ssl.days_remaining !== null ? data.ssl.days_remaining + ' días' : 'N/A']
    ];
    y = addTable(doc, sslRows, y);
  }
  
  // DNS Section
  y = addSection(doc, 'CONFIGURACIÓN DNS / EMAIL', y + 10);
  if (data.dns) {
    var dnsRows = [
      ['SPF', data.dns.spf ? '✓ Configurado' : '✗ Ausente - Riesgo de spoofing'],
      ['DMARC', data.dns.dmarc ? '✓ Configurado' : '✗ Ausente - Sin política de rechazo'],
      ['MX (servidor de correo)', data.dns.mx || 'No encontrado']
    ];
    y = addTable(doc, dnsRows, y);
  }
  
  // Ports Section  
  y = addSection(doc, 'PUERTOS ABIERTOS (vía Shodan InternetDB)', y + 10);
  if (data.ports && data.ports.ports && data.ports.ports.length > 0) {
    var portRows = data.ports.ports.map(function(p) {
      var risk = [21,23,445,3389,6379,27017].includes(p.port) ? '⚠ ALTO RIESGO' : '';
      return [p.port.toString(), p.service, p.status, risk];
    });
    y = addPortTable(doc, portRows, y);
    if (data.ports.vulns && data.ports.vulns.length > 0) {
      doc.fillColor('#ef4444').fontSize(9).font('Helvetica-Bold')
         .text('CVEs detectados: ' + data.ports.vulns.join(', '), 50, y + 5, {width: 495});
      y += 20;
    }
  } else {
    doc.fillColor('#666666').fontSize(9).font('Helvetica').text('No se detectaron puertos abiertos en el registro de Shodan.', 50, y);
    y += 20;
  }
  
  // Subdomains Section
  y = addSection(doc, 'SUBDOMINIOS (vía crt.sh Certificate Transparency)', y + 10);
  if (Array.isArray(data.subdomains) && data.subdomains.length > 0) {
    var cols = 3;
    var colWidth = 160;
    data.subdomains.forEach(function(sub, i) {
      var col = i % cols;
      var row = Math.floor(i / cols);
      doc.fillColor('#1a1a2e').fontSize(8).font('Helvetica')
         .text('• ' + sub, 50 + col * colWidth, y + row * 14, { width: colWidth - 5 });
    });
    y += Math.ceil(data.subdomains.length / cols) * 14 + 10;
  } else {
    doc.fillColor('#666666').fontSize(9).font('Helvetica').text('No se encontraron subdominios adicionales.', 50, y);
    y += 20;
  }
  
  // Breaches Section
  y = addSection(doc, 'FILTRACIONES DE DATOS (HIBP)', y + 10);
  if (data.breaches && data.breaches.count > 0) {
    doc.fillColor('#ef4444').fontSize(10).font('Helvetica-Bold')
       .text('⚠ ' + data.breaches.count + ' filtración(es) detectada(s)', 50, y);
    y += 15;
    if (Array.isArray(data.breaches.breaches)) {
      data.breaches.breaches.slice(0,5).forEach(function(b, i) {
        doc.fillColor('#000000').fontSize(9).font('Helvetica')
           .text((i+1) + '. ' + (typeof b === 'string' ? b : JSON.stringify(b)), 50, y + i*14, {width:495});
      });
      y += Math.min(data.breaches.breaches.length, 5) * 14 + 10;
    }
  } else {
    doc.fillColor('#22c55e').fontSize(10).font('Helvetica-Bold')
       .text('✓ Sin filtraciones detectadas en la base de datos HIBP', 50, y);
    y += 20;
  }
  
  // Footer
  doc.fillColor('#888888').fontSize(8)
     .text('ReconARG · Diagnóstico Express · Informe Técnico · ' + new Date().toLocaleDateString('es-AR'), 50, 780);
  doc.text('Datos obtenidos de: TLS nativo, Google DoH, Shodan InternetDB, crt.sh, HaveIBeenPwned', 50, 792);
  
  doc.end();
});

/* ─── Helpers para PDF ───────────────────────────────────────────────────── */
function calcRiskScore(data) {
  var score = 0;
  if (!data.ssl || !data.ssl.valid) score += 25;
  else if (data.ssl.days_remaining < 30) score += 10;
  if (!data.dns || !data.dns.spf) score += 10;
  if (!data.dns || !data.dns.dmarc) score += 10;
  var highRiskPorts = [21,23,445,3389,6379,27017];
  if (data.ports && data.ports.ports) {
    var dangerous = data.ports.ports.filter(function(p) { return highRiskPorts.includes(p.port); });
    score += dangerous.length * 8;
  }
  if (data.breaches && data.breaches.count > 0) score += Math.min(data.breaches.count * 5, 25);
  return Math.min(score, 100);
}

function buildRecommendations(data) {
  var recs = [];
  if (!data.ssl || !data.ssl.valid) recs.push('Instalar o renovar certificado SSL/TLS inmediatamente para proteger la comunicación.');
  else if (data.ssl.days_remaining < 30) recs.push('Renovar certificado SSL antes del vencimiento (' + data.ssl.days_remaining + ' días restantes).');
  if (!data.dns || !data.dns.spf) recs.push('Configurar registro SPF en DNS para prevenir spoofing de email.');
  if (!data.dns || !data.dns.dmarc) recs.push('Implementar política DMARC para controlar el uso del dominio en emails.');
  if (data.ports && data.ports.ports) {
    var dangerous = data.ports.ports.filter(function(p) { return [21,23,3389,6379,27017].includes(p.port); });
    if (dangerous.length > 0) recs.push('Restringir acceso a puertos sensibles: ' + dangerous.map(function(p){return p.port+'/'+p.service;}).join(', '));
  }
  if (data.breaches && data.breaches.count > 0) recs.push('Se detectaron ' + data.breaches.count + ' filtración(es): actualizar credenciales y revisar política de contraseñas.');
  if (recs.length === 0) recs.push('El dominio presenta una postura de seguridad aceptable. Mantener monitoreo periódico.');
  return recs;
}

function addSection(doc, title, y) {
  if (y > 720) { doc.addPage(); y = 50; }
  doc.fillColor('#0a0a1a').fontSize(11).font('Helvetica-Bold').text(title, 50, y);
  doc.moveTo(50, y + 16).lineTo(545, y + 16).stroke('#e8c84a');
  return y + 25;
}

function addTable(doc, rows, y) {
  rows.forEach(function(row) {
    if (y > 730) { doc.addPage(); y = 50; }
    doc.rect(50, y, 495, 18).fill('#f8f9fa').stroke('#e2e8f0');
    doc.fillColor('#555555').fontSize(9).font('Helvetica-Bold').text(row[0], 55, y + 4, {width:140});
    doc.fillColor('#000000').font('Helvetica').text(row[1] || '', 200, y + 4, {width:340});
    y += 20;
  });
  return y;
}

function addPortTable(doc, rows, y) {
  // Header
  doc.rect(50, y, 495, 18).fill('#1a1a2e');
  doc.fillColor('#ffffff').fontSize(9).font('Helvetica-Bold')
     .text('Puerto', 55, y+4).text('Servicio', 120, y+4).text('Estado', 250, y+4).text('Riesgo', 340, y+4);
  y += 20;
  rows.forEach(function(row, i) {
    if (y > 730) { doc.addPage(); y = 50; }
    var bg = i % 2 === 0 ? '#f8f9fa' : '#ffffff';
    doc.rect(50, y, 495, 18).fill(bg).stroke('#e2e8f0');
    doc.fillColor('#000000').fontSize(9).font('Helvetica')
       .text(row[0], 55, y+4).text(row[1], 120, y+4).text(row[2], 250, y+4);
    if (row[3]) doc.fillColor('#ef4444').font('Helvetica-Bold').text(row[3], 340, y+4);
    y += 20;
  });
  return y;
}

/* ─── Start server ───────────────────────────────────────────────────────── */
app.listen(PORT, '127.0.0.1', function() {
  console.log('ReconARG Desktop corriendo en http://localhost:' + PORT);
  // Auto-open browser
  var url = 'http://localhost:' + PORT;
  var start = process.platform === 'win32' ? 'start' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  require('child_process').exec(start + ' ' + url, function(){});
});
