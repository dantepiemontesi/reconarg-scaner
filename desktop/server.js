'use strict';
// ReconARG Desktop - server.js v2
// Servidor Express portable con scanner + generacion de PDFs
// FIXES: eliminado pdfkit (incompatible con pkg), usando PDF nativo
//        corregido auto-open en Windows, manejo de errores robusto

const express = require('express');
const path = require('path');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const { execFile, exec } = require('child_process');
const fs = require('fs');
const os = require('os');

const PORT = 3737;
const HIBP_KEY = '032a78c1720f4dadb2b86593991ce75b';

// Log a archivo para debug en caso de crash
const logFile = path.join(os.tmpdir(), 'reconarg-debug.log');
function log(msg) {
  const line = new Date().toISOString() + ' ' + msg + '\n';
  try { fs.appendFileSync(logFile, line); } catch(_) {}
  console.log(msg);
}

// Capturar errores no manejados para no crashear silenciosamente
process.on('uncaughtException', function(err) {
  log('UNCAUGHT: ' + err.message + '\n' + err.stack);
});
process.on('unhandledRejection', function(reason) {
  log('UNHANDLED REJECTION: ' + reason);
});

log('ReconARG Desktop v2 iniciando...');
log('Log en: ' + logFile);

/* Helper: fetch con timeout */
function fetchJSON(url, ms, headers) {
  ms = ms || 6000;
  headers = headers || {};
  return new Promise(function(resolve, reject) {
    var req = https.get(url, { headers: Object.assign({'User-Agent':'ReconARG-Desktop/2.0'}, headers) }, function(res) {
      var body = '';
      res.on('data', function(c) { body += c; });
      res.on('end', function() {
        if (res.statusCode === 404) return resolve([]);
        if (res.statusCode === 401) return reject(new Error('hibp-unauth'));
        if (res.statusCode === 429) return reject(new Error('hibp-ratelimit'));
        try { resolve(JSON.parse(body)); }
        catch(e) { reject(new Error('JSON parse error')); }
      });
    });
    req.setTimeout(ms, function() { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function dnsQ(name, type) {
  return fetchJSON('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type, 4000);
}

/* SSL */
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
        } catch(e) { resolve(fallback); }
      });
      s.setTimeout(5000, function() { s.destroy(); resolve(fallback); });
      s.on('error', function() { resolve(fallback); });
    } catch(e) { resolve(fallback); }
  });
}

/* DNS */
async function checkDNS(domain) {
  try {
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
  } catch(e) {
    return { spf: false, dmarc: false, mx: null };
  }
}

/* Ports via Shodan InternetDB */
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
  } catch(e) {
    return { status: 'ok', ip: null, ports: [] };
  }
}

/* Subdomains via crt.sh */
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
  } catch(e) { return []; }
}

/* HIBP */
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

/* Scanner principal */
async function scanDomain(domain) {
  domain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  log('Escaneando: ' + domain);
  var [ssl, dns_r, ports, subs, breaches] = await Promise.all([
    checkSSL(domain),
    checkDNS(domain),
    checkPorts(domain),
    checkSubdomains(domain),
    checkBreaches(domain)
  ]);
  log('Scan completo para: ' + domain);
  return { domain, timestamp: new Date().toISOString(), ssl, dns: dns_r, ports, subdomains: subs, breaches };
}

/* ============================================================
   PDF GENERATION - NATIVO SIN LIBRERIAS EXTERNAS
   Generamos PDF valido manualmente para evitar problemas con pkg
   ============================================================ */

function escPDF(s) {
  return String(s||'').replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)').replace(/\r/g,'').replace(/\n/g,' ');
}

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
  if (!data.ssl || !data.ssl.valid) recs.push('Instalar o renovar certificado SSL/TLS para proteger la comunicacion.');
  else if (data.ssl.days_remaining < 30) recs.push('Renovar certificado SSL (' + data.ssl.days_remaining + ' dias restantes).');
  if (!data.dns || !data.dns.spf) recs.push('Configurar registro SPF en DNS para prevenir spoofing de email.');
  if (!data.dns || !data.dns.dmarc) recs.push('Implementar politica DMARC para controlar uso del dominio en emails.');
  if (data.ports && data.ports.ports) {
    var d2 = data.ports.ports.filter(function(p) { return [21,23,3389,6379,27017].includes(p.port); });
    if (d2.length > 0) recs.push('Restringir acceso a puertos sensibles: ' + d2.map(function(p){return p.port+'/'+p.service;}).join(', '));
  }
  if (data.breaches && data.breaches.count > 0) recs.push('Se detectaron ' + data.breaches.count + ' filtracion(es): actualizar credenciales.');
  if (recs.length === 0) recs.push('El dominio presenta una postura de seguridad aceptable. Mantener monitoreo periodico.');
  return recs;
}

// Genera PDF usando solo streams nativos
// Usamos jsPDF-like approach: construimos el PDF como string
function generatePDF(title, lines) {
  // lines: array de {text, x, y, size, bold, color}
  // Retorna Buffer con PDF valido

  var objs = [];
  var offsets = [];
  var id = 0;

  function addObj(content) {
    id++;
    offsets.push(null); // placeholder
    objs.push({ id: id, content: content });
    return id;
  }

  // Catalog, Pages placeholders
  var catalogId = 1;
  var pagesId = 2;
  var fontHId = 3;
  var fontBId = 4;
  var pageId = 5;
  var contentId = 6;

  // Build content stream
  var stream = [];
  stream.push('BT');

  lines.forEach(function(l) {
    var r = 0, g = 0, b = 0;
    if (l.color === 'gold') { r=0.91; g=0.78; b=0.29; }
    else if (l.color === 'white') { r=1; g=1; b=1; }
    else if (l.color === 'gray') { r=0.5; g=0.5; b=0.5; }
    else if (l.color === 'red') { r=0.94; g=0.27; b=0.27; }
    else if (l.color === 'green') { r=0.13; g=0.77; b=0.37; }
    else if (l.color === 'orange') { r=0.96; g=0.62; b=0.04; }
    else if (l.color === 'dark') { r=0.04; g=0.04; b=0.1; }
    else { r=0; g=0; b=0; }

    var font = l.bold ? '/Fb' : '/Fh';
    var y842 = 842 - l.y; // PDF coords from bottom, A4=842pt

    stream.push(r.toFixed(2) + ' ' + g.toFixed(2) + ' ' + b.toFixed(2) + ' rg');
    stream.push(font + ' ' + (l.size||10) + ' Tf');
    stream.push(l.x + ' ' + y842 + ' Td');
    stream.push('(' + escPDF(l.text) + ') Tj');
    // reset position
    stream.push('-' + l.x + ' -' + y842 + ' Td');
  });

  stream.push('ET');

  // Background rects
  var rects = [];
  // Dark header
  rects.push('0.04 0.04 0.10 rg');
  rects.push('0 742 595 100 re f');
  // Light body bg
  rects.push('1 1 1 rg');
  rects.push('0 0 595 742 re f');

  var fullStream = rects.join('\n') + '\n' + stream.join('\n');
  var streamBytes = Buffer.from(fullStream, 'latin1');

  // Build PDF
  var parts = [];

  parts.push(Buffer.from('%PDF-1.4\n', 'latin1'));

  // Object 1: Catalog
  var catStr = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
  parts.push(Buffer.from(catStr, 'latin1'));

  // Object 2: Pages
  var pagesStr = '2 0 obj\n<< /Type /Pages /Kids [5 0 R] /Count 1 >>\nendobj\n';
  parts.push(Buffer.from(pagesStr, 'latin1'));

  // Object 3: Font Helvetica
  var fontHStr = '3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n';
  parts.push(Buffer.from(fontHStr, 'latin1'));

  // Object 4: Font Helvetica-Bold
  var fontBStr = '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n';
  parts.push(Buffer.from(fontBStr, 'latin1'));

  // Object 5: Page
  var pageStr = '5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /Fh 3 0 R /Fb 4 0 R >> >> /Contents 6 0 R >>\nendobj\n';
  parts.push(Buffer.from(pageStr, 'latin1'));

  // Object 6: Content stream
  var contHdr = '6 0 obj\n<< /Length ' + streamBytes.length + ' >>\nstream\n';
  var contFtr = '\nendstream\nendobj\n';
  parts.push(Buffer.from(contHdr, 'latin1'));
  parts.push(streamBytes);
  parts.push(Buffer.from(contFtr, 'latin1'));

  // Xref
  var bodyBuf = Buffer.concat(parts);
  var xrefOffset = bodyBuf.length;

  // Calculate object offsets
  var offArr = [];
  var pos = '%PDF-1.4\n'.length;
  offArr.push(pos); // obj 1
  pos += catStr.length;
  offArr.push(pos); // obj 2
  pos += pagesStr.length;
  offArr.push(pos); // obj 3
  pos += fontHStr.length;
  offArr.push(pos); // obj 4
  pos += fontBStr.length;
  offArr.push(pos); // obj 5
  pos += pageStr.length;
  offArr.push(pos); // obj 6

  var xref = 'xref\n0 7\n';
  xref += '0000000000 65535 f \n';
  offArr.forEach(function(o) {
    xref += String('0000000000' + o).slice(-10) + ' 00000 n \n';
  });
  xref += 'trailer\n<< /Size 7 /Root 1 0 R >>\n';
  xref += 'startxref\n' + xrefOffset + '\n%%EOF\n';

  return Buffer.concat([bodyBuf, Buffer.from(xref, 'latin1')]);
}

function buildEjecutivoPDF(data) {
  var score = calcRiskScore(data);
  var riskLabel = score <= 30 ? 'BAJO' : score <= 60 ? 'MEDIO' : 'ALTO';
  var riskColor = score <= 30 ? 'green' : score <= 60 ? 'orange' : 'red';
  var fecha = new Date(data.timestamp).toLocaleDateString('es-AR', {day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
  var recs = buildRecommendations(data);

  var lines = [
    // Header (sobre fondo oscuro)
    {text:'DIAGNOSTICO EXPRESS', x:50, y:35, size:20, bold:true, color:'gold'},
    {text:'ReconARG - Evaluacion de Seguridad', x:50, y:60, size:11, color:'white'},
    {text:'Confidencial - Solo para uso interno', x:50, y:78, size:9, color:'gray'},
    // Dominio
    {text:'Dominio analizado:', x:65, y:120, size:10, bold:true},
    {text:data.domain, x:65, y:137, size:15, bold:true, color:'dark'},
    {text:'Fecha: ' + fecha, x:65, y:158, size:9, color:'gray'},
    {text:'NIVEL DE RIESGO: ' + riskLabel + ' (' + score + '/100)', x:370, y:132, size:10, bold:true, color:riskColor},
    // Seccion hallazgos
    {text:'RESUMEN DE HALLAZGOS', x:50, y:200, size:13, bold:true},
    {text:'-------------------------------------------------------------', x:50, y:215, size:9, color:'gray'},
  ];

  var y = 230;
  var items = [
    ['Certificado SSL', data.ssl && data.ssl.valid ? 'VALIDO - ' + data.ssl.days_remaining + ' dias' : 'INVALIDO O AUSENTE',
      data.ssl && data.ssl.valid && data.ssl.days_remaining > 30 ? null : 'red'],
    ['Proteccion Email (SPF+DMARC)', (data.dns && data.dns.spf && data.dns.dmarc) ? 'Configurados correctamente' : 'Configuracion incompleta',
      (data.dns && data.dns.spf && data.dns.dmarc) ? null : 'orange'],
    ['Puertos expuestos', (data.ports && data.ports.ports ? data.ports.ports.length : 0) + ' puertos detectados', null],
    ['Subdominios encontrados', (Array.isArray(data.subdomains) ? data.subdomains.length : 0) + ' subdominios', null],
    ['Filtraciones de datos (HIBP)', data.breaches && data.breaches.count > 0 ? data.breaches.count + ' filtracion(es) detectada(s)' : 'Sin filtraciones conocidas',
      data.breaches && data.breaches.count > 0 ? 'red' : 'green'],
  ];

  items.forEach(function(item) {
    lines.push({text:'- ' + item[0] + ':', x:65, y:y, size:10, bold:true});
    lines.push({text:item[1], x:250, y:y, size:10, color: item[2] || null});
    y += 22;
  });

  y += 15;
  lines.push({text:'RECOMENDACIONES PRIORITARIAS', x:50, y:y, size:13, bold:true});
  y += 18;
  lines.push({text:'-------------------------------------------------------------', x:50, y:y, size:9, color:'gray'});
  y += 15;

  recs.forEach(function(rec, i) {
    lines.push({text:(i+1) + '. ' + rec, x:65, y:y, size:10});
    y += 20;
  });

  y += 20;
  lines.push({text:'Generado por ReconARG - Diagnostico Express - ' + new Date().toLocaleDateString('es-AR'), x:50, y:800, size:8, color:'gray'});

  return generatePDF('ejecutivo', lines);
}

function buildTecnicoPDF(data) {
  var score = calcRiskScore(data);
  var fecha = new Date(data.timestamp).toLocaleString('es-AR');

  var lines = [
    {text:'INFORME TECNICO DE SEGURIDAD', x:50, y:35, size:18, bold:true, color:'gold'},
    {text:'ReconARG - Analisis de superficie de ataque', x:50, y:58, size:11, color:'white'},
    {text:'Clasificacion: CONFIDENCIAL - TLP:AMBER', x:50, y:76, size:9, color:'gray'},
    // Meta
    {text:'Objetivo:', x:65, y:125, size:10, bold:true},
    {text:data.domain, x:145, y:125, size:10},
    {text:'Analisis:', x:65, y:140, size:10, bold:true},
    {text:fecha, x:145, y:140, size:10},
    {text:'IP:', x:65, y:155, size:10, bold:true},
    {text:(data.ports && data.ports.ip) || 'No resuelto', x:145, y:155, size:10},
    {text:'Score de riesgo:', x:350, y:130, size:10, bold:true},
    {text:score + '/100', x:460, y:130, size:14, bold:true, color: score<=30?'green':score<=60?'orange':'red'},
  ];

  var y = 185;

  // SSL
  lines.push({text:'CERTIFICADO SSL/TLS', x:50, y:y, size:11, bold:true});
  y += 18;
  lines.push({text:'Estado: ' + (data.ssl && data.ssl.valid ? 'Valido' : 'Invalido o ausente'), x:60, y:y, size:10, color: data.ssl&&data.ssl.valid?'green':'red'});
  y += 16;
  lines.push({text:'Emisor: ' + ((data.ssl && data.ssl.issuer) || 'Desconocido'), x:60, y:y, size:10});
  y += 16;
  lines.push({text:'Vencimiento: ' + ((data.ssl && data.ssl.expires) || 'N/A') + '  |  Dias restantes: ' + ((data.ssl && data.ssl.days_remaining) || 'N/A'), x:60, y:y, size:10});
  y += 25;

  // DNS
  lines.push({text:'CONFIGURACION DNS / EMAIL', x:50, y:y, size:11, bold:true});
  y += 18;
  lines.push({text:'SPF: ' + (data.dns && data.dns.spf ? 'Configurado' : 'AUSENTE - Riesgo de spoofing'), x:60, y:y, size:10, color: data.dns&&data.dns.spf?'green':'red'});
  y += 16;
  lines.push({text:'DMARC: ' + (data.dns && data.dns.dmarc ? 'Configurado' : 'AUSENTE - Sin politica de rechazo'), x:60, y:y, size:10, color: data.dns&&data.dns.dmarc?'green':'red'});
  y += 16;
  lines.push({text:'Servidor de correo (MX): ' + ((data.dns && data.dns.mx) || 'No encontrado'), x:60, y:y, size:10});
  y += 25;

  // Ports
  lines.push({text:'PUERTOS ABIERTOS (via Shodan InternetDB)', x:50, y:y, size:11, bold:true});
  y += 18;
  if (data.ports && data.ports.ports && data.ports.ports.length > 0) {
    lines.push({text:'Puerto  Servicio          Riesgo', x:60, y:y, size:9, bold:true});
    y += 14;
    data.ports.ports.forEach(function(p) {
      var highRisk = [21,23,445,3389,6379,27017].includes(p.port);
      lines.push({text:p.port + '      ' + (p.service + '               ').slice(0,16) + (highRisk ? 'ALTO RIESGO' : '-'), x:60, y:y, size:9, color: highRisk?'red':null});
      y += 13;
    });
    if (data.ports.vulns && data.ports.vulns.length > 0) {
      lines.push({text:'CVEs: ' + data.ports.vulns.join(', '), x:60, y:y, size:9, color:'red'});
      y += 16;
    }
  } else {
    lines.push({text:'No se detectaron puertos en registro de Shodan.', x:60, y:y, size:10, color:'gray'});
    y += 16;
  }
  y += 10;

  // Subdomains
  lines.push({text:'SUBDOMINIOS (via crt.sh Certificate Transparency)', x:50, y:y, size:11, bold:true});
  y += 18;
  if (Array.isArray(data.subdomains) && data.subdomains.length > 0) {
    var cols = 2;
    data.subdomains.forEach(function(sub, i) {
      var col = i % cols;
      var row = Math.floor(i / cols);
      if (col === 0 && i > 0) y += 13;
      lines.push({text:'- ' + sub, x:60 + col * 240, y: col === 0 ? y : y, size:9});
    });
    y += 20;
  } else {
    lines.push({text:'No se encontraron subdominios adicionales.', x:60, y:y, size:10, color:'gray'});
    y += 20;
  }

  // Breaches
  y += 5;
  lines.push({text:'FILTRACIONES DE DATOS (HIBP)', x:50, y:y, size:11, bold:true});
  y += 18;
  if (data.breaches && data.breaches.count > 0) {
    lines.push({text:'ALERTA: ' + data.breaches.count + ' filtracion(es) detectada(s)', x:60, y:y, size:10, bold:true, color:'red'});
    y += 16;
    if (Array.isArray(data.breaches.breaches)) {
      data.breaches.breaches.slice(0,5).forEach(function(b, i) {
        lines.push({text:(i+1) + '. ' + (typeof b === 'string' ? b : JSON.stringify(b)), x:70, y:y, size:9});
        y += 14;
      });
    }
  } else {
    lines.push({text:'Sin filtraciones detectadas en la base de datos HIBP.', x:60, y:y, size:10, color:'green'});
    y += 16;
  }

  lines.push({text:'ReconARG - Diagnostico Express - Informe Tecnico - ' + new Date().toLocaleDateString('es-AR'), x:50, y:800, size:8, color:'gray'});

  return generatePDF('tecnico', lines);
}

/* Express server */
const app = express();
app.use(express.json({ limit: '5mb' }));

// Serve static files - compatible con pkg
var publicDir;
if (process.pkg) {
  publicDir = path.join(path.dirname(process.execPath), 'public');
  // Si no existe junto al exe, usar el bundleado
  if (!fs.existsSync(publicDir)) {
    publicDir = path.join(__dirname, 'public');
  }
} else {
  publicDir = path.join(__dirname, 'public');
}
log('Sirviendo static desde: ' + publicDir);
app.use(express.static(publicDir));

app.get('/api/scan', async function(req, res) {
  var domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  try {
    var result = await scanDomain(domain);
    res.json(result);
  } catch(e) {
    log('Scan error: ' + e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/pdf/ejecutivo', function(req, res) {
  try {
    var data = req.body;
    var buf = buildEjecutivoPDF(data);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="informe-ejecutivo-' + data.domain + '.pdf"');
    res.setHeader('Content-Length', buf.length);
    res.end(buf);
    log('PDF ejecutivo generado para: ' + data.domain);
  } catch(e) {
    log('PDF ejecutivo error: ' + e.message + '\n' + e.stack);
    res.status(500).json({ error: 'Error generando PDF: ' + e.message });
  }
});

app.post('/api/pdf/tecnico', function(req, res) {
  try {
    var data = req.body;
    var buf = buildTecnicoPDF(data);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="informe-tecnico-' + data.domain + '.pdf"');
    res.setHeader('Content-Length', buf.length);
    res.end(buf);
    log('PDF tecnico generado para: ' + data.domain);
  } catch(e) {
    log('PDF tecnico error: ' + e.message + '\n' + e.stack);
    res.status(500).json({ error: 'Error generando PDF: ' + e.message });
  }
});

// Health check
app.get('/api/health', function(req, res) {
  res.json({ status: 'ok', version: '2.0', port: PORT });
});

/* Start server */
var server = app.listen(PORT, '127.0.0.1', function() {
  log('Servidor corriendo en http://localhost:' + PORT);
  openBrowser('http://localhost:' + PORT);
});

server.on('error', function(err) {
  if (err.code === 'EADDRINUSE') {
    log('Puerto ' + PORT + ' en uso, intentando con ' + (PORT+1));
    var PORT2 = PORT + 1;
    app.listen(PORT2, '127.0.0.1', function() {
      log('Servidor corriendo en http://localhost:' + PORT2);
      openBrowser('http://localhost:' + PORT2);
    });
  } else {
    log('Error del servidor: ' + err.message);
  }
});

function openBrowser(url) {
  log('Abriendo browser: ' + url);
  var platform = process.platform;
  if (platform === 'win32') {
    // En Windows: usar cmd /c start para abrir la URL correctamente
    exec('cmd /c start "" "' + url + '"', function(err) {
      if (err) {
        log('Browser open error (win32 start): ' + err.message);
        // Fallback: explorer
        exec('explorer "' + url + '"', function(err2) {
          if (err2) log('Browser open error (explorer): ' + err2.message);
        });
      }
    });
  } else if (platform === 'darwin') {
    exec('open ' + url, function(err) { if(err) log('open error: ' + err.message); });
  } else {
    exec('xdg-open ' + url, function(err) {
      if (err) exec('sensible-browser ' + url, function(){});
    });
  }
}
