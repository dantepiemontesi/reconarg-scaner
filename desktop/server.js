'use strict';
// ReconARG Desktop - server.js v4 - Portable Fix
// Scanner + Auth con login, sesiones, roles admin/usuario
// CAMBIOS v4: portabilidad pendrive, DATA_DIR en LOCALAPPDATA, cascada de puertos, logs mejorados

const express = require('express');
const path = require('path');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

// ============================================================
// PORTABILITY LAYER v4 - carpeta de datos en disco local
// ============================================================
const DATA_DIR = path.join(process.env.LOCALAPPDATA || process.env.HOME || os.homedir(), 'ReconARG');
try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
} catch(e) {
  console.error('[ReconARG] No se pudo crear DATA_DIR:', e.message);
}

const BASE_PORT = 3737;
const HIBP_KEY = '032a78c1720f4dadb2b86593991ce75b';
const SESSION_HOURS = 8;
const ENCRYPT_KEY = 'ReconARG-SecureKey-2024-v3!@#$$%^&';

// Log mejorado - siempre en disco local
const logFile = path.join(DATA_DIR, 'reconarg-debug.log');
function log(msg) {
  const line = new Date().toISOString() + ' ' + msg + '\n';
  try { fs.appendFileSync(logFile, line); } catch(_) {}
  console.log(msg);
}

process.on('uncaughtException', function(err) { log('UNCAUGHT: ' + err.message + (err.stack ? '\n' + err.stack : '')); });
process.on('unhandledRejection', function(r) { log('REJECTION: ' + r); });

// ============================================================

function encrypt(text) {
  var key = Buffer.from(ENCRYPT_KEY.slice(0,32), 'utf8');
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  var enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + enc.toString('hex');
}

function decrypt(text) {
  var parts = text.split(':');
  var iv = Buffer.from(parts[0], 'hex');
  var enc = Buffer.from(parts[1], 'hex');
  var key = Buffer.from(ENCRYPT_KEY.slice(0,32), 'utf8');
  var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  var hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return { hash: hash, salt: salt };
}

function verifyPassword(password, salt, storedHash) {
  var h = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return h === storedHash;
}

// Ruta del archivo de usuarios - SIEMPRE en DATA_DIR (disco local, nunca en el pendrive)
var usersFile = path.join(DATA_DIR, 'reconarg-users.dat');
log('DATA_DIR: ' + DATA_DIR);
log('Archivo de usuarios: ' + usersFile);

var MASTER_HASH = hashPassword('reconargscaner', 'reconarg-master-salt-2024');

function loadUsers() {
  var master = { username: 'dantepie1', salt: 'reconarg-master-salt-2024', hash: MASTER_HASH.hash, role: 'admin', created: '2024-01-01' };
  if (!fs.existsSync(usersFile)) return [master];
  try {
    var raw = fs.readFileSync(usersFile, 'utf8').trim();
    if (!raw) return [master];
    var dec = decrypt(raw);
    var extra = JSON.parse(dec);
    extra = extra.filter(function(u) { return u.username !== 'dantepie1'; });
    return [master].concat(extra);
  } catch(e) { log('loadUsers error: ' + e.message); return [master]; }
}

function saveUsers(users) {
  var toSave = users.filter(function(u) { return u.username !== 'dantepie1'; });
  var enc = encrypt(JSON.stringify(toSave));
  try {
    fs.writeFileSync(usersFile, enc, 'utf8');
  } catch(e) {
    log('saveUsers error: ' + e.message + ' - ruta: ' + usersFile);
  }
}

var sessions = {};

function createSession(username, role) {
  var token = crypto.randomBytes(32).toString('hex');
  var expires = Date.now() + SESSION_HOURS * 3600 * 1000;
  sessions[token] = { username: username, role: role, expires: expires };
  log('Sesion creada para: ' + username + ' rol: ' + role);
  return token;
}

function getSession(token) {
  if (!token || !sessions[token]) return null;
  var s = sessions[token];
  if (Date.now() > s.expires) { delete sessions[token]; return null; }
  return s;
}

function destroySession(token) {
  delete sessions[token];
}

setInterval(function() {
  var now = Date.now();
  Object.keys(sessions).forEach(function(t) {
    if (now > sessions[t].expires) delete sessions[t];
  });
}, 30 * 60 * 1000);

function requireAuth(req, res, next) {
  var token = req.headers['x-auth-token'] || req.cookies && req.cookies.token;
  var s = getSession(token);
  if (!s) return res.status(401).json({ error: 'No autorizado', redirect: '/login' });
  req.session = s;
  req.token = token;
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Se requiere rol administrador' });
  next();
}

function fetchJSON(url, ms, headers) {
  ms = ms || 6000; headers = headers || {};
  return new Promise(function(resolve, reject) {
    var req = https.get(url, { headers: Object.assign({'User-Agent':'ReconARG/4.0'}, headers) }, function(res) {
      var body = '';
      res.on('data', function(c) { body += c; });
      res.on('end', function() {
        if (res.statusCode === 404) return resolve([]);
        if (res.statusCode === 401) return reject(new Error('hibp-unauth'));
        if (res.statusCode === 429) return reject(new Error('hibp-ratelimit'));
        try { resolve(JSON.parse(body)); } catch(e) { reject(new Error('JSON parse error')); }
      });
    });
    req.setTimeout(ms, function() { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function dnsQ(name, type) {
  return fetchJSON('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type, 4000);
}

function checkSSL(domain) {
  var fb = { valid: false, issuer: null, expires: null, days_remaining: null };
  return new Promise(function(resolve) {
    try {
      var s = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, function() {
        try {
          var c = s.getPeerCertificate(false); s.destroy();
          if (!c || !c.valid_to) return resolve(fb);
          var exp = new Date(c.valid_to);
          var days = Math.floor((exp - Date.now()) / 86400000);
          resolve({ valid: days > 0, issuer: c.issuer ? (c.issuer.O || c.issuer.CN || null) : null,
            subject: c.subject ? (c.subject.CN || null) : null,
            expires: exp.toISOString().split('T')[0], days_remaining: days });
        } catch(e) { resolve(fb); }
      });
      s.setTimeout(5000, function() { s.destroy(); resolve(fb); });
      s.on('error', function() { resolve(fb); });
    } catch(e) { resolve(fb); }
  });
}

async function checkDNS(domain) {
  try {
    var r = await Promise.allSettled([dnsQ(domain,'TXT'), dnsQ('_dmarc.'+domain,'TXT'), dnsQ(domain,'MX')]);
    var spf = r[0].status==='fulfilled' && Array.isArray(r[0].value.Answer) && r[0].value.Answer.some(function(x){return (x.data||'').includes('v=spf1');});
    var dmarc = r[1].status==='fulfilled' && Array.isArray(r[1].value.Answer) && r[1].value.Answer.some(function(x){return (x.data||'').includes('v=DMARC1');});
    var mx = null;
    if (r[2].status==='fulfilled' && r[2].value.Answer && r[2].value.Answer.length) mx = (r[2].value.Answer[0].data||'').replace(/^\d+\s+/,'').replace(/\.$/,'');
    return { spf: !!spf, dmarc: !!dmarc, mx: mx };
  } catch(e) { return { spf: false, dmarc: false, mx: null }; }
}

var SVC = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
  143:'IMAP',443:'HTTPS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',
  5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};

async function checkPorts(domain) {
  try {
    var addrs = await dns.resolve4(domain).catch(function(){return [];});
    if (!addrs || !addrs.length) return { status:'ok', ip:null, ports:[] };
    var ip = addrs[0];
    var d = await fetchJSON('https://internetdb.shodan.io/'+ip, 6000);
    if (!d || d.detail || !Array.isArray(d.ports)) return { status:'ok', ip:ip, ports:[] };
    return { status:'ok', ip:ip, ports:d.ports.map(function(p){return {port:p,service:SVC[p]||'unknown',status:'open'};}), vulns:d.vulns||[] };
  } catch(e) { return { status:'ok', ip:null, ports:[] }; }
}

async function checkSubdomains(domain) {
  try {
    var rows = await fetchJSON('https://crt.sh/?q=%25.'+encodeURIComponent(domain)+'&output=json', 8000);
    if (!Array.isArray(rows)) return [];
    var set = new Set();
    rows.forEach(function(r) {
      (r.name_value||'').split('\n').forEach(function(n) {
        var c = n.trim().toLowerCase().replace(/^\*\./, '');
        if (c && c.endsWith(domain) && c !== domain) set.add(c);
      });
    });
    return Array.from(set).sort().slice(0,25);
  } catch(e) { return []; }
}

async function checkBreaches(domain) {
  try {
    var data = await fetchJSON('https://haveibeenpwned.com/api/v3/breacheddomain/'+encodeURIComponent(domain), 8000, {'hibp-api-key':HIBP_KEY});
    if (!Array.isArray(data)) return { status:'ok', breaches:[], count:0 };
    return { status:'ok', breaches:data.slice(0,5), count:data.length };
  } catch(e) { return { status:'error', error:e.message, breaches:[], count:0 }; }
}

function fetchRaw(url, ms) {
  ms = ms || 5000;
  return new Promise(function(resolve) {
    var req = https.get(url, { headers: {'User-Agent':'ReconARG/4.0'} }, function(res) {
      var body = '';
      res.on('data', function(c) { body += c; });
      res.on('end', function() { resolve({ status: res.statusCode, body: body.slice(0,3000), headers: res.headers }); });
    });
    req.setTimeout(ms, function() { req.destroy(); resolve({ status: 0, body: '', headers: {} }); });
    req.on('error', function() { resolve({ status: 0, body: '', headers: {} }); });
  });
}

async function checkSecHeaders(domain) {
  try {
    var r = await fetchRaw('https://' + domain + '/', 6000);
    var h = r.headers || {};
    var missing = [];
    if (!h['strict-transport-security']) missing.push('HSTS');
    if (!h['content-security-policy']) missing.push('CSP');
    if (!h['x-frame-options'] && !(h['content-security-policy']||'').includes('frame-ancestors')) missing.push('X-Frame-Options');
    if (!h['x-content-type-options']) missing.push('X-Content-Type-Options');
    if (!h['referrer-policy']) missing.push('Referrer-Policy');
    if (!h['permissions-policy']) missing.push('Permissions-Policy');
    var stack = [];
    if (h['x-powered-by']) stack.push(h['x-powered-by']);
    if (h['server']) stack.push(h['server']);
    return { missing: missing, score: missing.length, stack: stack, hsts: !!h['strict-transport-security'], csp: !!h['content-security-policy'] };
  } catch(e) { return { missing: [], score: 0, stack: [], hsts: false, csp: false }; }
}

async function checkCMS(domain) {
  try {
    var paths = [
      { path: '/wp-login.php', cms: 'WordPress' },
      { path: '/wp-admin/', cms: 'WordPress' },
      { path: '/wp-json/', cms: 'WordPress' },
      { path: '/xmlrpc.php', cms: 'WordPress' },
      { path: '/wp-content/debug.log', cms: 'WordPress' },
      { path: '/readme.html', cms: 'WordPress' },
      { path: '/administrator/', cms: 'Joomla' },
      { path: '/user/login', cms: 'Drupal' },
    ];
    var detected = new Set();
    var exposed = [];
    var checks = await Promise.allSettled(paths.map(function(p) {
      return fetchRaw('https://' + domain + p.path, 4000).then(function(r) {
        return { path: p.path, cms: p.cms, status: r.status };
      });
    }));
    checks.forEach(function(c) {
      if (c.status !== 'fulfilled') return;
      var r = c.value;
      if (r.status >= 200 && r.status < 400) {
        detected.add(r.cms);
        if (['/xmlrpc.php','/wp-content/debug.log','/readme.html'].includes(r.path) && r.status === 200) exposed.push(r.path);
      }
    });
    return { detected: Array.from(detected), exposed: exposed };
  } catch(e) { return { detected: [], exposed: [] }; }
}

async function checkSensitivePaths(domain) {
  try {
    var paths = [
      { p: '/robots.txt', risk: 'INFO' },
      { p: '/.env', risk: 'CRITICO' },
      { p: '/wp-config.php.bak', risk: 'CRITICO' },
      { p: '/backup.zip', risk: 'CRITICO' },
      { p: '/.git/HEAD', risk: 'CRITICO' },
      { p: '/phpinfo.php', risk: 'CRITICO' },
      { p: '/phpmyadmin', risk: 'ALTO' },
      { p: '/admin', risk: 'ALTO' },
      { p: '/api/v1/users', risk: 'ALTO' },
      { p: '/.htaccess', risk: 'ALTO' },
    ];
    var found = [];
    var checks = await Promise.allSettled(paths.map(function(p) {
      return fetchRaw('https://' + domain + p.p, 3000).then(function(r) {
        return { path: p.p, risk: p.risk, status: r.status };
      });
    }));
    checks.forEach(function(c) {
      if (c.status !== 'fulfilled') return;
      if (c.value.status === 200) found.push({ path: c.value.path, risk: c.value.risk });
    });
    return found;
  } catch(e) { return []; }
}

async function checkHTTPS(domain) {
  try {
    return new Promise(function(resolve) {
      var http = require('http');
      var req = http.get('http://' + domain + '/', { headers: {'User-Agent':'ReconARG/4.0'}, timeout: 5000 }, function(res) {
        var redirectsToHTTPS = (res.statusCode === 301 || res.statusCode === 302) && (res.headers.location||'').startsWith('https');
        resolve({ forcesHTTPS: redirectsToHTTPS, httpStatus: res.statusCode });
      });
      req.on('timeout', function() { req.destroy(); resolve({ forcesHTTPS: false, httpStatus: 0 }); });
      req.on('error', function() { resolve({ forcesHTTPS: true, httpStatus: 0 }); });
    });
  } catch(e) { return { forcesHTTPS: false, httpStatus: 0 }; }
}

async function checkEmailSec(domain) {
  try {
    var r = await Promise.allSettled([
      dnsQ(domain,'TXT'),
      dnsQ('_dmarc.'+domain,'TXT'),
      dnsQ('_domainkey.'+domain,'TXT')
    ]);
    var spf = r[0].status==='fulfilled' && Array.isArray(r[0].value.Answer) && r[0].value.Answer.some(function(x){return (x.data||'').includes('v=spf1');});
    var dmarc = r[1].status==='fulfilled' && Array.isArray(r[1].value.Answer) && r[1].value.Answer.some(function(x){return (x.data||'').includes('v=DMARC1');});
    var dkim = r[2].status==='fulfilled' && Array.isArray(r[2].value.Answer) && r[2].value.Answer.length > 0;
    var dmarcPolicy = 'none';
    if (r[1].status==='fulfilled' && r[1].value && r[1].value.Answer && r[1].value.Answer[0]) {
      var dr = (r[1].value.Answer[0].data||'');
      if (dr.includes('p=reject')) dmarcPolicy = 'reject';
      else if (dr.includes('p=quarantine')) dmarcPolicy = 'quarantine';
    }
    return { spf: !!spf, dmarc: !!dmarc, dkim: !!dkim, dmarcPolicy: dmarcPolicy };
  } catch(e) { return { spf: false, dmarc: false, dkim: false, dmarcPolicy: 'none' }; }
}

async function scanDomain(domain) {
  domain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  log('Escaneando: ' + domain);
  var [ssl, dns_r, ports, subs, breaches, secHdr, cms, sensitivePaths, httpsCheck, emailSec] = await Promise.all([
    checkSSL(domain), checkDNS(domain), checkPorts(domain), checkSubdomains(domain), checkBreaches(domain),
    checkSecHeaders(domain), checkCMS(domain), checkSensitivePaths(domain), checkHTTPS(domain), checkEmailSec(domain)
  ]);
  return { domain, timestamp: new Date().toISOString(), ssl, dns: dns_r, ports, subdomains: subs, breaches, secHeaders: secHdr, cms, sensitivePaths, httpsCheck, emailSec };
}

function escPDF(s) {
  return String(s||'').replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)').replace(/\r/g,'').replace(/\n/g,' ');
}

function calcRiskScore(data) {
  var score = 0;
  if (!data.ssl || !data.ssl.valid) score += 25;
  else if (data.ssl.days_remaining < 30) score += 10;
  if (!data.dns || !data.dns.spf) score += 10;
  if (!data.dns || !data.dns.dmarc) score += 10;
  var hr = [21,23,445,3389,6379,27017];
  if (data.ports && data.ports.ports) {
    var d2 = data.ports.ports.filter(function(p){return hr.includes(p.port);});
    score += d2.length * 8;
  }
  if (data.breaches && data.breaches.count > 0) score += Math.min(data.breaches.count*5,25);
  if (data.httpsCheck && !data.httpsCheck.forcesHTTPS) score += 8;
  if (data.cms && data.cms.exposed && data.cms.exposed.length > 0) score += data.cms.exposed.length * 5;
  if (data.sensitivePaths && data.sensitivePaths.length > 0) {
    data.sensitivePaths.forEach(function(p){if(p.risk==='CRITICO') score+=12; else if(p.risk==='ALTO') score+=6;});
  }
  if (data.secHeaders && data.secHeaders.score) score += Math.min(data.secHeaders.score * 2, 12);
  return Math.min(score,100);
}

function buildRecs(data) {
  var recs = [];
  if (!data.ssl||!data.ssl.valid) recs.push('SSL');
  else if (data.ssl.days_remaining<30) recs.push('SSL_VENCE:' + data.ssl.days_remaining);
  if (!data.dns||!data.dns.spf) recs.push('SPF');
  if (!data.dns||!data.dns.dmarc) recs.push('DMARC');
  if (data.ports&&data.ports.ports) {
    var d2 = data.ports.ports.filter(function(p){return [21,23,3389,6379,27017].includes(p.port);});
    if (d2.length>0) recs.push('PUERTOS:'+d2.map(function(p){return p.port+'/'+p.service;}).join(', '));
  }
  if (data.breaches&&data.breaches.count>0) recs.push('BRECHAS:'+data.breaches.count);
  if (recs.length===0) recs.push('OK');
  return recs;
}

function generatePDF(lines) {
  var stream = [];
  stream.push('BT');
  lines.forEach(function(l) {
    var r=0,g=0,b=0;
    if(l.color==='gold'){r=0.91;g=0.78;b=0.29;}
    else if(l.color==='white'){r=1;g=1;b=1;}
    else if(l.color==='gray'){r=0.5;g=0.5;b=0.5;}
    else if(l.color==='red'){r=0.94;g=0.27;b=0.27;}
    else if(l.color==='green'){r=0.13;g=0.77;b=0.37;}
    else if(l.color==='orange'){r=0.96;g=0.62;b=0.04;}
    var font = l.bold ? '/Fb' : '/Fh';
    var y842 = 842 - l.y;
    stream.push(r.toFixed(2)+' '+g.toFixed(2)+' '+b.toFixed(2)+' rg');
    stream.push(font+' '+(l.size||10)+' Tf');
    stream.push(l.x+' '+y842+' Td');
    stream.push('('+escPDF(l.text)+') Tj');
    stream.push('-'+l.x+' -'+y842+' Td');
  });
  stream.push('ET');
  var rects = ['0.04 0.04 0.10 rg','0 742 595 100 re f','1 1 1 rg','0 0 595 742 re f'];
  var fullStream = rects.join('\n')+'\n'+stream.join('\n');
  var sb = Buffer.from(fullStream,'latin1');
  var parts = [];
  parts.push(Buffer.from('%PDF-1.4\n','latin1'));
  var c1='1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
  var c2='2 0 obj\n<< /Type /Pages /Kids [5 0 R] /Count 1 >>\nendobj\n';
  var c3='3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n';
  var c4='4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n';
  var c5='5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /Fh 3 0 R /Fb 4 0 R >> >> /Contents 6 0 R >>\nendobj\n';
  parts.push(Buffer.from(c1,'latin1')); parts.push(Buffer.from(c2,'latin1'));
  parts.push(Buffer.from(c3,'latin1')); parts.push(Buffer.from(c4,'latin1'));
  parts.push(Buffer.from(c5,'latin1'));
  var ch='6 0 obj\n<< /Length '+sb.length+' >>\nstream\n';
  var cf='\nendstream\nendobj\n';
  parts.push(Buffer.from(ch,'latin1')); parts.push(sb); parts.push(Buffer.from(cf,'latin1'));
  var body = Buffer.concat(parts);
  var xOff = body.length;
  var pos = '%PDF-1.4\n'.length;
  var offs = [pos]; pos+=c1.length; offs.push(pos); pos+=c2.length; offs.push(pos); pos+=c3.length; offs.push(pos); pos+=c4.length; offs.push(pos); pos+=c5.length; offs.push(pos);
  var xref='xref\n0 7\n0000000000 65535 f \n';
  offs.forEach(function(o){xref+=String('0000000000'+o).slice(-10)+' 00000 n \n';});
  xref+='trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n'+xOff+'\n%%EOF\n';
  return Buffer.concat([body, Buffer.from(xref,'latin1')]);
}
function buildEjecutivoPDF(data) {
  var score = calcRiskScore(data);
  var riskLabel = score <= 30 ? 'BAJO' : score <= 60 ? 'MEDIO' : 'ALTO';
  var riskColor = score <= 30 ? 'green' : score <= 60 ? 'orange' : 'red';
  var fecha = new Date(data.timestamp).toLocaleDateString('es-AR', {day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
  var leyesIncumplidas = [];
  var multaMin = 0; var multaMax = 0;
  if (!data.ssl || !data.ssl.valid || (data.breaches && data.breaches.count > 0) || (data.dns && (!data.dns.spf || !data.dns.dmarc))) {
    leyesIncumplidas.push({ ley: 'Ley 25.326 - Proteccion de Datos Personales', art: 'Art. 9, 10, 11 - Seguridad e integridad de los datos', organismo: 'AAIP (Agencia de Acceso a la Informacion Publica)', extra: 'Multa entre USD 1.000 y USD 100.000 por infraccion', multa_min: 1000, multa_max: 100000 });
    multaMin += 1000; multaMax += 100000;
  }
  if (data.secHeaders && data.secHeaders.score >= 3) {
    leyesIncumplidas.push({ ley: 'Disposicion 11/2006 DNPDP', art: 'Medidas de seguridad minimas para sistemas informaticos', organismo: 'AAIP', extra: 'Sancion administrativa hasta USD 50.000 + inhabilitacion', multa_min: 500, multa_max: 50000 });
    multaMin += 500; multaMax += 50000;
  }
  var esSalud = ['clinica','sanatorio','medic','salud','hospital','consultorio'].some(function(k){ return (data.domain||'').includes(k); });
  if (esSalud && data.breaches && data.breaches.count > 0) {
    leyesIncumplidas.push({ ley: 'Ley 17.132 - Ejercicio de la Medicina', art: 'Art. 19 - Secreto profesional y proteccion de datos de pacientes', organismo: 'Ministerio de Salud + AAIP', extra: 'Multa hasta USD 200.000 + responsabilidad civil y penal', multa_min: 5000, multa_max: 200000 });
    multaMin += 5000; multaMax += 200000;
  }
  if (esSalud && (!data.ssl || !data.ssl.valid)) {
    leyesIncumplidas.push({ ley: 'Ley 26.529 - Derechos del Paciente', art: 'Art. 18 - Historia Clinica Digital debe garantizar confidencialidad', organismo: 'Ministerio de Salud de la Nacion', extra: 'Multa hasta USD 150.000 + posible inhabilitacion del establecimiento', multa_min: 10000, multa_max: 150000 });
    multaMin += 10000; multaMax += 150000;
  }
  if (data.sensitivePaths && data.sensitivePaths.some(function(p){ return p.risk === 'CRITICO'; })) {
    leyesIncumplidas.push({ ley: 'Ley 26.388 - Delitos Informaticos', art: 'Art. 157bis - Acceso no autorizado a datos personales', organismo: 'Poder Judicial - Fiscalia Informatica', extra: 'Pena de prision de 1 a 4 anios por exposicion de datos sensibles', multa_min: 0, multa_max: 0 });
  }
  var sslOk = data.ssl && data.ssl.valid && data.ssl.days_remaining > 30;
  var sslText = sslOk ? 'Su sitio tiene conexion segura. Los datos viajan protegidos.' : (!data.ssl || !data.ssl.valid) ? 'ALERTA: Su sitio NO tiene conexion segura. Los datos pueden ser interceptados.' : 'ATENCION: La conexion segura vence en ' + data.ssl.days_remaining + ' dias. Renovela pronto.';
  var spf = data.dns && data.dns.spf; var dmarc = data.dns && data.dns.dmarc;
  var emailText = (spf && dmarc) ? 'El correo electronico esta protegido contra suplantacion de identidad.' : (!spf && !dmarc) ? 'ALERTA: El correo no tiene proteccion. Alguien podria enviar emails falsos en nombre de la organizacion.' : 'ATENCION: La proteccion del correo esta incompleta. Riesgo de suplantacion parcial.';
  var puertos = data.ports && data.ports.ports ? data.ports.ports : [];
  var peligrosos = puertos.filter(function(p){return [21,23,445,3389,6379,27017].includes(p.port);});
  var puertosText = peligrosos.length > 0 ? 'ALERTA: Se encontraron ' + peligrosos.length + ' puerta(s) de acceso peligrosa(s) abiertas al publico.' : puertos.length > 0 ? 'Se detectaron ' + puertos.length + ' servicio(s) en linea. Sin puertas de alto riesgo detectadas.' : 'No se detectaron servicios expuestos publicamente.';
  var brechas = data.breaches && data.breaches.count > 0;
  var brechasText = brechas ? 'ALERTA: ' + data.breaches.count + ' filtracion(es) encontradas. Datos pueden estar circulando en Internet.' : 'No se encontraron datos de esta organizacion en filtraciones publicas conocidas.';
  var subdText = Array.isArray(data.subdomains) && data.subdomains.length > 0 ? 'Se encontraron ' + data.subdomains.length + ' sitio(s) adicionales ligados a este dominio que tambien deben revisarse.' : 'No se detectaron sitios adicionales ligados a este dominio.';
  var conclusionText, conclusionColor;
  if (score <= 30){conclusionText='La organizacion tiene una postura de seguridad aceptable. Se recomiendan mejoras preventivas.';conclusionColor='green';}
  else if (score <= 60){conclusionText='La organizacion tiene vulnerabilidades que deben atenderse. El riesgo es real pero manejable.';conclusionColor='orange';}
  else{conclusionText='RIESGO ALTO. Los datos de clientes/pacientes/alumnos pueden estar en peligro. Actuar de inmediato.';conclusionColor='red';}
  var recs = buildRecs(data);
  var recsHumanas = recs.map(function(rec){
    if(rec==='SSL') return 'Activar o renovar el candado de seguridad del sitio web.';
    if(rec.startsWith('SSL_VENCE:')) return 'Renovar el candado de seguridad. Vence en '+rec.split(':')[1]+' dias.';
    if(rec==='SPF') return 'Configurar proteccion en el correo contra emails falsos en nombre de la organizacion.';
    if(rec==='DMARC') return 'Activar segunda capa de proteccion del correo contra suplantacion de identidad.';
    if(rec.startsWith('PUERTOS:')) return 'Cerrar puertas de acceso tecnicas peligrosas: '+rec.split(':')[1];
    if(rec.startsWith('BRECHAS:')) return 'Cambiar contrasenas urgente. Datos en '+rec.split(':')[1]+' filtracion(es) publicas.';
    if(rec==='OK') return 'Postura aceptable. Mantener monitoreo periodico.';
    return rec;
  });
  var lines=[
    {text:'DIAGNOSTICO DE SEGURIDAD DIGITAL',x:50,y:35,size:17,bold:true,color:'gold'},
    {text:'Preparado por ReconARG para: '+data.domain,x:50,y:60,size:10,color:'white'},
    {text:'Fecha del analisis: '+fecha,x:50,y:78,size:9,color:'gray'},
    {text:'Organizacion analizada:',x:65,y:118,size:10,bold:true},
    {text:data.domain,x:65,y:135,size:16,bold:true},
    {text:'RESULTADO GENERAL',x:360,y:118,size:10,bold:true},
    {text:'NIVEL DE RIESGO: '+riskLabel,x:360,y:135,size:13,bold:true,color:riskColor},
    {text:'Puntaje: '+score+' de 100 puntos de riesgo',x:360,y:152,size:9,color:'gray'},
    {text:'QUE ENCONTRAMOS',x:50,y:195,size:13,bold:true},
    {text:'____________________________________________',x:50,y:208,size:9,color:'gray'},
  ];
  var y=228;
  lines.push({text:'Conexion segura del sitio web (HTTPS):',x:65,y:y,size:10,bold:true});y+=16;
  lines.push({text:sslText,x:65,y:y,size:9,color:sslOk?'green':'red'});y+=28;
  lines.push({text:'Proteccion del correo electronico:',x:65,y:y,size:10,bold:true});y+=16;
  lines.push({text:emailText,x:65,y:y,size:9,color:(spf&&dmarc)?'green':'orange'});y+=28;
  lines.push({text:'Puertas de acceso tecnicas (puertos):',x:65,y:y,size:10,bold:true});y+=16;
  lines.push({text:puertosText,x:65,y:y,size:9,color:peligrosos.length>0?'red':'green'});y+=28;
  lines.push({text:'Datos en filtraciones publicas de Internet:',x:65,y:y,size:10,bold:true});y+=16;
  lines.push({text:brechasText,x:65,y:y,size:9,color:brechas?'red':'green'});y+=28;
  lines.push({text:'Presencia digital adicional:',x:65,y:y,size:10,bold:true});y+=16;
  lines.push({text:subdText,x:65,y:y,size:9,color:'gray'});y+=35;
  lines.push({text:'CONCLUSION',x:50,y:y,size:13,bold:true});y+=18;
  lines.push({text:conclusionText,x:65,y:y,size:10,bold:true,color:conclusionColor});y+=35;
  lines.push({text:'QUE HACER AHORA',x:50,y:y,size:13,bold:true});y+=18;
  recsHumanas.forEach(function(rec,i){lines.push({text:(i+1)+'. '+rec,x:65,y:y,size:9});y+=22;});
  y+=15;
  lines.push({text:'MARCO LEGAL - INCUMPLIMIENTOS DETECTADOS',x:50,y:y,size:12,bold:true,color:'red'});y+=18;
  if (leyesIncumplidas.length > 0) {
    lines.push({text:'Las siguientes leyes argentinas aplican a esta organizacion:',x:65,y:y,size:9,color:'gray'});y+=16;
    leyesIncumplidas.forEach(function(l, i) {
      lines.push({text:(i+1)+'. '+l.ley,x:65,y:y,size:9,bold:true,color:'red'});y+=13;
      lines.push({text:' '+l.art,x:65,y:y,size:8,color:'gray'});y+=11;
      lines.push({text:' Organismo: '+l.organismo,x:65,y:y,size:8});y+=11;
      lines.push({text:' Sancion: '+l.extra,x:65,y:y,size:8,bold:true,color:'orange'});y+=15;
    });
    if (multaMax > 0) {
      y+=5;
      lines.push({text:'EXPOSICION ECONOMICA TOTAL ESTIMADA:',x:65,y:y,size:10,bold:true});y+=14;
      lines.push({text:'Minima: USD '+multaMin.toLocaleString()+' | Maxima: USD '+multaMax.toLocaleString(),x:65,y:y,size:11,bold:true,color:'red'});y+=18;
    }
  } else {
    lines.push({text:'Sin incumplimientos criticos detectados. Buena postura de cumplimiento.',x:65,y:y,size:9,color:'green'});y+=18;
  }
  y+=5;
  lines.push({text:'IMPORTANTE: Este diagnostico analiza la superficie publica del sitio.',x:65,y:y,size:8,color:'gray'});y+=11;
  lines.push({text:'Para certificacion de cumplimiento Ley 25.326 contactar a ReconARG.',x:65,y:y,size:8,color:'gray'});
  lines.push({text:'Generado por ReconARG - '+new Date().toLocaleDateString('es-AR')+' - Confidencial',x:50,y:800,size:8,color:'gray'});
  return generatePDF(lines);
}
function buildTecnicoPDF(data) {
  var score=calcRiskScore(data);
  var lines=[
    {text:'INFORME TECNICO DE SEGURIDAD',x:50,y:35,size:18,bold:true,color:'gold'},
    {text:'ReconARG - Analisis superficie de ataque',x:50,y:58,size:11,color:'white'},
    {text:'Clasificacion: CONFIDENCIAL TLP:AMBER',x:50,y:76,size:9,color:'gray'},
    {text:'Objetivo:',x:65,y:125,size:10,bold:true},{text:data.domain,x:145,y:125,size:10},
    {text:'IP:',x:65,y:142,size:10,bold:true},{text:(data.ports&&data.ports.ip)||'No resuelto',x:145,y:142,size:10},
    {text:'Score:',x:65,y:158,size:10,bold:true},{text:score+'/100',x:145,y:158,size:10,bold:true,color:score<=30?'green':score<=60?'orange':'red'},
  ];
  var y=185;
  lines.push({text:'SSL/TLS',x:50,y:y,size:11,bold:true}); y+=18;
  lines.push({text:'Estado: '+(data.ssl&&data.ssl.valid?'Valido':'Invalido'),x:60,y:y,size:10,color:data.ssl&&data.ssl.valid?'green':'red'}); y+=14;
  lines.push({text:'Emisor: '+((data.ssl&&data.ssl.issuer)||'Desconocido'),x:60,y:y,size:10}); y+=14;
  lines.push({text:'Vence: '+((data.ssl&&data.ssl.expires)||'N/A')+' Dias: '+((data.ssl&&data.ssl.days_remaining)||'N/A'),x:60,y:y,size:10}); y+=22;
  lines.push({text:'DNS / EMAIL',x:50,y:y,size:11,bold:true}); y+=18;
  lines.push({text:'SPF: '+(data.dns&&data.dns.spf?'Configurado':'AUSENTE - Riesgo spoofing'),x:60,y:y,size:10,color:data.dns&&data.dns.spf?'green':'red'}); y+=14;
  lines.push({text:'DMARC: '+(data.dns&&data.dns.dmarc?'Configurado':'AUSENTE'),x:60,y:y,size:10,color:data.dns&&data.dns.dmarc?'green':'red'}); y+=14;
  lines.push({text:'MX: '+((data.dns&&data.dns.mx)||'No encontrado'),x:60,y:y,size:10}); y+=22;
  lines.push({text:'PUERTOS ABIERTOS (Shodan InternetDB)',x:50,y:y,size:11,bold:true}); y+=18;
  if (data.ports&&data.ports.ports&&data.ports.ports.length>0) {
    data.ports.ports.forEach(function(p){
      var hr=[21,23,445,3389,6379,27017].includes(p.port);
      lines.push({text:p.port+' - '+p.service+(hr?' [ALTO RIESGO]':''),x:60,y:y,size:9,color:hr?'red':null}); y+=13;
    });
    if(data.ports.vulns&&data.ports.vulns.length>0){lines.push({text:'CVEs: '+data.ports.vulns.join(', '),x:60,y:y,size:9,color:'red'}); y+=16;}
  } else { lines.push({text:'No se detectaron puertos.',x:60,y:y,size:10,color:'gray'}); y+=14; }
  y+=8;
  lines.push({text:'SUBDOMINIOS (crt.sh)',x:50,y:y,size:11,bold:true}); y+=18;
  if (Array.isArray(data.subdomains)&&data.subdomains.length>0) {
    data.subdomains.forEach(function(s,i){
      var col=i%2; if(col===0&&i>0) y+=13;
      lines.push({text:'- '+s,x:60+col*240,y:y,size:9});
    });
    y+=20;
  } else { lines.push({text:'Sin subdominios.',x:60,y:y,size:10,color:'gray'}); y+=14; }
  y+=8;
  lines.push({text:'FILTRACIONES HIBP',x:50,y:y,size:11,bold:true}); y+=18;
  if (data.breaches&&data.breaches.count>0) {
    lines.push({text:'ALERTA: '+data.breaches.count+' filtracion(es)',x:60,y:y,size:10,bold:true,color:'red'}); y+=14;
    if(Array.isArray(data.breaches.breaches)) data.breaches.breaches.slice(0,5).forEach(function(b,i){lines.push({text:(i+1)+'. '+(typeof b==='string'?b:JSON.stringify(b)),x:70,y:y,size:9}); y+=13;});
  } else { lines.push({text:'Sin filtraciones detectadas.',x:60,y:y,size:10,color:'green'}); }
  lines.push({text:'ReconARG - Informe Tecnico - '+new Date().toLocaleDateString('es-AR'),x:50,y:800,size:8,color:'gray'});
  return generatePDF(lines);
}

var shareStore = {};

function createShareToken(scanData) {
  var token = crypto.randomBytes(16).toString('hex');
  var expires = Date.now() + 48 * 3600 * 1000;
  shareStore[token] = { data: scanData, expires: expires };
  Object.keys(shareStore).forEach(function(t) {
    if (Date.now() > shareStore[t].expires) delete shareStore[t];
  });
  return token;
}

const app = express();
app.use(express.json({ limit: '5mb' }));

// Static files - buscar en varias rutas para portabilidad
var publicDir;
if (process.pkg) {
  // En modo exe: primero junto al exe (pendrive), luego en DATA_DIR
  var dirExe = path.join(path.dirname(process.execPath), 'public');
  var dirData = path.join(DATA_DIR, 'public');
  if (fs.existsSync(dirExe)) {
    publicDir = dirExe;
  } else if (fs.existsSync(dirData)) {
    publicDir = dirData;
  } else {
    publicDir = dirExe; // fallback
  }
} else {
  publicDir = path.join(__dirname, 'public');
}
log('Static: ' + publicDir);
app.use(express.static(publicDir));

// AUTH ROUTES
app.post('/api/auth/login', function(req, res) {
  var username = (req.body.username || '').trim().toLowerCase();
  var password = req.body.password || '';
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contrasena requeridos' });
  var users = loadUsers();
  var user = users.find(function(u) { return u.username.toLowerCase() === username; });
  if (!user) return res.status(401).json({ error: 'Usuario o contrasena incorrectos' });
  if (!verifyPassword(password, user.salt, user.hash)) return res.status(401).json({ error: 'Usuario o contrasena incorrectos' });
  var token = createSession(user.username, user.role);
  log('Login exitoso: ' + user.username);
  res.json({ token: token, username: user.username, role: user.role });
});

app.post('/api/auth/logout', function(req, res) {
  var token = req.headers['x-auth-token'];
  destroySession(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, function(req, res) {
  res.json({ username: req.session.username, role: req.session.role });
});

// USER MANAGEMENT
app.get('/api/users', requireAuth, requireAdmin, function(req, res) {
  var users = loadUsers();
  var safe = users.map(function(u) { return { username: u.username, role: u.role, created: u.created }; });
  res.json(safe);
});

app.post('/api/users', requireAuth, requireAdmin, function(req, res) {
  var username = (req.body.username || '').trim().toLowerCase();
  var password = req.body.password || '';
  var role = req.body.role === 'admin' ? 'admin' : 'usuario';
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contrasena requeridos' });
  if (username.length < 3) return res.status(400).json({ error: 'Usuario minimo 3 caracteres' });
  if (password.length < 6) return res.status(400).json({ error: 'Contrasena minimo 6 caracteres' });
  if (!/^[a-z0-9_.-]+$/.test(username)) return res.status(400).json({ error: 'Usuario solo puede tener letras, numeros, _ . -' });
  var users = loadUsers();
  if (users.find(function(u) { return u.username.toLowerCase() === username; })) return res.status(409).json({ error: 'El usuario ya existe' });
  var ph = hashPassword(password);
  var newUser = { username: username, salt: ph.salt, hash: ph.hash, role: role, created: new Date().toISOString().split('T')[0] };
  users.push(newUser);
  saveUsers(users);
  log('Usuario creado: ' + username + ' rol: ' + role + ' por: ' + req.session.username);
  res.json({ ok: true, username: username, role: role });
});

app.delete('/api/users/:username', requireAuth, requireAdmin, function(req, res) {
  var target = req.params.username.toLowerCase();
  if (target === 'dantepie1') return res.status(403).json({ error: 'No se puede eliminar el usuario master' });
  if (target === req.session.username.toLowerCase()) return res.status(403).json({ error: 'No puedes eliminarte a ti mismo' });
  var users = loadUsers();
  var filtered = users.filter(function(u) { return u.username.toLowerCase() !== target; });
  if (filtered.length === users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  saveUsers(filtered);
  log('Usuario eliminado: ' + target + ' por: ' + req.session.username);
  res.json({ ok: true });
});

app.patch('/api/users/:username/role', requireAuth, requireAdmin, function(req, res) {
  var target = req.params.username.toLowerCase();
  if (target === 'dantepie1') return res.status(403).json({ error: 'No se puede cambiar el rol del usuario master' });
  var newRole = req.body.role === 'admin' ? 'admin' : 'usuario';
  var users = loadUsers();
  var user = users.find(function(u) { return u.username.toLowerCase() === target; });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  user.role = newRole;
  saveUsers(users);
  log('Rol cambiado: ' + target + ' -> ' + newRole + ' por: ' + req.session.username);
  res.json({ ok: true, username: target, role: newRole });
});

app.patch('/api/users/:username/password', requireAuth, function(req, res) {
  var target = req.params.username.toLowerCase();
  if (target !== req.session.username.toLowerCase() && req.session.role !== 'admin') return res.status(403).json({ error: 'Sin permisos' });
  if (target === 'dantepie1') return res.status(403).json({ error: 'Contrasena del master no modificable desde la app' });
  var newPwd = req.body.password || '';
  if (newPwd.length < 6) return res.status(400).json({ error: 'Contrasena minimo 6 caracteres' });
  var users = loadUsers();
  var user = users.find(function(u) { return u.username.toLowerCase() === target; });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  var ph = hashPassword(newPwd);
  user.salt = ph.salt; user.hash = ph.hash;
  saveUsers(users);
  log('Password cambiado: ' + target);
  res.json({ ok: true });
});

// SCAN & PDF
app.get('/api/scan', requireAuth, async function(req, res) {
  var domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  try {
    var result = await scanDomain(domain);
    log('Scan por ' + req.session.username + ': ' + domain);
    res.json(result);
  } catch(e) {
    log('Scan error: ' + e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/pdf/ejecutivo', requireAuth, function(req, res) {
  try {
    var buf = buildEjecutivoPDF(req.body);
    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition','attachment; filename="informe-ejecutivo-'+req.body.domain+'.pdf"');
    res.setHeader('Content-Length', buf.length);
    res.end(buf);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pdf/tecnico', requireAuth, function(req, res) {
  try {
    var buf = buildTecnicoPDF(req.body);
    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition','attachment; filename="informe-tecnico-'+req.body.domain+'.pdf"');
    res.setHeader('Content-Length', buf.length);
    res.end(buf);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/health', function(req, res) {
  res.json({ status: 'ok', version: '4.0' });
});
// SHARE & COMPARE
app.post('/api/share', requireAuth, function(req, res) {
  try {
    var token = createShareToken(req.body);
    var link = 'http://localhost:' + currentPort + '/share/' + token;
    log('Share creado por ' + req.session.username + ': ' + req.body.domain + ' token=' + token);
    res.json({ ok: true, token: token, link: link });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/share/:token', function(req, res) {
  var entry = shareStore[req.params.token];
  if (!entry || Date.now() > entry.expires) {
    return res.status(404).send('<html><body style="background:#0a0a1a;color:#e0e0e0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h2 style="color:#ef4444">Link expirado o invalido</h2><p style="color:#666;margin-top:12px">Este diagnostico ya no esta disponible.</p></div></body></html>');
  }
  var d = entry.data;
  var score = 0;
  if (!d.ssl || !d.ssl.valid) score += 25; else if (d.ssl && d.ssl.days_remaining < 30) score += 10;
  if (!d.dns || !d.dns.spf) score += 10;
  if (!d.dns || !d.dns.dmarc) score += 10;
  if (d.ports && d.ports.ports) { var hh=[21,23,445,3389,6379,27017]; d.ports.ports.forEach(function(p){if(hh.includes(p.port)) score+=8;}); }
  if (d.breaches && d.breaches.count > 0) score += Math.min(d.breaches.count*5,25);
  score = Math.min(score, 100);
  var riskLabel = score<=30?'BAJO':score<=60?'MEDIO':'ALTO';
  var riskColor = score<=30?'#22c55e':score<=60?'#f59e0b':'#ef4444';
  var fecha = new Date(d.timestamp).toLocaleString('es-AR');
  var sslOk = d.ssl && d.ssl.valid && d.ssl.days_remaining > 30;
  var sslText = sslOk ? 'Conexion segura activa' : (!d.ssl||!d.ssl.valid) ? 'ALERTA: Sin conexion segura' : 'Atencion: SSL vence en '+d.ssl.days_remaining+' dias';
  var spf = d.dns && d.dns.spf; var dmarc = d.dns && d.dns.dmarc;
  var emailText = (spf&&dmarc)?'Protegido contra suplantacion':(!spf&&!dmarc)?'ALERTA: Sin proteccion de correo':'Proteccion incompleta';
  var puertos = d.ports && d.ports.ports ? d.ports.ports : [];
  var peligrosos = puertos.filter(function(p){return [21,23,445,3389,6379,27017].includes(p.port);});
  var brechas = d.breaches && d.breaches.count > 0;
  var leyes = [];
  if (!d.ssl||!d.ssl.valid||(d.breaches&&d.breaches.count>0)||(d.dns&&(!d.dns.spf||!d.dns.dmarc))) leyes.push({l:'Ley 25.326 - Proteccion de Datos Personales',m:'Multa: USD 1.000 a 100.000'});
  if (d.secHeaders && d.secHeaders.score >= 3) leyes.push({l:'Disposicion 11/2006 DNPDP',m:'Sancion hasta USD 50.000'});
  var esSalud = ['clinica','sanatorio','medic','salud','hospital','consultorio'].some(function(k){return (d.domain||'').includes(k);});
  if (esSalud && d.breaches && d.breaches.count>0) leyes.push({l:'Ley 17.132 - Ejercicio de la Medicina',m:'Multa hasta USD 200.000'});
  if (esSalud && (!d.ssl||!d.ssl.valid)) leyes.push({l:'Ley 26.529 - Derechos del Paciente',m:'Multa hasta USD 150.000'});
  if (d.sensitivePaths && d.sensitivePaths.some(function(p){return p.risk==='CRITICO';})) leyes.push({l:'Ley 26.388 - Delitos Informaticos',m:'Pena de prision 1 a 4 anios'});
  var html = '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Diagnostico ReconARG: '+d.domain+'</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Segoe UI",Arial,sans-serif;background:#0a0a1a;color:#e0e0e0;min-height:100vh}.header{background:linear-gradient(135deg,#0a0a1a,#1a1a2e);padding:20px 32px;border-bottom:2px solid #e8c84a;display:flex;align-items:center;justify-content:space-between}.logo{color:#e8c84a;font-size:20px;font-weight:800;letter-spacing:2px}.sub{color:#666;font-size:11px}.container{max-width:760px;margin:32px auto;padding:0 20px}.hero{background:#12122a;border:1px solid #2a2a3a;border-radius:14px;padding:28px;margin-bottom:24px}.domain{font-size:24px;font-weight:800;color:#e8c84a}.fecha{color:#666;font-size:12px;margin-top:4px}.risk{display:inline-block;padding:6px 18px;border-radius:20px;font-weight:700;font-size:13px;margin-top:14px;border:2px solid '+riskColor+';color:'+riskColor+'}.score{font-size:28px;font-weight:800;color:'+riskColor+';margin-top:8px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}@media(max-width:540px){.grid{grid-template-columns:1fr}}.card{background:#12122a;border:1px solid #2a2a3a;border-radius:10px;padding:16px}.ct{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#666;margin-bottom:6px}.cv{font-size:18px;font-weight:700;margin-bottom:2px}.cs{font-size:11px;color:#666}.ok{color:#22c55e}.warn{color:#f59e0b}.bad{color:#ef4444}.section{background:#12122a;border:1px solid #2a2a3a;border-radius:10px;padding:18px;margin-bottom:14px}.st{font-size:13px;font-weight:700;color:#e8c84a;margin-bottom:12px}.leyes{background:#1a0a0a;border:1px solid #3a1a1a;border-radius:10px;padding:18px;margin-bottom:14px}.ley-item{margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #2a1a1a}.ley-item:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}.ley-nombre{font-size:12px;font-weight:700;color:#ef4444}.ley-multa{font-size:11px;color:#f59e0b;margin-top:3px}.footer{text-align:center;padding:32px 20px;color:#444;font-size:11px}.cta{background:#e8c84a;color:#0a0a1a;padding:14px 32px;border-radius:10px;font-weight:700;font-size:14px;display:inline-block;margin-top:16px;text-decoration:none}</style></head><body>';
  html += '<div class="header"><div><div class="logo">&#128274; RECONARG</div><div class="sub">Diagnostico de Seguridad Digital</div></div><div style="font-size:11px;color:#555">Valido 48hs desde la emision</div></div>';
  html += '<div class="container">';
  html += '<div class="hero"><div class="domain">'+d.domain+'</div><div class="fecha">Analizado el '+fecha+'</div><div class="risk">Nivel de Riesgo: '+riskLabel+'</div><div class="score">'+score+'/100</div></div>';
  html += '<div class="grid">';
  html += '<div class="card"><div class="ct">SSL / Conexion</div><div class="cv '+(sslOk?'ok':!d.ssl||!d.ssl.valid?'bad':'warn')+'">'+( sslOk?'&#10003; Valido':!d.ssl||!d.ssl.valid?'&#10007; Invalido':'&#9888; Por vencer')+'</div><div class="cs">'+sslText+'</div></div>';
  html += '<div class="card"><div class="ct">Correo Electronico</div><div class="cv '+(spf&&dmarc?'ok':'warn')+'">'+((spf&&dmarc)?'&#10003; Protegido':'&#9888; Vulnerable')+'</div><div class="cs">'+emailText+'</div></div>';
  html += '<div class="card"><div class="ct">Puertas de Acceso</div><div class="cv '+(peligrosos.length>0?'bad':'ok')+'">'+peligrosos.length+' peligrosa(s)</div><div class="cs">'+(puertos.length)+' puertos detectados</div></div>';
  html += '<div class="card"><div class="ct">Filtraciones de Datos</div><div class="cv '+(brechas?'bad':'ok')+'">'+(brechas?'&#10007; '+d.breaches.count+' filtracion(es)':'&#10003; Sin filtraciones')+'</div><div class="cs">'+(brechas?'Datos circulando en Internet':'Sin registros en HIBP')+'</div></div>';
  html += '</div>';
  if (leyes.length > 0) { html += '<div class="leyes"><div class="st" style="color:#ef4444">&#9888; Marco Legal - Incumplimientos Detectados</div>'; leyes.forEach(function(l){ html += '<div class="ley-item"><div class="ley-nombre">'+l.l+'</div><div class="ley-multa">'+l.m+'</div></div>'; }); html += '</div>'; }
  if (d.subdomains && d.subdomains.length > 0) { html += '<div class="section"><div class="st">&#127760; Subdominios Encontrados</div><div style="font-size:12px;color:#60a5fa">'+d.subdomains.slice(0,10).join(', ')+'</div></div>'; }
  html += '<div class="footer"><p>Diagnostico generado por <strong style="color:#e8c84a">ReconARG</strong>. Analisis de superficie publica, no reemplaza una auditoria formal.</p><br><p>Para auditoria completa y certificacion de cumplimiento Ley 25.326:</p><a class="cta" href="mailto:contacto@reconarg.com.ar">Contactar a ReconARG</a></div>';
  html += '</div></body></html>';
  res.send(html);
});

app.get('/api/compare', requireAuth, async function(req, res) {
  var d1 = req.query.domain1; var d2 = req.query.domain2;
  if (!d1 || !d2) return res.status(400).json({ error: 'domain1 y domain2 requeridos' });
  try {
    var [r1, r2] = await Promise.all([scanDomain(d1), scanDomain(d2)]);
    log('Compare por ' + req.session.username + ': ' + d1 + ' vs ' + d2);
    res.json({ domain1: r1, domain2: r2 });
  } catch(e) { log('Compare error: ' + e.message); res.status(500).json({ error: e.message }); }
});

// ============================================================
// SERVER START con cascada de puertos (v4 portability fix)
// ============================================================
var currentPort = BASE_PORT;

function openBrowser(url) {
  var p = process.platform;
  if (p === 'win32') {
    exec('cmd /c start "" "' + url + '"', function(err) {
      if (err) exec('rundll32 url.dll,FileProtocolHandler ' + url, function(err2) {
        if (err2) exec('explorer "' + url + '"', function(){});
      });
    });
  } else if (p === 'darwin') {
    exec('open ' + url, function(){});
  } else {
    exec('xdg-open ' + url, function(err) {
      if (err) exec('sensible-browser ' + url, function(err2) {
        if (err2) exec('firefox ' + url, function(){});
      });
    });
  }
}

function tryListen(port, attempt) {
  attempt = attempt || 0;
  if (attempt >= 6) {
    log('ERROR: no se pudo abrir ningun puerto entre ' + BASE_PORT + ' y ' + (BASE_PORT + 5));
    console.error('ERROR: todos los puertos ' + BASE_PORT + '-' + (BASE_PORT+5) + ' estan ocupados.');
    return;
  }
  var srv = app.listen(port, '127.0.0.1', function() {
    currentPort = port;
    log('ReconARG Desktop v4 corriendo en http://localhost:' + port);
    console.log('ReconARG Desktop v4 - http://localhost:' + port);
    if (port !== BASE_PORT) console.log('(Puerto ' + BASE_PORT + ' ocupado, usando ' + port + ')');
    setTimeout(function() { openBrowser('http://localhost:' + port); }, 500);
  });
  srv.on('error', function(err) {
    if (err.code === 'EADDRINUSE') {
      log('Puerto ' + port + ' ocupado, probando ' + (port+1));
      tryListen(port + 1, attempt + 1);
    } else {
      log('Server error: ' + err.message);
      console.error('Server error:', err.message);
    }
  });
}

log('ReconARG Desktop v4 iniciando...');
log('DATA_DIR: ' + DATA_DIR);
tryListen(BASE_PORT);
