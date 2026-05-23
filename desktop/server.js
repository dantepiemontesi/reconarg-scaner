'use strict';
// ReconARG Desktop - server.js v3
// Scanner + Auth con login, sesiones, roles admin/usuario

const express = require('express');
const path = require('path');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const PORT = 3737;
const HIBP_KEY = '032a78c1720f4dadb2b86593991ce75b';
const SESSION_HOURS = 8; // sesion expira a las 8hs
const ENCRYPT_KEY = 'ReconARG-SecureKey-2024-v3!@#$%^&'; // 32 chars para AES-256

// Log
const logFile = path.join(os.tmpdir(), 'reconarg-debug.log');
function log(msg) {
  const line = new Date().toISOString() + ' ' + msg + '\n';
  try { fs.appendFileSync(logFile, line); } catch(_) {}
  console.log(msg);
}

process.on('uncaughtException', function(err) { log('UNCAUGHT: ' + err.message); });
process.on('unhandledRejection', function(r) { log('REJECTION: ' + r); });

// Encriptacion AES-256-CBC para guardar usuarios
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

// Hash de password con SHA-256 + salt
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  var hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return { hash: hash, salt: salt };
}

function verifyPassword(password, salt, storedHash) {
  var h = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return h === storedHash;
}

// Ruta del archivo de usuarios (junto al ejecutable o en dev junto al script)
var usersFile;
if (process.pkg) {
  usersFile = path.join(path.dirname(process.execPath), 'reconarg-users.dat');
} else {
  usersFile = path.join(__dirname, 'reconarg-users.dat');
}
log('Archivo de usuarios: ' + usersFile);

// Usuario inicial hardcodeado (admin master)
var MASTER_HASH = hashPassword('reconargscaner', 'reconarg-master-salt-2024');

function loadUsers() {
  // Usuario master siempre presente
  var master = { username: 'dantepie1', salt: 'reconarg-master-salt-2024', hash: MASTER_HASH.hash, role: 'admin', created: '2024-01-01' };
  if (!fs.existsSync(usersFile)) return [master];
  try {
    var raw = fs.readFileSync(usersFile, 'utf8').trim();
    if (!raw) return [master];
    var dec = decrypt(raw);
    var extra = JSON.parse(dec);
    // Siempre re-inject master para que no pueda ser eliminado del archivo
    extra = extra.filter(function(u) { return u.username !== 'dantepie1'; });
    return [master].concat(extra);
  } catch(e) { log('loadUsers error: ' + e.message); return [master]; }
}

function saveUsers(users) {
  // Nunca guardar el master en el archivo (se inyecta en runtime)
  var toSave = users.filter(function(u) { return u.username !== 'dantepie1'; });
  var enc = encrypt(JSON.stringify(toSave));
  fs.writeFileSync(usersFile, enc, 'utf8');
}

// Sesiones en memoria (token -> {username, role, expires})
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

// Limpiar sesiones expiradas cada 30 min
setInterval(function() {
  var now = Date.now();
  Object.keys(sessions).forEach(function(t) {
    if (now > sessions[t].expires) delete sessions[t];
  });
}, 30 * 60 * 1000);

// Middleware: requiere sesion valida
function requireAuth(req, res, next) {
  var token = req.headers['x-auth-token'] || req.cookies && req.cookies.token;
  var s = getSession(token);
  if (!s) return res.status(401).json({ error: 'No autorizado', redirect: '/login' });
  req.session = s;
  req.token = token;
  next();
}

// Middleware: requiere rol admin
function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Se requiere rol administrador' });
  next();
}

/* ── Scanner ── */
function fetchJSON(url, ms, headers) {
  ms = ms || 6000; headers = headers || {};
  return new Promise(function(resolve, reject) {
    var req = https.get(url, { headers: Object.assign({'User-Agent':'ReconARG/3.0'}, headers) }, function(res) {
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

async function scanDomain(domain) {
  domain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  log('Escaneando: ' + domain);
  var [ssl, dns_r, ports, subs, breaches] = await Promise.all([checkSSL(domain), checkDNS(domain), checkPorts(domain), checkSubdomains(domain), checkBreaches(domain)]);
  return { domain, timestamp: new Date().toISOString(), ssl, dns: dns_r, ports, subdomains: subs, breaches };
}

/* ── PDF nativo ── */
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
  return Math.min(score,100);
}

function buildRecs(data) {
  var recs = [];
  if (!data.ssl||!data.ssl.valid) recs.push('Instalar o renovar certificado SSL/TLS.');
  else if (data.ssl.days_remaining<30) recs.push('Renovar SSL (' + data.ssl.days_remaining + ' dias restantes).');
  if (!data.dns||!data.dns.spf) recs.push('Configurar SPF en DNS para prevenir spoofing.');
  if (!data.dns||!data.dns.dmarc) recs.push('Implementar politica DMARC.');
  if (data.ports&&data.ports.ports) {
    var d2 = data.ports.ports.filter(function(p){return [21,23,3389,6379,27017].includes(p.port);});
    if (d2.length>0) recs.push('Restringir puertos sensibles: '+d2.map(function(p){return p.port+'/'+p.service;}).join(', '));
  }
  if (data.breaches&&data.breaches.count>0) recs.push(''+data.breaches.count+' filtracion(es): actualizar credenciales.');
  if (recs.length===0) recs.push('Postura de seguridad aceptable. Mantener monitoreo periodico.');
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
    var sslOk = data.ssl && data.ssl.valid && data.ssl.days_remaining > 30;
    var sslText = sslOk ? 'Su sitio tiene conexion segura. Los datos viajan protegidos.'
          : (!data.ssl || !data.ssl.valid) ? 'ALERTA: Su sitio NO tiene conexion segura. Los datos pueden ser interceptados.'
          : 'ATENCION: La conexion segura vence en ' + data.ssl.days_remaining + ' dias. Renuevela pronto.';
    var spf = data.dns && data.dns.spf;
    var dmarc = data.dns && data.dns.dmarc;
    var emailText = (spf && dmarc) ? 'El correo electronico esta protegido contra suplantacion de identidad.'
          : (!spf && !dmarc) ? 'ALERTA: El correo no tiene proteccion. Alguien podria enviar emails haciendose pasar por ustedes.'
          : 'ATENCION: La proteccion del correo esta incompleta. Riesgo de suplantacion parcial.';
    var puertos = data.ports && data.ports.ports ? data.ports.ports : [];
    var peligrosos = puertos.filter(function(p){return [21,23,445,3389,6379,27017].includes(p.port);});
    var puertosText = peligrosos.length > 0 ? 'ALERTA: Se encontraron ' + peligrosos.length + ' puerta(s) de acceso peligrosa(s) abiertas al publico.'
          : puertos.length > 0 ? 'Se detectaron ' + puertos.length + ' servicio(s) en linea. Sin puertas de alto riesgo detectadas.'
          : 'No se detectaron servicios expuestos publicamente.';
    var brechas = data.breaches && data.breaches.count > 0;
    var brechasText = brechas ? 'ALERTA: ' + data.breaches.count + ' filtracion(es) encontradas. Datos pueden estar circulando en Internet.'
          : 'No se encontraron datos de esta organizacion en filtraciones publicas conocidas.';
    var subdText = Array.isArray(data.subdomains) && data.subdomains.length > 0
          ? 'Se encontraron ' + data.subdomains.length + ' sitio(s) adicionales ligados a este dominio que tambien deben revisarse.'
          : 'No se detectaron sitios adicionales ligados a este dominio.';
    var conclusionText, conclusionColor;
    if (score <= 30){conclusionText='La organizacion tiene una postura de seguridad aceptable. Se recomiendan mejoras preventivas.';conclusionColor='green';}
    else if (score <= 60){conclusionText='La organizacion tiene vulnerabilidades que deben atenderse. El riesgo es real pero manejable.';conclusionColor='orange';}
    else{conclusionText='RIESGO ALTO. Los datos de clientes/pacientes/alumnos pueden estar en peligro. Actuar de inmediato.';conclusionColor='red';}
    var recs = buildRecs(data);
    var recsHumanas = recs.map(function(rec){
          if(rec==='SSL') return 'Activar o renovar el candado de seguridad del sitio web. Protege los datos que ingresan los usuarios.';
          if(rec.startsWith('SSL_VENCE:')) return 'Renovar el candado de seguridad del sitio. Vence en '+rec.split(':')[1]+' dias.';
          if(rec==='SPF') return 'Configurar proteccion en el correo para que nadie pueda enviar emails falsos en nombre de la organizacion.';
          if(rec==='DMARC') return 'Activar segunda capa de proteccion en el correo electronico contra suplantacion de identidad.';
          if(rec.startsWith('PUERTOS:')) return 'Cerrar puertas de acceso tecnicas peligrosas abiertas al publico: '+rec.split(':')[1];
          if(rec.startsWith('BRECHAS:')) return 'Cambiar contrasenas urgente. Datos de su organizacion aparecieron en '+rec.split(':')[1]+' filtracion(es) publicas.';
          if(rec==='OK') return 'Postura aceptable. Mantener monitoreo periodico para que la seguridad no decaiga con el tiempo.';
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
    y+=10;
    lines.push({text:'NOTA LEGAL:',x:65,y:y,size:9,bold:true});y+=14;
    lines.push({text:'La Ley 25.326 obliga a toda organizacion que guarda datos de personas a mantenerlos protegidos.',x:65,y:y,size:8,color:'gray'});y+=12;
    lines.push({text:'El incumplimiento puede derivar en sanciones de la AAIP (Agencia de Acceso a la Informacion Publica).',x:65,y:y,size:8,color:'gray'});
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
  lines.push({text:'Vence: '+((data.ssl&&data.ssl.expires)||'N/A')+'  Dias: '+((data.ssl&&data.ssl.days_remaining)||'N/A'),x:60,y:y,size:10}); y+=22;
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

/* ── Express app ── */
const app = express();
app.use(express.json({ limit: '5mb' }));

// Static files
var publicDir = process.pkg
  ? path.join(path.dirname(process.execPath), 'public')
  : path.join(__dirname, 'public');
if (process.pkg && !fs.existsSync(publicDir)) publicDir = path.join(__dirname, 'public');
log('Static: ' + publicDir);
app.use(express.static(publicDir));

/* ── AUTH ROUTES ── */

// POST /api/auth/login
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

// POST /api/auth/logout
app.post('/api/auth/logout', function(req, res) {
  var token = req.headers['x-auth-token'];
  destroySession(token);
  res.json({ ok: true });
});

// GET /api/auth/me - verificar sesion
app.get('/api/auth/me', requireAuth, function(req, res) {
  res.json({ username: req.session.username, role: req.session.role });
});

/* ── USER MANAGEMENT (solo admin) ── */

// GET /api/users - listar usuarios
app.get('/api/users', requireAuth, requireAdmin, function(req, res) {
  var users = loadUsers();
  var safe = users.map(function(u) {
    return { username: u.username, role: u.role, created: u.created };
  });
  res.json(safe);
});

// POST /api/users - crear usuario
app.post('/api/users', requireAuth, requireAdmin, function(req, res) {
  var username = (req.body.username || '').trim().toLowerCase();
  var password = req.body.password || '';
  var role = req.body.role === 'admin' ? 'admin' : 'usuario';
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contrasena requeridos' });
  if (username.length < 3) return res.status(400).json({ error: 'Usuario minimo 3 caracteres' });
  if (password.length < 6) return res.status(400).json({ error: 'Contrasena minimo 6 caracteres' });
  if (!/^[a-z0-9_.-]+$/.test(username)) return res.status(400).json({ error: 'Usuario solo puede tener letras, numeros, _ . -' });
  var users = loadUsers();
  if (users.find(function(u) { return u.username.toLowerCase() === username; })) {
    return res.status(409).json({ error: 'El usuario ya existe' });
  }
  var ph = hashPassword(password);
  var newUser = { username: username, salt: ph.salt, hash: ph.hash, role: role, created: new Date().toISOString().split('T')[0] };
  users.push(newUser);
  saveUsers(users);
  log('Usuario creado: ' + username + ' rol: ' + role + ' por: ' + req.session.username);
  res.json({ ok: true, username: username, role: role });
});

// DELETE /api/users/:username - eliminar usuario
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

// PATCH /api/users/:username/role - cambiar rol
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

// PATCH /api/users/:username/password - cambiar contrasena
app.patch('/api/users/:username/password', requireAuth, function(req, res) {
  var target = req.params.username.toLowerCase();
  // Solo admin puede cambiar la de otros; usuario puede cambiar la propia
  if (target !== req.session.username.toLowerCase() && req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Sin permisos' });
  }
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

/* ── SCAN & PDF (requieren auth) ── */

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
  res.json({ status: 'ok', version: '3.0' });
});

/* ── Server start ── */
log('ReconARG Desktop v3 iniciando...');
var server = app.listen(PORT, '127.0.0.1', function() {
  log('Servidor en http://localhost:' + PORT);
  openBrowser('http://localhost:' + PORT);
});

server.on('error', function(err) {
  if (err.code === 'EADDRINUSE') {
    var P2 = PORT + 1;
    app.listen(P2, '127.0.0.1', function() {
      log('Puerto alternativo: ' + P2);
      openBrowser('http://localhost:' + P2);
    });
  } else { log('Server error: ' + err.message); }
});

function openBrowser(url) {
  var p = process.platform;
  if (p === 'win32') {
    exec('cmd /c start "" "' + url + '"', function(err) {
      if (err) exec('explorer "' + url + '"', function(){});
    });
  } else if (p === 'darwin') {
    exec('open ' + url, function(){});
  } else {
    exec('xdg-open ' + url, function(err) {
      if (err) exec('sensible-browser ' + url, function(){});
    });
  }
}
