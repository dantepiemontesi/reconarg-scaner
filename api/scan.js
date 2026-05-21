// api/scan.js — ReconARG
// Stack 100 % gratuito, sin API keys, compatible con Vercel Serverless:
//   SSL    → tls nativo Node.js (conexión directa puerto 443)
//   DNS    → Google DNS-over-HTTPS  dns.google/resolve  (ilimitado)
//   Ports  → Shodan InternetDB  internetdb.shodan.io/{ip}  (sin key)
//   Subs   → crt.sh Certificate Transparency  (sin key)
//   Breach → informativo (HIBP requiere pago)
'use strict';

const https = require('https');
const tls   = require('tls');
const dns   = require('dns').promises;

/* ─── helper fetch JSON ─────────────────────────────────────────────────── */
function fetchJSON(url, timeoutMs = 9000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'ReconARG/2.0' } }, (res) => {
      let body = '';
      res.on('data', c => (body += c));
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('JSON parse: ' + body.slice(0, 80))); }
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function dnsQ(name, type) {
  return fetchJSON(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, 6000);
}

/* ─── SSL via TLS nativo ────────────────────────────────────────────────── */
function checkSSL(domain) {
  return new Promise((resolve) => {
    const fallback = { valid: false, issuer: null, expires: null, days_remaining: null };
    try {
      const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        try {
          const cert = socket.getPeerCertificate(false);
          socket.destroy();
          if (!cert || !cert.valid_to) return resolve(fallback);
          const expires = new Date(cert.valid_to);
          const days    = Math.floor((expires - Date.now()) / 86400000);
          const issuer  = cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null;
          const subject = cert.subject ? (cert.subject.CN || null) : null;
          resolve({ valid: days > 0, issuer, subject, expires: expires.toISOString().split('T')[0], days_remaining: days });
        } catch (_) { resolve(fallback); }
      });
      socket.setTimeout(7000, () => { socket.destroy(); resolve(fallback); });
      socket.on('error', () => resolve(fallback));
    } catch (_) { resolve(fallback); }
  });
}

/* ─── DNS: SPF, DMARC, MX ───────────────────────────────────────────────── */
async function checkDNS(domain) {
  const [spfR, dmarcR, mxR] = await Promise.allSettled([
    dnsQ(domain, 'TXT'),
    dnsQ('_dmarc.' + domain, 'TXT'),
    dnsQ(domain, 'MX'),
  ]);

  const spf = spfR.status === 'fulfilled' &&
    Array.isArray(spfR.value.Answer) &&
    spfR.value.Answer.some(r => r.data && r.data.includes('v=spf1'));

  const dmarc = dmarcR.status === 'fulfilled' &&
    Array.isArray(dmarcR.value.Answer) &&
    dmarcR.value.Answer.some(r => r.data && r.data.includes('v=DMARC1'));

  let mx = null;
  if (mxR.status === 'fulfilled' && Array.isArray(mxR.value.Answer) && mxR.value.Answer.length > 0) {
    mx = (mxR.value.Answer[0].data || '').replace(/^\d+\s+/, '').replace(/\.$/, '');
  }

  return { spf: !!spf, dmarc: !!dmarc, mx };
}

/* ─── Ports via Shodan InternetDB ───────────────────────────────────────── */
const PORT_NAMES = {
  21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
  143:'IMAP',443:'HTTPS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',
  5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB',
};

async function checkPorts(ip) {
  try {
    const data = await fetchJSON('https://internetdb.shodan.io/' + ip, 8000);
    // Shodan returns {"detail":"No information available"} when nothing is indexed
    if (!data || data.detail || !Array.isArray(data.ports)) {
      return { status: 'ok', ports: [], vulns: [], note: 'No data in Shodan for this IP' };
    }
    const ports = data.ports.map(p => ({
      port: p,
      service: PORT_NAMES[p] || 'unknown',
      status: 'open',
    }));
    return { status: 'ok', ports, vulns: data.vulns || [], hostnames: data.hostnames || [] };
  } catch (e) {
    return { status: 'ok', ports: [], error: e.message };
  }
}

/* ─── Subdomains via crt.sh ─────────────────────────────────────────────── */
async function checkSubdomains(domain) {
  try {
    const rows = await fetchJSON(
      'https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json',
      12000
    );
    if (!Array.isArray(rows)) return [];
    const set = new Set();
    for (const r of rows) {
      for (const n of (r.name_value || '').split('\n')) {
        const c = n.trim().toLowerCase().replace(/^\*\./, '');
        if (c && c.endsWith(domain) && c !== domain) set.add(c);
      }
    }
    return [...set].sort().slice(0, 30);
  } catch (_) {
    return [];
  }
}

/* ─── Resolver IP ───────────────────────────────────────────────────────── */
async function resolveIP(domain) {
  try {
    const res = await dnsQ(domain, 'A');
    if (res.Answer && res.Answer.length > 0) {
      // Return the last A record (most specific)
      const aRecs = res.Answer.filter(r => r.type === 1);
      if (aRecs.length > 0) return aRecs[aRecs.length - 1].data;
    }
  } catch (_) {}
  const lk = await dns.lookup(domain);
  return lk.address;
}

/* ─── Handler principal ─────────────────────────────────────────────────── */
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const raw    = req.query.domain || req.query.target || '';
  const domain = raw.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase().trim();

  if (!domain || !domain.includes('.')) {
    return res.status(400).json({ error: 'Parámetro domain inválido o ausente.' });
  }

  let ip;
  try {
    ip = await resolveIP(domain);
  } catch (_) {
    return res.status(400).json({ error: 'No se pudo resolver el dominio: ' + domain });
  }

  const [ssl, dnsData, portsData, subdomains] = await Promise.all([
    checkSSL(domain),
    checkDNS(domain),
    checkPorts(ip),
    checkSubdomains(domain),
  ]);

  return res.status(200).json({
    domain,
    ip,
    ssl,
    dns: dnsData,
    ports: portsData,
    subdomains,
    breaches: { status: 'no-key', breaches: [] },
  });
};
