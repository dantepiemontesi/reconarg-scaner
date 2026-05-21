// api/scan.js — ReconARG v4
// 100 % gratuito, compatible con Vercel Serverless (max 10s Hobby plan).
//   SSL    → tls nativo Node.js
//   DNS    → Google DNS-over-HTTPS (ilimitado)
//   Ports  → Shodan InternetDB (sin key, sin límite practico)
//   Subs   → crt.sh Certificate Transparency (sin key)
//   Breach → HaveIBeenPwned API v3 (key via env HIBP_API_KEY)
'use strict';

const https = require('https');
const tls   = require('tls');
const dns   = require('dns').promises;

/* ─── fetch con timeout ──────────────────────────────────────────────────── */
function fetchJSON(url, ms = 5000, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'ReconARG/4.0', ...headers } }, (res) => {
      let body = '';
      res.on('data', c => (body += c));
      res.on('end', () => {
        // HIBP returns 404 when domain has no breaches — that's ok
        if (res.statusCode === 404) return resolve([]);
        if (res.statusCode === 401) return reject(new Error('hibp-unauth'));
        if (res.statusCode === 429) return reject(new Error('hibp-ratelimit'));
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('JSON: ' + body.slice(0, 60))); }
      });
    });
    req.setTimeout(ms, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function dnsQ(name, type) {
  return fetchJSON('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type, 4000);
}

/* ─── SSL ────────────────────────────────────────────────────────────────── */
function checkSSL(domain) {
  const fallback = { valid: false, issuer: null, expires: null, days_remaining: null };
  return new Promise((resolve) => {
    try {
      const s = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        try {
          const c = s.getPeerCertificate(false);
          s.destroy();
          if (!c || !c.valid_to) return resolve(fallback);
          const exp  = new Date(c.valid_to);
          const days = Math.floor((exp - Date.now()) / 86400000);
          resolve({
            valid: days > 0,
            issuer:  c.issuer  ? (c.issuer.O  || c.issuer.CN  || null) : null,
            subject: c.subject ? (c.subject.CN || null) : null,
            expires: exp.toISOString().split('T')[0],
            days_remaining: days,
          });
        } catch (_) { resolve(fallback); }
      });
      s.setTimeout(5000, () => { s.destroy(); resolve(fallback); });
      s.on('error', () => resolve(fallback));
    } catch (_) { resolve(fallback); }
  });
}

/* ─── DNS: SPF, DMARC, MX ───────────────────────────────────────────────── */
async function checkDNS(domain) {
  const [sR, dR, mR] = await Promise.allSettled([
    dnsQ(domain, 'TXT'),
    dnsQ('_dmarc.' + domain, 'TXT'),
    dnsQ(domain, 'MX'),
  ]);
  const spf   = sR.status === 'fulfilled' && Array.isArray(sR.value.Answer) &&
                sR.value.Answer.some(r => (r.data || '').includes('v=spf1'));
  const dmarc = dR.status === 'fulfilled' && Array.isArray(dR.value.Answer) &&
                dR.value.Answer.some(r => (r.data || '').includes('v=DMARC1'));
  let mx = null;
  if (mR.status === 'fulfilled' && mR.value.Answer && mR.value.Answer.length) {
    mx = (mR.value.Answer[0].data || '').replace(/^\d+\s+/, '').replace(/\.$/, '');
  }
  return { spf: !!spf, dmarc: !!dmarc, mx };
}

/* ─── Ports: Shodan InternetDB ───────────────────────────────────────────── */
const SVC = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
             143:'IMAP',443:'HTTPS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',
             5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',
             27017:'MongoDB'};

async function checkPorts(ip) {
  try {
    const d = await fetchJSON('https://internetdb.shodan.io/' + ip, 6000);
    if (!d || d.detail || !Array.isArray(d.ports)) return { status: 'ok', ports: [] };
    return {
      status: 'ok',
      ports:  d.ports.map(p => ({ port: p, service: SVC[p] || 'unknown', status: 'open' })),
      vulns:  d.vulns || [],
    };
  } catch (_) {
    return { status: 'ok', ports: [] };
  }
}

/* ─── Subdominios: crt.sh ────────────────────────────────────────────────── */
async function checkSubdomains(domain) {
  try {
    const rows = await fetchJSON(
      'https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json', 8000
    );
    if (!Array.isArray(rows)) return [];
    const set = new Set();
    for (const r of rows) {
      for (const n of (r.name_value || '').split('\n')) {
        const c = n.trim().toLowerCase().replace(/^\*\./, '');
        if (c && c.endsWith(domain) && c !== domain) set.add(c);
      }
    }
    return [...set].sort().slice(0, 25);
  } catch (_) { return []; }
}

/* ─── Breaches: HaveIBeenPwned ───────────────────────────────────────────── */
async function checkBreaches(domain) {
  const key = process.env.HIBP_API_KEY;
  if (!key) return { status: 'no-key', breaches: [] };
  try {
    const data = await fetchJSON(
      'https://haveibeenpwned.com/api/v3/breacheddomain/' + encodeURIComponent(domain),
      6000,
      { 'hibp-api-key': key }
    );
    // data is [] (404→[]) or an object {email: [breachNames]}
    if (Array.isArray(data) && data.length === 0) {
      return { status: 'ok', breaches: [] };
    }
    if (typeof data === 'object' && !Array.isArray(data)) {
      // Flatten: collect unique breach names across all emails
      const names = new Set();
      for (const breachList of Object.values(data)) {
        for (const b of breachList) names.add(b);
      }
      const breaches = [...names].sort();
      return { status: 'ok', breaches };
    }
    return { status: 'ok', breaches: [] };
  } catch (e) {
    if (e.message === 'hibp-unauth') return { status: 'no-key', breaches: [] };
    if (e.message === 'hibp-ratelimit') return { status: 'ok', breaches: [], note: 'rate-limited' };
    return { status: 'ok', breaches: [] };
  }
}

/* ─── Resolver IP ────────────────────────────────────────────────────────── */
async function resolveIP(domain) {
  try {
    const r = await dnsQ(domain, 'A');
    const a = (r.Answer || []).filter(x => x.type === 1);
    if (a.length) return a[a.length - 1].data;
  } catch (_) {}
  return (await dns.lookup(domain)).address;
}

/* ─── Handler ────────────────────────────────────────────────────────────── */
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
  try { ip = await resolveIP(domain); }
  catch (_) { return res.status(400).json({ error: 'No se pudo resolver: ' + domain }); }

  const [ssl, dnsData, portsData, subdomains, breachData] = await Promise.all([
    checkSSL(domain),
    checkDNS(domain),
    checkPorts(ip),
    checkSubdomains(domain),
    checkBreaches(domain),
  ]);

  return res.status(200).json({
    domain, ip, ssl,
    dns:       dnsData,
    ports:     portsData,
    subdomains,
    breaches:  breachData,
  });
};
