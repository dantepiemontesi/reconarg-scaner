// api/scan.js — ReconARG
// Stack 100 % gratuito y sin API keys:
//   SSL   → tls nativo de Node.js (conexión directa al puerto 443)
//   DNS   → Google DNS-over-HTTPS  dns.google/resolve  (ilimitado)
//   Ports → Shodan InternetDB  internetdb.shodan.io/{ip}  (sin key, sin límite registrado)
//   Subs  → crt.sh Certificate Transparency  (sin key)
//   Breach→ mensaje informativo (HIBP requiere pago)
// Compatible con Vercel Serverless (solo HTTPS outbound, sin raw TCP).

'use strict';

const https = require('https');
const tls   = require('tls');
const dns   = require('dns').promises;

/* ─── helpers ──────────────────────────────────────────────────────────── */

function fetchJSON(url, timeoutMs = 8000) {
      return new Promise((resolve, reject) => {
              const req = https.get(url, { headers: { 'User-Agent': 'ReconARG-Scanner/2.0' } }, (res) => {
                        let body = '';
                        res.on('data', c => body += c);
                        res.on('end', () => {
                                    try { resolve(JSON.parse(body)); }
                                    catch (e) { reject(new Error('JSON parse error: ' + body.slice(0, 120))); }
                        });
              });
              req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('timeout')); });
              req.on('error', reject);
      });
}

function dnsQuery(name, type) {
      return fetchJSON(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, 6000);
}

/* ─── SSL via TLS nativo ───────────────────────────────────────────────── */

function checkSSL(domain) {
      return new Promise((resolve) => {
              const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
                        const cert = socket.getPeerCertificate(false);
                        socket.destroy();
                        if (!cert || !cert.valid_to) {
                                    return resolve({ valid: false, issuer: null, expires: null, days_remaining: null });
                        }
                        const expires = new Date(cert.valid_to);
                        const now     = new Date();
                        const days    = Math.floor((expires - now) / 86400000);
                        const issuer  = cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null;
                        resolve({
                                    valid: socket.authorized || days > 0,
                                    issuer,
                                    expires: expires.toISOString().split('T')[0],
                                    days_remaining: days,
                        });
              });
              socket.setTimeout(7000, () => { socket.destroy(); resolve({ valid: false, issuer: null, expires: null, days_remaining: null }); });
              socket.on('error', () => resolve({ valid: false, issuer: null, expires: null, days_remaining: null }));
      });
}

/* ─── DNS: SPF, DMARC, MX ──────────────────────────────────────────────── */

async function checkDNS(domain) {
      const [spfRes, dmarcRes, mxRes] = await Promise.allSettled([
              dnsQuery(domain, 'TXT'),
              dnsQuery(`_dmarc.${domain}`, 'TXT'),
              dnsQuery(domain, 'MX'),
            ]);

  let spf = false;
      if (spfRes.status === 'fulfilled' && spfRes.value.Answer) {
              spf = spfRes.value.Answer.some(r => r.data && r.data.includes('v=spf1'));
      }

  let dmarc = false;
      if (dmarcRes.status === 'fulfilled' && dmarcRes.value.Answer) {
              dmarc = dmarcRes.value.Answer.some(r => r.data && r.data.includes('v=DMARC1'));
      }

  let mx = null;
      if (mxRes.status === 'fulfilled' && mxRes.value.Answer && mxRes.value.Answer.length > 0) {
              const rec = mxRes.value.Answer[0].data || '';
              mx = rec.replace(/^\d+\s+/, '').replace(/\.$/, '');
      }

  return { spf, dmarc, mx };
}

/* ─── Ports via Shodan InternetDB (gratis, sin key) ────────────────────── */

const PORT_NAMES = {
      21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
      80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
      1433:'MSSQL', 3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL',
      5900:'VNC', 6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB',
};

async function checkPorts(ip) {
      try {
              const data = await fetchJSON(`https://internetdb.shodan.io/${ip}`, 8000);
              if (!data || !Array.isArray(data.ports)) return { status: 'ok', ports: [] };
              const ports = data.ports.map(p => ({
                        port: p,
                        service: PORT_NAMES[p] || 'unknown',
                        status: 'open',
              }));
              return { status: 'ok', ports, vulns: data.vulns || [], hostnames: data.hostnames || [] };
      } catch (e) {
              return { status: 'error', ports: [], error: e.message };
      }
}

/* ─── Subdomains via crt.sh ────────────────────────────────────────────── */

async function checkSubdomains(domain) {
      try {
              const rows = await fetchJSON(
                        `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
                        10000
                      );
              if (!Array.isArray(rows)) return [];
              const set = new Set();
              for (const r of rows) {
                        const names = (r.name_value || '').split('\n');
                        for (const n of names) {
                                    const clean = n.trim().toLowerCase().replace(/^\*\./, '');
                                    if (clean && clean.endsWith(domain) && clean !== domain) set.add(clean);
                        }
              }
              return [...set].sort().slice(0, 30);
      } catch (e) {
              return [];
      }
}

/* ─── Resolver dominio → IP ─────────────────────────────────────────────── */

async function resolveIP(domain) {
      // Intentar primero con Google DoH para mayor compatibilidad
  try {
          const res = await dnsQuery(domain, 'A');
          if (res.Answer && res.Answer.length > 0) {
                    return res.Answer[res.Answer.length - 1].data;
          }
  } catch (_) {}
      // Fallback a dns nativo de Node
  const lookup = await dns.lookup(domain);
      return lookup.address;
}

/* ─── Handler principal ─────────────────────────────────────────────────── */

module.exports = async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      if (req.method === 'OPTIONS') return res.status(200).end();

      const raw = req.query.domain || req.query.target || '';
      const domain = raw.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase().trim();

      if (!domain || !domain.includes('.')) {
              return res.status(400).json({ error: 'Parámetro domain inválido o ausente.' });
      }

      // Resolver IP antes de lanzar las consultas paralelas
      let ip;
      try {
              ip = await resolveIP(domain);
      } catch (e) {
              return res.status(400).json({ error: `No se pudo resolver el dominio: ${domain}` });
      }

      // Todas las consultas en paralelo
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
