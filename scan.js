const https = require('https');
const dns = require('dns').promises;
const tls = require('tls');

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'ReconARG-Scanner/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

function fetchText(url) {
  return new Promise((resolve) => {
    https.get(url, { headers: { 'User-Agent': 'ReconARG-Scanner/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', () => resolve(null));
  });
}

function checkSSL(domain) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (!cert || !cert.valid_to) return resolve(null);
        const expires = new Date(cert.valid_to);
        const now = new Date();
        const days = Math.floor((expires - now) / (1000 * 60 * 60 * 24));
        resolve({
          valid: days > 0,
          days_remaining: days,
          expires: expires.toLocaleDateString('es-AR'),
          issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || '—') : '—',
          subject: cert.subject ? cert.subject.CN : domain
        });
      });
      socket.on('error', () => resolve(null));
      setTimeout(() => { socket.destroy(); resolve(null); }, 8000);
    } catch(e) { resolve(null); }
  });
}

async function checkDNS(domain) {
  const result = { spf: false, dmarc: false, mx: null, spf_record: null, dmarc_record: null };
  try {
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    for (const recs of txtRecords) {
      const joined = recs.join('');
      if (joined.startsWith('v=spf')) { result.spf = true; result.spf_record = joined.substring(0, 80); }
    }
    const dmarcRecs = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
    for (const recs of dmarcRecs) {
      const joined = recs.join('');
      if (joined.includes('v=DMARC')) { result.dmarc = true; result.dmarc_record = joined.substring(0, 80); }
    }
    const mxRecs = await dns.resolveMx(domain).catch(() => []);
    if (mxRecs.length > 0) {
      mxRecs.sort((a, b) => a.priority - b.priority);
      result.mx = mxRecs[0].exchange;
    }
  } catch(e) {}
  return result;
}

async function checkPorts(domain) {
  const text = await fetchText(`https://api.hackertarget.com/nmap/?q=${encodeURIComponent(domain)}`);
  if (!text || text.includes('API count') || text.includes('Upgrade') || text.includes('error')) {
    return { status: 'limit', ports: [] };
  }
  const ports = [];
  for (const line of text.split('\n')) {
    const m = line.match(/(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)/);
    if (m) ports.push({ port: parseInt(m[1]), proto: m[2], state: m[3], service: m[4].trim() });
  }
  return { status: 'ok', ports };
}

async function checkBreaches(domain) {
  const data = await fetchJSON(`https://haveibeenpwned.com/api/v3/breacheddomain/${domain}`);
  if (!data) return { status: 'no-key', breaches: [] };
  if (Array.isArray(data)) return { status: 'ok', breaches: data };
  return { status: 'error', breaches: [] };
}

async function checkSubdomains(domain) {
  const data = await fetchJSON(`https://crt.sh/?q=%.${domain}&output=json`);
  if (!data || !Array.isArray(data)) return [];
  const subs = new Set();
  for (const entry of data) {
    const name = entry.name_value || '';
    for (const sub of name.split('\n')) {
      const clean = sub.trim().replace('*.', '');
      if (clean.endsWith(domain) && clean !== domain) subs.add(clean);
    }
  }
  return Array.from(subs).slice(0, 15);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Falta el dominio' });

  const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase().trim();
  if (!clean.includes('.')) return res.status(400).json({ error: 'Dominio inválido' });

  try {
    const [ssl, dnsData, portsData, subdomains] = await Promise.all([
      checkSSL(clean),
      checkDNS(clean),
      checkPorts(clean),
      checkSubdomains(clean)
    ]);

    const breachData = await checkBreaches(clean);

    res.status(200).json({ domain: clean, ssl, dns: dnsData, ports: portsData, breaches: breachData, subdomains });
  } catch(e) {
    res.status(500).json({ error: 'Error interno', detail: e.message });
  }
}
