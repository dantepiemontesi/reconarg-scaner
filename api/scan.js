const net = require('net');
const dns = require('dns').promises;

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];

const PORT_NAMES = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    1433: 'MSSQL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
};

function scanPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
          const socket = new net.Socket();
          let status = 'closed';

                           socket.setTimeout(timeout);

                           socket.on('connect', () => {
                                   status = 'open';
                                   socket.destroy();
                           });

                           socket.on('timeout', () => {
                                   status = 'filtered';
                                   socket.destroy();
                           });

                           socket.on('error', (err) => {
                                   if (err.code === 'ECONNREFUSED') {
                                             status = 'closed';
                                   } else {
                                             status = 'filtered';
                                   }
                                   socket.destroy();
                           });

                           socket.on('close', () => {
                                   resolve({
                                             port,
                                             name: PORT_NAMES[port] || 'unknown',
                                             status,
                                   });
                           });

                           socket.connect(port, host);
    });
}

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
          return res.status(200).end();
    }

    const { target } = req.query;

    if (!target) {
          return res.status(400).json({ error: 'Missing target parameter' });
    }

    // Sanitize target: strip protocol if present
    const cleanTarget = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

    if (!cleanTarget) {
          return res.status(400).json({ error: 'Invalid target' });
    }

    let ip;
    try {
          const lookup = await dns.lookup(cleanTarget);
          ip = lookup.address;
    } catch (err) {
          return res.status(400).json({ error: `Could not resolve domain: ${cleanTarget}` });
    }

    try {
          const results = await Promise.all(
                  COMMON_PORTS.map((port) => scanPort(ip, port))
                );

      const open = results.filter((r) => r.status === 'open');
          const closed = results.filter((r) => r.status === 'closed');
          const filtered = results.filter((r) => r.status === 'filtered');

      return res.status(200).json({
              target: cleanTarget,
              ip,
              scanned: COMMON_PORTS.length,
              open: open.length,
              results: {
                        open,
                        closed,
                        filtered,
              },
      });
    } catch (err) {
          return res.status(500).json({ error: 'Scan failed', details: err.message });
    }
};
