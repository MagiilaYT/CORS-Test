const express = require('express');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 8080;

// ── CONFIG ─────────────────────────────────────────────
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['*'];

const BLOCKED_HOSTS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '10.',
  '172.',
  '192.168.',
];

// ── MIDDLEWARE ─────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

// CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin) || !origin;
  
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Target-URL');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

// ── BLOCK INTERNAL HOSTS ─────────────────────────────
function isBlockedHost(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return BLOCKED_HOSTS.some(blocked => hostname === blocked || hostname.startsWith(blocked));
  } catch {
    return true;
  }
}

// ── FORWARD HEADERS ──────────────────────────────────
function forwardHeaders(srcHeaders) {
  const forwarded = {};
  const allowList = [
    'authorization', 'content-type', 'accept', 'accept-language',
    'accept-encoding', 'user-agent', 'cache-control', 'if-none-match',
    'if-modified-since', 'referer', 'cookie'
  ];
  
  for (const key of allowList) {
    if (srcHeaders[key]) forwarded[key] = srcHeaders[key];
  }
  return forwarded;
}

// ── PROXY ROUTE ──────────────────────────────────────
app.use('/proxy', async (req, res) => {
  const targetUrl = req.headers['x-target-url'] || req.query.url;

  if (!targetUrl) {
    return res.status(400).json({ 
      error: 'Missing target URL. Use X-Target-URL header or ?url= parameter.' 
    });
  }

  if (isBlockedHost(targetUrl)) {
    return res.status(403).json({ error: 'Access to this host is blocked.' });
  }

  try {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: req.method,
      headers: forwardHeaders(req.headers),
      timeout: 30000,
    };

    // Remove host header (let Node set it)
    delete options.headers.host;

    const proxyReq = client.request(options, (proxyRes) => {
      // Forward status
      res.status(proxyRes.statusCode);
      
      // Forward headers (filter out problematic ones)
      const skipHeaders = ['transfer-encoding', 'connection', 'keep-alive'];
      Object.entries(proxyRes.headers).forEach(([key, value]) => {
        if (!skipHeaders.includes(key.toLowerCase())) {
          res.setHeader(key, value);
        }
      });
      
      // Ensure CORS
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
      
      // Stream response
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error('Proxy error:', err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: 'Proxy error', message: err.message });
      }
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      if (!res.headersSent) {
        res.status(504).json({ error: 'Gateway timeout' });
      }
    });

    // Forward body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      req.pipe(proxyReq);
    } else {
      proxyReq.end();
    }

  } catch (err) {
    console.error('Proxy setup error:', err.message);
    res.status(500).json({ error: 'Invalid target URL', message: err.message });
  }
});

// ── HEALTH CHECK ───────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'cors-proxy',
    version: '1.1.0',
    usage: {
      endpoint: '/proxy',
      header: 'X-Target-URL: https://api.example.com/endpoint',
      query: '/proxy?url=https://api.example.com/endpoint',
    },
  });
});

// ── START ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`CORS Proxy running on port ${PORT}`);
});
