const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

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

// Trust Render's proxy
app.set('trust proxy', 1);

// CORS
app.use(cors({
  origin: (origin, callback) => {
    if (ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Target-URL', 'Accept'],
  credentials: true,
  maxAge: 86400,
}));

// ── BLOCK INTERNAL HOSTS ─────────────────────────────
function isBlockedHost(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return BLOCKED_HOSTS.some(blocked => hostname === blocked || hostname.startsWith(blocked));
  } catch {
    return true;
  }
}

// ── PROXY ROUTE ────────────────────────────────────────
app.use('/proxy', (req, res, next) => {
  const targetUrl = req.headers['x-target-url'] || req.query.url;

  if (!targetUrl) {
    return res.status(400).json({ 
      error: 'Missing target URL. Use X-Target-URL header or ?url= parameter.' 
    });
  }

  if (isBlockedHost(targetUrl)) {
    return res.status(403).json({ error: 'Access to this host is blocked.' });
  }

  const proxy = createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    secure: true,
    followRedirects: true,
    timeout: 30000,
    proxyTimeout: 30000,
    ws: false,
    onProxyReq: (proxyReq, req) => {
      const headersToForward = ['authorization', 'content-type', 'accept', 'accept-language'];
      headersToForward.forEach(h => {
        if (req.headers[h]) proxyReq.setHeader(h, req.headers[h]);
      });
      proxyReq.removeHeader('x-target-url');
    },
    onProxyRes: (proxyRes, req, res) => {
      proxyRes.headers['access-control-allow-origin'] = req.headers.origin || '*';
      proxyRes.headers['access-control-allow-credentials'] = 'true';
    },
    onError: (err, req, res) => {
      console.error('Proxy error:', err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: 'Proxy error', message: err.message });
      }
    },
  });

  proxy(req, res, next);
});

// ── HEALTH CHECK (Render pings this) ───────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'cors-proxy',
    version: '1.0.0',
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
