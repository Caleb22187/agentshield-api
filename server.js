/**
 * AgentShield Pro API Server
 * Free tier: 100 scans/day, basic results
 * Pro tier: unlimited scans, detailed analysis, webhook alerts
 */
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { scan } from './scanner.js';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// In-memory rate limiting and API key store
const rateLimits = new Map(); // ip -> { count, resetAt }
const apiKeys = new Map(); // key -> { tier, owner, created, scansToday, resetAt }

// Seed a demo key
apiKeys.set('demo-key-agentshield-2026', {
  tier: 'free',
  owner: 'demo',
  created: new Date().toISOString(),
  scansToday: 0,
  resetAt: Date.now() + 86400000,
});

const TIER_LIMITS = {
  free: { dailyScans: 100, includeMatches: false, batchSize: 1 },
  pro: { dailyScans: 10000, includeMatches: true, batchSize: 50 },
  enterprise: { dailyScans: 100000, includeMatches: true, batchSize: 200 },
};

function getApiKey(req) {
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) return auth.slice(7);
  return req.query.key || null;
}

function checkRateLimit(key) {
  if (!key) return { allowed: false, error: 'API key required' };
  
  const keyData = apiKeys.get(key);
  if (!keyData) return { allowed: false, error: 'Invalid API key' };
  
  // Reset daily counter
  if (Date.now() > keyData.resetAt) {
    keyData.scansToday = 0;
    keyData.resetAt = Date.now() + 86400000;
  }
  
  const limits = TIER_LIMITS[keyData.tier];
  if (keyData.scansToday >= limits.dailyScans) {
    return { 
      allowed: false, 
      error: `Daily scan limit reached (${limits.dailyScans}). Upgrade to Pro for more.`,
      remaining: 0,
    };
  }
  
  keyData.scansToday++;
  return { 
    allowed: true, 
    tier: keyData.tier,
    remaining: limits.dailyScans - keyData.scansToday,
    limits,
  };
}

// Health check
app.get('/', (req, res) => {
  res.json({
    name: 'AgentShield Pro API',
    version: '1.0.0',
    status: 'operational',
    docs: 'https://caleb22187.github.io/agentshield/',
    endpoints: {
      'POST /scan': 'Scan text for prompt injection',
      'POST /scan/batch': 'Scan multiple texts (Pro+)',
      'GET /health': 'Health check',
      'GET /stats': 'Usage statistics',
    },
    pricing: {
      free: '100 scans/day, basic results',
      pro: '$9/mo — 10K scans/day, detailed matches, batch scanning',
      enterprise: '$49/mo — 100K scans/day, webhook alerts, SLA',
    },
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Single scan endpoint
app.post('/scan', (req, res) => {
  const key = getApiKey(req);
  const rateCheck = checkRateLimit(key);
  
  if (!rateCheck.allowed) {
    return res.status(rateCheck.error.includes('Invalid') ? 401 : 429).json({ 
      error: rateCheck.error,
      upgrade: 'https://caleb22187.github.io/agentshield/#pricing',
    });
  }
  
  const { text, threshold, context } = req.body;
  
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Missing required field: text' });
  }
  
  if (text.length > 50000) {
    return res.status(400).json({ error: 'Text too long. Maximum 50,000 characters.' });
  }
  
  const result = scan(text, { 
    threshold: threshold || 0,
    includeMatches: rateCheck.limits.includeMatches,
  });
  
  result.remaining = rateCheck.remaining;
  result.tier = rateCheck.tier;
  
  res.json(result);
});

// Batch scan endpoint (Pro+)
app.post('/scan/batch', (req, res) => {
  const key = getApiKey(req);
  const rateCheck = checkRateLimit(key);
  
  if (!rateCheck.allowed) {
    return res.status(rateCheck.error.includes('Invalid') ? 401 : 429).json({ error: rateCheck.error });
  }
  
  if (rateCheck.tier === 'free') {
    return res.status(403).json({ 
      error: 'Batch scanning requires Pro tier',
      upgrade: 'https://caleb22187.github.io/agentshield/#pricing',
    });
  }
  
  const { texts, threshold } = req.body;
  
  if (!Array.isArray(texts)) {
    return res.status(400).json({ error: 'Missing required field: texts (array)' });
  }
  
  if (texts.length > rateCheck.limits.batchSize) {
    return res.status(400).json({ error: `Batch size limit: ${rateCheck.limits.batchSize}` });
  }
  
  const results = texts.map((text, i) => ({
    index: i,
    ...scan(typeof text === 'string' ? text : '', { 
      threshold: threshold || 0,
      includeMatches: rateCheck.limits.includeMatches,
    }),
  }));
  
  const unsafe = results.filter(r => !r.safe).length;
  
  res.json({
    total: results.length,
    safe: results.length - unsafe,
    unsafe,
    results,
    remaining: rateCheck.remaining - texts.length + 1,
    tier: rateCheck.tier,
  });
});

// Stats endpoint
app.get('/stats', (req, res) => {
  const key = getApiKey(req);
  if (!key || !apiKeys.has(key)) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  const keyData = apiKeys.get(key);
  const limits = TIER_LIMITS[keyData.tier];
  
  res.json({
    tier: keyData.tier,
    scansToday: keyData.scansToday,
    dailyLimit: limits.dailyScans,
    remaining: Math.max(0, limits.dailyScans - keyData.scansToday),
    resetsAt: new Date(keyData.resetAt).toISOString(),
  });
});

// Generate API key (for future self-service)
app.post('/keys/generate', (req, res) => {
  const { email, tier = 'free' } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  
  const key = `as_${tier}_${crypto.randomBytes(16).toString('hex')}`;
  apiKeys.set(key, {
    tier,
    owner: email,
    created: new Date().toISOString(),
    scansToday: 0,
    resetAt: Date.now() + 86400000,
  });
  
  res.json({ key, tier, dailyLimit: TIER_LIMITS[tier].dailyScans });
});

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`🛡️  AgentShield Pro API running on port ${PORT}`);
  console.log(`   Endpoints: http://localhost:${PORT}/`);
  console.log(`   Demo key: demo-key-agentshield-2026`);
});
