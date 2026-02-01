// Vercel Serverless Function — AgentShield Pro API
import { scan } from '../scanner.js';

export default function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  
  const { text, threshold } = req.body || {};
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Missing required field: text' });
  }
  if (text.length > 50000) {
    return res.status(400).json({ error: 'Text too long. Max 50,000 chars.' });
  }
  
  const result = scan(text, { threshold: threshold || 0, includeMatches: true });
  res.status(200).json(result);
}
