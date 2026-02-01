// Vercel Serverless Function — AgentShield API root
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({
    name: 'AgentShield Pro API',
    version: '1.0.0',
    status: 'operational',
    endpoints: {
      'POST /api/scan': 'Scan text for prompt injection',
    },
    usage: 'POST /api/scan with { "text": "your text here" }',
    github: 'https://github.com/Caleb22187/agentshield-api',
    browser: 'https://caleb22187.github.io/agentshield/',
  });
}
