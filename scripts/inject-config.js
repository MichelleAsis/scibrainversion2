// Injects API_URL into config.js at build time (Vercel deploy)
const fs = require('fs');
const path = require('path');

const apiUrl = process.env.API_URL || '';
const outPath = path.join(__dirname, '..', 'config.js');
const content = `// Injected at build time - do not edit\nwindow.SCIBRAIN_API_URL = ${JSON.stringify(apiUrl)};\n`;

fs.writeFileSync(outPath, content, 'utf8');
console.log('Wrote config.js with API_URL:', apiUrl || '(empty = use same host)');
