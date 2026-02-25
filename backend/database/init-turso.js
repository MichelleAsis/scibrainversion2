// Initialize Turso database (run schema). Call once at startup when TURSO_* env is set.
const { getTursoClient, isTursoConfigured } = require('./turso-client');
const fs = require('fs');
const path = require('path');

const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

// Strip line comments (-- to EOL) so we don't skip statements that have leading comment lines
function stripLineComments(sql) {
    return sql
        .split('\n')
        .map((line) => {
            const i = line.indexOf('--');
            if (i === -1) return line;
            const before = line.slice(0, i).trim();
            return before.length ? line.slice(0, i).trimEnd() : '';
        })
        .join('\n');
}

async function initializeTurso() {
    if (!isTursoConfigured()) return false;
    console.log('🗄️ Initializing Turso database...');
    try {
        const client = getTursoClient();
        const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
        const statements = schema
            .split(';')
            .map((s) => stripLineComments(s).trim())
            .filter((s) => s.length > 0);
        for (const stmt of statements) {
            await client.execute(stmt + ';');
        }
        console.log('✅ Turso schema applied successfully');
        return true;
    } catch (err) {
        console.error('❌ Turso initialization failed:', err);
        return false;
    }
}

module.exports = { initializeTurso };
