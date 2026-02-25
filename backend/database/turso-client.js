// Turso (libSQL) client - use when TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set
const { createClient } = require('@libsql/client');

let client = null;

function getTursoClient() {
    if (client) return client;
    const url = process.env.TURSO_DATABASE_URL;
    const authToken = process.env.TURSO_AUTH_TOKEN;
    if (!url || !authToken) return null;
    client = createClient({ url, authToken });
    return client;
}

function isTursoConfigured() {
    return !!(process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN);
}

module.exports = { getTursoClient, isTursoConfigured };
