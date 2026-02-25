// Turso-backed database service (async). Same API as service.js but using @libsql/client.
const fs = require('fs');
const path = require('path');
const { getTursoClient } = require('./turso-client');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

function row(r) {
    return r && r.length ? r[0] : null;
}

function rows(r) {
    return r || [];
}

class TursoDatabaseService {
    async exec(sql, args = []) {
        const c = getTursoClient();
        const res = await c.execute({ sql, args });
        return res;
    }

    async runSchema() {
        const sql = fs.readFileSync(SCHEMA_PATH, 'utf8');
        const c = getTursoClient();
        // Run each statement separately (libSQL may not run multi-statement in one execute)
        const statements = sql
            .split(';')
            .map((s) => s.trim())
            .filter((s) => s.length > 0 && !s.startsWith('--'));
        for (const stmt of statements) {
            await c.execute(stmt);
        }
    }

    // ---------- Users ----------
    async createUser(fullName, email, passwordHash) {
        const res = await this.exec(
            `INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)`,
            [fullName, email, passwordHash]
        );
        const id = Number(res.lastInsertRowid) || res.lastInsertRowid;
        console.log(`✅ User created: ID ${id}, Email: ${email}`);
        return id;
    }

    async getUserByEmail(email) {
        const res = await this.exec('SELECT * FROM users WHERE email = ?', [email]);
        return row(res.rows);
    }

    async getUserById(userId) {
        const res = await this.exec('SELECT * FROM users WHERE id = ?', [userId]);
        return row(res.rows);
    }

    async updateLastLogin(userId) {
        await this.exec(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [userId]);
    }

    // ---------- Sessions ----------
    async createSession(userId, sessionToken, expiresAt) {
        const res = await this.exec(
            `INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)`,
            [userId, sessionToken, expiresAt]
        );
        const id = Number(res.lastInsertRowid) || res.lastInsertRowid;
        console.log(`✅ Session created for user ${userId}`);
        return id;
    }

    async getSessionByToken(sessionToken) {
        const res = await this.exec(
            `SELECT s.*, u.full_name, u.email FROM sessions s
             JOIN users u ON s.user_id = u.id
             WHERE s.session_token = ? AND s.expires_at > datetime('now')`,
            [sessionToken]
        );
        return row(res.rows);
    }

    async deleteSession(sessionToken) {
        await this.exec('DELETE FROM sessions WHERE session_token = ?', [sessionToken]);
    }

    async deleteExpiredSessions() {
        const res = await this.exec(`DELETE FROM sessions WHERE expires_at <= datetime('now')`);
        if (res.rowsAffected > 0) console.log(`🗑️ Deleted ${res.rowsAffected} expired sessions`);
    }

    // ---------- Documents ----------
    async saveDocument(userId, title, originalText, fileType = 'text') {
        const wordCount = originalText.split(/\s+/).length;
        const res = await this.exec(
            `INSERT INTO documents (user_id, title, original_text, file_type, word_count) VALUES (?, ?, ?, ?, ?)`,
            [userId, title, originalText, fileType, wordCount]
        );
        const id = Number(res.lastInsertRowid) || res.lastInsertRowid;
        console.log(`✅ Document saved: ID ${id} for user ${userId}`);
        return id;
    }

    async getDocument(id, userId = null) {
        let res;
        if (userId) res = await this.exec('SELECT * FROM documents WHERE id = ? AND user_id = ?', [id, userId]);
        else res = await this.exec('SELECT * FROM documents WHERE id = ?', [id]);
        return row(res.rows);
    }

    async getAllDocuments(userId, limit = 50) {
        const res = await this.exec(
            `SELECT id, title, file_type, word_count, upload_date FROM documents WHERE user_id = ? ORDER BY upload_date DESC LIMIT ?`,
            [userId, limit]
        );
        return res.rows || [];
    }

    async deleteDocument(id, userId) {
        const res = await this.exec('DELETE FROM documents WHERE id = ? AND user_id = ?', [id, userId]);
        console.log(`🗑️ Document deleted: ID ${id}`);
        return (res.rowsAffected || 0) > 0;
    }

    // ---------- Reviewers ----------
    async saveReviewer(userId, documentId, reviewerData) {
        const res = await this.exec(
            `INSERT INTO reviewers (user_id, document_id, title, sections, concepts, metadata, original_text)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                userId,
                documentId,
                reviewerData.title,
                JSON.stringify(reviewerData.sections),
                JSON.stringify(reviewerData.concepts),
                JSON.stringify(reviewerData.metadata),
                reviewerData.originalText
            ]
        );
        const id = Number(res.lastInsertRowid) || res.lastInsertRowid;
        console.log(`✅ Reviewer saved: ID ${id} for user ${userId}`);
        return id;
    }

    _mapReviewer(row) {
        if (!row) return null;
        return {
            id: row.id,
            userId: row.user_id,
            documentId: row.document_id,
            title: row.title,
            sections: JSON.parse(row.sections),
            concepts: JSON.parse(row.concepts),
            metadata: JSON.parse(row.metadata),
            originalText: row.original_text,
            generatedAt: row.generated_at
        };
    }

    async getReviewer(id, userId = null) {
        let res;
        if (userId) res = await this.exec('SELECT * FROM reviewers WHERE id = ? AND user_id = ?', [id, userId]);
        else res = await this.exec('SELECT * FROM reviewers WHERE id = ?', [id]);
        const r = row(res.rows);
        return r ? this._mapReviewer(r) : null;
    }

    async getReviewerByDocumentId(documentId, userId) {
        const res = await this.exec(
            `SELECT * FROM reviewers WHERE document_id = ? AND user_id = ? ORDER BY generated_at DESC LIMIT 1`,
            [documentId, userId]
        );
        const r = row(res.rows);
        return r ? this._mapReviewer(r) : null;
    }

    async getAllReviewers(userId, limit = 50) {
        const res = await this.exec(
            `SELECT r.id, r.title, r.generated_at, d.title as document_title, json_extract(r.metadata, '$.wordCount') as word_count
             FROM reviewers r LEFT JOIN documents d ON r.document_id = d.id
             WHERE r.user_id = ? ORDER BY r.generated_at DESC LIMIT ?`,
            [userId, limit]
        );
        return res.rows || [];
    }

    async deleteReviewer(id, userId) {
        const res = await this.exec('DELETE FROM reviewers WHERE id = ? AND user_id = ?', [id, userId]);
        console.log(`🗑️ Reviewer deleted: ID ${id}`);
        return (res.rowsAffected || 0) > 0;
    }

    // ---------- Quiz questions ----------
    async saveQuizQuestions(reviewerId, allQuestions) {
        const c = getTursoClient();
        const stmt = `INSERT INTO quiz_questions (reviewer_id, quiz_type, difficulty, questions) VALUES (?, ?, ?, ?)`;
        for (const [quizType, difficulties] of Object.entries(allQuestions)) {
            for (const [difficulty, questionData] of Object.entries(difficulties)) {
                await c.execute({ sql: stmt, args: [reviewerId, quizType, difficulty, JSON.stringify(questionData)] });
            }
        }
        console.log(`✅ Quiz questions saved for reviewer: ${reviewerId}`);
        return true;
    }

    async getQuizQuestions(reviewerId) {
        const res = await this.exec(`SELECT quiz_type, difficulty, questions FROM quiz_questions WHERE reviewer_id = ?`, [reviewerId]);
        const allQuestions = {
            trueFalse: { easy: [], medium: [], hard: [] },
            multipleChoice: { easy: [], medium: [], hard: [] },
            identification: { easy: [], medium: [], hard: [] },
            matching: { easy: { pairs: [] }, medium: { pairs: [] }, hard: { pairs: [] } }
        };
        (res.rows || []).forEach((row) => {
            const q = typeof row.questions === 'string' ? JSON.parse(row.questions) : row.questions;
            allQuestions[row.quiz_type][row.difficulty] = q;
        });
        return allQuestions;
    }

    async getQuizQuestionsByType(reviewerId, quizType, difficulty) {
        const res = await this.exec(
            `SELECT questions FROM quiz_questions WHERE reviewer_id = ? AND quiz_type = ? AND difficulty = ?`,
            [reviewerId, quizType, difficulty]
        );
        const r = row(res.rows);
        return r && r.questions ? (typeof r.questions === 'string' ? JSON.parse(r.questions) : r.questions) : null;
    }

    // ---------- Quiz attempts ----------
    async saveQuizAttempt(userId, reviewerId, attemptData) {
        const res = await this.exec(
            `INSERT INTO quiz_attempts (user_id, reviewer_id, quiz_type, difficulty, total_questions, correct_answers, wrong_answers, percentage, time_taken, user_answers, questions_used)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                userId,
                reviewerId,
                attemptData.quizType,
                attemptData.difficulty,
                attemptData.totalQuestions,
                attemptData.correctAnswers,
                attemptData.wrongAnswers,
                attemptData.percentage,
                attemptData.timeTaken,
                JSON.stringify(attemptData.userAnswers || []),
                JSON.stringify(attemptData.questionsUsed || [])
            ]
        );
        const id = Number(res.lastInsertRowid) || res.lastInsertRowid;
        console.log(`✅ Quiz attempt saved: ID ${id}`);
        return id;
    }

    // ---------- Statistics ----------
    async getStatistics(userId) {
        const docs = await this.exec('SELECT COUNT(*) as count FROM documents WHERE user_id = ?', [userId]);
        const revs = await this.exec('SELECT COUNT(*) as count FROM reviewers WHERE user_id = ?', [userId]);
        const attempts = await this.exec('SELECT COUNT(*) as count FROM quiz_attempts WHERE user_id = ?', [userId]);
        const anns = await this.exec('SELECT COUNT(*) as count FROM annotations WHERE user_id = ?', [userId]);
        const avg = await this.exec('SELECT AVG(percentage) as avg FROM quiz_attempts WHERE user_id = ?', [userId]);
        const d = row(docs.rows) || {}, r = row(revs.rows) || {}, a = row(attempts.rows) || {}, an = row(anns.rows) || {}, av = row(avg.rows) || {};
        return {
            documents: Number(d.count) || 0,
            reviewers: Number(r.count) || 0,
            quizAttempts: Number(a.count) || 0,
            annotations: Number(an.count) || 0,
            avgQuizScore: Number(av.avg) || 0
        };
    }
}

// Singleton
let instance = null;
function getTursoService() {
    if (!instance) instance = new TursoDatabaseService();
    return instance;
}

module.exports = { TursoDatabaseService, getTursoService };
