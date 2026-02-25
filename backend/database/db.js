// Unified database entry point: Turso if TURSO_* env set, else SQLite (async wrapper).
const { isTursoConfigured } = require('./turso-client');

let dbService = null;

if (isTursoConfigured()) {
    const { getTursoService } = require('./service-turso');
    dbService = getTursoService();
} else {
    const sqlite = require('./service');
    // Wrap sync SQLite methods so they return Promises (same API as Turso).
    const wrap = (fn) => (...args) => Promise.resolve(fn.apply(sqlite, args));
    dbService = {
        createUser: wrap(sqlite.createUser.bind(sqlite)),
        getUserByEmail: wrap(sqlite.getUserByEmail.bind(sqlite)),
        getUserById: wrap(sqlite.getUserById.bind(sqlite)),
        updateLastLogin: wrap(sqlite.updateLastLogin.bind(sqlite)),
        createSession: wrap(sqlite.createSession.bind(sqlite)),
        getSessionByToken: wrap(sqlite.getSessionByToken.bind(sqlite)),
        deleteSession: wrap(sqlite.deleteSession.bind(sqlite)),
        deleteExpiredSessions: wrap(sqlite.deleteExpiredSessions.bind(sqlite)),
        saveDocument: wrap(sqlite.saveDocument.bind(sqlite)),
        getDocument: wrap(sqlite.getDocument.bind(sqlite)),
        getAllDocuments: wrap(sqlite.getAllDocuments.bind(sqlite)),
        deleteDocument: wrap(sqlite.deleteDocument.bind(sqlite)),
        saveReviewer: wrap(sqlite.saveReviewer.bind(sqlite)),
        getReviewer: wrap(sqlite.getReviewer.bind(sqlite)),
        getReviewerByDocumentId: wrap(sqlite.getReviewerByDocumentId.bind(sqlite)),
        getAllReviewers: wrap(sqlite.getAllReviewers.bind(sqlite)),
        deleteReviewer: wrap(sqlite.deleteReviewer.bind(sqlite)),
        saveQuizQuestions: wrap(sqlite.saveQuizQuestions.bind(sqlite)),
        getQuizQuestions: wrap(sqlite.getQuizQuestions.bind(sqlite)),
        getQuizQuestionsByType: wrap(sqlite.getQuizQuestionsByType.bind(sqlite)),
        saveQuizAttempt: wrap(sqlite.saveQuizAttempt.bind(sqlite)),
        getStatistics: wrap(sqlite.getStatistics.bind(sqlite))
    };
}

module.exports = dbService;
