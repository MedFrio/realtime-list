// db.js — helper SQLite (synchrone, simple et robuste)
const Database = require('better-sqlite3');

const db = new Database('data.db', { fileMustExist: false });
db.pragma('journal_mode = WAL');

module.exports = {
  db,
  init() {
    const fs = require('fs');
    const sql = fs.readFileSync('schema.sql', 'utf8');
    // Exécute chaque statement séparément
    sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean).forEach(stmt => db.prepare(stmt).run());
  }
};
