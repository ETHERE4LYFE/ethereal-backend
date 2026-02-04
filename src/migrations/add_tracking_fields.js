const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '../../data/database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    ALTER TABLE orders ADD COLUMN carrier_code TEXT;
  `, err => {
    if (err && !err.message.includes('duplicate')) console.log(err.message);
  });

  db.run(`
    ALTER TABLE orders ADD COLUMN tracking_history TEXT;
  `, err => {
    if (err && !err.message.includes('duplicate')) console.log(err.message);
  });

  db.run(`
    ALTER TABLE orders ADD COLUMN last_tracking_sync TEXT;
  `, err => {
    if (err && !err.message.includes('duplicate')) console.log(err.message);
  });
});

db.close(() => {
  console.log('✅ Migración tracking completada');
});
