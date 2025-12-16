import sqlite3

conn = sqlite3.connect("safecloud.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
               )
               """)
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,     
        user_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        uploaded_at TEXT  DEFAULT (CURRENT_TIMESTAMP),
        size INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
              )
               """)


conn.commit()
conn.close()


print("Database and users information table created")