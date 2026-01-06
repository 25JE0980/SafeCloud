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

cursor.execute("""
CREATE TABLE IF NOT EXISTS otp_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        user_id INTEGER NOT NULL,
        otp_hash TEXT NOT NULL,
        expiry_at TEXT NOT NULL,
        generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
               )
        """)

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        ip_address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) 
               )
               """)

cursor.execute("""
CREATE TABLE IF NOT EXISTS shared_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        shared_with_user_id INTEGER NOT NULL,
        shared_at TEXT DEFAULT CURRENT_TIMESTAMP,
        role TEXT NOT NULL
               )
         """)

conn.commit()
conn.close()


print("Database and users information table created")