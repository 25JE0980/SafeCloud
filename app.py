import sqlite3
import uuid
import os 
import random
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

MAX_OTP_ATEMPTS = 5
OTP_RESEND_TIME = 60

from cryptography.fernet import Fernet

fernet = Fernet(os.environ.get("FILE_ENCRYPTION_KEY"))

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect("/dashboard")
    
    error = None
    email = ""   

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        password2 = request.form.get("password2")

        if password != password2:
            error = "Error...Passwords Mismatch!!"
            return render_template("signup.html", error=error, email=email)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        exist_email = cursor.fetchone()

        if exist_email is not None:
            error = "Email already Exists!!"
            conn.close()
            return render_template("signup.html", error=error, email=email)

        password_hash = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash),
        )
        conn.commit()
        conn.close()

        return redirect("/login")

   
    return render_template("signup.html", error=error, email=email)

def generate_otp():
    return str(random.randint(100000, 999999))

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def is_expired(expires_at):
    return datetime.utcnow() > datetime.fromisoformat(expires_at)

@app.route("/login", methods=["POST", "GET"])
def login():

    if "user_id" in session:
        return redirect("/dashboard")
    

    error = None
    email = ""
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user is None:
            error = "No user with this Email!"
        else:
            if check_password_hash(user["password_hash"],password):
                
                otp = generate_otp()
                otp_hash = hash_otp(otp)

                expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

                conn = get_db_connection()
                cursor = conn.cursor()

                cursor.execute(
                    "DELETE FROM otp_codes WHERE user_id = ?", (user["id"],) 
                )

                cursor.execute(
                    "INSERT INTO otp_codes (user_id, otp_hash, expiry_at) VALUES (?,?,?)", (user['id'], otp_hash, expires_at)
                )

                conn.commit()
                conn.close()

                send_email(user["email"], otp)
                log_action("Otp_Sent", user["id"])
                session["otp_pending_user"] = user["id"]
                session["email"] = email
                return redirect("/verify_otp")
            else:
                error = "incorrect Password!"

    return render_template("login.html",error=error,email=email)

def resend_allowed(last_sent_at):
    if last_sent_at is None:
        return True
    
    last = datetime.fromisoformat(last_sent_at)
    return (datetime.utcnow() - last).seconds >= OTP_RESEND_TIME 

@app.route("/resend_otp")
def resend_otp():

    if "otp_pending_user" not in session:
        return redirect("/login")
    
    user_id = session["otp_pending_user"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM otp_codes WHERE user_id = ?", (user_id,)
    )
    otp_row = cursor.fetchone()

    if otp_row and not resend_allowed(otp_row["last_sent_at"]):
        return "Please wait before requesting another otp"
    
    otp =  generate_otp()
    otp_hash = hash_otp(otp)
    expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

    now = (datetime.utcnow()).isoformat()

    cursor.execute(
        "DELETE FROM otp_codes WHERE user_id = ?", (user_id,)
    )

    cursor.execute(
        """INSERT INTO otp_codes (user_id, otp_hash, expiry_at, attempts, last_sent_at) VALUES (?,?,?,0,?)""",
        (user_id, otp_hash, expires_at, now) 
    )

    conn.commit()
    conn.close()

    send_email(session.get("email"), otp)
    log_action("otp_resent", user_id)
        
    return redirect("/verify_otp")

@app.route("/verify_otp", methods=["GET","POST"])
def verify_otp():
    if "otp_pending_user" not in session:
        return redirect("/login")
    
    error = None

    if request.method == "POST":
        entered_otp = request.form.get("otp")
        user_id = session["otp_pending_user"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM otp_codes WHERE user_id = ?", (user_id,)
        )
        otp_row = cursor.fetchone()

        if otp_row is None:
            return "Otp Not Found. Please login again."
        
        elif is_expired(otp_row["expiry_at"]):
            cursor.execute(
                "DELETE FROM otp_codes WHERE user_id = ?", (user_id,)
            )
            conn.commit()
            log_action("Otp_expired", user_id)
            error = "Otp expired!"

        else:
            entered_hash = hash_otp(entered_otp)

            if entered_hash != otp_row["otp_hash"]:
                attempts = otp_row["attempts"] + 1

                cursor.execute(
                    "UPDATE otp_codes SET attempts = ? WHERE user_id = ?", (attempts, user_id)
                )
                conn.commit()

                log_action("Otp_failed", user_id)

                if attempts >= MAX_OTP_ATEMPTS:
                    cursor.execute(
                        "DELETE FROM otp_codes WHERE user_id = ?", (user_id,)
                    )
                    conn.commit()
                    log_action("otp_blocked", user_id)
                    conn.close()
                    return redirect("/login")

                error = f"invalid Otp! Attempts left = {MAX_OTP_ATEMPTS - attempts}"

            else:
                cursor.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
                conn.commit()

                session.pop("otp_pending_user", None)
                session["user_id"] = user_id
                log_action("Login_success", user_id)
                conn.close()
                return redirect("/dashboard") 

        conn.close() 


    return render_template("verify_otp.html",error=error)

import smtplib
from email.message import EmailMessage

def send_email(to_email, otp):
    sender_email = os.environ.get("GMAIL_EMAIL")
    sender_password = os.environ.get("GMAIL_APP_PASSWORD")
    
    msg = EmailMessage()
    msg["Subject"] = "SafeCloud Login Otp"
    msg["From"] = sender_email
    msg["To"] = to_email
    msg.set_content(
        f"Your SafeCloud Otp is {otp}\n\nThis Otp is Valid for 5 minutes."
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.send_message(msg)


@app.route("/logout")
def logout():
    log_action("Logout", session["user_id"])
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    
    if "user_id" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            file_size = len(file.read())
            file.seek(0)
        
        if file and file.filename != '':
            original_name = file.filename
            safe_name = secure_filename(original_name)
            unique_name = f"{uuid.uuid4().hex}_{safe_name}"

            data = file.read()
            encrypted_data = fernet.encrypt(data)
            with open(os.path.join(app.config["UPLOAD_FOLDER"], unique_name), "wb") as f:
                f.write(encrypted_data)

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO files (user_id, stored_name, original_name, size) VALUES (?,?,?,?)",
                (session["user_id"], unique_name, file.filename, file_size)
            )
            conn.commit()
            log_action("File_uploaded", session["user_id"])
            conn.close()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, stored_name, original_name FROM files WHERE user_id = ?", (session["user_id"],)
    )
    owned_files = cursor.fetchall()

    cursor.execute("""
    SELECT files.id,
           files.original_name,
           files.stored_name,
           shared_files.role
    FROM shared_files
    JOIN files ON shared_files.file_id = files.id
    WHERE shared_files.shared_with_user_id = ?
    """, (session["user_id"],))
    shared_files = cursor.fetchall()

    conn.close()
    return render_template("dashboard.html", owned_files=owned_files, shared_files=shared_files)
from flask import send_from_directory
import io
from flask import send_file
@app.route("/download/<int:file_id>")
def download(file_id):
    if "user_id" not in session:
        return redirect("/login")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    )
    file = cursor.fetchone()
    
    cursor.execute(
    "SELECT role FROM shared_files WHERE file_id=? AND shared_with_user_id=?",
    (file_id, session["user_id"])
    )
    shared = cursor.fetchone()
    conn.close()
    if file["user_id"] != session["user_id"] and shared is None:
        return "Access Denied"

    try:
        encrypted_data = open(os.path.join(app.config["UPLOAD_FOLDER"], file["stored_name"]), "rb").read()
        original_data = fernet.decrypt(encrypted_data)

        file_stream = io.BytesIO(original_data)
    except Exception:
        log_action("File_decrypt_failed", session["user_id"])
        return "File cannot be decrypted."
    
    log_action("File_downloaded", session["user_id"])
    return send_file(
        file_stream,
        as_attachment=True,
        download_name=file["original_name"]
    ) 

@app.route("/share/<int:file_id>", methods=["POST"])
def share_file(file_id):
    if "user_id" not in session:
        return redirect("/login")

    email = request.form.get("email")
    role = request.form.get("role")  

    if role not in ["viewer", "editor"]:
        return "Invalid role"

    with get_db_connection() as conn:
        cursor = conn.cursor()

        
        cursor.execute(
            "SELECT * FROM files WHERE id=? AND user_id=?",
            (file_id, session["user_id"])
        )
        if cursor.fetchone() is None:
            return "Access Denied"

       
        cursor.execute(
            "SELECT id FROM users WHERE email=?",
            (email,)
        )
        user = cursor.fetchone()
        if user is None:
            return "User not found"
        
        cursor.execute(
            "SELECT role FROM shared_files WHERE file_id=? AND shared_with_user_id=?",
            (file_id, session["user_id"])
            )
        shared = cursor.fetchone()

        if shared and shared["role"] != "editor":
            return "Access Denied"
            

        cursor.execute(
            "INSERT INTO shared_files (file_id, shared_with_user_id, role) VALUES (?,?,?)",
            (file_id, user["id"], role)
        )
        conn.commit()

    log_action(f"file_shared_{role}", session["user_id"])
    return redirect("/dashboard")




@app.route("/delete/<int:file_id>")
def delete(file_id):
    if "user_id" not in session:
        return redirect("/login")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    )
    file = cursor.fetchone()
    
    if file is None or file["user_id"] != session["user_id"]:
        return "Access Denied"
    
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file["stored_name"])
    if os.path.exists(file_path):
        os.remove(file_path)
    
    cursor.execute(
        "DELETE FROM files WHERE id = ?", (file_id,)
    )
    conn.commit()
    log_action("File_deleted", session["user_id"])
    conn.close()

    return redirect("/dashboard")

@app.route("/admin/audit_logs")
def audit_logs():
    if "user_id" not in  session:
        return redirect("/login")
    
    if "user_id" == 11:
        return "Access Denied"

    conn= get_db_connection()
    cursor=conn.cursor()
    cursor.execute("SELECT * FROM audit_logs")
    logs=cursor.fetchall()

    conn.close()
    return render_template("audit_logs.html", logs=logs)


def log_action(action, user_id=None):
    ip = request.remote_addr

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    )
    user = cursor.fetchone()
    cursor.execute(
        "INSERT INTO audit_logs (email, user_id, action, ip_address) VALUES (?,?,?,?)", (user["email"], user_id, action, ip)
    )
    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect("safecloud.db")
    conn.row_factory = sqlite3.Row
    return conn


if __name__ == "__main__":
    app.run(debug=True)