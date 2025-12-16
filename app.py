import sqlite3
import os 
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "Idontknow"

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


@app.route("/")
def home():
    email = session.get("email")
    
    return render_template("home.html",email=email)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "email" in session:
        return redirect("/")
    
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


@app.route("/login", methods=["POST", "GET"])
def login():

    if "email" in session:
        return redirect("/")
    

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
                session["email"] = user["email"] #stored in browser not in function
                session["test"] = "working"
                
                return redirect("/dashboard")
            else:
                error = "incorrect Password!"

    return render_template("login.html",error=error,email=email)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    email = session.get("email")
    if "email" is None:
        return redirect("/login")
    
    if request.method == "POST":
        file = request.files["file"]
        
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    return render_template("dashboard.html",email=email)



def get_db_connection():
    conn = sqlite3.connect("safecloud.db")
    conn.row_factory = sqlite3.Row
    return conn


if __name__ == "__main__":
    app.run(debug=True)