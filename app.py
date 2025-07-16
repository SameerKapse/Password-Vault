from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import bcrypt
import sqlite3
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)

### ---------- Encryption Key Management ----------

def generate_key():
    key = Fernet.generate_key()
    with open("vault.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("vault.key", "rb").read()

### ---------- Database Setup ----------

conn = sqlite3.connect("vault.db", check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS vault
             (site TEXT, password BLOB)''')
conn.commit()

### ---------- Master Password Setup and Verification ----------

if not os.path.exists("master.hash"):
    print("Setting up master password...")
    password = input("Set master password: ").encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    with open("master.hash", "wb") as f:
        f.write(hashed)
    print("Master password set successfully.")

### ---------- Encryption and Decryption ----------

def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

### ---------- Routes ----------

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form["password"].encode()
        with open("master.hash", "rb") as f:
            hashed = f.read()
            if bcrypt.checkpw(password, hashed):
                session["logged_in"] = True
                return redirect(url_for("dashboard"))
            else:
                flash("Incorrect master password.", "danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/add", methods=["GET", "POST"])
def add_password():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":
        site = request.form["site"]
        password = request.form["password"]
        key = load_key()
        encrypted = encrypt_password(password, key)
        c.execute("INSERT INTO vault (site, password) VALUES (?, ?)", (site, encrypted))
        conn.commit()
        flash("Password saved successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_password.html")

@app.route("/view")
def view_passwords():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    key = load_key()
    c.execute("SELECT site, password FROM vault")
    rows = c.fetchall()
    decrypted_passwords = []
    for row in rows:
        site = row[0]
        password = decrypt_password(row[1], key)
        decrypted_passwords.append((site, password))

    return render_template("view_passwords.html", passwords=decrypted_passwords)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

### ---------- Encryption Key Check ----------

if not os.path.exists("vault.key"):
    generate_key()

if __name__ == "__main__":
    app.run(debug=True)
