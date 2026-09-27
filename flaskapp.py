import os
import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = "/var/www/flaskapp/users.db"
UPLOAD_FOLDER = "/var/www/flaskapp/uploads"

app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            filename TEXT,
            word_count INTEGER
        )
    """)

    conn.commit()
    conn.close()


init_db()


@app.route("/")
def index():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    firstname = request.form["firstname"]
    lastname = request.form["lastname"]
    email = request.form["email"]
    address = request.form["address"]

    uploaded_file = request.files.get("file")

    filename = None
    word_count = None

    if uploaded_file and uploaded_file.filename:
        filename = secure_filename(uploaded_file.filename)

        if not filename.lower().endswith(".txt"):
            return "Only .txt files are allowed.", 400

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        uploaded_file.save(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            text = f.read()
            word_count = len(text.split())

    hashed_password = generate_password_hash(password)

    conn = get_db()

    try:
        cursor = conn.execute(
            """
            INSERT INTO users
            (username, password, firstname, lastname, email, address,
             filename, word_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                hashed_password,
                firstname,
                lastname,
                email,
                address,
                filename,
                word_count
            )
        )

        conn.commit()
        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        conn.close()
        return "Username already exists. Please choose another username.", 400

    conn.close()

    return redirect(url_for("profile", user_id=user_id))


@app.route("/profile/<int:user_id>")
def profile(user_id):
    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    conn.close()

    if user is None:
        return "User not found", 404

    return render_template("profile.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):
            return redirect(url_for("profile", user_id=user["id"]))

        return "Invalid username or password.", 401

    return render_template("login.html")


@app.route("/download/<int:user_id>")
def download_file(user_id):

    conn = get_db()

    user = conn.execute(
        "SELECT filename FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    conn.close()

    if user is None or not user["filename"]:
        return "No file available.", 404

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        user["filename"],
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
