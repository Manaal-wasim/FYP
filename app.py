
import base64
import hashlib
import os
from pathlib import Path
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    flash,
    render_template_string,
    session,
)
from werkzeug.utils import secure_filename

from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (generate_password_hash, check_password_hash,)
from database import get_db_connection
from signing.key_generation import generate_key_pair

load_dotenv()

app = Flask(__name__)

secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key or secret_key == "replace_with_a_long_random_secret":
    raise RuntimeError(
        "Set a real FLASK_SECRET_KEY in your .env file."
    )

app.config["SECRET_KEY"] = secret_key
# Secret used to encrypt users' private keys
encryption_secret = os.environ.get("KEY_ENCRYPTION_SECRET")

if not encryption_secret or len(encryption_secret) < 32:
    raise RuntimeError(
        "Set a valid KEY_ENCRYPTION_SECRET in your .env file."
    )
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

# Protect forms against CSRF attacks
csrf = CSRFProtect(app)

BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)
DOCUMENTS_DIR = BASE_DIR / "documents"
DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)


@app.route("/")
def home():
    return """
    <h1>Financial Document Management System</h1>
    <p>Flask application is running.</p>
    <p><a href="/register">Create an Account</a></p>
    <p><a href="/login">Login</a></p>
    <p><a href="/db-check">Test database connection</a></p>
    """


@app.route("/db-check")
def database_check():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT DATABASE()")
        database_name = cursor.fetchone()[0]

        return (
            "<h2>Database connection successful!</h2>"
            f"<p>Connected database: {database_name}</p>"
            "<p>Phase 1 is working.</p>"
        )

    except Exception:
        app.logger.exception("Database connection test failed")
        return (
            "<h2>Database connection failed.</h2>"
            "<p>Check your MySQL service, .env settings, "
            "and VS Code terminal for the error.</p>"
        ), 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()
@app.route("/register", methods=["GET", "POST"])
def register():
    # Display the registration form when the page is opened.
    if request.method == "GET":
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Create Account</title>
            </head>
            <body>
                <h1>Create an Account</h1>

                {% for message in get_flashed_messages() %}
                    <p>{{ message }}</p>
                {% endfor %}

                <form method="POST">
                    <input type="hidden"
                           name="csrf_token"
                           value="{{ csrf_token() }}">

                    <label>Name:</label>
                    <input type="text" name="name" required>
                    <br><br>

                    <label>Email:</label>
                    <input type="email" name="email" required>
                    <br><br>

                    <label>Password:</label>
                    <input type="password" name="password"
                           minlength="12" required>
                    <br><br>

                    <button type="submit">Register</button>
                </form>

                <p><a href="/">Back to Home</a></p>
            </body>
            </html>
        """)

    # Read the submitted form values.
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    # Perform basic input validation.
    if not name or len(name) > 100:
        flash("Enter a name of up to 100 characters.")
        return redirect(url_for("register"))

    if not email or len(email) > 255 or "@" not in email:
        flash("Enter a valid email address.")
        return redirect(url_for("register"))

    if len(password) < 12:
        flash("Your password must contain at least 12 characters.")
        return redirect(url_for("register"))

    connection = None
    cursor = None
    private_key_path = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check whether the email is already registered.
        cursor.execute(
            "SELECT user_id FROM users WHERE email = %s",
            (email,),
        )

        if cursor.fetchone():
            flash("An account with this email already exists.")
            return redirect(url_for("register"))

        # Hash the password before storing it.
        password_hash = generate_password_hash(password)

        # Generate the user's RSA key pair.
        public_key, encrypted_private_key = generate_key_pair(
            encryption_secret
        )

        # Create the account using the existing default User role.
        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash, public_key)
            VALUES (%s, %s, %s, %s)
            """,
            (name, email, password_hash, public_key),
        )

        user_id = cursor.lastrowid

        # Save the encrypted private key outside the database.
        private_key_path = KEYS_DIR / f"user_{user_id}_private.pem"

        with open(private_key_path, "xb") as key_file:
            key_file.write(encrypted_private_key)

        # Commit the account to MySQL.
        connection.commit()

        flash("Account created successfully. You can now log in.")
        return redirect(url_for("register"))

    except Exception:
        if connection is not None:
            connection.rollback()

        # Remove the newly created key file if registration fails.
        if private_key_path is not None and private_key_path.exists():
            private_key_path.unlink()

        app.logger.exception("Registration failed")
        flash("Registration failed. Check the server terminal for details.")
        return redirect(url_for("register"))

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login</title>
            </head>
            <body>
                <h1>Login to Your Account</h1>

                {% for message in get_flashed_messages() %}
                    <p>{{ message }}</p>
                {% endfor %}

                <form method="POST">
                    <input type="hidden"
                           name="csrf_token"
                           value="{{ csrf_token() }}">

                    <label>Email:</label>
                    <input type="email" name="email" required>
                    <br><br>

                    <label>Password:</label>
                    <input type="password"
                           name="password" required>
                    <br><br>

                    <button type="submit">Login</button>
                </form>

                <p>
                    <a href="/register">Create an account</a>
                </p>
            </body>
            </html>
        """)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT user_id, name, email, password_hash, role
            FROM users
            WHERE email = %s
            """,
            (email,),
        )

        user = cursor.fetchone()

        if (
            user is None
            or not check_password_hash(
                user["password_hash"], password
            )
        ):
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        # Start a fresh authenticated session.
        session.clear()
        session["user_id"] = user["user_id"]
        session["user_name"] = user["name"]
        session["role"] = user["role"]

        flash("Login successful.")
        return redirect(url_for("dashboard"))

    except Exception:
        app.logger.exception("Login failed")
        flash("Unable to log in. Check the server terminal.")
        return redirect(url_for("login"))

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()

@app.route("/dashboard")
def dashboard():
    # Only logged-in users can access the dashboard.
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
        </head>
        <body>
            <h1>Financial Document Management System</h1>

            <h2>Welcome, {{ session["user_name"] }}!</h2>

            <p>You are logged in successfully.</p>
            <p>Your role: {{ session["role"] }}</p>
            <p><a href="{{ url_for('upload_document') }}">Upload a PDF</a></p>

            <form method="POST" action="{{ url_for('logout') }}">
                <input type="hidden"
                       name="csrf_token"
                       value="{{ csrf_token() }}">

                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
    """)


@app.route("/upload", methods=["GET", "POST"])
def upload_document():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Upload a PDF</title>
            </head>
            <body>
                <h1>Upload a PDF</h1>

                {% for message in get_flashed_messages() %}
                    <p>{{ message }}</p>
                {% endfor %}

                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden"
                           name="csrf_token"
                           value="{{ csrf_token() }}">

                    <label for="pdf_file">PDF document:</label>
                    <input type="file" id="pdf_file" name="pdf_file"
                           accept=".pdf,application/pdf" required>
                    <br><br>

                    <button type="submit">Upload and Sign</button>
                </form>

                <p><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></p>
            </body>
            </html>
        """)

    uploaded_file = request.files.get("pdf_file")
    if uploaded_file is None or not uploaded_file.filename:
        flash("Select a PDF file to upload.")
        return redirect(url_for("upload_document"))

    original_filename = secure_filename(uploaded_file.filename)
    if not original_filename or Path(original_filename).suffix.lower() != ".pdf":
        flash("Upload a file with a .pdf extension.")
        return redirect(url_for("upload_document"))

    if uploaded_file.stream.read(5) != b"%PDF-":
        flash("The selected file does not appear to be a valid PDF.")
        return redirect(url_for("upload_document"))
    uploaded_file.stream.seek(0)

    user_id = session["user_id"]
    stored_filename = f"{uuid.uuid4().hex}.pdf"
    document_path = DOCUMENTS_DIR / stored_filename
    connection = None
    cursor = None
    document_saved = False

    try:
        uploaded_file.save(document_path)
        document_saved = True

        sha256 = hashlib.sha256()
        with document_path.open("rb") as pdf_file:
            for chunk in iter(lambda: pdf_file.read(64 * 1024), b""):
                sha256.update(chunk)
        file_digest = sha256.digest()
        file_hash = sha256.hexdigest()

        private_key_path = KEYS_DIR / f"user_{user_id}_private.pem"
        encrypted_private_key = private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=encryption_secret.encode("utf-8"),
        )
        signature = private_key.sign(
            file_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                document_id INT NOT NULL AUTO_INCREMENT,
                sender_id INT NOT NULL,
                document_name VARCHAR(255) NOT NULL,
                file_path VARCHAR(500) NOT NULL,
                document_hash CHAR(64) NOT NULL,
                signature TEXT NOT NULL,
                status ENUM(
                    'PENDING', 'VALID', 'FLAGGED', 'REJECTED', 'TAMPERED'
                ) NOT NULL DEFAULT 'PENDING',
                timestamp TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (document_id),
                INDEX idx_documents_sender_id (sender_id),
                INDEX idx_documents_hash (document_hash)
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO documents (
                sender_id, document_name, file_path, document_hash, signature
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user_id,
                original_filename,
                str(document_path),
                file_hash,
                base64.b64encode(signature).decode("ascii"),
            ),
        )
        connection.commit()

        flash(f"PDF uploaded and signed successfully. SHA-256: {file_hash}")
        return redirect(url_for("upload_document"))

    except Exception:
        if connection is not None:
            connection.rollback()
        if document_saved and document_path.exists():
            document_path.unlink()

        app.logger.exception("PDF upload or signing failed")
        flash("The PDF could not be uploaded and signed. Check the server log.")
        return redirect(url_for("upload_document"))

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
