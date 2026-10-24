
import base64
import hashlib
import os
from pathlib import Path
import uuid


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature
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
from flask import send_file
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
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT document_id, document_name, timestamp
            FROM documents
            WHERE sender_id = %s
            ORDER BY timestamp DESC
            """,
            (session["user_id"],)
        )

        documents = cursor.fetchall()
        cursor.execute(
            """
            SELECT
                d.document_id,
                d.document_name,
                d.timestamp,
                d.sender_id,
                u.name AS sender_name,
                ds.shared_at
            FROM document_shares AS ds
            JOIN documents AS d
                ON ds.document_id = d.document_id
            JOIN users AS u
                ON ds.sender_id = u.user_id
            WHERE ds.receiver_id = %s
            ORDER BY ds.shared_at DESC
            """,
            (session["user_id"],)
        )

        shared_documents = cursor.fetchall()

        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Dashboard</title>
            </head>
            <body>
                <h1>Financial Document Management System</h1>

                <h2>Welcome, {{ session["user_name"] }}!</h2>

                {% for message in get_flashed_messages() %}
                    <p>{{ message }}</p>
                {% endfor %}

                <p>Your role: {{ session["role"] }}</p>

                <p>
                    <a href="{{ url_for('upload_document') }}">
                        Upload a PDF
                    </a>
                </p>

                <p>
                    <a href="{{ url_for('verify_document') }}">
                        Verify a Received PDF
                    </a>
                </p>

                <h2>My Documents</h2>

                {% if documents %}
                    <table border="1" cellpadding="8">
                        <tr>
                            <th>Document ID</th>
                            <th>Document Name</th>
                            <th>Uploaded At</th>
                            <th>Action</th>
                        </tr>

                        {% for document in documents %}
                            <tr>
                                <td>{{ document["document_id"] }}</td>
                                <td>{{ document["document_name"] }}</td>
                                <td>{{ document["timestamp"] }}</td>
                                <td>
                                    <a href="{{ url_for(
                                        'download_document',
                                        document_id=document['document_id']
                                    ) }}">
                                        Download PDF
                                    </a>
                                </td>
                            </tr>
                        {% endfor %}
                    </table>
                {% else %}
                    <p>You have not uploaded any documents yet.</p>
                {% endif %}
                
                <h2>Shared With Me</h2>

                {% if shared_documents %}
                    <table border="1" cellpadding="8">
                        <tr>
                            <th>Document ID</th>
                            <th>Document Name</th>
                            <th>Shared By</th>
                            <th>Shared At</th>
                            <th>Action</th>
                        </tr>

                        {% for document in shared_documents %}
                            <tr>
                                <td>{{ document["document_id"] }}</td>
                                <td>{{ document["document_name"] }}</td>
                                <td>{{ document["sender_name"] }}</td>
                                <td>{{ document["shared_at"] }}</td>
                                <td>
                                    <a href="{{ url_for(
                                        'download_document',
                                        document_id=document['document_id']
                                    ) }}">
                                        Download PDF
                                    </a>
                                </td>
                            </tr>
                        {% endfor %}
                    </table>
                {% else %}
                    <p>No documents have been shared with you yet.</p>
                {% endif %}


                <br>

                <form method="POST"
                      action="{{ url_for('logout') }}">
                    <input type="hidden"
                           name="csrf_token"
                           value="{{ csrf_token() }}">
                    <button type="submit">Logout</button>
                </form>
            </body>
            </html>
        """, documents=documents, shared_documents=shared_documents)

    except Exception:
        app.logger.exception("Dashboard loading failed")
        return "Unable to load your dashboard. Check the server log.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


@app.route("/download/<int:document_id>")
def download_document(document_id):
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        
        cursor.execute(
            """
            SELECT d.document_name, d.file_path
            FROM documents AS d
            WHERE d.document_id = %s
              AND (
                  d.sender_id = %s
                  OR EXISTS (
                      SELECT 1
                      FROM document_shares AS ds
                      WHERE ds.document_id = d.document_id
                        AND ds.receiver_id = %s
                        AND ds.sender_id = d.sender_id
                  )
              )
            """,
            (
                document_id,
                session["user_id"],
                session["user_id"]
            )
        )

        document = cursor.fetchone()


        if document is None:
            return "Document not found or access denied.", 404

        document_path = Path(document["file_path"]).resolve()

        if not document_path.is_relative_to(DOCUMENTS_DIR.resolve()):
            return "Invalid document path.", 403

        if not document_path.is_file():
            return "PDF file not found on the server.", 404

        return send_file(
            document_path,
            as_attachment=True,
            download_name=document["document_name"]
        )

    except Exception:
        app.logger.exception("Document download failed")
        return "Unable to download the document.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


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
        document_id = cursor.lastrowid
        connection.commit()

        # flash(f"PDF uploaded and signed successfully. SHA-256: {file_hash}")
        # return redirect(url_for("upload_document"))

        document_id = cursor.lastrowid
        flash(
            f"PDF uploaded and signed successfully! "
            f"Document ID: {document_id}. SHA-256: {file_hash}")
        
        return redirect(url_for("dashboard"))

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


@app.route("/share-document", methods=["GET", "POST"])
def share_document():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if request.method == "POST":
        document_id = request.form.get("document_id", "").strip()
        receiver_email = request.form.get("receiver_email", "").strip().lower()

        if not document_id.isdigit() or int(document_id) < 1:
            flash("Enter a valid document ID.")
            return redirect(url_for("share_document"))

        if not receiver_email:
            flash("Enter the receiver's email.")
            return redirect(url_for("share_document"))

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            # Check that this document belongs to the logged-in sender.
            cursor.execute(
                """
                SELECT document_id
                FROM documents
                WHERE document_id = %s AND sender_id = %s
                """,
                (int(document_id), session["user_id"]),
            )

            if cursor.fetchone() is None:
                flash("Document not found or it does not belong to you.")
                return redirect(url_for("share_document"))

            # Find the receiver using their email.
            cursor.execute(
                """
                SELECT user_id
                FROM users
                WHERE LOWER(email) = %s AND user_id != %s
                """,
                (receiver_email, session["user_id"]),
            )
            receiver = cursor.fetchone()

            if receiver is None:
                flash("No other user was found with that email.")
                return redirect(url_for("share_document"))

            receiver_id = receiver[0]

            # Prevent duplicate sharing records.
            cursor.execute(
                """
                SELECT share_id
                FROM document_shares
                WHERE document_id = %s AND receiver_id = %s
                """,
                (int(document_id), receiver_id),
            )

            if cursor.fetchone() is not None:
                flash("This document has already been shared with that user.")
                return redirect(url_for("share_document"))

            # Save the sharing permission.
            cursor.execute(
                """
                INSERT INTO document_shares
                    (document_id, sender_id, receiver_id)
                VALUES (%s, %s, %s)
                """,
                (int(document_id), session["user_id"], receiver_id),
            )

            connection.commit()
            flash("Document shared successfully!")

        except Exception:
            if connection is not None:
                connection.rollback()

            app.logger.exception("Document sharing failed")
            flash("Could not share the document. Check the server log.")

        finally:
            if cursor is not None:
                cursor.close()

            if connection is not None and connection.is_connected():
                connection.close()

        return redirect(url_for("share_document"))

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Share Document</title>
        </head>
        <body>
            <h1>Share a Document</h1>

            {% for message in get_flashed_messages() %}
                <p>{{ message }}</p>
            {% endfor %}

            <form method="POST">
                <input type="hidden"
                       name="csrf_token"
                       value="{{ csrf_token() }}">

                <label for="document_id">Document ID:</label>
                <input type="number" id="document_id"
                       name="document_id" min="1" required>
                <br><br>

                <label for="receiver_email">Receiver's email:</label>
                <input type="email" id="receiver_email"
                       name="receiver_email" required>
                <br><br>

                <button type="submit">Share Document</button>
            </form>

            <p><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></p>
        </body>
        </html>
    """)


@app.route("/verify-document", methods=["GET", "POST"])
def verify_document():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":
        document_id = request.form.get("document_id", "").strip()
        uploaded_file = request.files.get("pdf_file")

        if not document_id.isdigit() or int(document_id) < 1:
            flash("Enter a valid document ID.")
            return redirect(url_for("verify_document"))

        if uploaded_file is None or not uploaded_file.filename:
            flash("Select the PDF you received.")
            return redirect(url_for("verify_document"))

        if Path(uploaded_file.filename).suffix.lower() != ".pdf":
            flash("Please select a PDF file.")
            return redirect(url_for("verify_document"))

        if uploaded_file.stream.read(5) != b"%PDF-":
            flash("The selected file does not appear to be a valid PDF.")
            return redirect(url_for("verify_document"))

        uploaded_file.stream.seek(0)

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            # Confirm that this document was shared with the receiver.
            cursor.execute(
                """
                SELECT
                    d.document_hash,
                    d.signature,
                    u.public_key
                FROM document_shares AS ds
                JOIN documents AS d
                    ON ds.document_id = d.document_id
                JOIN users AS u
                    ON d.sender_id = u.user_id
                WHERE ds.document_id = %s
                  AND ds.receiver_id = %s
                  AND ds.sender_id = d.sender_id
                """,
                (int(document_id), session["user_id"])
            )

            document = cursor.fetchone()

            if document is None:
                result = (
                    "Verification unavailable: this document was not "
                    "shared with your account."
                )
            else:
                # Calculate the received PDF's SHA-256 hash.
                sha256 = hashlib.sha256()

                for chunk in iter(
                    lambda: uploaded_file.stream.read(64 * 1024), b""
                ):
                    sha256.update(chunk)

                received_digest = sha256.digest()
                received_hash = sha256.hexdigest()

                hash_matches = (
                    received_hash == document["document_hash"]
                )

                # Load the sender's public key and stored signature.
                public_key_data = document["public_key"]

                if isinstance(public_key_data, str):
                    public_key_data = public_key_data.encode("utf-8")

                public_key = serialization.load_pem_public_key(
                    public_key_data
                )

                signature = base64.b64decode(
                    document["signature"],
                    validate=True
                )

                # Verify the signature against the received PDF.
                try:
                    public_key.verify(
                        signature,
                        received_digest,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        utils.Prehashed(hashes.SHA256()),
                    )
                    signature_valid = True

                except InvalidSignature:
                    signature_valid = False

                if hash_matches and signature_valid:
                    result = (
                        "VERIFIED: The PDF matches the stored original "
                        "and its digital signature is valid."
                    )
                else:
                    result = (
                        "VERIFICATION FAILED. "
                        f"Hash matches: {hash_matches}. "
                        f"Digital signature valid: {signature_valid}."
                    )

        except Exception:
            app.logger.exception("Document verification failed")
            result = (
                "Verification could not be completed. "
                "Check the server log for details."
            )

        finally:
            if cursor is not None:
                cursor.close()

            if connection is not None and connection.is_connected():
                connection.close()

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verify Document</title>
        </head>
        <body>
            <h1>Verify a Financial Document</h1>

            {% for message in get_flashed_messages() %}
                <p>{{ message }}</p>
            {% endfor %}

            <form method="POST" enctype="multipart/form-data">
                <input type="hidden"
                       name="csrf_token"
                       value="{{ csrf_token() }}">

                <label for="document_id">Document ID:</label>
                <input type="number" id="document_id"
                       name="document_id" min="1" required>
                <br><br>

                <label for="pdf_file">Received PDF:</label>
                <input type="file" id="pdf_file" name="pdf_file"
                       accept=".pdf,application/pdf" required>
                <br><br>

                <button type="submit">Verify PDF</button>
            </form>

            {% if result %}
                <h2>Verification Result</h2>
                <p>{{ result }}</p>
            {% endif %}

            <p><a href="{{ url_for('dashboard') }}">
                Back to Dashboard
            </a></p>
        </body>
        </html>
    """, result=result)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
