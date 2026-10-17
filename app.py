
import os

from flask import Flask
from dotenv import load_dotenv

from database import get_db_connection

load_dotenv()

app = Flask(__name__)

secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key or secret_key == "replace_with_a_long_random_secret":
    raise RuntimeError(
        "Set a real FLASK_SECRET_KEY in your .env file."
    )

app.config["SECRET_KEY"] = secret_key


@app.route("/")
def home():
    return """
    <h1>Financial Document Management System</h1>
    <p>Flask application is running.</p>
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


if __name__ == "__main__":
    app.run(debug=True)
