
import os

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """Create and return a connection to the project database."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.getenv(
            "DB_NAME",
            "financial_doc_verification"
        ),
    )
