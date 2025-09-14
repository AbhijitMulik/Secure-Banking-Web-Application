import os
import mysql.connector
from dotenv import load_dotenv
from pathlib import Path

# Load .env file
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

# Establish connection
try:
    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
    if connection.is_connected():
        print("✅ Database connection successful!")
except mysql.connector.Error as e:
    print(f"❌ Error: {e}")
