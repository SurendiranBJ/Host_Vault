# config.py

class Config:
    SECRET_KEY = 'your-secret-key'  # Replace with a strong, random secret key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Set the max upload size to 2 Gigabytes
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024
    MINIO_ENDPOINT = '127.0.0.1:9000'
    MINIO_ACCESS_KEY = 'minioadmin'
    MINIO_SECRET_KEY = 'StrongPass123!'
    MINIO_SECURE = False  # Set to True if you are using HTTPS