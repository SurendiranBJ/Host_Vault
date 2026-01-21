# Secure Cloud File Manager

A secure cloud-based file management system built using Flask and MinIO that allows authenticated users to upload, download, and manage files with strict access control.

This project demonstrates secure authentication, scalable object storage, and efficient file handling using modern backend technologies.

---

## Table of Contents
- Overview
- Features
- System Architecture
- Tech Stack
- Project Structure
- Installation & Setup
- How It Works
- Security Measures
- Screens
- Future Enhancements
- Author
- License

---

## Overview

The Secure Cloud File Manager is a web application that enables users to store and manage files securely on the cloud.  
Instead of saving files on the local server, the system uses **MinIO**, an S3-compatible object storage service, making the application scalable and production-ready.

Each user has isolated access to their files, ensuring privacy and security.

---

## Features

- User registration and login
- Secure password hashing
- Session-based authentication
- File upload with progress indicator
- File download with access control
- File deletion
- User-specific file isolation
- MinIO (S3-compatible) object storage
- Responsive and modern dashboard UI

---

## System Architecture

1. User authenticates using email and password  
2. Flask handles requests and session management  
3. File metadata is stored in the database  
4. Actual files are stored in MinIO object storage  
5. Users can only access their own files  

---

## Tech Stack

**Backend**
- Flask
- SQLAlchemy ORM

**Database**
- PostgreSQL / SQLite

**Storage**
- MinIO (S3-compatible object storage)

**Frontend**
- HTML
- Jinja2 Templates
- CSS
- JavaScript

**Security**
- Werkzeug password hashing
- Secure sessions
- Access control

---

## Project Structure
project/
│
├── app.py # Main Flask application and routes
├── config.py # Application configuration
├── models.py # Database models
│
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── dashboard.html
│ └── profile.html
│
├── static/
│ ├── style.css
│ └── dashboard.css
│
└── README.md
