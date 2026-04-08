import os
import socket
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from minio import Minio

# ---------------------- SETUP ----------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ---------------------- MINIO CONFIG ----------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


minio_host_ip = os.environ.get('MINIO_ENDPOINT_IP') or get_local_ip()
app.config['MINIO_ENDPOINT'] = f'{minio_host_ip}:9000'
app.config['MINIO_ACCESS_KEY'] = 'minioadmin'
app.config['MINIO_SECRET_KEY'] = 'StrongPassword123!'
app.config['MINIO_SECURE'] = False

minio_client = Minio(
    app.config['MINIO_ENDPOINT'],
    access_key=app.config['MINIO_ACCESS_KEY'],
    secret_key=app.config['MINIO_SECRET_KEY'],
    secure=app.config['MINIO_SECURE']
)


# ---------------------- MODELS ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# ---------------------- HELPERS ----------------------
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'mp3', 'mp4', 'zip', 'mkv','ppt','pptx','exe','html'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# ---------------------- ROUTES ----------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'warning')
        else:
            new_user = User(email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    files = File.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', files=files)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ---------------------- UPLOAD ----------------------
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file selected.', 'warning')
        return '', 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        flash('File type not allowed.', 'danger')
        return '', 400

    bucket_name = "user-files"
    try:
        if not minio_client.bucket_exists(bucket_name):
            minio_client.make_bucket(bucket_name)

        # File size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size == 0:
            flash("Cannot upload empty file.", 'danger')
            return '', 400

        minio_client.put_object(bucket_name, filename, file, length=file_size, part_size=10 * 1024 * 1024)

        new_file = File(filename=filename, size=file_size, user_id=session['user_id'])
        db.session.add(new_file)
        db.session.commit()

        return '', 200  # success for JS toast

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Upload failed: {e}")
        return '', 500


# ---------------------- DOWNLOAD ----------------------
@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()
        bucket_name = "user-files"
        obj_stat = minio_client.stat_object(bucket_name, file_record.filename)
        response = minio_client.get_object(bucket_name, file_record.filename)

        def generate():
            for chunk in response.stream(1024 * 1024):
                yield chunk
            response.close()
            response.release_conn()

        return Response(
            generate(),
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename="{file_record.filename}"',
                'Content-Length': str(obj_stat.size)
            }
        )

    except Exception as e:
        app.logger.error(f"Download failed: {e}")
        flash("Download failed.", "danger")
        return redirect(url_for('dashboard'))


# ---------------------- DELETE ----------------------
@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()
        bucket_name = "user-files"
        minio_client.remove_object(bucket_name, file_record.filename)
        db.session.delete(file_record)
        db.session.commit()
        flash(f'File "{file_record.filename}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete failed: {e}")
        flash("Delete failed.", "danger")

    return redirect(url_for('dashboard'))


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8001, debug=True)

