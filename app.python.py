import os
from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from sqlalchemy import Enum as SQLAlchemyEnum
from enum import Enum as PythonEnum
from functools import wraps
from werkzeug.utils import secure_filename
from flask import request, jsonify, send_from_directory




# Initialize Flask app and database
app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#app.config['MAX_CONTENT_LENGTH'] = 300 * 1024 * 1024  # 300 MB limit
# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'zip', 'exe'}

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# Session secret key for Flask sessions
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')

db_username = os.getenv('DB_USERNAME', 'root')
db_password = os.getenv('DB_PASSWORD', 'Cerufixime250.')
db_name = os.getenv('DB_NAME', 'xuremi_db')
db_host = os.getenv('DB_HOST', 'localhost')
db_port = os.getenv('DB_PORT', '3306')

# Configure MySQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define user roles
class Role(PythonEnum):
    USER = 'user'
    ADMIN = 'admin'
    SUPER_ADMIN = 'super_admin'

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(SQLAlchemyEnum(Role), default=Role.USER, nullable=False)
    can_add_admin = db.Column(db.Boolean, default=False)


UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    file_url = db.Column(db.String(255), nullable=False)
    credit_score = db.Column(db.Integer, nullable=False)  # Add this line
# Test database connection route
@app.route('/test_db', methods=['GET'])
def test_db():
    try:
        db.session.query(User).first()
        return jsonify({"message": "Database connection is working!"}), 200
    except Exception as e:
        return jsonify({"message": "Database connection failed.", "error": str(e)}), 500

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data['email']
    password = data['password']
    hashed_password = generate_password_hash(password)
    user_count = User.query.count()

    # First user becomes SUPER_ADMIN, others are users
    if user_count == 0:
        role = Role.SUPER_ADMIN
        can_add_admin = True
    else:
        role = Role.USER
        can_add_admin = False

    new_user = User(name=data['name'], email=email, password=hashed_password, role=role, can_add_admin=can_add_admin)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

# Signin route
@app.route('/signin', methods=['POST'])
def signin():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    # Store user details in session
    session['user_id'] = user.id
    session['role'] = user.role.value

    # Redirect based on role
    if user.role == Role.SUPER_ADMIN or user.role == Role.ADMIN:
        return jsonify({"message": "Login successful", "redirect": "admindash.html"}), 200
    else:
        return jsonify({"message": "Login successful", "redirect": "About.html"}), 200

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logout successful"}), 200

# Get logged-in user from session
def get_logged_in_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return User.query.get(user_id)

# Decorator to protect admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_in_user()
        if user is None or user.role not in [Role.ADMIN, Role.SUPER_ADMIN]:
            return jsonify({"message": "Admins only!"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Decorator to protect super admin routes
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_in_user()
        if user is None or user.role != Role.SUPER_ADMIN:
            return jsonify({"message": "Super Admins only!"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Route to grant admin access (only for super admins)
@app.route('/grant-admin', methods=['POST'])
@super_admin_required
def grant_admin():
    data = request.json
    email = data.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    user.role = Role.ADMIN
    db.session.commit()

    return jsonify({"message": f"User {email} is now an admin"}), 200

# Admin page route (accessible only to admins and super admins)
@app.route('/admin')
@admin_required
def admin_page():
    return redirect('adminupload.html')





# Run the Flask app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database tables
    app.run(debug=True)    