import os
from dotenv import load_dotenv, find_dotenv
import logging

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load .env file
env_path = find_dotenv()
if env_path:
    logger.info(f"Loading .env file from: {env_path}")
    load_dotenv(env_path)
else:
    logger.warning("No .env file found. Using system environment variables.")
import secrets
import smtplib
import json
from datetime import datetime, timedelta, UTC
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Groq client will be initialized after environment variables are loaded

from flask import render_template, redirect, url_for, flash, request, session, send_from_directory, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

from app import app, db, csrf
from models import User, Note, UserPreferences, LoginHistory, Bookmark, Rating, Comment, Assignment, Meeting, ProgressReport, AssignmentSubmission
from blockchain_utils import BlockchainUtils


logging.basicConfig(level=logging.INFO)

# Optional Google Drive integration. Uploads should still work locally when this is unavailable.
GOOGLE_DRIVE_ENABLED = False
try:
    from google_drive import get_google_auth_flow, create_drive_folder, upload_file_to_drive
    GOOGLE_DRIVE_ENABLED = True
except Exception as drive_import_error:
    logging.warning(f"Google Drive integration disabled: {drive_import_error}")

    def get_google_auth_flow():
        return None

    def create_drive_folder(folder_name):
        return None

    def upload_file_to_drive(filepath, original_filename, mimetype, folder_id=None):
        return (None, None, None)

EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

if os.environ.get("VERCEL"):
    UPLOAD_FOLDER = "/tmp/uploads"
else:
    UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'xls', 'xlsx', 
    'zip', 'rar', '7z', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    'mp4', 'avi', 'mov', 'wmv', 'mkv', 'mp3', 'wav', 'ogg', 'flac',
    'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'java', 'cpp', 'c'
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Groq client
groq_client = None
# Load API key from environment variables
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

logger.debug(f"Groq API Key found: {'Yes' if GROQ_API_KEY else 'No'}")
if GROQ_API_KEY:
    try:
        logger.debug("Initializing Groq client...")
        # Clean up any proxy environment variables that might interfere
        proxy_vars = ['http_proxy', 'https_proxy', 'no_proxy', 'all_proxy', 
                     'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY']
        
        for proxy_var in proxy_vars:
            if proxy_var in os.environ:
                logger.debug(f"Removing proxy environment variable: {proxy_var}")
                os.environ.pop(proxy_var)
                
        import groq
        logger.debug("Groq module imported successfully")
        
        # Initialize with just the API key
        groq_client = groq.Client(api_key=GROQ_API_KEY)
        logger.debug("Groq client created successfully")
        
        # Test the client with a simple request
        logger.debug("Testing Groq API connection...")
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=5
        )
        logger.info("✅ Groq AI client initialized and tested successfully")
    except ImportError:
        logging.warning("❌ Groq Python client not installed. AI features will be disabled.")
        logging.warning("To enable AI features, install the Groq client: pip install groq")
        groq_client = None
    except Exception as e:
        logging.error(f"❌ Failed to initialize Groq AI client: {str(e)}")
        logging.error("Please check your API key and network connection.")
        groq_client = None
else:
    logging.warning("⚠️  GROQ_API_KEY not found in environment variables. AI features will be disabled.")

with app.app_context():
    import models
    try:
        db.create_all()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Database initialization error: {e}")
        # On Vercel, we might not have write access to the root, 
        # but we should have attempted /tmp/ in app.py or used a remote DB.
        pass


def get_file_type(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext in ['pdf']:
        return 'pdf'
    elif ext in ['doc', 'docx']:
        return 'document'
    elif ext in ['ppt', 'pptx']:
        return 'presentation'
    elif ext in ['xls', 'xlsx', 'csv']:
        return 'spreadsheet'
    elif ext in ['txt', 'py', 'java', 'cpp', 'c', 'js', 'html', 'css', 'json', 'xml']:
        return 'text'
    elif ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov', 'wmv', 'mkv']:
        return 'video'
    elif ext in ['mp3', 'wav', 'ogg', 'flac']:
        return 'audio'
    elif ext in ['zip', 'rar', '7z']:
        return 'archive'
    return 'other'


def send_email(to_email, subject, html_content):
    if not EMAIL_USER or not EMAIL_PASSWORD:
        logging.warning(f"Email credentials not configured - Email would be sent to: {to_email}")
        logging.warning(f"Subject: {subject}")
        # In development mode, just log and return True
        return True  # Changed from False to True for dev mode
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"College Notes Portal <{EMAIL_USER}>"
        msg['To'] = to_email
        msg.attach(MIMEText(html_content, 'html'))
        
        # Use a timeout of 10 seconds for SMTP connection
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as server:
            server.set_debuglevel(0) # Set to 1 for detailed SMTP logs if needed
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logging.error(f"Critical Email Error: {e}")
        return False


def send_otp_email(email, otp_code, username):
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #f8f9fa; border-radius: 10px; border: 1px solid #e0e0e0;">
        <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="color: #4361ee; margin: 0;">College Notes Portal</h2>
            <p style="color: #6c757d; font-size: 14px;">Secure Verification Code</p>
        </div>
        <p>Hello <strong>{username}</strong>,</p>
        <p>To access your account, please enter the following One-Time Password (OTP):</p>
        <div style="background: white; padding: 25px; text-align: center; border-radius: 12px; margin: 25px 0; border: 2px solid #4361ee;">
            <h1 style="color: #4361ee; letter-spacing: 10px; font-size: 48px; margin: 0;">{otp_code}</h1>
        </div>
        <p style="color: #6c757d; font-size: 13px; text-align: center;">This code is valid for <strong>10 minutes</strong>. If you did not request this code, please ignore this email.</p>
        <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #adb5bd; font-size: 11px; text-align: center;">This is an automated message, please do not reply.</p>
    </div>
    """
    
    # If no email credentials, log the OTP for development
    if not EMAIL_USER or not EMAIL_PASSWORD:
        logging.info(f"=" * 80)
        logging.info(f"{'  DEVELOPMENT MODE - OTP CODE  ':^80}")
        logging.info(f"=" * 80)
        logging.info(f"  Email: {email}")
        logging.info(f"  Username: {username}")
        logging.info(f"  OTP CODE: {otp_code}")
        logging.info(f"=" * 80)
        print(f"\n\n{'='*80}")
        print(f"{'  🔐 DEVELOPMENT MODE - OTP CODE  ':^80}")
        print(f"{'='*80}")
        print(f"  📧 Email: {email}")
        print(f"  👤 Username: {username}")
        print(f"  🔢 OTP CODE: {otp_code}")
        print(f"{'='*80}\n\n")
        # Return True and the OTP code for dev mode display
        return (True, otp_code)
    
    # In production, send email and return success status without OTP
    success = send_email(email, f'College Notes Portal - {otp_code} is your verification code', html)
    return (success, None)



def send_reset_email(email, reset_link, username):
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #f8f9fa; border-radius: 10px; border: 1px solid #e0e0e0;">
        <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="color: #4361ee; margin: 0;">College Notes Portal</h2>
            <p style="color: #6c757d; font-size: 14px;">Password Reset Request</p>
        </div>
        <p>Hello <strong>{username}</strong>,</p>
        <p>You recently requested to reset your password for your College Notes Portal account. Click the button below to proceed:</p>
        <div style="text-align: center; margin: 35px 0;">
            <a href="{reset_link}" style="background-color: #4361ee; color: white; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block; box-shadow: 0 4px 6px rgba(67, 97, 238, 0.2);">Reset Password</a>
        </div>
        <p style="font-size: 14px; color: #6c757d;">This link will expire in <strong>1 hour</strong>.</p>
        <p style="font-size: 13px; color: #6c757d;">If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
        <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #adb5bd;">
            <p>If the button above doesn't work, copy and paste the following link into your browser:</p>
            <p style="word-break: break-all;">{reset_link}</p>
        </div>
    </div>
    """
    
    # If no email credentials, log the reset link for development
    if not EMAIL_USER or not EMAIL_PASSWORD:
        logging.info(f"=" * 80)
        logging.info(f"{'  DEVELOPMENT MODE - PASSWORD RESET LINK  ':^80}")
        logging.info(f"=" * 80)
        logging.info(f"  Email: {email}")
        logging.info(f"  Username: {username}")
        logging.info(f"  Reset Link: {reset_link}")
        logging.info(f"=" * 80)
        print(f"\n\n{'='*80}")
        print(f"{'  🔓 DEVELOPMENT MODE - PASSWORD RESET LINK  ':^80}")
        print(f"{'='*80}")
        print(f"  📧 Email: {email}")
        print(f"  👤 Username: {username}")
        print(f"  🔗 Reset Link: {reset_link}")
        print(f"{'='*80}\n\n")
        # Flash the reset link to the user's browser session
        from flask import flash
        flash(f'Development Mode - Password reset link: {reset_link}', 'info')
        return True
    
    return send_email(email, 'College Notes Portal - Password Reset Request', html)


def generate_otp():
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])


def generate_reset_token():
    return secrets.token_urlsafe(32)


def is_otp_valid(user):
    if not user.otp_created_at:
        return False
    return datetime.now(UTC).replace(tzinfo=None) < user.otp_created_at + timedelta(minutes=5)


def is_reset_token_valid(user):
    if not user.reset_token_created_at:
        return False
    return datetime.now(UTC).replace(tzinfo=None) < user.reset_token_created_at + timedelta(hours=1)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_filesize(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


@app.template_filter('filesize')
def filesize_filter(size):
    return format_filesize(size) if size else "Unknown"


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in.', 'warning')
                return redirect(url_for('login'))
            if current_user.role != role:
                flash('Not authorized.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', '')
        
        if role not in ['student', 'professor']:
            flash('Invalid role.', 'danger')
            return render_template('register.html')
        
        enrollment_number = None
        if role == 'student':
            enrollment_number = request.form.get('enrollment_number', '').strip().upper()
            if not enrollment_number:
                flash('Enrollment number required for students.', 'danger')
                return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if not full_name:
            flash('Full Name is required.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
            
        if not email:
            flash('Email is required.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
            
        if not password:
            flash('Password is required.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
            
        if not confirm_password:
            flash('Please confirm your password.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if User.query.filter((User.username == full_name) | (User.email == email)).first():
            flash('Name or email already exists.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if enrollment_number and User.query.filter_by(enrollment_number=enrollment_number).first():
            flash('Enrollment number already registered.', 'danger')
            return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        new_user = User(username=full_name, enrollment_number=enrollment_number, email=email, role=role, auth_method='password')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', google_enabled=bool(GOOGLE_CLIENT_ID))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        password = request.form.get('password', '')
        login_method = request.form.get('login_method', 'password')
        
        if not login_id:
            flash('Enter email or enrollment number.', 'danger')
            return render_template('login.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        user = User.query.filter_by(email=login_id.lower()).first() if '@' in login_id else User.query.filter_by(enrollment_number=login_id.upper()).first()
        
        if not user:
            flash('Account not found.', 'danger')
            return render_template('login.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if login_method == 'otp':
            otp_code = generate_otp()
            user.otp_code = otp_code
            user.otp_created_at = datetime.now(UTC)
            user.otp_attempts = 0
            db.session.commit()
            
            success, dev_otp = send_otp_email(user.email, otp_code, user.username)
            if success:
                session['otp_user_id'] = user.id
                if dev_otp:  # Development mode - show OTP
                    flash(f'DEV MODE - Your OTP: {dev_otp}', 'info')
                else:  # Production mode - email sent
                    flash(f'OTP sent to {user.email[:3]}***', 'success')
                return redirect(url_for('verify_otp'))
            flash('Could not send OTP.', 'warning')
            return render_template('login.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if not password:
            flash('Enter password.', 'danger')
            return render_template('login.html', google_enabled=bool(GOOGLE_CLIENT_ID))
        
        if user.check_password(password):
            log_login(user.id, success=True)
            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid password.', 'danger')
    
    return render_template('login.html', google_enabled=bool(GOOGLE_CLIENT_ID))


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if 'otp_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['otp_user_id'])
    if not user:
        session.pop('otp_user_id', None)
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        
        if user.otp_attempts >= 3:
            user.otp_code = None
            db.session.commit()
            session.pop('otp_user_id', None)
            flash('Too many attempts.', 'danger')
            return redirect(url_for('login'))
        
        if not is_otp_valid(user):
            session.pop('otp_user_id', None)
            flash('OTP expired.', 'danger')
            return redirect(url_for('login'))
        
        if user.otp_code == otp_input:
            user.otp_code = None
            db.session.commit()
            session.pop('otp_user_id', None)
            log_login(user.id, success=True)
            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        user.otp_attempts += 1
        db.session.commit()
        flash(f'Invalid OTP. {3 - user.otp_attempts} attempts left.', 'danger')
    
    return render_template('verify_otp.html')


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'otp_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['otp_user_id'])
    if user:
        otp_code = generate_otp()
        user.otp_code = otp_code
        user.otp_created_at = datetime.now(UTC)
        user.otp_attempts = 0
        db.session.commit()
        success, dev_otp = send_otp_email(user.email, otp_code, user.username)
        if success:
            if dev_otp:  # Development mode
                flash(f'DEV MODE - New OTP: {dev_otp}', 'info')
            else:  # Production mode
                flash('New OTP sent!', 'success')
    
    return redirect(url_for('verify_otp'))







def validate_password_strength(password):
    """
    Validate password strength
    Requirements: min 8 chars, uppercase, lowercase, number, special char
    """
    if len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
    
    return has_upper and has_lower and has_digit and has_special


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    user = User.query.filter_by(reset_token=token).first()
    if not user or not is_reset_token_valid(user):
        flash('Invalid or expired link.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        if len(password) < 6 or password != confirm:
            flash('Password error.', 'danger')
            return render_template('reset_password.html', token=token)
        
        user.set_password(password)
        user.reset_token = None
        db.session.commit()
        flash('Password reset!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


# ========== FORGOT PASSWORD API ROUTES ==========

@app.route('/forgot-password')
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('forgot_password.html')


@app.route('/forgot-password-otp')
def forgot_password_otp():
    """Render the OTP-based forgot password page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('forgot_password_otp.html')





@app.route('/api/forgot-password/send-otp', methods=['POST'])
@csrf.exempt
def api_send_forgot_password_otp():
    """Send OTP for password reset"""
    data = request.get_json()
    login_id = data.get('login_id', '').strip()
    
    if not login_id:
        return jsonify({'success': False, 'error': 'Email or enrollment number required'}), 400
    
    # Find user by email or enrollment number
    user = None
    if '@' in login_id:
        user = User.query.filter_by(email=login_id.lower()).first()
    else:
        user = User.query.filter_by(enrollment_number=login_id.upper()).first()
    
    if not user:
        return jsonify({'success': False, 'error': 'Account not found'}), 404
    
    # Generate OTP
    otp_code = generate_otp()
    user.otp_code = otp_code
    user.otp_created_at = datetime.now(UTC)
    user.otp_attempts = 0
    db.session.commit()
    
    # Send OTP email
    success, dev_otp = send_otp_email(user.email, otp_code, user.username)
    
    if success:
        # Mask email for security
        email_parts = user.email.split('@')
        masked_email = f"{email_parts[0][:2]}***@{email_parts[1]}"
        
        response_data = {
            'success': True,
            'masked_email': masked_email
        }
        
        # Include OTP in response for development mode
        if dev_otp:
            response_data['dev_otp'] = dev_otp
        
        return jsonify(response_data)
    else:
        return jsonify({'success': False, 'error': 'Failed to send verification code'}), 500


@app.route('/api/forgot-password/verify-otp', methods=['POST'])
@csrf.exempt
def api_verify_forgot_password_otp():
    """Verify OTP for password reset"""
    data = request.get_json()
    otp = data.get('otp', '').strip()
    
    if not otp or len(otp) != 6:
        return jsonify({'success': False, 'error': 'Invalid OTP format'}), 400
    
    # Get user from session (set during send-otp)
    # For security, we'll find the user with this OTP
    user = User.query.filter_by(otp_code=otp).first()
    
    if not user:
        return jsonify({'success': False, 'error': 'Invalid verification code'}), 400
    
    # Check if OTP is expired
    if not is_otp_valid(user):
        user.otp_code = None
        db.session.commit()
        return jsonify({'success': False, 'error': 'Code expired. Please request a new one'}), 400
    
    # Check attempts
    if user.otp_attempts >= 5:
        user.otp_code = None
        db.session.commit()
        return jsonify({'success': False, 'error': 'Too many attempts. Please request a new code'}), 400
    
    # Verify OTP
    if user.otp_code == otp:
        # Mark OTP as verified but don't clear it yet (needed for password reset)
        session['reset_user_id'] = user.id
        session['otp_verified'] = True
        return jsonify({'success': True})
    else:
        user.otp_attempts += 1
        db.session.commit()
        remaining = 5 - user.otp_attempts
        return jsonify({
            'success': False, 
            'error': f'Invalid code. {remaining} attempts remaining'
        }), 400


@app.route('/api/forgot-password/reset', methods=['POST'])
@csrf.exempt
def api_reset_password_with_otp():
    """Reset password after OTP verification"""
    # Check if OTP was verified
    if not session.get('otp_verified') or not session.get('reset_user_id'):
        return jsonify({'success': False, 'error': 'Unauthorized. Please verify OTP first'}), 401
    
    data = request.get_json()
    password = data.get('password', '')
    
    if not password or len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    user = User.query.get(session['reset_user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    # Update password
    user.set_password(password)
    user.otp_code = None
    user.otp_attempts = 0
    user.password_changed_at = datetime.now(UTC)
    db.session.commit()
    
    # Clear session
    session.pop('reset_user_id', None)
    session.pop('otp_verified', None)
    
    logging.info(f"Password reset successful for user: {user.username}")
    
    return jsonify({'success': True, 'message': 'Password reset successfully'})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('home'))


# ========== GOOGLE OAUTH ROUTES ==========

@app.route('/auth/google')
def google_login():
    """Initiate Google OAuth login"""
    if not GOOGLE_CLIENT_ID:
        flash('Google login is not configured. Please use email login.', 'warning')
        return redirect(url_for('login'))
    
    # Google OAuth authorization URL
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    redirect_uri = url_for('google_callback', _external=True)
    
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'select_account'
    }
    
    auth_url = f"{google_auth_url}?" + "&".join([f"{k}={v}" for k, v in params.items()])
    return redirect(auth_url)


@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    import urllib.request
    import urllib.parse
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google login is not configured.', 'danger')
        return redirect(url_for('login'))
    
    code = request.args.get('code')
    
    error = request.args.get('error')
    
    if error:
        flash(f'Google login failed: {error}', 'danger')
        return redirect(url_for('login'))
    
    if not code:
        flash('No authorization code received.', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Exchange code for token
        token_url = "https://oauth2.googleapis.com/token"
        redirect_uri = url_for('google_callback', _external=True)
        
        token_data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        token_req = urllib.request.Request(
            token_url,
            data=urllib.parse.urlencode(token_data).encode('utf-8'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        with urllib.request.urlopen(token_req) as response:
            token_response = json.loads(response.read().decode('utf-8'))
        
        access_token = token_response.get('access_token')
        
        # Get user info from Google
        userinfo_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        with urllib.request.urlopen(userinfo_url) as response:
            userinfo = json.loads(response.read().decode('utf-8'))
        
        google_id = userinfo.get('id')
        email = userinfo.get('email')
        name = userinfo.get('name', email.split('@')[0])
        picture = userinfo.get('picture')
        
        # Check if user exists by Google ID
        user = User.query.filter_by(google_id=google_id).first()
        
        if not user:
            # Check if user exists by email
            user = User.query.filter_by(email=email).first()
            
            if user:
                # Link Google account to existing user
                user.google_id = google_id
                user.profile_picture_url = picture
                user.auth_method = 'google'
            else:
                # Create new user
                user = User(
                    username=name,
                    email=email,
                    google_id=google_id,
                    profile_picture_url=picture,
                    role='student',
                    auth_method='google',
                    email_verified=True
                )
                db.session.add(user)
        else:
            # Update profile picture if changed
            if picture and user.profile_picture_url != picture:
                user.profile_picture_url = picture
        
        db.session.commit()
        
        # Log the login
        log_login(user.id, success=True)
        
        login_user(user)
        flash(f'Welcome, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logging.error(f"Google OAuth error: {e}")
        flash('Google login failed. Please try again or use email login.', 'danger')
        return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    upcoming_meetings = Meeting.query.filter(Meeting.is_active == True, Meeting.start_time >= datetime.now(UTC).replace(tzinfo=None)).order_by(Meeting.start_time.asc()).limit(3).all()
    if current_user.role == 'professor':
        my_notes = Note.query.filter_by(uploaded_by=current_user.id).order_by(Note.upload_time.desc()).limit(5).all()
        total_notes = Note.query.filter_by(uploaded_by=current_user.id).count()
        recent_reports = ProgressReport.query.filter_by(professor_id=current_user.id).order_by(ProgressReport.created_at.desc()).limit(3).all()
        return render_template('dashboard_professor.html', 
                             username=current_user.username, 
                             profile_picture=current_user.profile_picture_url, 
                             my_notes=my_notes, 
                             total_notes=total_notes, 
                             upcoming_meetings=upcoming_meetings,
                             recent_reports=recent_reports)
    
    recent_notes = Note.query.order_by(Note.upload_time.desc()).limit(5).all()
    total_notes = Note.query.count()
    total_assignments = Assignment.query.count()
    
    # Calculate Student Progress
    completed_assignments = AssignmentSubmission.query.filter_by(student_id=current_user.id).count()
    progress_percent = (completed_assignments / total_assignments * 100) if total_assignments > 0 else 0
    
    # Latest Progress Reports
    latest_reports = ProgressReport.query.filter_by(student_id=current_user.id).order_by(ProgressReport.created_at.desc()).limit(3).all()
    
    return render_template('dashboard_student.html', 
                         username=current_user.username, 
                         profile_picture=current_user.profile_picture_url, 
                         recent_notes=recent_notes, 
                         total_notes=total_notes, 
                         total_assignments=total_assignments, 
                         completed_assignments=completed_assignments,
                         progress_percent=int(progress_percent),
                         latest_reports=latest_reports,
                         upcoming_meetings=upcoming_meetings)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required('professor')
def upload_note():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        subject = request.form.get('subject', '').strip()
        semester = request.form.get('semester', '').strip()
        description = request.form.get('description', '').strip()
        department = request.form.get('department', '').strip()

        # Check for Firebase URL upload first
        
        if 'file' not in request.files or not request.files['file'].filename:
            flash('No file selected.', 'danger')
            return render_template('upload.html')
        
        if not title:
            flash('Title required.', 'danger')
            return render_template('upload.html')
        
        file = request.files['file']
        if file and allowed_file(file.filename):
            original_filename = file.filename
            filename = secure_filename(file.filename)
            unique_filename = datetime.now(UTC).strftime('%Y%m%d_%H%M%S_') + filename
            filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
            try:
                # Save locally first
                file.save(filepath)
                file_size = os.path.getsize(filepath)
                
                # Check for Google Drive Storage
                drive_web_link = None
                drive_file_id = None
                
                if GOOGLE_DRIVE_ENABLED:
                    try:
                        # We now use a central service account for all uploads
                        # This ensures reliability without requiring user-specific OAuth
                        logging.info("Uploading to Google Drive...")
                        # Use user's enrollment/username as folder
                        user_folder_name = f"{current_user.username}_{current_user.enrollment_number or 'no_id'}"
                        # Create/Get user folder (optional optimization: cache folder ID in User model)
                        user_folder_id = create_drive_folder(user_folder_name)
                        
                        drive_id, web_link, content_link = upload_file_to_drive(
                            filepath, 
                            original_filename, 
                            file.mimetype,
                            folder_id=user_folder_id
                        )
                        
                        if drive_id:
                            drive_file_id = drive_id
                            drive_web_link = web_link
                            flash('Note uploaded to local server AND Google Drive!', 'success')
                        else:
                            flash('Note uploaded locally, but Google Drive upload failed.', 'warning')
                    except Exception as drive_error:
                        logging.warning(f"Google Drive upload skipped: {drive_error}")
                        flash('Note uploaded locally, but Google Drive upload failed.', 'warning')
                else:
                    flash('Note uploaded successfully.', 'success')


                # Blockchain Verification
                logging.info("Generating blockchain hash...")
                with open(filepath, 'rb') as f:
                    file_hash = BlockchainUtils.calculate_file_hash(f)
                
                # Get last block for chaining (optional)
                last_note = Note.query.order_by(Note.upload_time.desc()).first()
                previous_hash = last_note.block_hash if last_note and last_note.block_hash else "0" * 64
                
                block_hash = BlockchainUtils.generate_block(
                    index=Note.query.count() + 1,
                    previous_hash=previous_hash,
                    timestamp=datetime.now(UTC).timestamp(),
                    data={'file_hash': file_hash, 'title': title}
                )

                new_note = Note(
                    title=title, subject=subject, semester=semester,
                    filename=unique_filename, original_filename=original_filename,
                    file_type=get_file_type(original_filename),
                    uploaded_by=current_user.id, file_size=file_size,
                    description=description,
                    
                    # Store drive link
                    google_drive_file_id=drive_file_id,
                    google_drive_web_link=drive_web_link,
                    
                    # Blockchain fields
                    file_hash=file_hash,
                    block_hash=block_hash,
                    previous_hash=previous_hash,
                    is_verified=True
                )
                
                if department:
                    new_note.subject = f"{department} - {subject}" if subject else department

                db.session.add(new_note)
                db.session.commit()
                return redirect(url_for('list_notes'))
                
            except Exception as e:
                logging.error(f"Upload error: {e}")
                flash('An error occurred during upload.', 'danger')
                return render_template('upload.html')
        
        flash('Invalid file type.', 'danger')
    
    return render_template('upload.html')


@app.route('/notes')
@login_required
def list_notes():
    search = request.args.get('search', '').strip()
    subject = request.args.get('subject', '').strip()
    semester = request.args.get('semester', '').strip()
    file_type = request.args.get('file_type', '').strip()
    view_mode = request.args.get('view', 'grid')
    sort_by = request.args.get('sort', 'date_desc')
    
    query = Note.query
    if subject:
        query = query.filter(Note.subject.ilike(f'%{subject}%'))
    if semester:
        query = query.filter(Note.semester.ilike(f'%{semester}%'))
    if file_type:
        query = query.filter(Note.file_type == file_type)
    if search:
        query = query.filter((Note.title.ilike(f'%{search}%')) | (Note.subject.ilike(f'%{search}%')))
    
    if sort_by == 'date_asc':
        query = query.order_by(Note.upload_time.asc())
    elif sort_by == 'name_asc':
        query = query.order_by(Note.title.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Note.title.desc())
    elif sort_by == 'size_desc':
        query = query.order_by(Note.file_size.desc())
    elif sort_by == 'popular':
        query = query.order_by(Note.view_count.desc())
    else:
        query = query.order_by(Note.upload_time.desc())
    
    page = request.args.get('page', 1, type=int)
    per_page = 12
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    notes = pagination.items
    
    subjects = [s[0] for s in db.session.query(Note.subject).distinct().filter(Note.subject != None, Note.subject != '').all()]
    semesters = [s[0] for s in db.session.query(Note.semester).distinct().filter(Note.semester != None, Note.semester != '').all()]
    file_types = [f[0] for f in db.session.query(Note.file_type).distinct().filter(Note.file_type != None).all()]
    
    return render_template('notes.html', notes=notes, pagination=pagination, subjects=subjects, semesters=semesters, file_types=file_types,
                         search_query=search, current_subject=subject, current_semester=semester, 
                         current_file_type=file_type, view_mode=view_mode, sort_by=sort_by)


@app.route('/note/<int:note_id>')
@login_required
def note_detail(note_id):
    return render_template('note_detail.html', note=Note.query.get_or_404(note_id))


@app.route('/note/<int:note_id>/view')
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    note.view_count = (note.view_count or 0) + 1
    db.session.commit()
    return render_template('viewer.html', note=note)


@app.route('/note/<int:note_id>/verify')
@login_required
def verify_note_integrity(note_id):
    note = Note.query.get_or_404(note_id)
    if not note.file_hash:
        flash('This note does not have a blockchain hash.', 'warning')
        return redirect(url_for('note_detail', note_id=note.id))
    
    filepath = os.path.join(UPLOAD_FOLDER, note.filename)
    if not os.path.exists(filepath):
        flash('File not found on server.', 'danger')
        return redirect(url_for('note_detail', note_id=note.id))
        
    with open(filepath, 'rb') as f:
        current_hash = BlockchainUtils.calculate_file_hash(f)
        
    if current_hash == note.file_hash:
        flash('Integrity Verified! The file matches its blockchain record.', 'success')
        note.is_verified = True
    else:
        flash('WARNING: File integrity check failed! The file may have been tampered with.', 'danger')
        note.is_verified = False
        
    db.session.commit()
    return redirect(url_for('note_detail', note_id=note.id))


@app.route('/download/<int:note_id>')
@login_required
def download_note(note_id):
    note = Note.query.get_or_404(note_id)
    note.download_count = (note.download_count or 0) + 1
    db.session.commit()
    
    if note.filename.startswith('http') or note.filename.startswith('https'):
        return redirect(note.filename)
    
    return send_from_directory(UPLOAD_FOLDER, note.filename, as_attachment=True, download_name=note.original_filename)


@app.route('/uploads/<path:filename>')
@login_required
def serve_file(filename):
    if filename.startswith('http') or filename.startswith('https'):
        return redirect(filename)
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route('/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.uploaded_by != current_user.id:
        flash('Not authorized.', 'danger')
        return redirect(url_for('list_notes'))
    
    filepath = os.path.join(UPLOAD_FOLDER, note.filename)
    # Only try to delete local files
    if not (note.filename.startswith('http') or note.filename.startswith('https')) and os.path.exists(filepath):
        try:
            os.remove(filepath)
        except OSError:
            pass # Ignore if file not found or permission error
    db.session.delete(note)
    db.session.commit()
    flash('Note deleted.', 'success')
    return redirect(url_for('list_notes'))


@app.route('/api/ai/ask', methods=['POST'])
@login_required
@csrf.exempt
def ai_ask():
    if not groq_client:
        return jsonify({'error': 'AI not configured (GROQ_API_KEY missing)'}), 400
    data = request.get_json()
    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a helpful and knowledgeable college study assistant. Keep answers concise and relevant to academic subjects."},
                {"role": "user", "content": data.get('question', '')}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        return jsonify({'answer': response.choices[0].message.content})
    except Exception as e:
        print(f"AI Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/quiz', methods=['POST'])
@login_required
@csrf.exempt
def ai_generate_quiz():
    if not groq_client:
        return jsonify({'error': 'AI not configured'}), 400
    data = request.get_json()
    try:
        topic = data.get('topic', 'General Knowledge')
        num_questions = data.get('num_questions', 5)
        
        prompt = f"""Generate {num_questions} multiple choice questions about "{topic}".
        Return ONLY a JSON object with this structure:
        {{
            "questions": [
                {{
                    "question": "Question text here",
                    "options": ["Option A", "Option B", "Option C", "Option D"],
                    "correct": 0  // Index of correct option (0-3)
                }}
            ]
        }}
        """
        
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a quiz generator. You output valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        return jsonify(json.loads(response.choices[0].message.content))
    except Exception as e:
        print(f"Quiz Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/flashcards', methods=['POST'])
@login_required
@csrf.exempt
def ai_flashcards():
    if not groq_client:
        return jsonify({'error': 'AI not configured'}), 400
    data = request.get_json()
    try:
        topic = data.get('topic', 'General Knowledge')
        
        prompt = f"""Generate 10 study flashcards for the topic: "{topic}".
        Return ONLY a JSON object with this structure:
        {{
            "flashcards": [
                {{ "front": "Concept/Question", "back": "Definition/Answer" }}
            ]
        }}
        Keep answers concise."""
        
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a flashcard generator. You output valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        return jsonify(json.loads(response.choices[0].message.content))
    except Exception as e:
        print(f"Flashcard Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/mcq', methods=['POST'])
@login_required
@csrf.exempt
def ai_mcq():
    if not groq_client:
        return jsonify({'error': 'AI not configured'}), 400
    data = request.get_json()
    try:
        topic = data.get('topic', 'General Knowledge')
        difficulty = data.get('difficulty', 'Medium')
        
        prompt = f"""Generate a high-quality multiple choice question about "{topic}" at {difficulty} level.
        Include a detailed explanation for why the correct answer is right and why others are wrong.
        Return ONLY a JSON object with this structure:
        {{
            "question": "Question text here",
            "options": ["Option A", "Option B", "Option C", "Option D"],
            "correct": 0,  // Index of correct option (0-3)
            "explanation": "Detailed explanation here"
        }}
        """
        
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a specialized MCQ generator. You provide challenging questions and comprehensive explanations."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        return jsonify(json.loads(response.choices[0].message.content))
    except Exception as e:
        print(f"MCQ Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/ai-assistant')
@login_required
def ai_assistant():
    subjects = [s[0] for s in db.session.query(Note.subject).distinct().filter(Note.subject != None, Note.subject != '').all()]
    return render_template('ai_assistant.html', subjects=subjects)



# ========== SETTINGS ROUTES ==========

def get_device_info(user_agent_string):
    """Parse user agent to get device info"""
    ua = user_agent_string.lower() if user_agent_string else ''
    device_type = 'desktop'
    browser = 'Unknown'
    
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        device_type = 'mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        device_type = 'tablet'
    
    if 'chrome' in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua:
        browser = 'Safari'
    elif 'edge' in ua:
        browser = 'Edge'
    elif 'opera' in ua:
        browser = 'Opera'
    
    return device_type, browser


def log_login(user_id, success=True):
    """Log login attempt"""
    device_type, browser = get_device_info(request.headers.get('User-Agent'))
    login_record = LoginHistory(
        user_id=user_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        device_type=device_type,
        browser=browser,
        success=success
    )
    db.session.add(login_record)
    db.session.commit()


@app.route('/settings')
@login_required
def settings():
    prefs = current_user.get_preferences()
    login_history = LoginHistory.query.filter_by(user_id=current_user.id).order_by(LoginHistory.login_time.desc()).limit(10).all()
    bookmarks = Bookmark.query.filter_by(user_id=current_user.id).all()
    subjects = [s[0] for s in db.session.query(Note.subject).distinct().filter(Note.subject != None, Note.subject != '').all()]
    
    return render_template('settings.html', 
                         user=current_user, 
                         prefs=prefs, 
                         login_history=login_history,
                         bookmarks=bookmarks,
                         subjects=subjects)


@app.route('/settings/account', methods=['POST'])
@login_required
def update_account_settings():
    username = request.form.get('username', '').strip()
    bio = request.form.get('bio', '').strip()
    phone = request.form.get('phone', '').strip()
    
    if username and username != current_user.username:
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash('Username already taken.', 'danger')
            return redirect(url_for('settings'))
        current_user.username = username
    
    current_user.bio = bio
    current_user.phone = phone
    
    # Handle profile picture upload
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"profile_{current_user.id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{filename}"
            filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
            file.save(filepath)
            current_user.profile_picture_url = url_for('serve_file', filename=unique_filename)
    
    db.session.commit()
    flash('Account settings updated!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('settings'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters.', 'danger')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('settings'))
    
    current_user.set_password(new_password)
    db.session.commit()
    flash('Password updated successfully!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/academic', methods=['POST'])
@login_required
def update_academic_settings():
    current_user.college = request.form.get('college', '').strip()
    current_user.course = request.form.get('course', '').strip()
    current_user.department = request.form.get('department', '').strip()
    current_user.current_semester = request.form.get('semester', '').strip()
    
    db.session.commit()
    flash('Academic settings updated!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/notifications', methods=['POST'])
@login_required
def update_notification_settings():
    prefs = current_user.get_preferences()
    
    # Email notifications
    prefs.email_new_notes = 'email_new_notes' in request.form
    prefs.email_assignments = 'email_assignments' in request.form
    prefs.email_exam_updates = 'email_exam_updates' in request.form
    prefs.email_comments = 'email_comments' in request.form
    
    # In-app notifications
    prefs.inapp_new_notes = 'inapp_new_notes' in request.form
    prefs.inapp_assignments = 'inapp_assignments' in request.form
    prefs.inapp_exam_updates = 'inapp_exam_updates' in request.form
    prefs.inapp_comments = 'inapp_comments' in request.form
    
    # Push notifications
    prefs.push_enabled = 'push_enabled' in request.form
    
    db.session.commit()
    flash('Notification settings updated!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/content', methods=['POST'])
@login_required
def update_content_settings():
    prefs = current_user.get_preferences()
    
    prefs.notes_visibility = request.form.get('notes_visibility', 'class')
    prefs.allow_downloads = 'allow_downloads' in request.form
    prefs.offline_access = 'offline_access' in request.form
    
    db.session.commit()
    flash('Content settings updated!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/privacy', methods=['POST'])
@login_required
def update_privacy_settings():
    prefs = current_user.get_preferences()
    
    session_timeout = request.form.get('session_timeout', '30')
    prefs.session_timeout = int(session_timeout) if session_timeout.isdigit() else 30
    
    current_user.two_factor_enabled = 'two_factor_enabled' in request.form
    
    db.session.commit()
    flash('Privacy settings updated!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/display', methods=['POST'])
@login_required
def update_display_settings():
    prefs = current_user.get_preferences()
    
    prefs.theme = request.form.get('theme', 'system')
    prefs.font_size = request.form.get('font_size', 'medium')
    prefs.language = request.form.get('language', 'en')
    prefs.accessibility_mode = 'accessibility_mode' in request.form
    prefs.high_contrast = 'high_contrast' in request.form
    
    db.session.commit()
    flash('Display settings updated!', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/subjects', methods=['POST'])
@login_required
def update_subject_preferences():
    prefs = current_user.get_preferences()
    subjects = request.form.getlist('subjects')
    prefs.subject_preferences = json.dumps(subjects)
    
    db.session.commit()
    flash('Subject preferences updated!', 'success')
    return redirect(url_for('settings'))


# ========== BOOKMARK ROUTES ==========




@app.route('/api/bookmark/<int:note_id>', methods=['POST'])
@login_required
def toggle_bookmark(note_id):
    note = Note.query.get_or_404(note_id)
    existing = Bookmark.query.filter_by(user_id=current_user.id, note_id=note_id).first()
    
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({'bookmarked': False, 'message': 'Bookmark removed'})
    else:
        bookmark = Bookmark(user_id=current_user.id, note_id=note_id)
        db.session.add(bookmark)
        db.session.commit()
        return jsonify({'bookmarked': True, 'message': 'Note bookmarked'})


@app.route('/api/bookmark/check/<int:note_id>')
@login_required
def check_bookmark(note_id):
    existing = Bookmark.query.filter_by(user_id=current_user.id, note_id=note_id).first()
    return jsonify({'bookmarked': existing is not None})


# ========== RATING ROUTES ==========

@app.route('/api/rate/<int:note_id>', methods=['POST'])
@login_required
def rate_note(note_id):
    note = Note.query.get_or_404(note_id)
    data = request.get_json()
    rating_value = data.get('rating', 5)
    
    if rating_value < 1 or rating_value > 5:
        return jsonify({'error': 'Rating must be 1-5'}), 400
    
    existing = Rating.query.filter_by(user_id=current_user.id, note_id=note_id).first()
    
    if existing:
        existing.rating = rating_value
    else:
        rating = Rating(user_id=current_user.id, note_id=note_id, rating=rating_value)
        db.session.add(rating)
    
    db.session.commit()
    return jsonify({
        'success': True, 
        'average': note.get_average_rating(),
        'count': note.get_rating_count()
    })


@app.route('/api/rating/<int:note_id>')
@login_required
def get_rating(note_id):
    note = Note.query.get_or_404(note_id)
    user_rating = Rating.query.filter_by(user_id=current_user.id, note_id=note_id).first()
    
    return jsonify({
        'average': note.get_average_rating(),
        'count': note.get_rating_count(),
        'user_rating': user_rating.rating if user_rating else 0
    })


# ========== COMMENT ROUTES ==========

@app.route('/api/comments/<int:note_id>')
@login_required
def get_comments(note_id):
    comments = Comment.query.filter_by(note_id=note_id, parent_id=None).order_by(Comment.created_at.desc()).all()
    
    result = []
    for comment in comments:
        result.append({
            'id': comment.id,
            'content': comment.content,
            'user': comment.user.username,
            'user_picture': comment.user.profile_picture_url,
            'created_at': comment.created_at.strftime('%b %d, %Y %H:%M'),
            'replies': [{
                'id': r.id,
                'content': r.content,
                'user': r.user.username,
                'user_picture': r.user.profile_picture_url,
                'created_at': r.created_at.strftime('%b %d, %Y %H:%M')
            } for r in comment.replies]
        })
    
    return jsonify(result)


@app.route('/api/comments/<int:note_id>', methods=['POST'])
@login_required
def add_comment(note_id):
    note = Note.query.get_or_404(note_id)
    data = request.get_json()
    content = data.get('content', '').strip()
    parent_id = data.get('parent_id')
    
    if not content:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    comment = Comment(
        user_id=current_user.id,
        note_id=note_id,
        content=content,
        parent_id=parent_id
    )
    db.session.add(comment)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'comment': {
            'id': comment.id,
            'content': comment.content,
            'user': current_user.username,
            'user_picture': current_user.profile_picture_url,
            'created_at': comment.created_at.strftime('%b %d, %Y %H:%M')
        }
    })


@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    if comment.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Not authorized'}), 403
    
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'success': True})



# ========== ASSIGNMENT ROUTES ==========

@app.route('/assignments')
@login_required
def list_assignments():
    assignments = Assignment.query.order_by(Assignment.deadline.asc()).all()
    return render_template('assignments.html', assignments=assignments, now=datetime.now(UTC).replace(tzinfo=None))


@app.route('/assignments/create', methods=['GET', 'POST'])
@login_required
@role_required('professor')
def create_assignment():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        subject = request.form.get('subject', '').strip()
        semester = request.form.get('semester', '').strip()
        deadline_str = request.form.get('deadline', '')
        
        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid deadline format.', 'danger')
                return render_template('create_assignment.html')
        
        if not title:
            flash('Title required.', 'danger')
            return render_template('create_assignment.html')
            
        assignment = Assignment(
            title=title, description=description, subject=subject,
            semester=semester, deadline=deadline, created_by=current_user.id
        )
        db.session.add(assignment)
        db.session.commit()
        flash('Assignment created successfully!', 'success')
        return redirect(url_for('list_assignments'))
        
    return render_template('create_assignment.html')


@app.route('/assignments/delete/<int:assignment_id>', methods=['POST'])
@login_required
@role_required('professor')
def delete_assignment(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    
    # Check checks if the current user created the assignment
    if assignment.created_by != current_user.id and current_user.role != 'admin':
        flash('Not authorized to delete this assignment.', 'danger')
        return redirect(url_for('list_assignments'))
    
    # Manually delete related submissions first to avoid Foreign Key errors
    try:
        AssignmentSubmission.query.filter_by(assignment_id=assignment.id).delete()
        db.session.delete(assignment)
        db.session.commit()
        flash('Assignment deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting assignment: {str(e)}', 'danger')
        
    return redirect(url_for('list_assignments'))



@app.route('/assignments/submit/<int:assignment_id>', methods=['GET', 'POST'])
@login_required
@role_required('student')
def submit_assignment(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    existing_submission = AssignmentSubmission.query.filter_by(assignment_id=assignment_id, student_id=current_user.id).first()
    
    if request.method == 'POST':
        submission_text = request.form.get('submission_text', '').strip()
        file = request.files.get('file')
        
        unique_name = existing_submission.filename if existing_submission else None
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_name = datetime.now(UTC).strftime('%Y%m%d_%H%M%S_') + filename
            filepath = os.path.join(UPLOAD_FOLDER, unique_name)
            file.save(filepath)
            
        if existing_submission:
            existing_submission.submission_text = submission_text
            existing_submission.filename = unique_name
            existing_submission.submitted_at = datetime.now(UTC)
        else:
            submission = AssignmentSubmission(
                assignment_id=assignment_id,
                student_id=current_user.id,
                submission_text=submission_text,
                filename=unique_name
            )
            db.session.add(submission)
            
        db.session.commit()
        flash('Assignment submitted successfully!', 'success')
        return redirect(url_for('list_assignments'))
        
    return render_template('submit_assignment.html', assignment=assignment, submission=existing_submission)


# ========== MEETING ROUTES ==========

@app.route('/meetings')
@login_required
def list_meetings():
    meetings = Meeting.query.filter_by(is_active=True).order_by(Meeting.start_time.asc()).all()
    return render_template('meetings.html', meetings=meetings, now=datetime.now(UTC).replace(tzinfo=None))


@app.route('/meetings/create', methods=['GET', 'POST'])
@login_required
@role_required('professor')
def create_meeting():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        subject = request.form.get('subject', '').strip()
        semester = request.form.get('semester', '').strip()
        start_time_str = request.form.get('start_time', '')
        meeting_link = request.form.get('meeting_link', '').strip()
        
        start_time = None
        if start_time_str:
            try:
                start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid date format.', 'danger')
                return render_template('create_meeting.html')
        
        if not title or not start_time:
            flash('Title and start time required.', 'danger')
            return render_template('create_meeting.html')
            
        # If no link provided, create a Jitsi link
        if not meeting_link:
            import secrets
            room_name = f"CNP_{secrets.token_hex(4)}"
            meeting_link = f"https://meet.jit.si/{room_name}"
            
        meeting = Meeting(
            title=title, description=description, subject=subject,
            semester=semester, start_time=start_time, meeting_link=meeting_link,
            host_id=current_user.id
        )
        db.session.add(meeting)
        db.session.commit()
        flash('Meeting scheduled successfully!', 'success')
        return redirect(url_for('list_meetings'))
        
    return render_template('create_meeting.html')


# ========== PROGRESS REPORT ROUTES ==========

@app.route('/students')
@login_required
@role_required('professor')
def list_students():
    """List all students for professors to view and manage"""
    search = request.args.get('search', '').strip()
    
    query = User.query.filter_by(role='student')
    
    if search:
        query = query.filter((User.username.ilike(f'%{search}%')) | (User.email.ilike(f'%{search}%')) | (User.enrollment_number.ilike(f'%{search}%')))
        
    students = query.order_by(User.username.asc()).all()
    return render_template('students_list.html', students=students, search=search)

@app.route('/progress')
@login_required
def list_progress():
    if current_user.role == 'professor':
        # Professors see reports they uploaded
        query = ProgressReport.query.filter_by(professor_id=current_user.id)
        
        # Filter by student if provided
        student_id = request.args.get('student_id')
        if student_id:
            query = query.filter_by(student_id=student_id)
            
        reports = query.order_by(ProgressReport.created_at.desc()).all()
    else:
        # Students see their own reports
        reports = ProgressReport.query.filter_by(student_id=current_user.id).order_by(ProgressReport.created_at.desc()).all()
    return render_template('progress_list.html', reports=reports)


@app.route('/progress/upload', methods=['GET', 'POST'])
@login_required
@role_required('professor')
def upload_progress():
    students = User.query.filter_by(role='student').order_by(User.username).all()
    selected_student_id = request.args.get('student_id')
    
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        semester = request.form.get('semester', '').strip()
        
        if not student_id or not title:
            flash('Student and title are required.', 'danger')
            return render_template('upload_progress.html', students=students, selected_student_id=selected_student_id)
            
        file = request.files.get('file')
        unique_name = None
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_name = datetime.now(UTC).strftime('%Y%m%d_%H%M%S_') + filename
            filepath = os.path.join(UPLOAD_FOLDER, unique_name)
            file.save(filepath)
            
        report = ProgressReport(
            student_id=int(student_id),
            professor_id=current_user.id,
            title=title,
            description=description,
            filename=unique_name,
            semester=semester
        )
        db.session.add(report)
        db.session.commit()
        
        flash('Progress report uploaded successfully!', 'success')
        return redirect(url_for('list_progress'))
        
    return render_template('upload_progress.html', students=students, selected_student_id=selected_student_id)


@app.route('/progress/view/<int:report_id>')
@login_required
def view_progress_file(report_id):
    report = ProgressReport.query.get_or_404(report_id)
    # Check permission
    if current_user.role != 'professor' and report.student_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
        
    if not report.filename:
        flash('No file associated with this report.', 'warning')
        return redirect(url_for('list_progress'))
        
    return send_from_directory(UPLOAD_FOLDER, report.filename)


# ========== ADMIN ROUTES ==========

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    total_users = User.query.count()
    total_students = User.query.filter_by(role='student').count()
    total_teachers = User.query.filter_by(role='professor').count()
    total_notes = Note.query.count()
    total_downloads = db.session.query(db.func.sum(Note.download_count)).scalar() or 0
    total_views = db.session.query(db.func.sum(Note.view_count)).scalar() or 0
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_notes = Note.query.order_by(Note.upload_time.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_students=total_students,
                         total_teachers=total_teachers,
                         total_notes=total_notes,
                         total_downloads=total_downloads,
                         total_views=total_views,
                         recent_users=recent_users,
                         recent_notes=recent_notes)


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
def change_user_role(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    new_role = data.get('role')
    
    if new_role not in ['student', 'professor', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400
    
    user.role = new_role
    db.session.commit()
    return jsonify({'success': True, 'new_role': new_role})




@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_title="Page Not Found", 
                         error_description="The page you are looking for might have been removed, had its name changed, or is temporarily unavailable."), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error_code=403, error_title="Access Forbidden", 
                         error_description="You don't have permission to access this resource."), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_title="Server Error", 
                         error_description="Something went wrong on our end. Please try again later."), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
