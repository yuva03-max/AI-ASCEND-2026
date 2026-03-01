from datetime import datetime, UTC
from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    enrollment_number = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    # Profile fields
    bio = db.Column(db.Text, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    phone_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    # Google Drive Integration - Removed user specific credentials as we use service account
    # google_drive_credentials = db.Column(db.Text, nullable=True) 
    # google_drive_folder_id = db.Column(db.String(100), nullable=True)


    password_changed_at = db.Column(db.DateTime, nullable=True)
    
    # Academic fields
    college = db.Column(db.String(200), nullable=True)
    course = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    current_semester = db.Column(db.String(50), nullable=True)
    
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    profile_picture_url = db.Column(db.String(500), nullable=True)
    auth_method = db.Column(db.String(20), default='password')
    
    otp_code = db.Column(db.String(6), nullable=True)
    otp_created_at = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0)
    
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_created_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    notes = db.relationship('Note', backref='uploader', lazy=True)
    preferences = db.relationship('UserPreferences', backref='user', uselist=False, lazy=True)
    login_history = db.relationship('LoginHistory', backref='user', lazy=True)
    bookmarks = db.relationship('Bookmark', backref='user', lazy=True)
    ratings = db.relationship('Rating', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    
    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def get_preferences(self):
        if not self.preferences:
            prefs = UserPreferences(user_id=self.id)
            db.session.add(prefs)
            db.session.commit()
        return self.preferences


class UserPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    
    # Display Settings
    theme = db.Column(db.String(20), default='system')  # light, dark, system
    font_size = db.Column(db.String(20), default='medium')  # small, medium, large
    language = db.Column(db.String(10), default='en')
    accessibility_mode = db.Column(db.Boolean, default=False)
    high_contrast = db.Column(db.Boolean, default=False)
    
    # Notification Settings
    email_new_notes = db.Column(db.Boolean, default=True)
    email_assignments = db.Column(db.Boolean, default=True)
    email_exam_updates = db.Column(db.Boolean, default=True)
    email_comments = db.Column(db.Boolean, default=True)
    inapp_new_notes = db.Column(db.Boolean, default=True)
    inapp_assignments = db.Column(db.Boolean, default=True)
    inapp_exam_updates = db.Column(db.Boolean, default=True)
    inapp_comments = db.Column(db.Boolean, default=True)
    push_enabled = db.Column(db.Boolean, default=False)
    
    # Content Settings
    notes_visibility = db.Column(db.String(20), default='class')  # public, class
    allow_downloads = db.Column(db.Boolean, default=True)
    offline_access = db.Column(db.Boolean, default=True)
    
    # Privacy Settings
    session_timeout = db.Column(db.Integer, default=30)  # minutes
    
    # Subject Preferences (stored as JSON string)
    subject_preferences = db.Column(db.Text, default='[]')
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    device_type = db.Column(db.String(50), nullable=True)  # desktop, mobile, tablet
    browser = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(200), nullable=True)
    login_time = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    success = db.Column(db.Boolean, default=True)
    session_active = db.Column(db.Boolean, default=True)


class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    note = db.relationship('Note', backref='bookmarks')
    
    __table_args__ = (db.UniqueConstraint('user_id', 'note_id', name='unique_user_bookmark'),)


class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    note = db.relationship('Note', backref='ratings')
    
    __table_args__ = (db.UniqueConstraint('user_id', 'note_id', name='unique_user_rating'),)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    
    note = db.relationship('Note', backref='comments')
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=True)
    semester = db.Column(db.String(50), nullable=True)
    deadline = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    creator = db.relationship('User', backref='assignments')


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(100))
    semester = db.Column(db.String(50))
    filename = db.Column(db.Text, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_time = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    file_size = db.Column(db.BigInteger)
    description = db.Column(db.Text)
    view_count = db.Column(db.Integer, default=0)
    download_count = db.Column(db.Integer, default=0)
    visibility = db.Column(db.String(20), default='public')  # public, class
    allow_download = db.Column(db.Boolean, default=True)
    
    # Google Drive Link
    google_drive_file_id = db.Column(db.String(100), nullable=True)
    google_drive_web_link = db.Column(db.Text, nullable=True)

    
    # Blockchain Verification Fields
    file_hash = db.Column(db.String(64), nullable=True)
    block_index = db.Column(db.Integer, nullable=True)
    previous_hash = db.Column(db.String(64), nullable=True)
    block_hash = db.Column(db.String(64), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    def get_average_rating(self):
        if not self.ratings:
            return 0
        return sum(r.rating for r in self.ratings) / len(self.ratings)
    
    def get_rating_count(self):
        return len(self.ratings) if self.ratings else 0


class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=True)
    semester = db.Column(db.String(50), nullable=True)
    start_time = db.Column(db.DateTime, nullable=False)
    meeting_link = db.Column(db.Text, nullable=True)  # External link or Jitsi room name
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    host = db.relationship('User', backref='hosted_meetings')


class ProgressReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.Text, nullable=True)  # File path for the report
    semester = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    student = db.relationship('User', foreign_keys=[student_id], backref='my_progress_reports')
    professor = db.relationship('User', foreign_keys=[professor_id], backref='uploaded_progress_reports')


class AssignmentSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submission_text = db.Column(db.Text, nullable=True)
    filename = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='submitted') # submitted, graded, late
    grade = db.Column(db.String(10), nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    
    assignment = db.relationship('Assignment', backref='submissions')
    student = db.relationship('User', backref='assignment_submissions')
