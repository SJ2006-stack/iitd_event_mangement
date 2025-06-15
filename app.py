# --- START OF FILE app.py ---

from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify, flash ,Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
import json
import smtplib
import random
import os
import ssl
from dotenv import load_dotenv
from sqlalchemy import text # Keep if you have raw SQL, otherwise optional
import hashlib # For token generation, though uuid is better for uniqueness
import uuid # For truly unique tokens
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
from functools import wraps
import io
import csv


# Place this in the "Helper Functions" section of app.py

load_dotenv()

# --- Configuration ---
# It's good practice to make UPLOAD_FOLDER relative to the app's root
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure the upload folder exists

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "a_very_strong_default_secret_key_that_should_be_changed") # CHANGE THIS
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SSL context for database if needed (depends on your DBaaS provider)
if os.getenv("DB_SSL_REQUIRED", "false").lower() == "true":
    ssl_context = ssl.create_default_context()
    # Potentially load CA certs if required by your DB provider
    # ssl_context.load_verify_locations(cafile='/path/to/ca.pem')
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "connect_args": {
            "ssl_context": ssl_context
        }
    }

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Models ---
class Registration(db.Model):
    entryno = db.Column(db.String(11), primary_key=True) # Increased length for flexibility
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False) # Store hashed passwords
    hostel = db.Column(db.String(30), nullable=True)
    role = db.Column(db.String(255), nullable=False)  # JSON string of roles
    department = db.Column(db.String(100))
    photo = db.Column(db.String(255)) # Path to photo
    interest = db.Column(db.String(500)) # JSON string of interests
    entryyear=db.Column(db.Integer,nullable=False)
    exityear=db.Column(db.Integer,nullable=False)
    currentyear=db.Column(db.Integer,nullable=True)
    course=db.Column(db.String(30), nullable=True)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    otp_token = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)

class CalendarShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(11), db.ForeignKey('registration.entryno'), nullable=False)
    share_token = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    registration = db.relationship('Registration', backref=db.backref('calendar_shares', lazy=True))

class ClubProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # This must match the 'organization' name exactly and should be unique.
    organization_name = db.Column(db.String(100), unique=True, nullable=False)
    logo_path = db.Column(db.String(255), nullable=True) # Path to the club's logo
    description = db.Column(db.Text, nullable=True)
    # Flexible field for social media links, contact email, etc.
    contact_info_json = db.Column(db.Text, nullable=True) 

    def __repr__(self):
        return f'<ClubProfile {self.organization_name}>'

class EventAuthorization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False) # Should match a Registration email
    name = db.Column(db.String(100), nullable=False) # Name of the authorized person
    role = db.Column(db.String(50), nullable=False)  # 'club_head', 'fest_head', 'department_head', 'admin'
    organization = db.Column(db.String(100), nullable=False)  # Club name, Fest name, or Department name
    event_type = db.Column(db.String(50), nullable=False) # e.g., 'club', 'fest', 'department_activity'
    authorized_by = db.Column(db.String(120), nullable=True)  # Email of authorizer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class events(db.Model): # Represents all types of events/activities
    id = db.Column(db.Integer, primary_key=True) # Auto-incrementing ID is generally better
    name = db.Column(db.String(100), nullable=False, unique=True) # Event/Activity Name, ensure uniqueness
    event_manager = db.Column(db.String(100), nullable=False) # Name of the person creating/managing
    organiser = db.Column(db.String(100), nullable=False) # Club, Fest, or Department Name
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(20), nullable=True) # Store as YYYY-MM-DD
    venue = db.Column(db.String(150), nullable=True)
    starttime = db.Column(db.String(10), nullable=True) # Store as HH:MM
    endtime = db.Column(db.String(10), nullable=True)   # Store as HH:MM
    photo = db.Column(db.String(255), nullable=True) # Path to photo
    link = db.Column(db.String(255), nullable=True)  # Registration or info link
    tags = db.Column(db.String(300), nullable=True)  # Comma-separated
    event_type = db.Column(db.String(50), nullable=False) # 'fest', 'club', 'department_activity'
    category = db.Column(db.String(50), nullable=True) # e.g., 'Workshop', 'Seminar', 'RDV', 'Tryst', 'Cultural', 'Technical'
    target_departments = db.Column(db.String(1500), nullable=True)  # JSON or comma-separated
    target_years = db.Column(db.String(100), nullable=True)  # JSON or comma-separated integers
    target_hostels= db.Column(db.String(500), nullable=True)
    is_private = db.Column(db.Boolean, default=False, nullable=False)

class students_events(db.Model): # Tracks student registrations for events/activities
    srno = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(100), db.ForeignKey('events.name'), nullable=False) # Changed to event_name
    entryno = db.Column(db.String(11), db.ForeignKey('registration.entryno'), nullable=False)
    feedback = db.Column(db.Integer, nullable=True) # 0 for no feedback, 1-5 for rating
    event = db.relationship('events', backref=db.backref('registrations', lazy='dynamic'))
    student = db.relationship('Registration', backref=db.backref('event_registrations', lazy='dynamic'))

class course_events(db.Model): # Academic schedule items
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True) # e.g., "CSL303 Midsem"
    course = db.Column(db.String(50), nullable=False) # e.g., "CSL303"
    description = db.Column(db.Text, nullable=False)
    day = db.Column(db.String(20), nullable=True) # YYYY-MM-DD
    venue = db.Column(db.String(100), nullable=True)
    starttime = db.Column(db.String(10), nullable=True) # HH:MM
    target_group = db.Column(db.String(20), nullable=False, default='All') # e.g., 1, 2, or All

class StudentCourseSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_entryno = db.Column(db.String(11), db.ForeignKey('registration.entryno'), nullable=False)
    course_code = db.Column(db.String(20), nullable=False) # e.g., CSL303
    course_group = db.Column(db.String(20), nullable=False, default='All') # e.g., 1, 2, or All
    
    # Add relationships for easier querying
    student = db.relationship('Registration', backref=db.backref('course_subscriptions', lazy='dynamic'))
    
    # Ensure a student can only subscribe to a course once
    __table_args__ = (db.UniqueConstraint('student_entryno', 'course_code', name='_student_course_uc'),)

class CourseCoordinatorAuthorization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coordinator_email = db.Column(db.String(120), db.ForeignKey('registration.email'), nullable=False)
    course_code = db.Column(db.String(20), nullable=False)
    # --- ADD THIS NEW COLUMN ---
    groups_json = db.Column(db.Text, nullable=True) # e.g., '["1", "2", "3", "4"]' or '["A1", "B2"]'
    
    coordinator = db.relationship('Registration', backref=db.backref('managed_courses', lazy='dynamic'))
    __table_args__ = (db.UniqueConstraint('coordinator_email', 'course_code', name='_coordinator_course_uc'),)

class CustomFormField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Foreign key to link this question to a specific event
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    question_text = db.Column(db.String(300), nullable=False)
    # 'text', 'textarea', 'radio', 'checkbox'
    question_type = db.Column(db.String(50), nullable=False)
    # For radio/checkbox, stores a JSON list of options: e.g., '["Small", "Medium", "Large"]'
    options_json = db.Column(db.Text, nullable=True)
    is_required = db.Column(db.Boolean, default=False, nullable=False)
    # To maintain the order of questions in the form
    order = db.Column(db.Integer, nullable=False)

    # This relationship makes it easy to get all questions for an event
    event = db.relationship('events', backref=db.backref('custom_form_fields', lazy='dynamic', cascade="all, delete-orphan"))

class CustomFormResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Foreign key to link this answer to a specific registration instance
    registration_id = db.Column(db.Integer, db.ForeignKey('students_events.srno'), nullable=False)
    # Foreign key to link this answer to a specific question
    field_id = db.Column(db.Integer, db.ForeignKey('custom_form_field.id'), nullable=False)
    # The actual answer provided by the student
    response_text = db.Column(db.Text, nullable=False)
    
    # Relationships for easier querying
    registration = db.relationship('students_events', backref=db.backref('custom_responses', lazy='dynamic', cascade="all, delete-orphan"))
    field = db.relationship('CustomFormField', backref=db.backref('responses', lazy='dynamic'))

# --- Helper Functions ---

@app.context_processor
def utility_processor():
    def from_json(json_string):
        if not json_string:
            return []
        try:
            return json.loads(json_string)
        except (json.JSONDecodeError, TypeError):
            return []
    return dict(from_json=from_json)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('kars_registration_or_login'))
        
        user = Registration.query.get(session['user_id'])
        if not user:
            flash("User not found.", "error")
            session.clear()
            return redirect(url_for('kars_registration_or_login'))

        user_roles = json_to_list(user.role)
        if 'admin' not in user_roles:
            flash("You do not have permission to access the admin panel.", "error")
            return redirect(url_for('kars_student')) # Or wherever you want non-admins to go
            
        return f(*args, **kwargs)
    return decorated_function

def get_recommendations(user, all_events, registered_events, count=5):
    """
    Generates event recommendations for a user.

    Args:
        user (Registration): The user object for whom to generate recommendations.
        all_events (list): A list of all event objects in the system.
        registered_events (list): A list of event objects the user is already registered for.
        count (int): The number of recommendations to return.

    Returns:
        list: A list of recommended event objects.
    """
    if not all_events:
        return []

    # --- Step 1: Build a "User Profile" based on their interests and rated events ---
    user_profile_tags = set(json_to_list(user.interest))
    
    # Get events the user has attended and rated
    rated_event_registrations = students_events.query.filter(
        students_events.entryno == user.entryno,
        students_events.feedback.isnot(None),
        students_events.feedback > 0  # Assuming feedback is a 1-10 rating
    ).all()

    # Add tags from rated events, weighted by the rating
    for reg in rated_event_registrations:
        event = reg.event
        if event and event.tags:
            tags = [tag.strip() for tag in event.tags.split(',')]
            # Add tags multiple times for higher rated events to give them more weight
            # A rating of 6/10 adds tags twice, 8/10 three times, etc.
            weight = int(reg.feedback / 3) 
            for _ in range(weight):
                user_profile_tags.update(tags)

    if not user_profile_tags:
        # If user has no interests or rated events, we can't recommend.
        # Fallback: could return most popular or most recent events.
        # For now, we return nothing.
        return []

    user_profile_str = " ".join(list(user_profile_tags))

    # --- Step 2: Create a Feature Matrix of all available events ---
    
    # Filter out events the user is already registered for
    registered_event_names = {e.name for e in registered_events}
    available_events = [e for e in all_events if e.name not in registered_event_names]

    if not available_events:
        return []
    
    # Use event tags as the content for TF-IDF
    event_tags_corpus = [event.tags.replace(",", " ") if event.tags else "" for event in available_events]
    
    # Include the user profile at the top of the corpus to compare against
    corpus = [user_profile_str] + event_tags_corpus

    # --- Step 3: Calculate Similarity ---
    try:
        tfidf = TfidfVectorizer(stop_words='english')
        tfidf_matrix = tfidf.fit_transform(corpus)
        
        # Calculate cosine similarity between the user profile (first item) and all events
        cosine_sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])
    except ValueError:
        # This can happen if the corpus is empty after stopword removal.
        return []

    # --- Step 4: Rank and Return Top Recommendations ---
    
    # Get similarity scores for each event
    sim_scores = list(enumerate(cosine_sim[0]))
    
    # Sort events based on similarity scores in descending order
    sim_scores = sorted(sim_scores, key=lambda x: x[1], reverse=True)
    
    # Get the indices of the top 'count' most similar events
    top_event_indices = [i[0] for i in sim_scores[:count]]
    
    # Return the event objects corresponding to those indices
    recommended_events = [available_events[i] for i in top_event_indices]
    
    return recommended_events

def json_to_list(json_str):
    if not json_str or json_str == "null":
        return []
    try:
        data = json.loads(json_str)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        # Fallback for old format if necessary, but ideally data is stored as valid JSON
        # print(f"Warning: Could not parse JSON: {json_str}. Trying legacy split.")
        # result = json_str[1:-1].split(",")
        # result = [item.strip()[1:-1] for item in result if item.strip()]
        return []

def get_all_user_authorizations(email, expected_role_prefix):
    return EventAuthorization.query.filter(
        EventAuthorization.email == email,
        EventAuthorization.role.startswith(expected_role_prefix),
        EventAuthorization.is_active == True
    ).all()

def get_user_authorization(user_email, expected_role_prefix, organisation):
    return EventAuthorization.query.filter(
        EventAuthorization.email == user_email,
        EventAuthorization.role.startswith(expected_role_prefix),
        EventAuthorization.organization==organisation,
        EventAuthorization.is_active == True
    ).first()

def send_otp_email(receiver_email, otp_code):
    my_email = os.getenv("email")
    app_pass = os.getenv("app_pass")
    if not my_email or not app_pass:
        print("Email credentials not configured. Skipping OTP email.")
        return False
    subject = "OTP for KARS Registration"
    message = f"Your OTP for KARS registration is: {otp_code}"
    text = f"Subject: {subject}\n\n{message}"
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(my_email, app_pass)
        server.sendmail(my_email, receiver_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        return False

def to_entryno(username):
    return "20"+username[3:5]+username[:3].upper()+username[5:]

def find_department(entryno):
    departmentID=entryno[4:7]
    department_codes = {
        "AM1": "Applied Mechanics",
        "BB1": "Biochemical Engineering and Biotechnology",
        "BB5": "Biochemical Engineering and Biotechnology (Dual/M.Tech)",
        "CH1": "Chemical Engineering",
        "CH5": "Chemical Engineering (Dual/M.Tech)",
        "CY1": "Chemistry",
        "CE1": "Civil Engineering",
        "CE5": "Civil Engineering (Dual/M.Tech)",
        "CS1": "Computer Science and Engineering",
        "CS5": "Computer Science and Engineering (Dual/M.Tech)",
        "DS1": "Design",
        "EE1": "Electrical Engineering",
        "EE3": "Electrical Engineering (M.Tech)",
        "EE5": "Electrical Engineering (Dual Degree)",
        "EN1": "Energy Science and Engineering",
        "EN5": "Energy Science and Engineering (Dual/M.Tech)",
        "HS1": "Humanities and Social Sciences",
        "MS1": "Management Studies",
        "MT1": "Materials Science and Engineering",
        "MT5": "Materials Science and Engineering (Dual/M.Tech)",
        "MA1": "Mathematics",
        "ME1": "Mechanical Engineering",
        "ME5": "Mechanical Engineering (Dual/M.Tech)",
        "PH1": "Physics",
        "TT1": "Textile and Fibre Engineering",
        "TT5": "Textile and Fibre Engineering (Dual/M.Tech)"
    }
    return department_codes.get(departmentID)

def cousre_duration(course):
    """
    Returns the course duration in years based on course type.

    Returns:
        int: Duration of the course in years (returns 0 if unknown)
    """

    # Normalize input
    course = course.strip().lower()

    # Duration mapping
    duration_by_course = {
        "btech": 4,
        "dual-degree": 5,
        "mtech": 2,
        "msc": 2,
        "mba": 2,
        "ma": 2,
        "mdes": 2,
        "phd": 5  # varies, but assume 5
    }

    return duration_by_course.get(course, 0)

def get_organization_stats(org_name, org_event_type, manager_name=None):
    if manager_name: # Stats for events managed by a specific person in that org
        base_query = events.query.filter_by(organiser=org_name, event_type=org_event_type, event_manager=manager_name)
    else: # Stats for all events of that org
        base_query = events.query.filter_by(organiser=org_name, event_type=org_event_type)
    
    all_org_events = base_query.all()
    
    current_time = datetime.now()
    upcoming_count = 0
    total_regs = 0
    
    for event_item in all_org_events:
        if event_item.date and event_item.starttime:
            try:
                event_dt = datetime.strptime(f"{event_item.date} {event_item.starttime}", "%Y-%m-%d %H:%M")
                if event_dt >= current_time:
                    upcoming_count += 1
            except (ValueError, TypeError):
                pass # Skip if date/time is invalid
        total_regs += students_events.query.filter_by(event_name=event_item.name).count()
        
    return {
        "managed_events_count": len(all_org_events), # Or specific managed count if manager_name is used
        "upcoming_events_count": upcoming_count,
        "total_registrations_count": total_regs,
    }

def club_head_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Basic session checks
        if 'user_email' not in session or 'user_organization' not in session:
            flash("You must be logged into a club portal to access this page.", "error")
            return redirect(url_for('kars_registration_or_login'))

        # 2. Query for the specific authorization
        auth = EventAuthorization.query.filter_by(
            email=session['user_email'],
            organization=session['user_organization'],
            role='club_head'  # We are specifically checking for 'club_head'
        ).first()

        # 3. If authorization is not found, deny access
        if not auth:
            flash("You do not have the required permissions (Club Head) to perform this action.", "error")
            return redirect(url_for('club_dashboard')) # Redirect to their normal club dashboard
            
        # 4. If all checks pass, proceed to the route
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/uploads/<path:filename>') # Use path converter for flexibility
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# --- Authentication Routes ---
@app.route('/', methods=['GET', 'POST'])
def kars_registration_or_login():
    """
    Handles both user registration and login from the main landing page.
    - GET: Renders the login/signup page.
    - POST: Differentiates between a login attempt and a registration attempt
      based on the submitted form fields.
    """
    if request.method == 'POST':
        # --- REGISTRATION LOGIC ---
        # A registration form is identified by the presence of 'name' and 'confirm_password' fields.
        if 'name' in request.form and 'confirm_password' in request.form:
            # Step 1: Collect form data and perform initial validation
            email = request.form['email'].lower()
            password = request.form['password']

            if password != request.form['confirm_password']:
                flash("Passwords do not match. Please try again.", "error")
                return redirect(url_for('kars_registration_or_login'))
            
            if not email.endswith("@iitd.ac.in"):
                flash("Only @iitd.ac.in emails are allowed for registration.", "error")
                return redirect(url_for('kars_registration_or_login'))

            # Step 2: Check the database for an existing user with this email
            existing_user = Registration.query.filter_by(email=email).first()

            otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
            otp_expiry_time = datetime.utcnow() + timedelta(minutes=10)  # OTP is valid for 10 minutes

            if existing_user:
                if existing_user.is_verified:
                    # Case A: User is already fully registered.
                    flash("This email is already registered. Please log in.", "info")
                    return redirect(url_for('kars_registration_or_login'))
                else:
                    # Case B: User started registration but didn't verify. Update their record with a new OTP.
                    user_to_update = existing_user
                    user_to_update.password = generate_password_hash(password)
                    user_to_update.otp_token = otp
                    user_to_update.otp_expiry = otp_expiry_time
            else:
                # Case C: This is a brand new registration. Create a new pending user record.
                entryno = to_entryno(email.split('@')[0])
                new_user_data = {
                    'entryno': entryno,
                    'name': request.form['name'],
                    'hostel': request.form['hostel'],
                    'email': email,
                    'password': generate_password_hash(password),
                    'role': json.dumps(['student']),
                    'interest': json.dumps([]),
                    'photo': None,
                    'department': find_department(entryno),
                    'entryyear': int(entryno[:4]),
                    'course': request.form['course'],
                    'exityear': int(entryno[:4]) + cousre_duration(request.form['course']),
                    'is_verified': False,
                    'otp_token': otp,
                    'otp_expiry': otp_expiry_time
                }
                user_to_update = Registration(**new_user_data)
                db.session.add(user_to_update)

            # Step 3: Commit changes to the database and send the OTP email
            try:
                db.session.commit()
                if send_otp_email(email, otp):
                    flash("An OTP has been sent to your email. It is valid for 10 minutes.", "success")
                else:
                    flash("Could not send OTP email, but registration is pending. Check server logs for OTP.", "warning")
                
                # Redirect to the OTP page, passing the email for identification
                return redirect(url_for('verify_otp', email=email))

            except Exception as e:
                db.session.rollback()
                print(f"Database error during registration: {e}")
                flash("A database error occurred during registration. Please try again.", "error")
                return redirect(url_for('kars_registration_or_login'))
        
        # --- LOGIN LOGIC ---
        # If the form does not have a 'name' field, it's a login attempt.
        else:
            email = request.form['email'].lower()
            password = request.form['password']
            login_role_selection = request.form.get('role')

            user = Registration.query.filter_by(email=email).first() 
            # IMPORTANT: Check if user exists, is verified, and password matches
            if user and user.is_verified and check_password_hash(user.password, password):
                session['user_id'] = user.entryno
                session['user_email'] = user.email
                session['user_name'] = user.name
                
                user_roles = json_to_list(user.role)

                # --- Redirection Logic based on selected role ---
                if login_role_selection == "admin" and "admin" in user_roles:
                    return redirect(url_for('admin_dashboard'))

                elif login_role_selection == "student" and "student" in user_roles:
                    return redirect(url_for('kars_student'))
                
                elif login_role_selection == "course-coordinator":
                    is_coordinator = CourseCoordinatorAuthorization.query.filter_by(coordinator_email=user.email).first()
                    if is_coordinator:
                        return redirect(url_for('course_coordinator_dashboard'))
                    else:
                        flash("You are not authorized to access the Course Coordinator portal.", "error")
                        return redirect(url_for('kars_registration_or_login'))
                
                elif login_role_selection in ["fest", "club", "department"]:
                    role_prefix_map = {"fest": "fest_head", "club": "club_head", "department": "department_head"}
                    auth_role_prefix = role_prefix_map.get(login_role_selection)
                    auth_records = get_all_user_authorizations(user.email, auth_role_prefix)
                    
                    if len(auth_records) == 1:
                        auth_record = auth_records[0]
                        session['user_organization'] = auth_record.organization
                        session['auth_role'] = auth_record.role
                        if auth_record.role.startswith("fest_head"): return redirect(url_for('fest_dashboard'))
                        elif auth_record.role.startswith("club_head"): return redirect(url_for('club_dashboard'))
                        elif auth_record.role.startswith("department_head"): return redirect(url_for('department_dashboard'))
                            
                    elif len(auth_records) > 1:
                        session['multi_auth_roles'] = [{'organization': a.organization, 'role': a.role} for a in auth_records]
                        return redirect(url_for('choose_organization'))

                # Fallback: If no specific portal login succeeds, or if no authorization was found for the selected role
                if "student" in user_roles:
                    flash("Could not log you into the selected portal. Redirecting to student dashboard.", "info")
                    return redirect(url_for('kars_student'))
                else:
                    flash("No suitable portal found for your roles, or authorization failed.", "error")
                    return redirect(url_for('kars_registration_or_login'))

            elif user and not user.is_verified:
                 flash("Your account is not verified. Please check your email for the OTP or try signing up again.", "warning")
                 return redirect(url_for('verify_otp', email=user.email))
            else:
                flash("Invalid email or password.", "error")
                return redirect(url_for('kars_registration_or_login'))
                
    # For GET requests, just show the main page
    return render_template('login.html')

@app.route('/choose_organization', methods=['GET', 'POST'])
def choose_organization():
    if 'multi_auth_roles' not in session:
        flash("No roles found in your session. Please log in again.", "error")
        return redirect(url_for('kars_registration_or_login'))

    if request.method == 'POST':
        # This part remains the same
        selected_org = request.form.get('organization')
        selected_role = request.form.get('role')

        if not selected_org or not selected_role:
             flash("Invalid selection. Please try again.", "error")
             return redirect(url_for('choose_organization'))

        # Store the selected role and organization in the session
        session['user_organization'] = selected_org
        session['auth_role'] = selected_role
        
        # Remove the list of multiple roles now that one is chosen
        session.pop('multi_auth_roles', None) 

        # Redirect to the correct dashboard
        if selected_role.startswith("fest_head"):
            return redirect(url_for('fest_dashboard'))
        elif selected_role.startswith("club_head"):
            return redirect(url_for('club_dashboard'))
        elif selected_role.startswith("department_head"):
            return redirect(url_for('department_dashboard'))
        else:
            flash("Invalid role selected.", "error")
            return redirect(url_for('kars_registration_or_login'))
    
    # --- NEW LOGIC FOR GET REQUEST: Group roles by type ---
    roles_by_type = {
        'Fests': [],
        'Clubs': [],
        'Departments': []
    }
    for auth in session.get('multi_auth_roles', []):
        if auth['role'].startswith('fest_head'):
            roles_by_type['Fests'].append(auth)
        elif auth['role'].startswith('club_head'):
            roles_by_type['Clubs'].append(auth)
        elif auth['role'].startswith('department_head'):
            roles_by_type['Departments'].append(auth)
            
    return render_template("choose_organization.html", roles_by_type=roles_by_type)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # The email is passed as a URL parameter to identify the user
    email = request.args.get('email')
    if not email:
        flash("No email specified for verification.", "error")
        return redirect(url_for('kars_registration_or_login'))

    if request.method == 'POST':
        # The form should also submit the email back to us
        submitted_email = request.form.get('email')
        submitted_otp = "".join([request.form.get(f'digit{i+1}', '') for i in range(6)])

        user = Registration.query.filter_by(email=submitted_email).first()

        # Perform all checks
        if not user:
            flash("No pending registration found for this email.", "error")
        elif user.is_verified:
            flash("This account has already been verified. Please log in.", "info")
        elif user.otp_expiry < datetime.utcnow():
            flash("Your OTP has expired. Please try signing up again to receive a new one.", "error")
        elif user.otp_token != submitted_otp:
            flash("The OTP you entered is incorrect. Please try again.", "error")
        else:
            # --- Success! Activate the account. ---
            user.is_verified = True
            user.otp_token = None  # Clear the token
            user.otp_expiry = None # Clear the expiry
            db.session.commit()

            # Log the user in automatically
            session['user_id'] = user.entryno
            session['user_email'] = user.email
            session['user_name'] = user.name
            
            flash("Your account has been successfully verified!", "success")
            return redirect(url_for('kars_student'))
        
        # If any check failed, redirect back to the OTP page to try again
        return redirect(url_for('verify_otp', email=submitted_email))

    # For GET request, just render the page
    return render_template('otp.html', email=email)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('kars_registration_or_login'))

@app.route('/student')
def kars_student():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear() # Clear invalid session
        return redirect(url_for('kars_registration_or_login'))
    
    # --- Part 1: Fetch NON-ACADEMIC (fest, club, etc.) events. (No changes here) ---
    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    all_student_registered_activities = events.query.filter(events.name.in_(registered_event_names)).all()
    
    calendar_events_data = []
    for reg_event in all_student_registered_activities:
        if reg_event.date and reg_event.starttime and reg_event.endtime:
            start_datetime_str = f"{reg_event.date}T{reg_event.starttime}"
            end_datetime_str = f"{reg_event.date}T{reg_event.endtime}"

            calendar_events_data.append({
                'title': reg_event.name,
                'start': start_datetime_str,
                'end': end_datetime_str,
                'description': reg_event.description,
                'location': reg_event.venue,
                'extendedProps': {
                    'organiser': reg_event.organiser,
                    'type': 'General Event' # Differentiate event type
                }
            })

    # --- Part 2: ADD LOGIC to fetch ACADEMIC events ---
    
    # Get all of the student's course subscriptions
    subscriptions = StudentCourseSubscription.query.filter_by(student_entryno=user_id).all()
    if subscriptions:
        # Create a list of course codes the student is subscribed to
        subscribed_course_codes = [sub.course_code for sub in subscriptions]
        
        # Fetch all potentially relevant academic events in one query
        relevant_academic_events = course_events.query.filter(course_events.course.in_(subscribed_course_codes)).all()
        
        # Create a mapping of course_code to the student's group for easy lookup
        student_group_map = {sub.course_code: sub.course_group for sub in subscriptions}

        # Filter the events to match the student's group
        for acad_event in relevant_academic_events:
            student_group = student_group_map.get(acad_event.course)
            
            # The event is relevant if its target group is 'All' OR it matches the student's specific group
            if acad_event.target_group.lower() == 'all' or acad_event.target_group == student_group:
                # Assuming acad_event has day and starttime. A default endtime might be needed.
                if acad_event.day and acad_event.starttime:
                    start_datetime_str = f"{acad_event.day}T{acad_event.starttime}"
                    
                    # You might want to define a default duration for academic events if endtime is not stored
                    end_datetime_str = start_datetime_str # Or calculate end time

                    calendar_events_data.append({
                        'title': f"{acad_event.course}: {acad_event.name}",
                        'start': start_datetime_str,
                        'end': end_datetime_str,
                        'description': acad_event.description,
                        'location': acad_event.venue,
                        'backgroundColor': '#4CAF50', # Give academic events a different color
                        'borderColor': '#388E3C',
                        'extendedProps': {
                            'organiser': f"Course: {acad_event.course}",
                            'type': 'Academic Event'
                        }
                    })

    # --- Part 3: Recommendation and Feedback Logic (No changes here) ---
    feedback_needed_activities = []
    current_time = datetime.now()
    feedback_pending_regs = students_events.query.filter(
        students_events.entryno == user.entryno,
        (students_events.feedback == None) | (students_events.feedback == 0)
    ).all()

    for reg in feedback_pending_regs:
        event_obj = events.query.filter_by(name=reg.event_name).first()
        if event_obj and event_obj.date and event_obj.starttime:
            try:
                event_datetime = datetime.strptime(f"{event_obj.date} {event_obj.starttime}", "%Y-%m-%d %H:%M")
                if event_datetime < current_time:
                    feedback_needed_activities.append(event_obj)
            except (ValueError, TypeError):
                continue
    
    all_events_in_db = events.query.order_by(events.date.desc()).all()
    recommended_events_list = get_recommendations(
        user=user,
        all_events=all_events_in_db,
        registered_events=all_student_registered_activities,
        count=5
    )

    # --- Part 4: Render the template with the combined event data ---
    return render_template('student_portal.html',
                           recommend_events=recommended_events_list,
                           feedback_remaining=feedback_needed_activities,
                           calendar_events=json.dumps(calendar_events_data))

@app.route('/student/profile', methods=['GET', 'POST'])
def kars_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear()
        return redirect(url_for('kars_registration_or_login'))

    if request.method == 'POST':
        user.name = request.form.get('name', user.name) # Allow name update
        user.currentyear = int(request.form.get('currentyear', user.currentyear))
        user.hostel = request.form.get('hostel', user.hostel)
        user.exityear = int(request.form.get('exityear', user.exityear))
        interests_list = request.form.getlist('interests') # Assuming checkboxes or multi-select
        user.interest = json.dumps(interests_list) if interests_list else json.dumps([])
        if 'photo' in request.files:
            photo_file = request.files['photo']
            if photo_file.filename:
                filename = secure_filename(f"{user_id}_{photo_file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    photo_file.save(file_path)
                    user.photo = filename # Store only the filename
                except Exception as e:
                    print(f"Error saving photo: {e}") # Handle error appropriately
        try:
            db.session.commit()
            return redirect(url_for('kars_profile')) # Redirect to refresh
        except Exception as e:
            db.session.rollback()
            print(f"Error updating profile: {e}") # Show error to user
            # Add flash message for error

    current_interests = json_to_list(user.interest)
    # Define all possible interests for the form
    all_possible_interests = ["Coding", "Music", "Sports", "Dance", "Literature", "Gaming", "Art", "Photography"]
    return render_template('profile.html', User=user, current_interests=current_interests, all_possible_interests=all_possible_interests)

@app.route('/student/events_to_join')
def student_events_to_join():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear()
        return redirect(url_for('kars_registration_or_login'))

    # --- 1. Get a set of clubs the user is a "member" of ---
    # We do this once to avoid querying the database inside a loop.
    member_clubs_query = db.session.query(events.organiser).join(
        students_events, events.name == students_events.event_name
    ).filter(students_events.entryno == user.entryno, events.event_type == 'club').distinct()
    
    member_of_clubs = {row.organiser for row in member_clubs_query}

    # --- 2. Get all events the user is NOT already registered for ---
    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    all_upcoming_activities = events.query.filter(
        ~events.name.in_(registered_event_names)
    ).order_by(events.date, events.starttime).all()

    # --- 3. Filter the events based on public/private status and eligibility ---
    available_activities = []
    current_time = datetime.now()

    for activity in all_upcoming_activities:
        # Basic check for date/time validity
        if not (activity.date and activity.starttime):
            continue
        try:
            activity_datetime = datetime.strptime(f"{activity.date} {activity.starttime}", "%Y-%m-%d %H:%M")
            if activity_datetime < current_time:
                continue # Skip past events
        except (ValueError, TypeError):
            continue
            
        # --- 3a. Assume the user is not eligible by default ---
        is_eligible = False

        # --- 3b. Check for private event visibility ---
        if activity.event_type == 'club' and activity.is_private:
            # If it's a private club event, user MUST be a member to see it
            if activity.organiser in member_of_clubs:
                is_eligible = True
        else:
            # If it's a public event (any type), it's potentially visible
            is_eligible = True

        # --- 3c. If potentially eligible, check other filters ---
        if is_eligible:
            try:
                target_depts = json.loads(activity.target_departments or "[]")
                target_yrs = json.loads(activity.target_years or "[]")
                target_hostels = json.loads(activity.target_hostels or "[]")
            except json.JSONDecodeError:
                target_depts, target_yrs, target_hostels = [], [], []

            # Final check of department, year, and hostel
            if (not target_depts or user.department in target_depts) and \
               (not target_yrs or user.currentyear in target_yrs) and \
               (not target_hostels or user.hostel in target_hostels):
                available_activities.append(activity)

    return render_template('event.html', Events=available_activities)

@app.route('/student/register_event/<string:event_name>')
def register_student_for_event(event_name):
    user_id = session.get('user_id')
    if not user_id: return redirect(url_for('kars_registration_or_login'))

    event_exists = events.query.filter_by(name=event_name).first()
    if not event_exists:
        return "Event not found", 404 # Or redirect with flash message

    already_registered = students_events.query.filter_by(entryno=user_id, event_name=event_name).first()
    if already_registered:
        # Add flash message: "You are already registered for this event."
        return redirect(url_for('student_events_to_join'))

    new_registration = students_events(event_name=event_name, entryno=user_id, feedback=None) # None for pending feedback
    try:
        db.session.add(new_registration)
        db.session.commit()
        # Add flash message: "Successfully registered for {event_name}"
    except Exception as e:
        db.session.rollback()
        print(f"Error registering for event: {e}")
        # Add flash message: "Error registering for event."
    return redirect(url_for('student_events_to_join'))

# In app.py, add this new route

@app.route('/student/register/<string:event_name>', methods=['GET', 'POST'])
def register_for_event_page(event_name):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    
    user = db.session.get(Registration, user_id)
    event = events.query.filter_by(name=event_name).first_or_404()

    # Check if the student is already registered
    existing_registration = students_events.query.filter_by(entryno=user_id, event_name=event.name).first()
    if existing_registration:
        flash("You are already registered for this event.", "info")
        return redirect(url_for('student_events_to_join'))
        
    # --- FORM SUBMISSION LOGIC ---
    if request.method == 'POST':
        try:
            # Step 1: Create the main registration record
            new_registration = students_events(
                event_name=event.name,
                entryno=user.entryno,
                feedback=None 
            )
            db.session.add(new_registration)
            # We must commit here to get the new_registration.srno (the primary key)
            db.session.commit() 

            # Step 2: Process and save answers to custom questions
            for field in event.custom_form_fields:
                response_data = request.form.get(f'custom_field_{field.id}')
                if response_data: # Only save if an answer was provided
                    new_response = CustomFormResponse(
                        registration_id=new_registration.srno, # Link to the main registration
                        field_id=field.id, # Link to the question
                        response_text=response_data
                    )
                    db.session.add(new_response)

            # Final commit for all custom responses
            db.session.commit()
            flash(f"You have successfully registered for '{event.name}'!", "success")
            return redirect(url_for('kars_student')) # Redirect to the main dashboard after success

        except Exception as e:
            db.session.rollback()
            print(f"Error during registration submission: {e}")
            flash("An error occurred during registration. Please try again.", "error")
            return redirect(url_for('student_events_to_join'))

    # --- DISPLAY FORM LOGIC (for GET request) ---
    # Fetch the custom form fields for this event, ordered correctly
    custom_fields = event.custom_form_fields.order_by(CustomFormField.order).all()
    
    return render_template('register_for_event.html', event=event, user=user, custom_fields=custom_fields)

@app.route('/student/submit_feedback/<string:event_name>', methods=['POST'])
def submit_event_feedback(event_name):
    user_id = session.get('user_id')
    if not user_id: return redirect(url_for('kars_registration_or_login'))

    feedback_value = request.form.get('feedback_rating') # Assuming 'feedback_rating' from form
    if not feedback_value:
        # Add flash message "Feedback rating is required."
        return redirect(url_for('kars_student'))
    
    registration_record = students_events.query.filter_by(entryno=user_id, event_name=event_name).first()
    if registration_record:
        try:
            registration_record.feedback = int(feedback_value)
            db.session.commit()
            # Add flash "Feedback submitted successfully"
        except ValueError:
            # Add flash "Invalid feedback value"
            pass
        except Exception as e:
            db.session.rollback()
            print(f"Error submitting feedback: {e}")
            # Add flash "Error submitting feedback"
    else:
        # Add flash "Registration not found for this event to submit feedback."
        pass
    return redirect(url_for('kars_student'))

@app.route('/api/student/calendar-events')
def calendar_events_api():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user = db.session.get(Registration, user_id)
    if not user:
        session.clear() # Clear invalid session
        return redirect(url_for('kars_registration_or_login'))
    
    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    current_time = datetime.now()
    
    all_student_registered_activities = events.query.filter(events.name.in_(registered_event_names)).all()
    
    calendar_events_data = []

    # Add registered events
    for reg_event in all_student_registered_activities:
        event_obj = events.query.filter_by(name=reg_event.name).first() # Ensure this lookup is correct
        if event_obj:
            # Construct ISO 8601 strings for start and end
            # Assuming event_obj.date is 'YYYY-MM-DD' and starttime/endtime are 'HH:MM'
            start_datetime_str = f"{event_obj.date}T{event_obj.starttime}"
            end_datetime_str = f"{event_obj.date}T{event_obj.endtime}" # Or handle if endtime is optional/different

            calendar_events_data.append({
                'title': event_obj.name,
                'start': start_datetime_str,
                'end': end_datetime_str,
                'description': event_obj.description,
                'location': event_obj.venue,
                'extendedProps': { # Use extendedProps for custom data
                    'organiser': event_obj.organiser
                }
            })

    return jsonify({'events': calendar_events_data})

@app.route('/student/calendar/generate-link', methods=['POST'])
def generate_calendar_link():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    existing = CalendarShare.query.filter_by(user_id=user_id, is_active=True).first()
    if existing:
        share_token = existing.share_token
    else:
        share_token = str(uuid.uuid4())
        new_share = CalendarShare(user_id=user_id, share_token=share_token)
        db.session.add(new_share)
        db.session.commit()

    return jsonify({
        'calendar_url': url_for('shared_calendar', token=share_token, _external=True),
        'ics_url': url_for('shared_calendar_ics', token=share_token, _external=True)
    })

@app.route('/student/calendar/revoke-link', methods=['POST'])
def revoke_calendar_link():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    CalendarShare.query.filter_by(user_id=user_id).update({'is_active': False})
    db.session.commit()
    return jsonify({'message': 'Access revoked successfully.'})

@app.route('/calendar/<token>')
def shared_calendar(token):
    share = CalendarShare.query.filter_by(share_token=token, is_active=True).first()
    if not share:
        return "Invalid or expired calendar link.", 404
    user = Registration.query.get(share.user_id)
    if not user:
        # Invalidate the token to prevent further access to a broken link
        share.is_active = False
        db.session.commit()
        return "Invalid calendar: The user associated with this link could not be found.", 404

    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    all_student_registered_activities = events.query.filter(events.name.in_(registered_event_names)).all()

    calendar_events_data = []

    # Add registered events
    for reg_event in all_student_registered_activities:
        if reg_event.date and reg_event.starttime and reg_event.endtime:
            start_datetime_str = f"{reg_event.date}T{reg_event.starttime}"
            end_datetime_str = f"{reg_event.date}T{reg_event.endtime}"

            calendar_events_data.append({
                'title': reg_event.name,
                'start': start_datetime_str,
                'end': end_datetime_str,
                'description': reg_event.description,
                'location': reg_event.venue,
                'extendedProps': {
                    'organiser': reg_event.organiser
                }
            })

    return render_template('shared_calendar.html',
                           calendar_events=json.dumps(calendar_events_data),
                           user_name=user.name)

@app.route('/calendar/<token>.ics')
def shared_calendar_ics(token):
    share = CalendarShare.query.filter_by(share_token=token, is_active=True).first()
    if not share:
        return "Invalid or expired ICS link.", 404
    user = Registration.query.get(share.user_id)
    if not user:
        return "User not found for this calendar.", 404

    # Fetch registered non-academic events
    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    all_student_registered_activities = events.query.filter(events.name.in_(registered_event_names)).all()

    # Start ICS generation
    ics_content = 'BEGIN:VCALENDAR\n'
    ics_content += 'VERSION:2.0\n'
    ics_content += 'PRODID:-//KARS//IITD Event Calendar//EN\n'
    ics_content += 'CALSCALE:GREGORIAN\n'

    # Process non-academic events
    for event_item in all_student_registered_activities:
        if not all([event_item.date, event_item.starttime, event_item.endtime]):
            continue  # Skip events with incomplete time data

        try:
            # Format for ICS: YYYYMMDDTHHMMSS (floating time)
            dtstart_str = f"{event_item.date.replace('-', '')}T{event_item.starttime.replace(':', '')}00"
            dtend_str = f"{event_item.date.replace('-', '')}T{event_item.endtime.replace(':', '')}00"
        except AttributeError:
            continue  # Skip if date/time format is unexpectedly wrong

        # Clean strings for ICS format (escape special characters)
        summary = (event_item.name or '').replace(',', '\\,').replace(';', '\\;')
        description = (event_item.description or '').replace('\n', '\\n').replace(',', '\\,').replace(';', '\\;')
        location = (event_item.venue or '').replace(',', '\\,').replace(';', '\\;')

        # Create a stable, unique ID for this specific event on this user's calendar
        uid = f"KARS-EVENT-{event_item.id}-{user.entryno}@iitd.ac.in"

        ics_content += 'BEGIN:VEVENT\n'
        ics_content += f'DTSTAMP:{datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}\n'
        ics_content += f'UID:{uid}\n'
        ics_content += f'DTSTART:{dtstart_str}\n'
        ics_content += f'DTEND:{dtend_str}\n'
        ics_content += f'SUMMARY:{summary}\n'
        ics_content += f'DESCRIPTION:{description}\n'
        ics_content += f'LOCATION:{location}\n'
        ics_content += 'END:VEVENT\n'

    ics_content += 'END:VCALENDAR\n'

    return Response(
        ics_content,
        mimetype='text/calendar',
        headers={"Content-Disposition": "attachment;filename=kars_calendar.ics"}
    )

@app.route('/student/academic_schedule')
def kars_schedule():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    
    # Fetch the student's current subscriptions (same as before)
    subscriptions = StudentCourseSubscription.query.filter_by(student_entryno=user_id).order_by(StudentCourseSubscription.course_code).all()
    
    # NEW: Fetch all unique, available course codes that a coordinator has set up
    # This ensures students can only subscribe to courses that actually exist in the system.
    available_courses_query = db.session.query(CourseCoordinatorAuthorization.course_code).distinct().all()
    available_courses = [course.course_code for course in available_courses_query]
    
    return render_template(
        'academic_schedule.html', 
        subscriptions=subscriptions,
        available_courses=available_courses  # Pass the new list to the template
    )


@app.route('/api/course_groups/<string:course_code>')
def get_course_groups(course_code):
    # This is a public-facing API, but security is implicit as it only reveals group structure.
    # We could add @login_required if we wanted to restrict it further.
    
    # Find the authorization for this course to get its defined groups
    auth_record = CourseCoordinatorAuthorization.query.filter_by(course_code=course_code).first()

    if auth_record and auth_record.groups_json:
        try:
            # Parse the JSON string and return the list of groups
            groups = json.loads(auth_record.groups_json)
            return jsonify({'groups': groups})
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid group format for this course.'}), 500
            
    # If no groups are defined, return an empty list. The frontend should handle this.
    return jsonify({'groups': []})

# In add_course_subscription() route:
@app.route('/student/subscribe_course', methods=['POST'])
def add_course_subscription():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    
    course_code = request.form.get('course_code', '').upper().strip()
    course_group = request.form.get('course_group', 'All').strip()

    if not course_code:
        flash("Course code cannot be empty.", "error") # Replaces comment
        return redirect(url_for('kars_schedule'))

    existing_sub = StudentCourseSubscription.query.filter_by(student_entryno=user_id, course_code=course_code).first()

    if existing_sub:
        flash(f"You are already subscribed to {course_code}.", "info") # Replaces comment
        return redirect(url_for('kars_schedule'))

    new_sub = StudentCourseSubscription(student_entryno=user_id, course_code=course_code, course_group=course_group)
    db.session.add(new_sub)
    db.session.commit()
    
    flash(f"Successfully subscribed to {course_code}.", "success") # Replaces comment
    return redirect(url_for('kars_schedule'))

# In remove_course_subscription() route:
@app.route('/student/unsubscribe_course/<int:sub_id>', methods=['POST'])
def remove_course_subscription(sub_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))

    sub_to_delete = StudentCourseSubscription.query.filter_by(id=sub_id, student_entryno=user_id).first()

    if sub_to_delete:
        db.session.delete(sub_to_delete)
        db.session.commit()
        flash("Course subscription removed successfully.", "success") # Replaces comment
    else:
        # This is the line you specifically asked about:
        flash("Subscription not found or you are not authorized to remove it.", "error") # Replaces comment
    
    return redirect(url_for('kars_schedule'))

# --- Add this new route to app.py ---

@app.route('/course_coordinator/update_structure', methods=['POST'])
def update_course_structure():
    user_email = session.get('user_email')
    if not user_email:
        return redirect(url_for('kars_registration_or_login'))

    course_code = request.form.get('course_code')
    
    # Security Check: Ensure the logged-in user is an authorized coordinator for this course
    auth_record = CourseCoordinatorAuthorization.query.filter_by(
        coordinator_email=user_email,
        course_code=course_code
    ).first()

    if not auth_record:
        flash("You are not authorized to manage this course.", "error")
        return redirect(url_for('course_coordinator_dashboard'))

    # Process the group names from the textarea
    groups_str = request.form.get('groups', '')
    # Create a clean list: split by comma, strip whitespace, remove empty items
    groups_list = [group.strip() for group in groups_str.split(',') if group.strip()]
    
    # Save the cleaned list as a JSON string
    auth_record.groups_json = json.dumps(groups_list)
    
    try:
        db.session.commit()
        flash(f"Structure for {course_code} updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"Error updating course structure: {e}")
        flash("An error occurred while updating the course structure.", "error")
        
    return redirect(url_for('course_coordinator_dashboard'))

# --- FEST PORTAL ---
@app.route('/fest')
def fest_dashboard():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized as Fest Head.", 403

    fest_name = auth.organization
    manager_name = auth.name
    
    managed_events_list = events.query.filter_by(event_manager=manager_name, organiser=fest_name, event_type='fest').all()
    stats = get_organization_stats(fest_name, 'fest', manager_name)
    
    return render_template('fest.html', 
                         fest_name=fest_name, event_manager=manager_name,
                         events=managed_events_list, # For "My Managed Events"
                         upcoming_events=stats["upcoming_events_count"], # From calculated stats
                         total_registrations=stats["total_registrations_count"], # From calculated stats
                         current_tab='dashboard')

@app.route('/fest/events') # Shows all events of this fest
def fest_all_events():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized.", 403

    fest_name = auth.organization
    all_fest_events_list = events.query.filter_by(organiser=fest_name, event_type='fest').all()
    # Stats for the 'events' tab could be overall fest stats
    stats = get_organization_stats(fest_name, 'fest')


    return render_template('fest.html',
                         fest_name=fest_name, event_manager=auth.name,
                         events=all_fest_events_list, # For "All Fest Events" tab
                         upcoming_events=stats["upcoming_events_count"],
                         total_registrations=stats["total_registrations_count"],
                         current_tab='events')

@app.route('/fest/settings')
def fest_settings():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized.", 403
    return render_template('fest.html', fest_name=auth.organization, event_manager=auth.name, events=[], upcoming_events=0, total_registrations=0, current_tab='settings')

@app.route('/fest/create-event', methods=['POST'])
def create_fest_event():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized to create fest events.", 403

    fest_name_org = auth.organization
    event_manager_name = auth.name
    target_departments = request.form.getlist("target_departments")
    target_years = request.form.getlist("target_years")
    target_hostels = request.form.getlist("target_hostels")
    name = request.form['eventName']
    description = request.form['description']
    date = request.form['date']
    starttime = request.form['starttime']
    endtime = request.form['endtime']
    venue = request.form['venue']
    link = request.form.get("link")
    tags = request.form.get("tags")
    category_from_form = request.form.get('fest_type') # fest.html form uses name="fest_type" for this
    photo_file = request.files.get("photo")
    filename = None
    print(f"Creating fest event: {name}, Manager: {event_manager_name}, Org: {fest_name_org}, Date: {date}, Venue: {venue}, Category: {category_from_form}, Tags: {tags}, Target Depts: {target_departments}, Target Years: {target_years}, Target Hostels: {target_hostels}")
    if photo_file and photo_file.filename:
        filename = secure_filename(f"fest_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    if events.query.filter_by(name=name).first():
        # Add flash message "Event name already exists"
        return redirect(url_for('fest_dashboard')) # Or back to form with error

    new_event = events(
        name=name, photo=filename, event_manager=event_manager_name,
        organiser=fest_name_org, description=description, date=date, venue=venue,
        starttime=starttime, endtime=endtime, link=link, tags=tags,
        event_type='fest', category=category_from_form,
        target_departments=json.dumps(target_departments),
        target_years=json.dumps([int(y) for y in target_years]),
        target_hostels=json.dumps(target_hostels)
    )
    try:
        db.session.add(new_event)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error creating fest event: {e}")
        # Add flash message
    return redirect(url_for('fest_dashboard'))

@app.route('/fest/edit-event/<string:event_name>', methods=['GET', 'POST'])
def edit_fest_event(event_name):
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized.", 403

    event_to_edit = events.query.filter_by(name=event_name, organiser=auth.organization, event_type='fest').first_or_404()
    if event_to_edit.event_manager != auth.name: # Basic check
        return "You can only edit events you manage.", 403

    if request.method == 'POST':
        event_to_edit.organiser = request.form.get('organiser', event_to_edit.organiser) # Should be fest name
        event_to_edit.description = request.form['description']
        event_to_edit.date = request.form['date']
        event_to_edit.starttime = request.form['starttime']
        event_to_edit.endtime = request.form['endtime']
        event_to_edit.venue = request.form['venue']
        event_to_edit.link = request.form.get('link')
        event_to_edit.tags = request.form.get('tags')
        event_to_edit.category = request.form.get('fest_type') # From form

        if 'photo' in request.files:
            photo = request.files['photo']
            if photo.filename:
                filename = secure_filename(f"fest_edit_{event_name.replace(' ','_')}_{photo.filename}")
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                event_to_edit.photo = filename
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error editing fest event: {e}")
        return redirect(url_for('fest_dashboard'))
    
    # For GET, pass event_type for conditional rendering in a shared edit template
    return render_template('edit_event.html', event=event_to_edit, event_type='fest')

@app.route('/api/event/<string:event_name>/registrations') # Generic API for fest events
def get_event_registrations(event_name):
    user_email = session.get('user_email')
    if not user_email: return jsonify({'error': 'Not authenticated'}), 401
    
    # More robust auth: check if user is fest_head of the event's fest OR the event_manager
    event_obj = events.query.filter_by(name=event_name, event_type='fest').first_or_404()
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    
    is_authorized = False
    if auth and auth.organization == event_obj.organiser: # Is head of the fest
        is_authorized = True
    if event_obj.event_manager == session.get('user_name'): # Is the direct manager
        is_authorized = True
        
    if not is_authorized:
        return jsonify({'error': 'Not authorized to view these registrations'}), 403
    
    registrations_query = db.session.query(students_events, Registration).join(
        Registration, students_events.entryno == Registration.entryno
    ).filter(students_events.event_name == event_name).all()
    
    registration_data = [{
        'name': student.name, 'email': student.email, 'entryno': student.entryno,
        'department': student.department, 'feedback': reg.feedback
    } for reg, student in registrations_query]
    
    return jsonify({
        'event_name': event_name,
        'total_registrations': len(registration_data),
        'registrations': registration_data
    })

# --- CLUB PORTAL ---
@app.route('/club')
def club_dashboard():
    # --- 1. Authorization & Session Check ---
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    auth_role = session.get('auth_role')
    manager_name = session.get('user_name')
    club_profile = ClubProfile.query.filter_by(organization_name=organization).first()

    if not user_email or not organization or not auth_role:
        flash("Session is invalid. Please log in again.", "error")
        return redirect(url_for('kars_registration_or_login'))

    # --- 2. Fetch ALL Data Needed for All Tabs ---

    # Data for Dashboard & Events Tabs
    managed_events_list = events.query.filter_by(event_manager=manager_name, organiser=organization, event_type='club').all()
    all_club_events_list = events.query.filter_by(organiser=organization, event_type='club').order_by(events.date.desc()).all()
    stats = get_organization_stats(organization, 'club')

    # Data for Settings Tab (only fetch if user is a club_head)
    team_members = []
    all_users_for_dropdown = []

    if auth_role == 'club_head':
        # Get current team members
        team_members = EventAuthorization.query.filter_by(organization=organization).order_by(EventAuthorization.role).all()
        current_member_emails = {member.email for member in team_members}

        # Get all users who are NOT already on the team to populate the dropdown
        all_users_for_dropdown = Registration.query.filter(
            Registration.is_verified == True,
            ~Registration.email.in_(current_member_emails)
        ).order_by(Registration.name).all()

    # --- 3. Render the single, comprehensive template ---
    return render_template(
        'club.html',
        # Data for all tabs
        club_name=organization,
        club_manager_name=manager_name,
        current_tab='dashboard', # Default to dashboard
        # Dashboard data
        managed_events=managed_events_list,
        stats=stats,
        # Events tab data
        all_club_events=all_club_events_list,
        club_profile=club_profile,
        # Settings tab data
        team_members=team_members,
        all_users=all_users_for_dropdown  # Pass the filtered list
    )

# --- THIS NEW ROUTE for handling team management actions ---

@app.route('/club/manage_team', methods=['POST'])
@club_head_required # Protect this route!
def manage_team_action():
    action = request.form.get('action')
    target_email = request.form.get('email')
    target_role = request.form.get('role') # e.g., 'club_coordinator'
    auth_id = request.form.get('auth_id')
    club_name = session.get('user_organization')

    # --- ACTION: ADD a new member ---
    if action == 'add':
        user_to_add = Registration.query.filter_by(email=target_email).first()
        if not user_to_add:
            flash(f"User with email {target_email} not found.", "error")
            # CORRECTED: Redirect to the main club dashboard
            return redirect(url_for('club_dashboard'))

        existing_auth = EventAuthorization.query.filter_by(email=target_email, organization=club_name).first()
        if existing_auth:
            flash(f"{user_to_add.name} already has a role in this club.", "info")
            # CORRECTED: Redirect to the main club dashboard
            return redirect(url_for('club_dashboard'))
        
        new_auth = EventAuthorization(
            email=target_email,
            name=user_to_add.name,
            role=target_role,
            organization=club_name,
            event_type='club',
            authorized_by=session.get('user_email'),
            is_active=True
        )
        db.session.add(new_auth)
        flash(f"Successfully appointed {user_to_add.name} as {target_role.replace('_', ' ').title()}.", "success")

    # --- ACTION: REMOVE a member's role ---
    elif action == 'remove':
        auth_to_remove = EventAuthorization.query.get(auth_id)
        if auth_to_remove and auth_to_remove.organization == club_name:
            if auth_to_remove.role == 'club_head':
                flash("Club Heads cannot be removed from this panel. Please contact the site admin.", "error")
            else:
                flash(f"Removed {auth_to_remove.name} from the team.", "success")
                db.session.delete(auth_to_remove)
        else:
            flash("Authorization not found or invalid.", "error")

    # --- ACTION: UPDATE a member's role (Promote/Demote) ---
    elif action == 'update_role':
        auth_to_update = EventAuthorization.query.get(auth_id)
        if auth_to_update and auth_to_update.organization == club_name:
             if auth_to_update.role == 'club_head':
                flash("Cannot change the role of a Club Head.", "error")
             else:
                auth_to_update.role = target_role
                flash(f"Updated {auth_to_update.name}'s role to {target_role.replace('_', ' ').title()}.", "success")
        else:
            flash("Authorization not found or invalid.", "error")
            
    db.session.commit()
    # CORRECTED: Redirect to the main club dashboard.
    # We add '#settings' to the URL so the page automatically jumps to the right tab.
    return redirect(url_for('club_dashboard') + '#settings')

@app.route('/club/create-event', methods=['POST'])
def create_club_event():
    # --- 1. Security & Authorization ---
    user_email = session.get('user_email')
    organization = session.get('user_organization')

    # Verify the user has ANY valid role in this club to be able to create an event.
    auth = EventAuthorization.query.filter(
        EventAuthorization.email == user_email,
        EventAuthorization.organization == organization,
        EventAuthorization.role.in_(['club_head', 'club_coordinator', 'club_executive'])
    ).first()
    
    if not auth:
        flash("You do not have permission to create events for this club.", "error")
        return redirect(url_for('club_dashboard'))

    # --- 2. Form Data Retrieval ---
    # Standard event details
    name = request.form['eventName']
    description = request.form['description']
    date = request.form['date']
    starttime = request.form['starttime']
    endtime = request.form['endtime']
    venue = request.form['venue']
    link = request.form.get("link")
    tags = request.form.get("tags")
    category = request.form.get('event_category')
    
    # List-based target filters
    target_departments = request.form.getlist("target_departments")
    target_years = request.form.getlist("target_years")
    target_hostels = request.form.getlist("target_hostels")

    # Boolean flag for private events (get value from the new checkbox)
    is_private_event = request.form.get('is_private') == 'true'

    # Custom form field count
    custom_field_count = int(request.form.get('custom_field_count', 0))

    # --- 3. Data Validation & Processing ---
    # Ensure event name is unique
    if events.query.filter_by(name=name).first():
        flash("An event with this name already exists. Please choose a unique name.", "error")
        return redirect(url_for('club_dashboard'))
    
    # Handle file upload
    photo_file = request.files.get("photo")
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"club_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    # --- 4. Database Interaction ---
    try:
        # Create the main event object with all attributes
        new_event = events(
            name=name,
            photo=filename,
            event_manager=auth.name, # The creator is the default manager
            organiser=auth.organization,
            description=description,
            date=date,
            venue=venue,
            starttime=starttime,
            endtime=endtime,
            link=link,
            tags=tags,
            event_type='club',
            category=category,
            target_departments=json.dumps(target_departments),
            target_years=json.dumps([int(y) for y in target_years if y.isdigit()]), # Ensure years are integers
            target_hostels=json.dumps(target_hostels),
            is_private=is_private_event # Save the privacy setting
        )
        db.session.add(new_event)
        
        # Process and add any custom form fields
        for i in range(custom_field_count):
            question_text = request.form.get(f'question_text_{i}')
            # Only process fields that have actual question text
            if question_text:
                new_field = CustomFormField(
                    event=new_event, # Link to the event being created
                    question_text=question_text,
                    question_type=request.form.get(f'question_type_{i}'),
                    options_json=request.form.get(f'options_{i}'),
                    is_required=(request.form.get(f'is_required_{i}') == 'on'), # Checkbox value
                    order=i
                )
                db.session.add(new_field)

        # Commit all changes to the database
        db.session.commit()
        flash(f"Event '{name}' created successfully!", "success")

    except Exception as e:
        # If any error occurs, roll back the entire transaction
        db.session.rollback()
        print(f"Error creating club event: {e}")
        flash("An error occurred while creating the event. Please check your inputs and try again.", "error")

    # --- 5. Redirect on Success ---
    return redirect(url_for('club_dashboard'))

@app.route('/club/edit-event/<string:event_name>', methods=['GET', 'POST'])
def edit_club_event(event_name):
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    user_name = session.get('user_name')

    if not user_email or not organization:
        return redirect(url_for('kars_registration_or_login'))

    event_to_edit = events.query.filter_by(name=event_name, organiser=organization, event_type='club').first_or_404()
    
    # --- START PERMISSION CHECK ---
    # Get the user's role for this specific club
    user_auth = EventAuthorization.query.filter_by(email=user_email, organization=organization).first()
    
    # A user is authorized if they are a Head/Coordinator OR they are the specific manager of this event
    is_privileged = user_auth and user_auth.role in ['club_head', 'club_coordinator']
    is_event_manager = (event_to_edit.event_manager == user_name)

    if not (is_privileged or is_event_manager):
        flash("You are not authorized to edit this event.", "error")
        return redirect(url_for('club_dashboard'))
    # --- END PERMISSION CHECK ---

    if request.method == 'POST':
        # ... (The POST logic for updating the event remains the same) ...
        event_to_edit.description = request.form['description']
        event_to_edit.date = request.form['date']
        # ... etc. ...
        db.session.commit()
        return redirect(url_for('club_dashboard'))
    
    # The GET request to show the form is fine if the permission check passed
    return render_template('edit_event.html', event=event_to_edit, event_type='club')

@app.route('/club/update_profile', methods=['POST'])
@club_head_required # Only the Club Head can do this
def update_club_profile():
    organization = session.get('user_organization')
    
    # Find the existing profile or create a new one
    profile = ClubProfile.query.filter_by(organization_name=organization).first()
    if not profile:
        profile = ClubProfile(organization_name=organization)
        db.session.add(profile)

    # Update description
    profile.description = request.form.get('description')

    # Handle logo upload
    if 'logo' in request.files:
        logo_file = request.files['logo']
        if logo_file.filename:
            # Securely save the file with a unique name
            filename = secure_filename(f"logo_{organization.replace(' ', '_')}_{logo_file.filename}")
            logo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile.logo_path = filename

    try:
        db.session.commit()
        flash("Club profile updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {e}", "error")

    return redirect(url_for('club_dashboard') + '#settings')


@app.route('/club/export_data/<string:export_type>')
@club_head_required # Only the Club Head can export data
def export_club_data(export_type):
    organization = session.get('user_organization')
    
    # Use StringIO to build the CSV in memory
    si = io.StringIO()
    cw = csv.writer(si)

    if export_type == 'members':
        # Fetch all unique members who have ever registered for an event
        member_entry_numbers = db.session.query(students_events.entryno).join(events).filter(events.organiser == organization).distinct()
        members = Registration.query.filter(Registration.entryno.in_(member_entry_numbers)).all()
        
        # Write headers and rows
        cw.writerow(['EntryNo', 'Name', 'Email', 'Department', 'Year'])
        for member in members:
            cw.writerow([member.entryno, member.name, member.email, member.department, member.currentyear])
        
        filename = f"{organization.replace(' ', '_')}_members.csv"

    elif export_type == 'registrations':
        # Fetch all registration details for all events of the club
        all_regs = db.session.query(Registration.entryno, Registration.name, Registration.email, events.name.label('event_name'), events.date)\
            .join(students_events, Registration.entryno == students_events.entryno)\
            .join(events, students_events.event_name == events.name)\
            .filter(events.organiser == organization).order_by(events.date).all()
            
        cw.writerow(['EntryNo', 'StudentName', 'StudentEmail', 'EventName', 'EventDate'])
        for reg in all_regs:
            cw.writerow([reg.entryno, reg.name, reg.email, reg.event_name, reg.date])

        filename = f"{organization.replace(' ', '_')}_all_registrations.csv"
        
    else:
        return "Invalid export type", 400

    # Prepare and return the response
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route('/api/club-event/<string:event_name>/registrations')
def get_club_event_registrations(event_name):
    # --- FIX 1: Get ALL required variables from the session ---
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    user_name = session.get('user_name')

    if not user_email: 
        return jsonify({'error': 'Not authenticated'}), 401
    
    event_obj = events.query.filter_by(name=event_name, event_type='club').first_or_404()
    
    # Authorization check (now works correctly)
    user_auth = EventAuthorization.query.filter_by(email=user_email, organization=organization).first()
    is_privileged = user_auth and user_auth.role in ['club_head', 'club_coordinator']
    is_event_manager = (event_obj.event_manager == user_name)

    if not (is_privileged or is_event_manager):
        return jsonify({'error': 'Not authorized to view these registrations'}), 403

    # --- Comprehensive Data Fetching (Optimized) ---
    
    # 1. Get all registrations for the event, joining with student details (Same as before)
    registrations = db.session.query(students_events, Registration)\
        .join(Registration, students_events.entryno == Registration.entryno)\
        .filter(students_events.event_name == event_name).all()

    if not registrations:
        # Handle case with no registrations gracefully
        return jsonify({
            'event_name': event_name, 'total_registrations': 0, 'registrants': [],
            'custom_fields': [], 'analytics': {}
        })

    # --- FIX 2: Solve the N+1 Query Problem ---
    # 2a. Get all registration IDs from the first query
    registration_ids = [reg.srno for reg, student in registrations]
    
    # 2b. Fetch ALL custom responses for these registrations in a SINGLE query
    all_responses = CustomFormResponse.query.filter(CustomFormResponse.registration_id.in_(registration_ids)).all()

    # 2c. Organize the responses into a dictionary for fast lookup
    responses_by_reg_id = {}
    for response in all_responses:
        if response.registration_id not in responses_by_reg_id:
            responses_by_reg_id[response.registration_id] = {}
        responses_by_reg_id[response.registration_id][response.field_id] = response.response_text
    # --- End of N+1 Fix ---

    # 3. Prepare the list of registrants, now using our efficient lookup dictionary
    registrants_data = []
    for reg, student in registrations:
        custom_answers = responses_by_reg_id.get(reg.srno, {}) # Get answers from our dictionary
        
        registrants_data.append({
            'name': student.name, 'email': student.email, 'entryno': student.entryno,
            'department': student.department, 'year': student.currentyear,
            'custom_answers': custom_answers
        })
    
    # 4. Prepare data for analytics charts (This part of your logic was already correct)
    analytics = { 'year_distribution': {}, 'department_distribution': {}, 'custom_question_analytics': {} }
    
    for registrant in registrants_data:
        year = registrant.get('year', 'Unknown')
        analytics['year_distribution'][year] = analytics['year_distribution'].get(year, 0) + 1
        dept = registrant.get('department', 'Unknown')
        analytics['department_distribution'][dept] = analytics['department_distribution'].get(dept, 0) + 1

    custom_fields = CustomFormField.query.filter_by(event_id=event_obj.id).all()
    for field in custom_fields:
        if field.question_type in ['radio', 'checkbox']:
            analytics['custom_question_analytics'][field.id] = { 'question': field.question_text, 'type': field.question_type, 'responses': {} }
            for registrant in registrants_data:
                answer = registrant['custom_answers'].get(field.id)
                if answer:
                    analytics['custom_question_analytics'][field.id]['responses'][answer] = analytics['custom_question_analytics'][field.id]['responses'].get(answer, 0) + 1

    return jsonify({
        'event_name': event_name,
        'total_registrations': len(registrants_data),
        'registrants': registrants_data,
        'custom_fields': [{'id': f.id, 'text': f.question_text} for f in custom_fields],
        'analytics': analytics
    })

# --- DEPARTMENT PORTAL ---
@app.route('/department')
def department_dashboard():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized as Department Head.", 403

    department_name = auth.organization
    manager_name = auth.name
    
    managed_activities_list = events.query.filter_by(event_manager=manager_name, organiser=department_name, event_type='department_activity').all()
    stats = get_organization_stats(department_name, 'department_activity', manager_name)

    return render_template('department.html',
                           department_name=department_name, department_manager_name=manager_name,
                           managed_activities=managed_activities_list,
                           stats=stats,
                           current_tab='dashboard')

@app.route('/department/activities')
def department_all_activities():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized.", 403

    department_name = auth.organization
    all_dept_activities = events.query.filter_by(organiser=department_name, event_type='department_activity').all()
    stats = get_organization_stats(department_name, 'department_activity')

    return render_template('department.html',
                           department_name=department_name, department_manager_name=auth.name,
                           all_department_activities=all_dept_activities,
                           managed_activities=[], # Or pass managed if needed
                           stats=stats,
                           current_tab='activities')

@app.route('/department/settings')
def department_settings():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized.", 403
    return render_template('department.html', department_name=auth.organization, department_manager_name=auth.name, stats={}, current_tab='settings')

@app.route('/department/create-activity', methods=['POST'])
def create_department_activity():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized to create department activities.", 403

    department_name_org = auth.organization
    event_manager_name = auth.name

    name = request.form['activityName'] # From department.html modal
    description = request.form['description']
    date = request.form['date']
    starttime = request.form['starttime']
    endtime = request.form['endtime']
    venue = request.form['venue']
    link = request.form.get("link")
    tags = request.form.get("tags")
    activity_category = request.form.get('activity_type') # e.g., Seminar, Workshop
    target_departments = request.form.getlist("target_departments")
    target_years = request.form.getlist("target_years")
    target_hostels = request.form.getlist("target_hostels")
    photo_file = request.files.get("photo")
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"dept_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    if events.query.filter_by(name=name).first():
        # Add flash message "Activity name already exists"
        return redirect(url_for('department_dashboard'))

    new_activity = events(
        name=name, photo=filename, event_manager=event_manager_name,
        organiser=department_name_org, description=description, date=date, venue=venue,
        starttime=starttime, endtime=endtime, link=link, tags=tags,
        event_type='department_activity', category=activity_category,
        target_departments=json.dumps(target_departments),
        target_years=json.dumps([int(y) for y in target_years]),
        target_hostels=json.dumps(target_hostels)
    )
    try:
        db.session.add(new_activity)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error creating department activity: {e}")
    return redirect(url_for('department_dashboard'))

@app.route('/department/edit-activity/<string:activity_name>', methods=['GET', 'POST'])
def edit_department_activity(activity_name):
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized.", 403

    activity_to_edit = events.query.filter_by(name=activity_name, organiser=auth.organization, event_type='department_activity').first_or_404()
    if activity_to_edit.event_manager != auth.name:
        return "You can only edit activities you manage for this department.", 403

    if request.method == 'POST':
        activity_to_edit.description = request.form['description']
        activity_to_edit.date = request.form['date']
        activity_to_edit.starttime = request.form['starttime']
        activity_to_edit.endtime = request.form['endtime']
        activity_to_edit.venue = request.form['venue']
        activity_to_edit.link = request.form.get('link')
        activity_to_edit.tags = request.form.get('tags')
        activity_to_edit.category = request.form.get('activity_type') # from form

        if 'photo' in request.files:
            photo = request.files['photo']
            if photo.filename:
                filename = secure_filename(f"dept_edit_{activity_name.replace(' ','_')}_{photo.filename}")
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                activity_to_edit.photo = filename
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error editing department activity: {e}")
        return redirect(url_for('department_dashboard'))
    
    return render_template('edit_event.html', event=activity_to_edit, event_type='department_activity')

@app.route('/api/department-activity/<string:activity_name>/registrations')
def get_department_activity_registrations(activity_name):
    user_email = session.get('user_email')
    if not user_email: return jsonify({'error': 'Not authenticated'}), 401
    
    activity_obj = events.query.filter_by(name=activity_name, event_type='department_activity').first_or_404()
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    
    is_authorized = False
    if auth and auth.organization == activity_obj.organiser: is_authorized = True
    if activity_obj.event_manager == session.get('user_name'): is_authorized = True
        
    if not is_authorized:
        return jsonify({'error': 'Not authorized to view these registrations'}), 403
    
    registrations_query = db.session.query(students_events, Registration).join(
        Registration, students_events.entryno == Registration.entryno
    ).filter(students_events.event_name == activity_name).all()
    
    registration_data = [{
        'name': student.name, 'email': student.email, 'entryno': student.entryno,
        'department': student.department, 'feedback': reg.feedback # Department might be redundant here
    } for reg, student in registrations_query]
    
    return jsonify({
        'activity_name': activity_name,
        'total_registrations': len(registration_data),
        'registrations': registration_data
    })

@app.route('/course_coordinator')
def course_coordinator_dashboard():
    user_email = session.get('user_email')
    if not user_email:
        return redirect(url_for('kars_registration_or_login'))
    
    # Verify the user has a coordinator role in general.
    # In a real system, you might also check a 'role' field in the Registration table.
    
    # Fetch all courses this user is authorized to coordinate
    managed_courses = CourseCoordinatorAuthorization.query.filter_by(coordinator_email=user_email).all()
    
    return render_template('course.html', 
                           managed_courses=managed_courses,
                           coordinator_name=session.get('user_name', 'Coordinator'))

@app.route('/course_coordinator/create_event', methods=['POST'])
def create_academic_event():
    user_email = session.get('user_email')
    if not user_email:
        return jsonify({'error': 'Unauthorized'}), 401 # Use JSON for form submissions if possible

    # --- Security Check: Verify this coordinator is authorized for this specific course ---
    course_code = request.form.get('course_code')
    is_authorized = CourseCoordinatorAuthorization.query.filter_by(
        coordinator_email=user_email,
        course_code=course_code
    ).first()

    if not is_authorized:
        flash("You are not authorized to add events to this course.", "error")
        return redirect(url_for('course_coordinator_dashboard'))

    # --- Create the Event ---
    new_academic_event = course_events(
        name=request.form.get('name'),
        course=course_code, # Use the verified course code
        description=request.form.get('description'),
        day=request.form.get('day'),
        venue=request.form.get('venue'),
        starttime=request.form.get('starttime'),
        target_group=request.form.get('target_group', 'All')
    )
    
    try:
        db.session.add(new_academic_event)
        db.session.commit()
        flash(f"Academic event '{new_academic_event.name}' created successfully for {course_code}.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating academic event: {e}")
        flash("An error occurred while creating the event.", "error")

    return redirect(url_for('course_coordinator_dashboard'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    all_users = Registration.query.filter_by(is_verified=True).order_by(Registration.name).all()
    event_auths = EventAuthorization.query.order_by(EventAuthorization.organization).all()
    course_auths = CourseCoordinatorAuthorization.query.all()
    
    return render_template('admin.html',
                           all_users=all_users,
                           event_authorizations=event_auths,
                           course_authorizations=course_auths)

@app.route('/admin/authorize', methods=['POST'])
@admin_required
def admin_authorize():
    auth_type = request.form.get('auth_type')
    email = request.form.get('email')
    
    user = Registration.query.filter_by(email=email).first()
    if not user:
        flash(f"User with email '{email}' not found.", "error")
        return redirect(url_for('admin_dashboard'))

    if auth_type == 'event_org':
        role = request.form.get('role_prefix')
        organization = request.form.get('organization_name')
        event_type_map = {
            'club_head': 'club',
            'fest_head': 'fest',
            'department_head': 'department_activity'
        }
        event_type = event_type_map.get(role)
        if not event_type:
            flash("Invalid role prefix selected.", "error")
            return redirect(url_for('admin_dashboard'))
        existing_auth = EventAuthorization.query.filter_by(email=email, role=role, organization=organization).first()
        if existing_auth:
            flash(f"{user.name} is already authorized as a {role.replace('_', ' ')} for {organization}.", "info")
            return redirect(url_for('admin_dashboard'))
        print(f"DEBUG authorized_by {session.get('user_email')}")
        new_auth = EventAuthorization(
            email=email,
            name=user.name,
            role=role,
            organization=organization,
            event_type=event_type,
            authorized_by=session.get('user_email')
        )
        db.session.add(new_auth)
        flash(f"Successfully authorized {user.name} for {organization}.", "success")

    elif auth_type == 'course_coord':
        course_code = request.form.get('course_code').upper().strip()

        existing_auth = CourseCoordinatorAuthorization.query.filter_by(coordinator_email=email, course_code=course_code).first()
        if existing_auth:
            flash(f"{user.name} is already a coordinator for {course_code}.", "info")
            return redirect(url_for('admin_dashboard'))
        
        new_auth = CourseCoordinatorAuthorization(
            coordinator_email=email,
            course_code=course_code
        )
        db.session.add(new_auth)
        flash(f"Successfully authorized {user.name} as coordinator for {course_code}.", "success")
        
    else:
        flash("Invalid authorization type.", "error")
        return redirect(url_for('admin_dashboard'))
        
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/revoke/<string:auth_type>/<int:auth_id>', methods=['POST'])
@admin_required
def admin_revoke(auth_type, auth_id):
    if auth_type == 'event':
        auth_to_revoke = EventAuthorization.query.get_or_404(auth_id)
        flash(f"Revoked permission for {auth_to_revoke.name} from {auth_to_revoke.organization}.", "success")
    elif auth_type == 'course':
        auth_to_revoke = CourseCoordinatorAuthorization.query.get_or_404(auth_id)
        flash(f"Revoked coordinator role for {auth_to_revoke.coordinator.name} from {auth_to_revoke.course_code}.", "success")
    else:
        flash("Invalid authorization type for revoking.", "error")
        return redirect(url_for('admin_dashboard'))
    
    db.session.delete(auth_to_revoke)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run(debug=True, port=5000)