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
from sqlalchemy.orm import joinedload
from sqlalchemy import text, func # Keep if you have raw SQL, otherwise optional
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
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application. This is required for security.")
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

ALL_DEPARTMENTS = [
    "Applied Mechanics", "Biochemical Engineering and Biotechnology", "Chemical Engineering", 
    "Chemistry", "Civil Engineering", "Computer Science and Engineering", "Design", 
    "Electrical Engineering", "Energy Science and Engineering", "Humanities and Social Sciences", 
    "Management Studies", "Materials Science and Engineering", "Mathematics", 
    "Mechanical Engineering", "Physics", "Textile and Fibre Engineering"
]
ALL_HOSTELS = [
    "Shivalik", "Nilgiri", "Karakoram", "Aravali", "Jwala", "Satpura", "Udaigiri", 
    "Vindhyachal", "Girnar", "Kumaon", "Zanskar", "Himadri", "Kailash"
]
ALL_YEARS = [1, 2, 3, 4, 5, 6]

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

class students_events(db.Model):
    srno = db.Column(db.Integer, primary_key=True)
    # The foreign key is now to the event's ID, not its name.
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False) 
    entryno = db.Column(db.String(11), db.ForeignKey('registration.entryno'), nullable=False)
    feedback = db.Column(db.Integer, nullable=True)
    
    # The relationship now correctly uses the event_id foreign key.
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
    # Link to the user's primary key
    coordinator_entryno = db.Column(db.String(11), db.ForeignKey('registration.entryno'), nullable=False)
    course_code = db.Column(db.String(20), nullable=False)
    groups_json = db.Column(db.Text, nullable=True)
    
    # The relationship now correctly uses the coordinator_entryno foreign key.
    coordinator = db.relationship('Registration', backref=db.backref('managed_courses', lazy='dynamic'))
    
    __table_args__ = (db.UniqueConstraint('coordinator_entryno', 'course_code', name='_coordinator_course_uc'),)

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
            return redirect(url_for('login'))
        
        user = Registration.query.get(session['user_id'])
        if not user:
            flash("User not found.", "error")
            session.clear()
            return redirect(url_for('login'))

        user_roles = json_to_list(user.role)
        if 'admin' not in user_roles:
            flash("You do not have permission to access the admin panel.", "error")
            return redirect(url_for('Synapse_student')) # Or wherever you want non-admins to go
            
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
        return False
    subject = "OTP for Synapse Registration"
    message = f"Your OTP for Synapse registration is: {otp_code}"
    text = f"Subject: {subject}\n\n{message}"
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(my_email, app_pass)
        server.sendmail(my_email, receiver_email, text)
        server.quit()
        return True
    except Exception as e:
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
        # Corrected to use event_id for counting
        total_regs += students_events.query.filter_by(event_id=event_item.id).count()
        
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
            return redirect(url_for('login'))

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
@app.route('/')
def home():
    today = datetime.now().strftime('%Y-%m-%d')
    featured_events = events.query.filter(
        events.is_private == False,
        events.date >= today
    ).order_by(events.date.asc()).limit(6).all()
    stats = {
        'users': Registration.query.filter_by(is_verified=True).count(),
        'events': events.query.count(),
        'orgs': db.session.query(EventAuthorization.organization).distinct().count()
    }
    # Pass the current year to the template context
    return render_template('home.html', featured_events=featured_events, stats=stats, current_year=datetime.now().year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('Synapse_student'))

    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']
        login_role_selection = request.form.get('role')

        user = Registration.query.filter_by(email=email).first()
        
        if user and user.is_verified and check_password_hash(user.password, password):
            session['user_id'] = user.entryno
            session['user_email'] = user.email
            session['user_name'] = user.name
            
            user_roles = json_to_list(user.role)

            if login_role_selection == "admin" and "admin" in user_roles:
                return redirect(url_for('admin_dashboard'))

            elif login_role_selection == "student" and "student" in user_roles:
                return redirect(url_for('Synapse_student'))
            
            elif login_role_selection == "course-coordinator":
                # Corrected to check by primary key
                if CourseCoordinatorAuthorization.query.filter_by(coordinator_entryno=user.entryno).first():
                    return redirect(url_for('course_coordinator_dashboard'))
                else:
                    flash("You are not authorized for the Course Coordinator portal.", "error")
                    return redirect(url_for('login'))
            
            elif login_role_selection in ["fest", "club", "department"]:
                role_prefix_map = {"fest": "fest_head", "club": "club_head", "department": "department_head"}
                auth_role_prefix = role_prefix_map.get(login_role_selection)
                auth_records = get_all_user_authorizations(user.email, auth_role_prefix)
                
                if len(auth_records) == 1:
                    auth = auth_records[0]
                    session['user_organization'] = auth.organization
                    session['auth_role'] = auth.role
                    if auth.role.startswith("fest_head"): return redirect(url_for('fest_dashboard'))
                    if auth.role.startswith("club_head"): return redirect(url_for('club_dashboard'))
                    if auth.role.startswith("department_head"): return redirect(url_for('department_dashboard'))
                        
                elif len(auth_records) > 1:
                    session['multi_auth_roles'] = [{'organization': a.organization, 'role': a.role} for a in auth_records]
                    return redirect(url_for('choose_organization'))

            # Fallback if selected role authorization fails
            if "student" in user_roles:
                flash("Could not log you into the selected portal. Redirecting to student dashboard.", "info")
                return redirect(url_for('Synapse_student'))
            else:
                flash("No suitable portal found or authorization failed.", "error")
                return redirect(url_for('login'))

        elif user and not user.is_verified:
             flash("Account not verified. Please check your email for the OTP.", "warning")
             return redirect(url_for('verify_otp', email=user.email))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for('login'))
            
    # For GET requests, render the login page
    return render_template('login.html', form_type='login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('Synapse_student'))

    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']

        if password != request.form['confirm_password']:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))
        
        if not email.endswith("@iitd.ac.in"):
            flash("Only @iitd.ac.in emails are allowed.", "error")
            return redirect(url_for('signup'))

        existing_user = Registration.query.filter_by(email=email).first()

        otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
        otp_expiry_time = datetime.utcnow() + timedelta(minutes=10)

        if existing_user:
            if existing_user.is_verified:
                flash("This email is already registered. Please log in.", "info")
                return redirect(url_for('login'))
            else:
                # Update existing unverified user with new details and OTP
                existing_user.password = generate_password_hash(password)
                existing_user.otp_token = otp
                existing_user.otp_expiry = otp_expiry_time
                user_to_update = existing_user
        else:
            # Create a new user record
            entryno = to_entryno(email.split('@')[0])
            new_user = Registration(
                entryno=entryno,
                name=request.form['name'],
                hostel=request.form['hostel'],
                email=email,
                password=generate_password_hash(password),
                role=json.dumps(['student']),
                interest=json.dumps([]),
                department=find_department(entryno),
                entryyear=int(entryno[:4]),
                course=request.form['course'],
                exityear=int(entryno[:4]) + cousre_duration(request.form['course']),
                is_verified=False,
                otp_token=otp,
                otp_expiry=otp_expiry_time
            )
            db.session.add(new_user)
            user_to_update = new_user

        try:
            db.session.commit()
            if send_otp_email(email, otp):
                flash("An OTP has been sent to your email.", "success")
            else:
                flash("Could not send OTP email. Please contact admin.", "warning")
            return redirect(url_for('verify_otp', email=email))

        except Exception as e:
            db.session.rollback()
            flash("A database error occurred. Please try again.", "error")
            return redirect(url_for('signup'))
            
    # For GET requests, render the login page but tell it to show the signup form
    return render_template('login.html', form_type='signup')

@app.route('/choose_organization', methods=['GET', 'POST'])
def choose_organization():
    if 'multi_auth_roles' not in session:
        flash("No roles found in your session. Please log in again.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Now we get the clean, separate values directly from the form
        selected_org = request.form.get('organization')
        selected_role = request.form.get('role')

        if not selected_org or not selected_role:
             flash("Invalid selection. Please try again.", "error")
             return redirect(url_for('choose_organization'))

        # Verify the selected combination is actually in their list of roles
        # This is an important security check
        is_authorized = any(
            auth['organization'] == selected_org and auth['role'] == selected_role
            for auth in session.get('multi_auth_roles', [])
        )

        if not is_authorized:
            flash("You are not authorized for the selected role. Please try again.", "error")
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
            return redirect(url_for('login'))
    
    # Logic for GET request: Group roles by type for display
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
    if request.method == 'POST':
        # --- Handle the form submission FIRST ---
        submitted_email = request.form.get('email')
        if not submitted_email:
            # This is a fallback in case the hidden input fails, but the primary error is now fixed.
            flash("Verification session expired. Please try again.", "error")
            return redirect(url_for('login'))
            
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
            user.otp_token = None
            user.otp_expiry = None
            db.session.commit()

            session['user_id'] = user.entryno
            session['user_email'] = user.email
            session['user_name'] = user.name
            
            flash("Your account has been successfully verified!", "success")
            return redirect(url_for('Synapse_student'))
        
        # If any check failed, redirect back to the OTP page to try again
        return redirect(url_for('verify_otp', email=submitted_email))

    # --- This part now ONLY runs for GET requests ---
    email_from_url = request.args.get('email')
    if not email_from_url:
        flash("No email specified for verification.", "error")
        return redirect(url_for('login'))

    # For GET request, just render the page
    return render_template('otp.html', email=email_from_url)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/student')
def Synapse_student():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear() # Clear invalid session
        return redirect(url_for('login'))
    
    # --- Part 1: Fetch all student registrations and EAGERLY LOAD related event data ---
    all_student_regs = students_events.query.filter_by(entryno=user.entryno)\
        .options(joinedload(students_events.event))\
        .all()
    
    # Extract the event objects from the registrations
    all_student_registered_activities = [reg.event for reg in all_student_regs if reg.event]
    
    calendar_events_data = []
    feedback_needed_activities = []
    current_time = datetime.now()

    # --- Part 2: Process the already-fetched data (NO new queries in the loop) ---
    for reg in all_student_regs:
        event_obj = reg.event
        if not event_obj:
            continue

        # A. Build Calendar Data
        if event_obj.date and event_obj.starttime and event_obj.endtime:
            start_datetime_str = f"{event_obj.date}T{event_obj.starttime}"
            end_datetime_str = f"{event_obj.date}T{event_obj.endtime}"
            calendar_events_data.append({
                'title': event_obj.name,
                'start': start_datetime_str,
                'end': end_datetime_str,
                'description': event_obj.description,
                'location': event_obj.venue,
                'extendedProps': {
                    'organiser': event_obj.organiser,
                    'type': 'General Event'
                }
            })
            
        # B. Build Feedback Needed List
        if (reg.feedback is None or reg.feedback == 0):
            try:
                event_datetime = datetime.strptime(f"{event_obj.date} {event_obj.starttime}", "%Y-%m-%d %H:%M")
                if event_datetime < current_time:
                    feedback_needed_activities.append(event_obj)
            except (ValueError, TypeError):
                continue

    # --- Part 3: Fetch ACADEMIC events ---
    subscriptions = StudentCourseSubscription.query.filter_by(student_entryno=user_id).all()
    if subscriptions:
        subscribed_course_codes = [sub.course_code for sub in subscriptions]
        relevant_academic_events = course_events.query.filter(course_events.course.in_(subscribed_course_codes)).all()
        student_group_map = {sub.course_code: sub.course_group for sub in subscriptions}

        for acad_event in relevant_academic_events:
            student_group = student_group_map.get(acad_event.course)
            if acad_event.target_group.lower() == 'all' or acad_event.target_group == student_group:
                if acad_event.day and acad_event.starttime:
                    start_datetime_str = f"{acad_event.day}T{acad_event.starttime}"
                    end_datetime_str = start_datetime_str 
                    calendar_events_data.append({
                        'title': f"{acad_event.course}: {acad_event.name}",
                        'start': start_datetime_str,
                        'end': end_datetime_str,
                        'description': acad_event.description,
                        'location': acad_event.venue,
                        'backgroundColor': '#4CAF50',
                        'borderColor': '#388E3C',
                        'extendedProps': {
                            'organiser': f"Course: {acad_event.course}",
                            'type': 'Academic Event'
                        }
                    })

    # --- Part 4: Recommendation Logic ---
    current_time = datetime.now()
    upcoming_events_for_reco = events.query.filter(
        events.date >= current_time.strftime('%Y-%m-%d')
    ).order_by(events.date.asc()).all()
    eligible_upcoming_events = []
    for event in upcoming_events_for_reco:
        # --- Check standard targeting criteria ---
        try:
            target_depts = json.loads(event.target_departments or "[]")
            target_yrs = json.loads(event.target_years or "[]")
            target_hostels = json.loads(event.target_hostels or "[]")
        except json.JSONDecodeError:
            target_depts, target_yrs, target_hostels = [], [], []

        # Check if user matches the target audience
        dept_match = not target_depts or user.department in target_depts
        year_match = not target_yrs or user.currentyear in target_yrs
        hostel_match = not target_hostels or user.hostel in target_hostels

        # Only add the event to the list if it's public AND the user is eligible
        if not event.is_private and dept_match and year_match and hostel_match:
            eligible_upcoming_events.append(event)
    recommended_events_list = get_recommendations(
        user=user,
        all_events=eligible_upcoming_events,
        registered_events=all_student_registered_activities,
        count=5
    )

    # --- Part 5: Render the template ---
    return render_template('student_portal.html',
                           recommend_events=recommended_events_list,
                           feedback_remaining=feedback_needed_activities,
                           calendar_events=json.dumps(calendar_events_data))

@app.route('/student/profile', methods=['GET', 'POST'])
def Synapse_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        user.name = request.form.get('name', user.name)
        user.currentyear = int(request.form.get('currentyear', user.currentyear))
        user.hostel = request.form.get('hostel', user.hostel)
        user.exityear = int(request.form.get('exityear', user.exityear))
        interests_list = request.form.getlist('interests')
        user.interest = json.dumps(interests_list) if interests_list else json.dumps([])
        if 'photo' in request.files:
            photo_file = request.files['photo']
            if photo_file.filename:
                filename = secure_filename(f"{user_id}_{photo_file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    photo_file.save(file_path)
                    user.photo = filename
                except Exception as e:

        try:
            db.session.commit()
            return redirect(url_for('Synapse_profile'))
        except Exception as e:
            db.session.rollback()


    current_interests = json_to_list(user.interest)
    all_possible_interests = ["Coding", "Music", "Sports", "Dance", "Literature", "Gaming", "Art", "Photography"]
    return render_template('profile.html', User=user, current_interests=current_interests, all_possible_interests=all_possible_interests)

@app.route('/student/events_to_join')
def student_events_to_join():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # --- Step 1: Get the set of clubs the user is an authorized member of ---
    authorized_clubs_query = EventAuthorization.query.filter_by(
        email=user.email, 
        event_type='club',
        is_active=True
    ).all()
    # A set is much faster for checking 'in'
    member_of_clubs = {auth.organization for auth in authorized_clubs_query}

    # --- Step 2: Get IDs of events the user has already registered for ---
    registered_event_ids = {reg.event_id for reg in students_events.query.filter_by(entryno=user.entryno).all()}
    
    # --- Step 3: Get all upcoming events the user is NOT registered for ---
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    all_upcoming_activities = events.query.filter(
        (func.coalesce(events.date, '') + ' ' + func.coalesce(events.starttime, '')) >= current_time_str,
        ~events.id.in_(registered_event_ids)
    ).order_by(events.date, events.starttime).all()

    # --- Step 4: Filter the activities based on user eligibility ---
    available_activities = []
    for activity in all_upcoming_activities:
        # --- LOGIC FOR PRIVATE EVENTS ---
        if activity.is_private:
            # A user can only see a private event if it's a club event
            # AND they are a member of that specific club.
            if activity.event_type == 'club' and activity.organiser in member_of_clubs:
                available_activities.append(activity)
        
        # --- LOGIC FOR PUBLIC EVENTS ---
        else: 
            # If it's not private, check standard targeting criteria.
            try:
                target_depts = json.loads(activity.target_departments or "[]")
                target_yrs = json.loads(activity.target_years or "[]")
                target_hostels = json.loads(activity.target_hostels or "[]")
            except json.JSONDecodeError:
                target_depts, target_yrs, target_hostels = [], [], []

            dept_match = not target_depts or user.department in target_depts
            year_match = not target_yrs or user.currentyear in target_yrs
            hostel_match = not target_hostels or user.hostel in target_hostels

            if dept_match and year_match and hostel_match:
                available_activities.append(activity)

    return render_template('event.html', Events=available_activities)

@app.route('/student/register/<string:event_name>', methods=['GET', 'POST'])
def register_for_event_page(event_name):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = db.session.get(Registration, user_id)
    event = events.query.filter_by(name=event_name).first_or_404()

    # Corrected to check by event_id
    existing_registration = students_events.query.filter_by(entryno=user_id, event_id=event.id).first()
    if existing_registration:
        flash("You are already registered for this event.", "info")
        return redirect(url_for('student_events_to_join'))
        
    if request.method == 'POST':
        try:
            # Corrected to use event_id
            new_registration = students_events(
                event_id=event.id,
                entryno=user.entryno,
                feedback=None 
            )
            db.session.add(new_registration)
            db.session.commit()

            for field in event.custom_form_fields:
                response_data = request.form.get(f'custom_field_{field.id}')
                if response_data:
                    new_response = CustomFormResponse(
                        registration_id=new_registration.srno,
                        field_id=field.id,
                        response_text=response_data
                    )
                    db.session.add(new_response)

            db.session.commit()
            flash(f"You have successfully registered for '{event.name}'!", "success")
            return redirect(url_for('Synapse_student'))

        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration. Please try again.", "error")
            return redirect(url_for('student_events_to_join'))

    custom_fields = event.custom_form_fields.order_by(CustomFormField.order).all()
    return render_template('register_for_event.html', event=event, user=user, custom_fields=custom_fields)

@app.route('/student/submit_feedback/<string:event_name>', methods=['POST'])
def submit_event_feedback(event_name):
    user_id = session.get('user_id')
    if not user_id: return redirect(url_for('login'))

    feedback_value = request.form.get('feedback_rating')
    if not feedback_value:
        flash("Feedback rating is required.", "error")
        return redirect(url_for('Synapse_student'))
    
    # Corrected to find event first, then registration by ID
    event = events.query.filter_by(name=event_name).first()
    if not event:
        flash("Event not found.", "error")
        return redirect(url_for('Synapse_student'))
        
    registration_record = students_events.query.filter_by(entryno=user_id, event_id=event.id).first()
    if registration_record:
        try:
            registration_record.feedback = int(feedback_value)
            db.session.commit()
            flash("Feedback submitted successfully!", "success")
        except ValueError:
            flash("Invalid feedback value.", "error")
        except Exception as e:
            db.session.rollback()
            flash("Error submitting feedback.", "error")
    else:
        flash("Registration not found for this event to submit feedback.", "warning")
    return redirect(url_for('Synapse_student'))

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
        share.is_active = False
        db.session.commit()
        return "Invalid calendar: The user associated with this link could not be found.", 404

    # Using the relationship is more efficient here
    registered_events_ids = [reg.event_id for reg in user.event_registrations]
    all_student_registered_activities = events.query.filter(events.id.in_(registered_events_ids)).all()

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
                'extendedProps': { 'organiser': reg_event.organiser }
            })

    return render_template('shared_calendar.html',
                           calendar_events=json.dumps(calendar_events_data),
                           user_name=user.name,
                           token=token)

@app.route('/calendar/<token>.ics')
def shared_calendar_ics(token):
    share = CalendarShare.query.filter_by(share_token=token, is_active=True).first()
    if not share:
        return "Invalid or expired ICS link.", 404
    user = Registration.query.get(share.user_id)
    if not user:
        return "User not found for this calendar.", 404

    # Using the relationship is more efficient here
    registered_events_ids = [reg.event_id for reg in user.event_registrations]
    all_student_registered_activities = events.query.filter(events.id.in_(registered_events_ids)).all()

    ics_content = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Synapse//IITD Event Calendar//EN\nCALSCALE:GREGORIAN\n'

    for event_item in all_student_registered_activities:
        if not all([event_item.date, event_item.starttime, event_item.endtime]):
            continue

        try:
            dtstart_str = f"{event_item.date.replace('-', '')}T{event_item.starttime.replace(':', '')}00"
            dtend_str = f"{event_item.date.replace('-', '')}T{event_item.endtime.replace(':', '')}00"
        except AttributeError:
            continue

        summary = (event_item.name or '').replace(',', '\\,').replace(';', '\\;')
        description = (event_item.description or '').replace('\n', '\\n').replace(',', '\\,').replace(';', '\\;')
        location = (event_item.venue or '').replace(',', '\\,').replace(';', '\\;')
        uid = f"Synapse-EVENT-{event_item.id}-{user.entryno}@iitd.ac.in"

        ics_content += f'BEGIN:VEVENT\nDTSTAMP:{datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}\nUID:{uid}\nDTSTART:{dtstart_str}\nDTEND:{dtend_str}\nSUMMARY:{summary}\nDESCRIPTION:{description}\nLOCATION:{location}\nEND:VEVENT\n'

    ics_content += 'END:VCALENDAR\n'

    return Response(
        ics_content,
        mimetype='text/calendar',
        headers={"Content-Disposition": "attachment;filename=Synapse_calendar.ics"}
    )

@app.route('/student/register_recommendation/<int:event_id>', methods=['POST'])
def register_from_recommendation(event_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to register.", "error")
        return redirect(url_for('login'))

    # 1. Check if the event exists
    event_to_join = events.query.get(event_id)
    if not event_to_join:
        flash("The event you tried to register for does not exist.", "error")
        return redirect(url_for('Synapse_student'))

    # 2. Check if the user is already registered
    already_registered = students_events.query.filter_by(
        entryno=user_id, 
        event_id=event_id
    ).first()

    if already_registered:
        flash(f"You are already registered for '{event_to_join.name}'.", "info")
        return redirect(url_for('Synapse_student'))

    # 3. Check if the event has custom registration questions
    if event_to_join.custom_form_fields.first():
        # If there are custom questions, we cannot do a one-click register.
        # We must redirect the user to the full registration page for that event.
        flash("This event has custom questions. Please complete the full registration form.", "info")
        return redirect(url_for('register_for_event_page', event_name=event_to_join.name))

    # 4. If all checks pass, create the registration
    new_registration = students_events(
        event_id=event_id, 
        entryno=user_id, 
        feedback=None
    )
    try:
        db.session.add(new_registration)
        db.session.commit()
        flash(f"Successfully registered for '{event_to_join.name}'!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while trying to register.", "error")
    
    return redirect(url_for('Synapse_student'))

@app.route('/student/academic_schedule')
def Synapse_schedule():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    subscriptions = StudentCourseSubscription.query.filter_by(student_entryno=user_id).order_by(StudentCourseSubscription.course_code).all()
    available_courses_query = db.session.query(CourseCoordinatorAuthorization.course_code).distinct().all()
    available_courses = [course.course_code for course in available_courses_query]
    
    return render_template(
        'academic_schedule.html', 
        subscriptions=subscriptions,
        available_courses=available_courses
    )

@app.route('/api/course_groups/<string:course_code>')
def get_course_groups(course_code):
    auth_record = CourseCoordinatorAuthorization.query.filter_by(course_code=course_code).first()
    if auth_record and auth_record.groups_json:
        try:
            groups = json.loads(auth_record.groups_json)
            return jsonify({'groups': groups})
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid group format for this course.'}), 500
    return jsonify({'groups': []})

@app.route('/student/subscribe_course', methods=['POST'])
def add_course_subscription():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    course_code = request.form.get('course_code', '').upper().strip()
    course_group = request.form.get('course_group', 'All').strip()

    if not course_code:
        flash("Course code cannot be empty.", "error")
        return redirect(url_for('Synapse_schedule'))

    existing_sub = StudentCourseSubscription.query.filter_by(student_entryno=user_id, course_code=course_code).first()
    if existing_sub:
        flash(f"You are already subscribed to {course_code}.", "info")
        return redirect(url_for('Synapse_schedule'))

    new_sub = StudentCourseSubscription(student_entryno=user_id, course_code=course_code, course_group=course_group)
    db.session.add(new_sub)
    db.session.commit()
    
    flash(f"Successfully subscribed to {course_code}.", "success")
    return redirect(url_for('Synapse_schedule'))

@app.route('/student/unsubscribe_course/<int:sub_id>', methods=['POST'])
def remove_course_subscription(sub_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    sub_to_delete = StudentCourseSubscription.query.filter_by(id=sub_id, student_entryno=user_id).first()
    if sub_to_delete:
        db.session.delete(sub_to_delete)
        db.session.commit()
        flash("Course subscription removed successfully.", "success")
    else:
        flash("Subscription not found or you are not authorized to remove it.", "error")
    
    return redirect(url_for('Synapse_schedule'))

# --- FEST PORTAL ---
@app.route('/fest')
def fest_dashboard():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('login'))
    
    auth = get_user_authorization(user_email, "fest_head", session.get('user_organization'))
    if not auth: 
        flash("You are not authorized to access this fest portal.", "error")
        return redirect(url_for('login'))

    fest_name = auth.organization
    manager_name = auth.name
    
    managed_events_list = events.query.filter_by(event_manager=manager_name, organiser=fest_name, event_type='fest').order_by(events.date.desc()).all()
    all_fest_events = events.query.filter_by(organiser=fest_name, event_type='fest').order_by(events.date.desc()).all()
    stats = get_organization_stats(fest_name, 'fest')
    
    return render_template('fest.html', 
                         portal_name=fest_name,
                         logo_url=url_for('static', filename='logo.png'),
                         portal_type='fest',
                         api_endpoint='/api/event',
                         edit_event_route='edit_fest_event',
                         fest_name=fest_name,
                         event_manager=manager_name,
                         managed_events=managed_events_list,
                         all_fest_events=all_fest_events,
                         stats=stats)

@app.route('/fest/create-event', methods=['POST'])
def create_fest_event():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized to create fest events.", 403

    name = request.form['eventName']
    if events.query.filter_by(name=name).first():
        flash("An event with this name already exists.", "error")
        return redirect(url_for('fest_dashboard'))

    photo_file = request.files.get("photo")
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"fest_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    new_event = events(
        name=name, photo=filename, event_manager=auth.name,
        organiser=auth.organization, description=request.form['description'], date=request.form['date'], 
        venue=request.form['venue'], starttime=request.form['starttime'], endtime=request.form['endtime'], 
        link=request.form.get("link"), tags=request.form.get("tags"), event_type='fest', 
        category=request.form.get('event_category'),
        target_departments=json.dumps(request.form.getlist("target_departments")),
        target_years=json.dumps(request.form.getlist("target_years")),
        target_hostels=json.dumps(request.form.getlist("target_hostels"))
    )
    try:
        db.session.add(new_event)
        db.session.commit()
        flash(f"Event '{name}' created successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while creating the event.", "error")
    return redirect(url_for('fest_dashboard'))

@app.route('/fest/edit-event/<string:event_name>', methods=['GET', 'POST'])
def edit_fest_event(event_name):
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('login'))
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    if not auth: return "Not authorized.", 403

    event_to_edit = events.query.filter_by(name=event_name, organiser=auth.organization, event_type='fest').first_or_404()
    if event_to_edit.event_manager != auth.name:
        flash("You can only edit events you manage.", "error")
        return redirect(url_for('fest_dashboard'))

    if request.method == 'POST':
        event_to_edit.description = request.form['description']
        event_to_edit.date = request.form['date']
        event_to_edit.starttime = request.form['starttime']
        event_to_edit.endtime = request.form['endtime']
        event_to_edit.venue = request.form['venue']
        event_to_edit.link = request.form.get('link')
        event_to_edit.tags = request.form.get('tags')
        event_to_edit.category = request.form.get('event_category')

        if 'photo' in request.files:
            photo = request.files['photo']
            if photo.filename:
                filename = secure_filename(f"fest_edit_{event_name.replace(' ','_')}_{photo.filename}")
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                event_to_edit.photo = filename
        try:
            db.session.commit()
            flash("Event updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error updating event.", "error")
        return redirect(url_for('fest_dashboard'))
    
    return render_template('edit_event.html', event=event_to_edit, event_type='fest')

@app.route('/api/event/<string:event_name>/registrations')
def get_event_registrations(event_name):
    user_email = session.get('user_email')
    if not user_email: return jsonify({'error': 'Not authenticated'}), 401
    
    event_obj = events.query.filter_by(name=event_name, event_type='fest').first_or_404()
    auth = get_user_authorization(user_email, "fest_head",session['user_organization'])
    
    is_authorized = (auth and auth.organization == event_obj.organiser) or (event_obj.event_manager == session.get('user_name'))
        
    if not is_authorized:
        return jsonify({'error': 'Not authorized to view these registrations'}), 403
    
    # Corrected to join and filter by event ID
    registrations_query = db.session.query(students_events, Registration).join(
        Registration, students_events.entryno == Registration.entryno
    ).filter(students_events.event_id == event_obj.id).all()
    
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
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    auth_role = session.get('auth_role')
    manager_name = session.get('user_name')

    if not all([user_email, organization, auth_role]):
        flash("Session is invalid. Please log in again.", "error")
        return redirect(url_for('login'))

    club_profile = ClubProfile.query.filter_by(organization_name=organization).first()
    managed_events_list = events.query.filter_by(event_manager=manager_name, organiser=organization, event_type='club').all()
    all_club_events_list = events.query.filter_by(organiser=organization, event_type='club').order_by(events.date.desc()).all()
    stats = get_organization_stats(organization, 'club')

    team_members, all_users_for_dropdown = [], []
    if auth_role == 'club_head':
        team_members = EventAuthorization.query.filter_by(organization=organization).order_by(EventAuthorization.role).all()
        current_member_emails = {member.email for member in team_members}
        all_users_for_dropdown = Registration.query.filter(
            Registration.is_verified == True,
            ~Registration.email.in_(current_member_emails)
        ).order_by(Registration.name).all()
    
    logo_url = url_for('uploaded_file', filename=club_profile.logo_path) if club_profile and club_profile.logo_path else url_for('static', filename='logo.png')

    return render_template(
        'club.html', portal_name=organization, logo_url=logo_url, portal_type='club',
        api_endpoint='/api/club-event', edit_event_route='edit_club_event', club_name=organization,
        club_manager_name=manager_name, managed_events=managed_events_list, stats=stats,
        all_club_events=all_club_events_list, club_profile=club_profile,
        team_members=team_members, all_users=all_users_for_dropdown,
        all_departments=ALL_DEPARTMENTS,
        all_hostels=ALL_HOSTELS,
        all_years=ALL_YEARS
    )

@app.route('/club/manage_team', methods=['POST'])
@club_head_required
def manage_team_action():
    action = request.form.get('action')
    target_email = request.form.get('email')
    target_role = request.form.get('role')
    auth_id = request.form.get('auth_id')
    club_name = session.get('user_organization')

    if action == 'add':
        user_to_add = Registration.query.filter_by(email=target_email).first()
        if not user_to_add:
            flash(f"User with email {target_email} not found.", "error")
            return redirect(url_for('club_dashboard'))
        if EventAuthorization.query.filter_by(email=target_email, organization=club_name).first():
            flash(f"{user_to_add.name} already has a role in this club.", "info")
            return redirect(url_for('club_dashboard'))
        
        new_auth = EventAuthorization(
            email=target_email, name=user_to_add.name, role=target_role, organization=club_name,
            event_type='club', authorized_by=session.get('user_email'), is_active=True
        )
        db.session.add(new_auth)
        flash(f"Successfully appointed {user_to_add.name} as {target_role.replace('_', ' ').title()}.", "success")

    elif action == 'remove':
        auth_to_remove = EventAuthorization.query.get(auth_id)
        if auth_to_remove and auth_to_remove.organization == club_name:
            if auth_to_remove.role == 'club_head':
                flash("Club Heads cannot be removed from this panel.", "error")
            else:
                db.session.delete(auth_to_remove)
                flash(f"Removed {auth_to_remove.name} from the team.", "success")
        else:
            flash("Authorization not found or invalid.", "error")

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
    return redirect(url_for('club_dashboard') + '#settings')

@app.route('/club/create-event', methods=['POST'])
def create_club_event():
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    auth = EventAuthorization.query.filter(
        EventAuthorization.email == user_email,
        EventAuthorization.organization == organization,
        EventAuthorization.role.in_(['club_head', 'club_coordinator', 'club_executive'])
    ).first()
    
    if not auth:
        flash("You do not have permission to create events for this club.", "error")
        return redirect(url_for('club_dashboard'))

    name = request.form['eventName']
    if events.query.filter_by(name=name).first():
        flash("An event with this name already exists. Please choose a unique name.", "error")
        return redirect(url_for('club_dashboard'))
    
    photo_file = request.files.get("photo")
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"club_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    try:
        new_event = events(
            name=name, photo=filename, event_manager=auth.name, organiser=auth.organization,
            description=request.form['description'], date=request.form['date'], venue=request.form['venue'],
            starttime=request.form['starttime'], endtime=request.form['endtime'], link=request.form.get("link"),
            tags=request.form.get("tags"), event_type='club', category=request.form.get('event_category'),
            target_departments=json.dumps(request.form.getlist("target_departments")),
            target_years=json.dumps([int(y) for y in request.form.getlist("target_years") if y.isdigit()]),
            target_hostels=json.dumps(request.form.getlist("target_hostels")),
            is_private=(request.form.get('is_private') == 'true')
        )
        db.session.add(new_event)
        
        custom_field_count = int(request.form.get('custom_field_count', 0))
        for i in range(custom_field_count):
            question_text = request.form.get(f'question_text_{i}')
            if question_text:
                new_field = CustomFormField(
                    event=new_event, question_text=question_text,
                    question_type=request.form.get(f'question_type_{i}'),
                    options_json=request.form.get(f'options_{i}'),
                    is_required=(request.form.get(f'is_required_{i}') == 'on'),
                    order=i
                )
                db.session.add(new_field)

        db.session.commit()
        flash(f"Event '{name}' created successfully!", "success")

    except Exception as e:
        db.session.rollback()
        flash("An error occurred while creating the event. Please check your inputs and try again.", "error")

    return redirect(url_for('club_dashboard'))

@app.route('/club/edit-event/<string:event_name>', methods=['GET', 'POST'])
def edit_club_event(event_name):
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    user_name = session.get('user_name')

    if not user_email or not organization:
        flash("Your session has expired. Please log in again.", "error")
        return redirect(url_for('login'))

    event_to_edit = events.query.filter_by(name=event_name, organiser=organization, event_type='club').first_or_404()
    
    # Authorization Check
    user_auth = EventAuthorization.query.filter_by(email=user_email, organization=organization).first()
    is_privileged = user_auth and user_auth.role in ['club_head', 'club_coordinator']
    is_event_manager = (event_to_edit.event_manager == user_name)

    if not (is_privileged or is_event_manager):
        flash("You are not authorized to edit this event.", "error")
        return redirect(url_for('club_dashboard'))

    if request.method == 'POST':
        try:
            # Update all fields from the form
            event_to_edit.description = request.form['description']
            event_to_edit.date = request.form['date']
            event_to_edit.starttime = request.form['starttime']
            event_to_edit.endtime = request.form['endtime']
            event_to_edit.venue = request.form['venue']
            event_to_edit.link = request.form.get('link')
            event_to_edit.tags = request.form.get('tags')
            event_to_edit.category = request.form.get('event_category')
            event_to_edit.target_departments = json.dumps(request.form.getlist("target_departments"))
            event_to_edit.target_years = json.dumps([int(y) for y in request.form.getlist("target_years") if y.isdigit()])
            event_to_edit.target_hostels = json.dumps(request.form.getlist("target_hostels"))
            event_to_edit.is_private = (request.form.get('is_private') == 'true')

            # Handle optional photo upload
            if 'photo' in request.files:
                photo = request.files['photo']
                if photo.filename:
                    filename = secure_filename(f"club_edit_{event_name.replace(' ','_')}_{photo.filename}")
                    photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    event_to_edit.photo = filename
            
            db.session.commit()
            flash(f"Event '{event_to_edit.name}' updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating the event.", "error")
        
        return redirect(url_for('club_dashboard'))
    
    # For GET request, render the pre-filled form
    return render_template('edit_event.html', 
                        event=event_to_edit, 
                        event_type='club',
                        all_departments=ALL_DEPARTMENTS,
                        all_hostels=ALL_HOSTELS,
                        all_years=ALL_YEARS)

@app.route('/club/update_profile', methods=['POST'])
@club_head_required
def update_club_profile():
    organization = session.get('user_organization')
    profile = ClubProfile.query.filter_by(organization_name=organization).first()
    if not profile:
        profile = ClubProfile(organization_name=organization)
        db.session.add(profile)

    profile.description = request.form.get('description')
    if 'logo' in request.files:
        logo_file = request.files['logo']
        if logo_file.filename:
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
@club_head_required
def export_club_data(export_type):
    organization = session.get('user_organization')
    si = io.StringIO()
    cw = csv.writer(si)

    if export_type == 'members':
        member_entry_numbers = db.session.query(students_events.entryno).join(events).filter(events.organiser == organization).distinct()
        members = Registration.query.filter(Registration.entryno.in_(member_entry_numbers)).all()
        cw.writerow(['EntryNo', 'Name', 'Email', 'Department', 'Year'])
        for member in members:
            cw.writerow([member.entryno, member.name, member.email, member.department, member.currentyear])
        filename = f"{organization.replace(' ', '_')}_members.csv"
    elif export_type == 'registrations':
        all_regs = db.session.query(Registration.entryno, Registration.name, Registration.email, events.name.label('event_name'), events.date)\
            .join(students_events, Registration.entryno == students_events.entryno)\
            .join(events, students_events.event_id == events.id)\
            .filter(events.organiser == organization).order_by(events.date).all()
        cw.writerow(['EntryNo', 'StudentName', 'StudentEmail', 'EventName', 'EventDate'])
        for reg in all_regs:
            cw.writerow([reg.entryno, reg.name, reg.email, reg.event_name, reg.date])
        filename = f"{organization.replace(' ', '_')}_all_registrations.csv"
    else:
        return "Invalid export type", 400

    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route('/api/club-event/<string:event_name>/registrations')
def get_club_event_registrations(event_name):
    user_email = session.get('user_email')
    organization = session.get('user_organization')
    user_name = session.get('user_name')

    if not user_email: 
        return jsonify({'error': 'Not authenticated'}), 401
    
    event_obj = events.query.filter_by(name=event_name, event_type='club').first_or_404()
    
    user_auth = EventAuthorization.query.filter_by(email=user_email, organization=organization).first()
    is_privileged = user_auth and user_auth.role in ['club_head', 'club_coordinator']
    is_event_manager = (event_obj.event_manager == user_name)

    if not (is_privileged or is_event_manager):
        return jsonify({'error': 'Not authorized to view these registrations'}), 403

    # Corrected to filter by event_id
    registrations = db.session.query(students_events, Registration)\
        .join(Registration, students_events.entryno == Registration.entryno)\
        .filter(students_events.event_id == event_obj.id).all()

    if not registrations:
        return jsonify({ 'event_name': event_name, 'total_registrations': 0, 'registrants': [], 'custom_fields': [], 'analytics': {} })

    registration_ids = [reg.srno for reg, student in registrations]
    all_responses = CustomFormResponse.query.filter(CustomFormResponse.registration_id.in_(registration_ids)).all()

    responses_by_reg_id = {}
    for response in all_responses:
        if response.registration_id not in responses_by_reg_id:
            responses_by_reg_id[response.registration_id] = {}
        responses_by_reg_id[response.registration_id][response.field_id] = response.response_text

    registrants_data = []
    for reg, student in registrations:
        custom_answers = responses_by_reg_id.get(reg.srno, {})
        registrants_data.append({
            'name': student.name, 'email': student.email, 'entryno': student.entryno,
            'department': student.department, 'year': student.currentyear,
            'custom_answers': custom_answers
        })
    
    analytics = { 'year_distribution': {}, 'department_distribution': {}, 'custom_question_analytics': {} }
    for registrant in registrants_data:
        year = registrant.get('year', 'Unknown')
        analytics['year_distribution'][year] = analytics['year_distribution'].get(year, 0) + 1
        dept = registrant.get('department', 'Unknown')
        analytics['department_distribution'][dept] = analytics['department_distribution'].get(dept, 0) + 1

    custom_fields = CustomFormField.query.filter_by(event_id=event_obj.id).order_by(CustomFormField.order).all()
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
    if not user_email: return redirect(url_for('login'))
    
    auth = get_user_authorization(user_email, "department_head", session.get('user_organization'))
    if not auth:
        flash("You are not authorized to access this department portal.", "error")
        return redirect(url_for('login'))

    department_name = auth.organization
    manager_name = auth.name
    
    managed_activities_list = events.query.filter_by(event_manager=manager_name, organiser=department_name, event_type='department_activity').order_by(events.date.desc()).all()
    all_department_activities = events.query.filter_by(organiser=department_name, event_type='department_activity').order_by(events.date.desc()).all()
    stats = get_organization_stats(department_name, 'department_activity', manager_name)

    return render_template('department.html',
                           portal_name=department_name,
                           logo_url=url_for('static', filename='logo.png'),
                           portal_type='department',
                           api_endpoint='/api/department-activity',
                           edit_event_route='edit_department_activity',
                           department_name=department_name, 
                           department_manager_name=manager_name,
                           managed_activities=managed_activities_list,
                           all_department_activities=all_department_activities,
                           stats=stats)

@app.route('/department/create-activity', methods=['POST'])
def create_department_activity():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized to create department activities.", 403

    name = request.form['eventName']
    if events.query.filter_by(name=name).first():
        flash("An activity with this name already exists.", "error")
        return redirect(url_for('department_dashboard'))

    photo_file = request.files.get("photo")
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"dept_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    new_activity = events(
        name=name, photo=filename, event_manager=auth.name, organiser=auth.organization,
        description=request.form['description'], date=request.form['date'], venue=request.form['venue'],
        starttime=request.form['starttime'], endtime=request.form['endtime'], link=request.form.get("link"),
        tags=request.form.get("tags"), event_type='department_activity', category=request.form.get('event_category'),
        target_departments=json.dumps(request.form.getlist("target_departments")),
        target_years=json.dumps([int(y) for y in request.form.getlist("target_years") if y.isdigit()]),
        target_hostels=json.dumps(request.form.getlist("target_hostels"))
    )
    try:
        db.session.add(new_activity)
        db.session.commit()
        flash("Activity created successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error creating activity.", "error")
    return redirect(url_for('department_dashboard'))

@app.route('/department/edit-activity/<string:activity_name>', methods=['GET', 'POST'])
def edit_department_activity(activity_name):
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('login'))
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    if not auth: return "Not authorized.", 403

    activity_to_edit = events.query.filter_by(name=activity_name, organiser=auth.organization, event_type='department_activity').first_or_404()
    if activity_to_edit.event_manager != auth.name:
        flash("You can only edit activities you manage.", "error")
        return redirect(url_for('department_dashboard'))

    if request.method == 'POST':
        activity_to_edit.description = request.form['description']
        # ... and so on for other fields ...
        try:
            db.session.commit()
            flash("Activity updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error updating activity.", "error")
        return redirect(url_for('department_dashboard'))
    
    return render_template('edit_event.html', event=activity_to_edit, event_type='department_activity')

@app.route('/api/department-activity/<string:activity_name>/registrations')
def get_department_activity_registrations(activity_name):
    user_email = session.get('user_email')
    if not user_email: return jsonify({'error': 'Not authenticated'}), 401
    
    activity_obj = events.query.filter_by(name=activity_name, event_type='department_activity').first_or_404()
    auth = get_user_authorization(user_email, "department_head",session['user_organization'])
    
    is_authorized = (auth and auth.organization == activity_obj.organiser) or (activity_obj.event_manager == session.get('user_name'))
        
    if not is_authorized:
        return jsonify({'error': 'Not authorized to view these registrations'}), 403
    
    # Corrected to join and filter by event ID
    registrations_query = db.session.query(students_events, Registration).join(
        Registration, students_events.entryno == Registration.entryno
    ).filter(students_events.event_id == activity_obj.id).all()
    
    registration_data = [{
        'name': student.name, 'email': student.email, 'entryno': student.entryno,
        'department': student.department, 'feedback': reg.feedback
    } for reg, student in registrations_query]
    
    return jsonify({
        'activity_name': activity_name,
        'total_registrations': len(registration_data),
        'registrations': registration_data
    })

# --- COURSE COORDINATOR PORTAL ---
@app.route('/course_coordinator')
def course_coordinator_dashboard():
    user_email = session.get('user_email')
    user_id = session.get('user_id')
    if not all([user_email, user_id]):
        return redirect(url_for('login'))
    
    # Corrected to query by entryno
    managed_courses = CourseCoordinatorAuthorization.query.filter_by(coordinator_entryno=user_id).all()
    
    return render_template('course.html', 
                           managed_courses=managed_courses,
                           coordinator_name=session.get('user_name', 'Coordinator'))

@app.route('/course_coordinator/create_event', methods=['POST'])
def create_academic_event():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    course_code = request.form.get('course_code')
    # Corrected security check
    is_authorized = CourseCoordinatorAuthorization.query.filter_by(
        coordinator_entryno=user_id,
        course_code=course_code
    ).first()

    if not is_authorized:
        flash("You are not authorized to add events to this course.", "error")
        return redirect(url_for('course_coordinator_dashboard'))

    new_academic_event = course_events(
        name=request.form.get('name'), course=course_code, description=request.form.get('description'),
        day=request.form.get('day'), venue=request.form.get('venue'), starttime=request.form.get('starttime'),
        target_group=request.form.get('target_group', 'All')
    )
    
    try:
        db.session.add(new_academic_event)
        db.session.commit()
        flash(f"Academic event '{new_academic_event.name}' created successfully for {course_code}.", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while creating the event.", "error")

    return redirect(url_for('course_coordinator_dashboard'))

@app.route('/course_coordinator/update_structure', methods=['POST'])
def update_course_structure():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    course_code = request.form.get('course_code')
    
    # Corrected security check
    auth_record = CourseCoordinatorAuthorization.query.filter_by(
        coordinator_entryno=user_id,
        course_code=course_code
    ).first()

    if not auth_record:
        flash("You are not authorized to manage this course.", "error")
        return redirect(url_for('course_coordinator_dashboard'))

    groups_str = request.form.get('groups', '')
    groups_list = [group.strip() for group in groups_str.split(',') if group.strip()]
    auth_record.groups_json = json.dumps(groups_list)
    
    try:
        db.session.commit()
        flash(f"Structure for {course_code} updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while updating the course structure.", "error")
        
    return redirect(url_for('course_coordinator_dashboard'))

# --- ADMIN PORTAL ---
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
        event_type_map = { 'club_head': 'club', 'fest_head': 'fest', 'department_head': 'department_activity' }
        event_type = event_type_map.get(role)
        if not event_type:
            flash("Invalid role prefix selected.", "error")
            return redirect(url_for('admin_dashboard'))
        
        if EventAuthorization.query.filter_by(email=email, role=role, organization=organization).first():
            flash(f"{user.name} is already authorized as a {role.replace('_', ' ')} for {organization}.", "info")
        else:
            new_auth = EventAuthorization(
                email=email, name=user.name, role=role, organization=organization,
                event_type=event_type, authorized_by=session.get('user_email')
            )
            db.session.add(new_auth)
            flash(f"Successfully authorized {user.name} for {organization}.", "success")

    elif auth_type == 'course_coord':
        course_code = request.form.get('course_code').upper().strip()

        # Corrected to use entryno
        if CourseCoordinatorAuthorization.query.filter_by(coordinator_entryno=user.entryno, course_code=course_code).first():
            flash(f"{user.name} is already a coordinator for {course_code}.", "info")
        else:
            new_auth = CourseCoordinatorAuthorization(
                coordinator_entryno=user.entryno,
                course_code=course_code
            )
            db.session.add(new_auth)
            flash(f"Successfully authorized {user.name} as coordinator for {course_code}.", "success")
    else:
        flash("Invalid authorization type.", "error")
        
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