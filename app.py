from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
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
from flask import Response
from datetime import datetime

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
    password = db.Column(db.String(128), nullable=False) # Store hashed passwords
    hostel = db.Column(db.String(30), nullable=True)
    role = db.Column(db.String(255), nullable=False)  # JSON string of roles
    department = db.Column(db.String(100))
    photo = db.Column(db.String(255)) # Path to photo
    interest = db.Column(db.String(500)) # JSON string of interests
    entryyear=db.Column(db.Integer,nullable=False)
    exityear=db.Column(db.Integer,nullable=False)
    currentyear=db.Column(db.Integer,nullable=True)
    course=db.Column(db.String(30), nullable=True)

class CalendarShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(11), db.ForeignKey('registration.entryno'), nullable=False)
    share_token = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    registration = db.relationship('Registration', backref=db.backref('calendar_shares', lazy=True))

class EventAuthorization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True) # Should match a Registration email
    name = db.Column(db.String(100), nullable=False) # Name of the authorized person
    role = db.Column(db.String(50), nullable=False)  # 'club_head', 'fest_head', 'department_head', 'admin'
    organization = db.Column(db.String(100), nullable=False)  # Club name, Fest name, or Department name
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
    target_departments = db.Column(db.String(500), nullable=True)  # JSON or comma-separated
    target_years = db.Column(db.String(100), nullable=True)  # JSON or comma-separated integers
    target_hostels= db.Column(db.String(500), nullable=True)

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

# --- Helper Functions ---
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


def get_user_authorization(email, expected_role_prefix):
    auth_record = EventAuthorization.query.filter(
        EventAuthorization.email == email,
        EventAuthorization.role.startswith(expected_role_prefix),
        EventAuthorization.is_active == True
    ).first()
    return auth_record

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


# --- Routes ---
@app.route('/uploads/<path:filename>') # Use path converter for flexibility
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# --- Authentication Routes ---
@app.route('/', methods=['GET', 'POST'])
def kars_registration_or_login(): # Combined landing page
    # if 'user_id' in session: # If already logged in, redirect appropriately
    #     # This logic could be more sophisticated based on last role or a default dashboard
    #     return redirect(url_for('kars_student')) # Default to student portal for now
    if request.method == 'POST':
        # This form should distinguish between login and registration actions
        # For simplicity, assuming it's a registration attempt if certain fields are present
        print(request.form)
        if 'name' in request.form and 'confirm_password' in request.form: # Registration
            name = request.form['name']
            hostel = request.form['hostel']
            email = request.form['email'].lower()
            entryno_parts = email.split('@')
            course=request.form['course']
            if len(entryno_parts) > 0 and entryno_parts[0]:
                entryno = to_entryno(entryno_parts[0]) # Using email prefix as entryno
            else:
                return "Invalid email format for entry number generation.", 400
            password = request.form['password']
            confirm_password = request.form['confirm_password']            
            if password != confirm_password:
                return "Passwords do not match.", 400
            if not email.endswith("@iitd.ac.in"): # Example domain
                return "Only @iitd.ac.in emails are allowed for registration.", 400
            if Registration.query.filter_by(email=email).first():
                return "Email already registered.", 400
            if Registration.query.filter_by(entryno=entryno).first():
                 return "Entry number already registered (derived from email).", 400
            hashed_password = hashlib.sha256(password.encode()).hexdigest() # Basic hashing, consider bcrypt
            role_json = json.dumps(['student'])

            session['registration_data'] = {
                'entryno': entryno, 'name': name,'hostel':hostel, 'email': email,
                'password': hashed_password, 'role': role_json,
                'interest': json.dumps([]), 'photo': None, 'department': find_department(entryno),
                'entryyear':int(entryno[:4]),'course':course,'exityear':int(entryno[:4])+cousre_duration(course)
            }
            
            otp = "".join([str(random.randint(0,9)) for _ in range(6)])
            session['otp'] = otp
            session['otp_email'] = email # Store email for OTP verification page
            
            if send_otp_email(email, otp):
                return redirect(url_for('verify_otp'))
            else:
                # For testing if email fails, allow proceeding or show error
                # return "OTP email could not be sent. Please try again later or contact support.", 500
                print(f"DEBUG: OTP for {email} is {otp} (email sending failed or disabled)")
                return redirect(url_for('verify_otp')) # Proceed for testing without email
        else: # Login
            email = request.form['email'].lower()
            password = request.form['password']
            # Role selection at login is important for portal access
            login_role_selection = request.form.get('role') # e.g. "student", "fest_head", "club_head"

            user = Registration.query.filter_by(email=email).first()
            hashed_password_attempt = hashlib.sha256(password.encode()).hexdigest()

            if user and user.password == hashed_password_attempt:
                session['user_id'] = user.entryno
                session['user_email'] = user.email
                session['user_name'] = user.name
                
                user_roles = json_to_list(user.role)

                # Redirect logic based on login_role_selection and actual user roles/authorizations
                if login_role_selection == "student" and "student" in user_roles:
                    return redirect(url_for('kars_student'))
                
                auth_record = None
                if login_role_selection and login_role_selection != "student":
                    # Map form role to auth role prefix
                    # e.g., if form has "fest_manager", map to "fest_head" for get_user_authorization
                    role_prefix_map = {
                        "fest": "fest_head", # Assuming form might use 'fest_manager'
                        "club": "club_head",
                        "department": "department_head",
                        # Direct mapping if form uses the exact EventAuthorization roles
                        "fest_head": "fest_head",
                        "club_head": "club_head",
                        "department_head": "department_head"
                    }
                    auth_role_prefix = role_prefix_map.get(login_role_selection)

                    if auth_role_prefix:
                        auth_record = get_user_authorization(user.email, auth_role_prefix)

                if auth_record:
                    session['user_organization'] = auth_record.organization # Store club/fest/dept name
                    session['auth_role'] = auth_record.role # Store the specific authorized role

                    if auth_record.role.startswith("fest_head"):
                        return redirect(url_for('fest_dashboard'))
                    elif auth_record.role.startswith("club_head"):
                        return redirect(url_for('club_dashboard'))
                    elif auth_record.role.startswith("department_head"):
                        return redirect(url_for('department_dashboard'))
                
                # Fallback if selected role auth fails or no specific portal role chosen
                if "student" in user_roles:
                    return redirect(url_for('kars_student'))
                else:
                    return "No suitable portal found for your roles.", 403
            else:
                return "Invalid email or password.", 401
    return render_template('login.html') # Your main login/registration page

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or 'registration_data' not in session:
        return redirect(url_for('kars_registration_or_login'))
    target_email = session.get('otp_email', 'the provided email')
    if request.method == 'POST':
        submitted_otp = "".join([request.form.get(f'digit{i+1}', '') for i in range(6)])
        if submitted_otp == session['otp']:
            reg_data = session['registration_data']
            new_user = Registration(**reg_data)
            try:
                db.session.add(new_user)
                db.session.commit()
                session.pop('otp', None)
                session.pop('registration_data', None)
                session.pop('otp_email', None)
                # Log in the user directly after successful registration
                session['user_id'] = new_user.entryno
                session['user_email'] = new_user.email
                session['user_name'] = new_user.name
                return redirect(url_for('kars_student')) # Redirect to student portal or profile setup
            except Exception as e:
                db.session.rollback()
                print(f"Error during registration commit: {e}")
                return "Registration failed due to a database error. Please try again.", 500
        else:
            return render_template('otp.html', error="Incorrect OTP. Please try again.", email=target_email)
    return render_template('otp.html', email=target_email)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('kars_registration_or_login'))

# --- Student Portal Routes (largely from your existing code, with minor adjustments) ---
@app.route('/student')
def kars_student():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('kars_registration_or_login'))
    
    user = db.session.get(Registration, user_id)
    if not user:
        session.clear() # Clear invalid session
        return redirect(url_for('kars_registration_or_login'))
    
    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    current_time = datetime.now()
    
    all_student_registered_activities = events.query.filter(events.name.in_(registered_event_names)).all()
    
    upcoming_student_activities = []
        # app.py - inside the /student route

    # ... existing code ...

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

    # # Add academic schedule events
    # for course_event in course_events_obj:
    #     # Construct ISO 8601 strings for start and end
    #     # Assuming course_event.day is 'YYYY-MM-DD' and starttime is 'HH:MM'
    #     # If course_event doesn't have an endtime, you might use starttime for both or calculate a default duration
    #     start_datetime_str = f"{course_event.day}T{course_event.starttime}"
    #     # Example if endtime is missing: assume 1 hour duration
    #     # You might need to parse start_datetime_str into datetime object to add 1 hour
    #     # For now, let's assume it's also available or default
    #     end_datetime_str = f"{course_event.day}T{course_event.starttime}" # Adjust if course_events has an endtime

    #     calendar_events_data.append({
    #         'title': course_event.name,
    #         'start': start_datetime_str,
    #         'end': end_datetime_str, # Make sure this is correct for course events
    #         'description': course_event.description,
    #         'location': course_event.venue,
    #         'extendedProps': { # Use extendedProps for custom data
    #             'course': course_event.course
    #         }
    #     })
    recommend_events = events.query.filter(events.name.notin_(registered_event_names)).order_by(events.date.desc()).limit(5).all()

    feedback_pending_regs = students_events.query.filter(
        students_events.entryno == user.entryno,
        (students_events.feedback == None) | (students_events.feedback == 0) # Assuming 0 or None means pending
    ).all()

    feedback_needed_activities = []
    for reg in feedback_pending_regs:
        event_obj = events.query.filter_by(name=reg.event_name).first()
        if event_obj and event_obj.date and event_obj.starttime:
            try:
                event_datetime = datetime.strptime(f"{event_obj.date} {event_obj.starttime}", "%Y-%m-%d %H:%M")
                if event_datetime < current_time: # Only ask for feedback for past events
                    feedback_needed_activities.append(event_obj) # Pass the event object
            except (ValueError, TypeError):
                continue
    

    return render_template('student_portal.html',
                        recommend_events=recommend_events,
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

    registered_event_names = [reg.event_name for reg in students_events.query.filter_by(entryno=user.entryno).all()]
    
    current_time = datetime.now()
    available_activities = []

    all_upcoming_activities = events.query.filter(
        ~events.name.in_(registered_event_names)
    ).order_by(events.date, events.starttime).all()

    for activity in all_upcoming_activities:
        if activity.date and activity.starttime:
            try:
                activity_datetime = datetime.strptime(f"{activity.date} {activity.starttime}", "%Y-%m-%d %H:%M")
                if activity_datetime >= current_time:
                    # Load target filters
                    try:
                        target_depts = json.loads(activity.target_departments or "[]")
                        target_yrs = json.loads(activity.target_years or "[]")
                        target_hostels = json.loads(activity.target_hostels or "[]")
                    except json.JSONDecodeError:
                        target_depts, target_yrs, target_hostels = [], [], []

                    # Match eligibility
                    if (not target_depts or user.department in target_depts) and \
                       (not target_yrs or user.currentyear in target_yrs) and \
                       (not target_hostels or user.hostel in target_hostels):
                        available_activities.append(activity)
            except (ValueError, TypeError):
                continue  # Skip if date/time is invalid

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

# --- Calendar Sharing Routes (from your existing code, ensure they use event_name) ---
# ... (generate_calendar_link, shared_calendar, shared_calendar_ics, revoke_calendar_link, email_calendar)
# Make sure these routes fetch event_name from students_events table.

# --- Fest, Club, Department Portal Routes ---
# Common function to get stats
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


@app.route('/student/academic_schedule')
def kars_schedule():
    return render_template('academic_schedule.html')

# --- FEST PORTAL ---
@app.route('/fest')
def fest_dashboard():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head")
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
    auth = get_user_authorization(user_email, "fest_head")
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
    auth = get_user_authorization(user_email, "fest_head")
    if not auth: return "Not authorized.", 403
    return render_template('fest.html', fest_name=auth.organization, event_manager=auth.name, events=[], upcoming_events=0, total_registrations=0, current_tab='settings')

@app.route('/fest/create-event', methods=['POST'])
def create_fest_event():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "fest_head")
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
    auth = get_user_authorization(user_email, "fest_head")
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
    auth = get_user_authorization(user_email, "fest_head")
    
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
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "club_head")
    if not auth: return "Not authorized as Club Head.", 403

    club_name = auth.organization
    manager_name = auth.name
    
    managed_events_list = events.query.filter_by(event_manager=manager_name, organiser=club_name, event_type='club').all()
    stats = get_organization_stats(club_name, 'club', manager_name)

    return render_template('club.html',
                           club_name=club_name, club_manager_name=manager_name,
                           managed_events=managed_events_list, # For "My Managed Events"
                           stats=stats,
                           current_tab='dashboard')

@app.route('/club/events') # Shows all events of this club
def club_all_events():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "club_head")
    if not auth: return "Not authorized.", 403

    club_name = auth.organization
    all_club_events_list = events.query.filter_by(organiser=club_name, event_type='club').all()
    stats = get_organization_stats(club_name, 'club') # Overall club stats

    return render_template('club.html',
                           club_name=club_name, club_manager_name=auth.name,
                           all_club_events=all_club_events_list, # For "All Club Events" tab
                           managed_events=[], # Or pass managed_events if needed on this view
                           stats=stats,
                           current_tab='events')

@app.route('/club/settings')
def club_settings():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "club_head")
    if not auth: return "Not authorized.", 403
    return render_template('club.html', club_name=auth.organization, club_manager_name=auth.name, stats={}, current_tab='settings')


@app.route('/club/create-event', methods=['POST'])
def create_club_event():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "club_head")
    if not auth: return "Not authorized to create club events.", 403

    club_name_org = auth.organization
    event_manager_name = auth.name

    name = request.form['eventName']
    description = request.form['description']
    date = request.form['date']
    starttime = request.form['starttime']
    endtime = request.form['endtime']
    venue = request.form['venue']
    link = request.form.get("link")
    tags = request.form.get("tags")
    target_departments = request.form.getlist("target_departments")
    target_years = request.form.getlist("target_years")
    target_hostels = request.form.getlist("target_hostels")
    event_category = request.form.get('event_category') # From club.html modal

    photo_file = request.files.get("photo")
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"club_{name.replace(' ','_')}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    if events.query.filter_by(name=name).first(): # Check for unique event name
        # Add flash message "Event name already exists"
        return redirect(url_for('club_dashboard'))

    new_event = events(
        name=name, photo=filename, event_manager=event_manager_name,
        organiser=club_name_org, description=description, date=date, venue=venue,
        starttime=starttime, endtime=endtime, link=link, tags=tags,
        event_type='club', category=event_category,
        target_departments=json.dumps(target_departments),
        target_years=json.dumps([int(y) for y in target_years]),
        target_hostels=json.dumps(target_hostels)
    )
    try:
        db.session.add(new_event)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error creating club event: {e}")
    return redirect(url_for('club_dashboard'))


@app.route('/club/edit-event/<string:event_name>', methods=['GET', 'POST'])
def edit_club_event(event_name):
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "club_head")
    if not auth: return "Not authorized.", 403

    event_to_edit = events.query.filter_by(name=event_name, organiser=auth.organization, event_type='club').first_or_404()
    if event_to_edit.event_manager != auth.name:
        return "You can only edit events you manage for this club.", 403

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
                filename = secure_filename(f"club_edit_{event_name.replace(' ','_')}_{photo.filename}")
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                event_to_edit.photo = filename
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error editing club event: {e}")
        return redirect(url_for('club_dashboard'))
    
    return render_template('edit_event.html', event=event_to_edit, event_type='club') # Reusing fest's edit template


@app.route('/api/club-event/<string:event_name>/registrations')
def get_club_event_registrations(event_name):
    user_email = session.get('user_email')
    if not user_email: return jsonify({'error': 'Not authenticated'}), 401
    
    event_obj = events.query.filter_by(name=event_name, event_type='club').first_or_404()
    auth = get_user_authorization(user_email, "club_head")
    
    is_authorized = False
    if auth and auth.organization == event_obj.organiser: is_authorized = True
    if event_obj.event_manager == session.get('user_name'): is_authorized = True
        
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


# --- DEPARTMENT PORTAL ---
@app.route('/department')
def department_dashboard():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head")
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
    auth = get_user_authorization(user_email, "department_head")
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
    auth = get_user_authorization(user_email, "department_head")
    if not auth: return "Not authorized.", 403
    return render_template('department.html', department_name=auth.organization, department_manager_name=auth.name, stats={}, current_tab='settings')


@app.route('/department/create-activity', methods=['POST'])
def create_department_activity():
    user_email = session.get('user_email')
    if not user_email: return redirect(url_for('kars_registration_or_login'))
    auth = get_user_authorization(user_email, "department_head")
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
    auth = get_user_authorization(user_email, "department_head")
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
    auth = get_user_authorization(user_email, "department_head")
    
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


if __name__ == "__main__":
    # with app.app_context():
    #     # You can use this to create tables if not using migrations for the first time
    #     # db.create_all()
    #     pass
    app.run(debug=True, port=5000)