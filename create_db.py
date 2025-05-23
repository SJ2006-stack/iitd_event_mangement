# create_db.py
# Make sure your main Flask app file (e.g., app_py_complete.py or app.py)
# contains the SQLAlchemy instance (db) and all your model definitions.
# This script will import 'app' and 'db' from that file.

# Assuming your main Flask app file is named app_py_complete.py
# If it's app.py, change the import to: from app import app, db
from app import app, db 
from datetime import datetime # Import datetime if any models in app_py_complete.py use it for default values and it's not already there.

def initialize_database():
    """
    Creates all database tables based on the defined SQLAlchemy models
    in your main application file (e.g., app_py_complete.py)
    if they don't already exist.
    """
    with app.app_context():
        print("Initializing database and creating tables...")
        try:
            # The db.Model definitions (Registration, CalendarShare, etc.)
            # should be in app_py_complete.py (or your main app file)
            # and associated with the 'db' instance imported from there.
            db.create_all()
            print("Database tables created successfully (if they didn't exist).")
            print("If you made changes to existing models, consider using Flask-Migrate for migrations.")
        except Exception as e:
            print(f"An error occurred during database initialization: {e}")

if __name__ == "__main__":
    # This allows you to run this script directly: python create_db.py
    # Make sure your DATABASE_URL environment variable is set correctly in your .env file
    # and that your main app file (e.g., app_py_complete.py) can access it and defines the models.
    
    # Important: For production or complex changes, Flask-Migrate is highly recommended
    # to handle schema changes without data loss. This script is primarily for initial setup
    # or simple updates where data loss is not a concern or tables are empty.

    print("Attempting to initialize the database...")
    initialize_database()
    print("\nScript finished.")
    print("Please ensure your Flask-Migrate setup is also up to date if you are managing schema changes.")
    print("You can typically run 'flask db upgrade' after 'flask db migrate' for migrations.")

