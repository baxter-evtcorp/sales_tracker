from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, timezone, date # Explicitly import 'date'
from calendar import monthrange # Added for month range
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort # Added flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # current_user is here
from flask_cors import CORS
from flask_migrate import Migrate
from sqlalchemy import MetaData, or_, extract, func # Added for dashboard filtering
from sqlalchemy.orm import joinedload, contains_eager # Import joinedload
# Corrected SendGrid imports
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email as SendGridEmail, To, Content, MimeType
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView # Import AdminIndexView
from flask_admin.menu import MenuLink # Import MenuLink
from wtforms import Form # Added Form
from wtforms.fields import PasswordField, StringField, SelectField # Added SelectField
from wtforms.validators import DataRequired, Length, Email, Optional, NumberRange
import click  # Added for CLI
import bcrypt # Added for password hashing
import random # Added for seeding
from flask import url_for, redirect, request # Added for redirect
from werkzeug.utils import secure_filename # Added for file uploads
import enum # Added for AttachmentType
from flask_wtf import FlaskForm # Added for attachment form
from wtforms import FileField, SelectField as WTSelectField, SubmitField # Added for attachment form fields
from wtforms import DecimalField, DateField, TextAreaField # Added for DealForm fields
from wtforms_sqlalchemy.fields import QuerySelectField # Updated import for WTForms-SQLAlchemy
from flask_wtf.file import FileAllowed, FileRequired # Added for file upload validation
from flask_wtf import FlaskForm # Added for attachment form
from wtforms.validators import DataRequired # Added for attachment form validators
from flask import send_from_directory # Added for serving files


# --- App Initialization ---
app = Flask(__name__, instance_relative_config=True)
app.jinja_env.add_extension('jinja2.ext.do') # Enable the 'do' extension

# Context processor to inject 'now' for templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# --- Configuration Loading ---
# Load .env file first
load_dotenv()

# Database configuration
def get_database_uri():
    # Prefer DATABASE_URL from environment variable (for production/external DBs)
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        print("---> [DB Config] Using DATABASE_URL from environment")
        # Ensure SQLAlchemy uses 'postgresql' scheme for psycopg2
        if database_url.startswith("postgres://"): 
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        return database_url
    else:
        # Fallback to SQLite in instance folder for local development if DATABASE_URL not set
        basedir = os.path.abspath(os.path.dirname(__file__))
        instance_path = os.path.join(basedir, 'instance')
        db_path = os.path.join(instance_path, 'site.db')
        print(f"---> [DB Config] Using SQLite fallback: {db_path}")
        return f'sqlite:///{db_path}'

# Secret Key configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key_only_for_dev')
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads', 'deals') # Define upload folder

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    print(f"---> [App Setup] Created upload folder: {app.config['UPLOAD_FOLDER']}")

# Print final DB URI being used
print(f"---> [Flask App] FINAL Database URI set to: {app.config['SQLALCHEMY_DATABASE_URI']}")

# SendGrid Configuration (already reading from os.environ)
app.config['SENDGRID_API_KEY'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_FROM_EMAIL'] = os.environ.get('MAIL_FROM_EMAIL')

# Debug print Flask config for SendGrid keys
print(f"--- DEBUG: Flask Config API Key: {app.config.get('SENDGRID_API_KEY')} ---")
print(f"--- DEBUG: Flask Config From Email: {app.config.get('MAIL_FROM_EMAIL')} ---")


# --- Password Hashing --- 
def set_password(password):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode('utf-8')

def check_password(stored_hash, provided_password):
    stored_hash_bytes = stored_hash.encode('utf-8')
    provided_password_bytes = provided_password.encode('utf-8')
    return bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)

# --- Email Helper Function (SendGrid) ---
def send_email(to, subject, body, html_body=None):
    api_key = app.config.get('SENDGRID_API_KEY')
    from_email = app.config.get('MAIL_FROM_EMAIL')
    if not api_key or not from_email:
        print("Error: Email configuration missing.")
        return False
    message = Mail(
        from_email=from_email,
        to_emails=to,
        subject=subject,
        plain_text_content=body
    )
    if html_body:
        message.add_content(Content(mime_type='text/html', content=html_body))
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        print(f"Email sent! Status Code: {response.status_code}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# --- Database Setup ---
db = SQLAlchemy(app)
migrate = Migrate(app, db) # Initialize Flask-Migrate
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to 'login' view if @login_required fails

# Configure Naming Convention for SQLAlchemy/Alembic
# (Required for SQLite compatibility with Flask-Migrate batch mode)
convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}
metadata = MetaData(naming_convention=convention)

# --- Extensions Initialization ---
CORS(app, resources={r"/api/*": {"origins": "*"}}) # Basic CORS for API routes
# Pass metadata to SQLAlchemy for naming convention

# Custom Admin Index View with Role Check
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and hasattr(current_user, 'role') and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        else:
            return redirect(url_for('index'))

# Initialize Admin with custom index view
admin = Admin(app, name='Activity Tracker Admin', index_view=MyAdminIndexView())

# Base Admin View with Role Check
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and hasattr(current_user, 'role') and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        else:
            return redirect(url_for('index'))

# Custom Form for Editing Users
class UserEditForm(Form):
    email = StringField('Email')
    # Use SelectField for role
    role = SelectField('Role', choices=[
        ('member', 'Member'),
        ('manager', 'Manager'),
        ('admin', 'Admin')
    ])
    password = PasswordField('New Password (optional)')

# Enum for Attachment Types
class AttachmentType(enum.Enum):
    MANUFACTURER_QUOTE = 'Manufacturer Quote'
    CUSTOMER_QUOTE = 'Customer Quote'
    CUSTOMER_PO = 'Customer PO'
    EVT_PO = 'EVT PO'
    SOW = 'Statement of Work' # Added Statement of Work

    @classmethod
    def choices(cls):
        return [(choice.name, choice.value) for choice in cls]

    @classmethod
    def coerce(cls, item):
        # If item is already an instance of the enum, return it directly
        if isinstance(item, cls):
            return item
        # Otherwise, assume item is the NAME (e.g., 'MANUFACTURER_QUOTE') 
        # and look up the member by name.
        try:
            return cls[item]
        except KeyError:
            # Optionally, try by value if lookup by name fails, although
            # with how SelectField uses choices, name lookup is expected.
            # If both fail, raise an error.
            raise ValueError(f"Invalid value for AttachmentType: {item!r}")

    def __str__(self):
        return self.value

# Form for adding Deal Attachments
class DealAttachmentForm(FlaskForm):
    attachment_file = FileField('Attach File', validators=[DataRequired()])
    attachment_type = WTSelectField('File Type', 
                                    choices=AttachmentType.choices(), 
                                    coerce=AttachmentType.coerce, 
                                    validators=[DataRequired()])
    submit_attachment = SubmitField('Upload Attachment')

# Define DealForm
class DealForm(FlaskForm):
    name = StringField('Deal Name', validators=[DataRequired(), Length(max=100)])
    # Use a different name for the input field to avoid conflict with the model's relationship attribute
    customer_name_input = StringField('Customer Name', validators=[DataRequired(), Length(max=100)])
    contact_name = StringField('Contact Name', validators=[Optional(), Length(max=100)])
    contact_email = StringField('Contact Email', validators=[Optional(), Email(), Length(max=120)])
    revenue = DecimalField('Revenue', places=2, validators=[Optional(), NumberRange(min=0)], default=0.00)
    gross_profit = DecimalField('Gross Profit', places=2, validators=[Optional(), NumberRange(min=0)], default=0.00) # Added Gross Profit
    stage = SelectField('Stage', choices=[
        ('Prospecting', 'Prospecting'),
        ('Qualification', 'Qualification'),
        ('Needs Analysis', 'Needs Analysis'),
        ('Value Proposition', 'Value Proposition'),
        ('Decision Makers', 'Decision Makers'),
        ('Proposal/Quote', 'Proposal/Quote'),
        ('Negotiation', 'Negotiation'),
        ('Closed Won', 'Closed Won'),
        ('Closed Lost', 'Closed Lost')
    ], validators=[DataRequired()])
    expected_close_date = DateField('Expected Close Date', format='%Y-%m-%d', validators=[Optional()])
    # MEDDPICC Fields
    metrics = TextAreaField('MEDDPICC - Metrics', validators=[Optional()])
    economic_buyer = TextAreaField('MEDDPICC - Economic Buyer', validators=[Optional()])
    decision_criteria = TextAreaField('MEDDPICC - Decision Criteria', validators=[Optional()])
    decision_process = TextAreaField('MEDDPICC - Decision Process', validators=[Optional()])
    paper_process = TextAreaField('MEDDPICC - Paper Process', validators=[Optional()])
    identify_pain = TextAreaField('MEDDPICC - Identify Pain', validators=[Optional()]) # Changed name to match model
    champion = TextAreaField('MEDDPICC - Champion', validators=[Optional()])
    submit_deal_changes = SubmitField('Save Deal Changes') # Changed submit name for clarity

# Specific view for User model using the custom form
class UserAdminView(AdminModelView):
    form = UserEditForm
    can_create = False # Disable creation

    def on_model_change(self, form, model, is_created):
        # Let Flask-Admin handle standard field population first
        super(UserAdminView, self).on_model_change(form, model, is_created)

        # Hash password ONLY if a new one was provided in the form
        if form.password.data:
            model.set_password(form.password.data) # Use the User model's method

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member', index=True)
    activities = db.relationship('Activity', backref='author', lazy='dynamic')
    deals = db.relationship('Deal', backref='owner', lazy='dynamic')

    # Add set_password method to User model
    def set_password(self, password):
        self.password_hash = set_password(password)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    # Add backref for deals and activities for easier querying from customer side if needed

    def __repr__(self):
        return f'<Customer {self.name}>'

class Deal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    stage = db.Column(db.String(50), nullable=False)
    revenue = db.Column(db.Float, nullable=True)
    gross_profit = db.Column(db.Float, nullable=True)
    expected_close_date = db.Column(db.DateTime, nullable=True)
    # MEDDPIC Fields
    metrics = db.Column(db.Text, nullable=True)
    economic_buyer = db.Column(db.Text, nullable=True)
    decision_criteria = db.Column(db.Text, nullable=True)
    decision_process = db.Column(db.Text, nullable=True)
    paper_process = db.Column(db.Text, nullable=True)
    identify_pain = db.Column(db.Text, nullable=True)
    champion = db.Column(db.Text, nullable=True)
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Foreign Key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Remove old text field
    # customer = db.Column(db.String(100), nullable=True)
    # Add Customer Foreign Key and Relationship
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    customer = db.relationship('Customer', backref=db.backref('deals', lazy=True))

    # Add contact fields based on memory
    contact_name = db.Column(db.String(100), nullable=True)
    contact_email = db.Column(db.String(120), nullable=True)

    # Relationship back to activities associated with this deal
    activities = db.relationship('Activity', backref='deal', lazy='dynamic', cascade='all, delete-orphan') # Added cascade
    # Add missing relationship back to DealAttachment
    attachments = db.relationship('DealAttachment', backref='deal', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Deal {self.name}>'

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_type = db.Column(db.String(50), nullable=False) # e.g., 'Call', 'Email', 'Meeting'
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=True)
    deal_id = db.Column(db.Integer, db.ForeignKey('deal.id'), nullable=True) # Optional link to a deal
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_name = db.Column(db.String(100), nullable=True)
    # Remove old text field
    # company_name = db.Column(db.String(100), nullable=True)
    # Add Customer Foreign Key and Relationship
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=True)
    customer = db.relationship('Customer', backref=db.backref('activities', lazy=True))

    def __repr__(self):
        return f'<Activity {self.activity_type} on {self.date}>'

# New Model for Deal Attachments
class DealAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False) # Original filename
    filepath = db.Column(db.String(512), nullable=False) # Path relative to UPLOAD_FOLDER
    file_type = db.Column(db.Enum(AttachmentType), nullable=False) # Use the Enum
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    deal_id = db.Column(db.Integer, db.ForeignKey('deal.id'), nullable=False)

    def __repr__(self):
        return f'<DealAttachment {self.filename} for Deal {self.deal_id}>'

# Add Flask-Admin views AFTER model definitions
admin.add_view(UserAdminView(User, db.session))
admin.add_view(AdminModelView(Customer, db.session))
admin.add_view(AdminModelView(Deal, db.session))
admin.add_view(AdminModelView(Activity, db.session))

# Add a link back to the main application
admin.add_link(MenuLink(name='Back to App', category='', url='/'))

# --- Flask-Login Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) # Use db.session.get for newer Flask-SQLAlchemy

# --- CLI Commands --- #

@app.cli.command('add-user')
@click.argument('email')
@click.argument('password')
@click.option('--role', default='member', help='User role (e.g., member, manager)')
def add_user(email, password, role):
    """Adds a new user to the database."""
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        print(f'Error: User with email {email} already exists.')
        return

    hashed_password = set_password(password) # Use the helper function
    new_user = User(email=email, password_hash=hashed_password, role=role)
    db.session.add(new_user)
    try:
        db.session.commit()
        print(f"User {email} added successfully with role {role}!")
    except Exception as e:
        db.session.rollback()
        print(f'Error adding user: {e}')

# Command to update user role
@app.cli.command('set-role')
@click.argument('email')
@click.argument('role')
def set_role(email, role):
    """Updates the role for an existing user."""
    # Debugging: Print config info like other CLI commands
    print(f"---> [DB Config] Using DATABASE_URL from environment")
    print(f"---> [Flask App] FINAL Database URI set to: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"--- DEBUG: Flask Config API Key: {app.config.get('SENDGRID_API_KEY', 'Not Set')} ---")
    print(f"--- DEBUG: Flask Config From Email: {app.config.get('MAIL_FROM_EMAIL', 'Not Set')} ---")

    user = User.query.filter_by(email=email).first()
    if user:
        # Validate the role
        valid_roles = ['admin', 'manager', 'member']
        if role not in valid_roles:
            print(f"Error: Invalid role '{role}'. Must be one of {valid_roles}.")
            return
        user.role = role
        db.session.commit()
        print(f"User {email}'s role updated to {role}.")
    else:
        print(f"Error: User with email {email} not found.")

@app.cli.command('seed-db')
def seed_db():
    """Populates the database with sample deals and activities."""
    print('Seeding database...')

    # Find users
    user_baxter = User.query.filter_by(email='bconley@evtcorp.com').first()
    user_member = User.query.filter_by(email='test.member@evtcorp.com').first()
    user_manager = User.query.filter_by(email='test.manager@evtcorp.com').first()

    if not all([user_baxter, user_member, user_manager]):
        print('Error: One or more required users (bconley, test.member, test.manager) not found. Run add-user first.')
        return

    users = [user_baxter, user_member, user_manager]

    # Clear existing test data (optional, but good for repeatable seeding)
    # Be CAREFUL with this in production!
    print('Deleting existing test Activities and Deals...')
    Activity.query.delete()
    Deal.query.delete()
    db.session.commit()
    print('Existing test data deleted.')

    # Sample Deals
    deals_data = [
        {'name': 'Alpha Project', 'stage': 'Prospecting', 'revenue': 50000, 'contact_name': 'Alice Alpha', 'contact_email': 'alice@alpha.com', 'owner': user_baxter}, 
        {'name': 'Beta Initiative', 'stage': 'Qualification', 'revenue': 120000, 'contact_name': 'Bob Beta', 'contact_email': 'bob@beta.com', 'owner': user_member}, 
        {'name': 'Gamma Launch', 'stage': 'Proposal', 'revenue': 75000, 'contact_name': 'Charlie Gamma', 'contact_email': 'charlie@gamma.com', 'owner': user_baxter}, 
        {'name': 'Delta Rollout', 'stage': 'Negotiation', 'revenue': 250000, 'contact_name': 'Diana Delta', 'contact_email': 'diana@delta.com', 'owner': user_manager}, 
        {'name': 'Epsilon Upgrade', 'stage': 'Closed Won', 'revenue': 90000, 'contact_name': 'Evan Epsilon', 'contact_email': 'evan@epsilon.com', 'owner': user_member}, 
        {'name': 'Zeta Opportunity', 'stage': 'Closed Lost', 'revenue': 30000, 'contact_name': 'Zoe Zeta', 'contact_email': 'zoe@zeta.com', 'owner': user_baxter}, 
    ]

    created_deals = []
    print('Creating Deals...')
    for data in deals_data:
        deal = Deal(**data)
        db.session.add(deal)
        created_deals.append(deal)
    
    try:
        db.session.commit()
        print(f'{len(created_deals)} Deals created.')
    except Exception as e:
        db.session.rollback()
        print(f'Error creating deals: {e}')
        return # Stop if deals fail

    # Sample Activities
    activities_data = [
        {'activity_type': 'Call', 'description': 'Initial contact call with Alice.', 'date': datetime.utcnow() - timedelta(days=10), 'author': user_baxter, 'deal': created_deals[0]}, 
        {'activity_type': 'Email', 'description': 'Sent follow-up email to Bob.', 'date': datetime.utcnow() - timedelta(days=8), 'author': user_member, 'deal': created_deals[1]}, 
        {'activity_type': 'Meeting', 'description': 'Proposal presentation with Charlie.', 'date': datetime.utcnow() - timedelta(days=5), 'author': user_baxter, 'deal': created_deals[2]}, 
        {'activity_type': 'Call', 'description': 'Negotiation call with Diana.', 'date': datetime.utcnow() - timedelta(days=3), 'author': user_manager, 'deal': created_deals[3]}, 
        {'activity_type': 'Email', 'description': 'Sent contract to Evan.', 'date': datetime.utcnow() - timedelta(days=2), 'author': user_member, 'deal': created_deals[4]}, 
        {'activity_type': 'Meeting', 'description': 'Discussed Beta requirements internally.', 'date': datetime.utcnow() - timedelta(days=7), 'author': user_member, 'deal': created_deals[1]}, 
        {'activity_type': 'Call', 'description': 'Quick check-in call with Alice.', 'date': datetime.utcnow() - timedelta(days=1), 'author': user_baxter, 'deal': created_deals[0]}, 
        {'activity_type': 'Email', 'description': 'Followed up on proposal for Gamma.', 'date': datetime.utcnow() - timedelta(days=1), 'author': user_baxter, 'deal': created_deals[2]}, 
    ]

    print('Creating Activities...')
    for data in activities_data:
        activity = Activity(**data)
        db.session.add(activity)

    try:
        db.session.commit()
        print(f'{len(activities_data)} Activities created.')
        print('Database seeding complete.')
    except Exception as e:
        db.session.rollback()
        print(f'Error creating activities: {e}')


# --- Routes ---
@app.route('/')
# @login_required # Remove: We want logged-out users to see the landing page
def index():
    if current_user.is_authenticated:
        # If logged in, redirect to the main dashboard
        return redirect(url_for('dashboard'))
    else:
        # If logged out, show the public landing page (public_index.html)
        return render_template('public_index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index')) # Redirect if already logged in

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password(user.password_hash, password):
            login_user(user) # Log the user in
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html') # Show login form on GET or failed POST

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index')) # Redirect if already logged in

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic validation (can be expanded)
        if not email or not password:
            flash('Email and password are required.', 'warning')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered.', 'warning')
            return redirect(url_for('register'))

        # Create new user
        hashed_password = set_password(password)
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html') # Show registration form on GET

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Dashboard --- #
@app.route('/dashboard')
@login_required
def dashboard():
    # --- Activities Pagination ---
    act_page = request.args.get('act_page', 1, type=int)
    act_per_page_str = request.args.get('act_per_page', '5') # Default 5 for dashboard
    activities_query = Activity.query.options(joinedload(Activity.deal), joinedload(Activity.customer)).filter_by(user_id=current_user.id).order_by(Activity.date.desc())
    if act_per_page_str.lower() == 'all':
        act_per_page = activities_query.count()
        if act_per_page == 0: act_per_page = 1
        activities_pagination = activities_query.paginate(page=1, per_page=act_per_page, error_out=False)
    else:
        try:
            act_per_page = int(act_per_page_str)
            if act_per_page <= 0: act_per_page = 5
        except ValueError:
            act_per_page = 5
        activities_pagination = activities_query.paginate(page=act_page, per_page=act_per_page, error_out=False)

    # --- Deals Filtering & Summation ---
    current_dt = datetime.now()
    current_year = date.today().year # Use the explicitly imported 'date'
    selected_year = request.args.get('year', str(current_year), type=str) # Use string for "All" option
    selected_quarter = request.args.get('quarter', 'All', type=str)
    selected_status = request.args.get('status', 'Open', type=str) # Default to Open

    # Generate year options for the dropdown
    year_options = ["All"] + [str(y) for y in range(current_year + 2, current_year - 4, -1)] # e.g., All, 2026, 2025, ..., 2022

    # Base query
    deals_query = Deal.query.filter(Deal.user_id == current_user.id)

    # Apply date filters
    if selected_year != "All":
        try:
            year_int = int(selected_year)
            # Filter out deals with NULL close date when filtering by date
            deals_query = deals_query.filter(
                Deal.expected_close_date.isnot(None),
                extract('year', Deal.expected_close_date) == year_int
            )
            if selected_quarter != "All":
                 try:
                     # Quarters are 1-based
                     quarter_int = int(selected_quarter.replace('Q', ''))
                     if 1 <= quarter_int <= 4:
                         deals_query = deals_query.filter(
                             extract('quarter', Deal.expected_close_date) == quarter_int
                         )
                     else:
                         selected_quarter = "All" # Invalid quarter, reset to All
                 except (ValueError, TypeError):
                     selected_quarter = "All" # Invalid quarter format, reset to All
        except (ValueError, TypeError):
            selected_year = "All" # Invalid year format, reset to All

    # Apply status filter
    if selected_status == "Open":
        deals_query = deals_query.filter(~Deal.stage.in_(['Closed Won', 'Closed Lost']))
    elif selected_status == "Closed Won":
        deals_query = deals_query.filter(Deal.stage == 'Closed Won')
    elif selected_status == "Closed Lost":
        deals_query = deals_query.filter(Deal.stage == 'Closed Lost')
    # Else ("All"): no status filter applied

    # Order results (e.g., by close date, newest first if available)
    deals_query = deals_query.order_by(Deal.expected_close_date.desc().nullslast(), Deal.id.desc())

    # Execute query to get filtered deals
    filtered_deals = deals_query.all()

    # Calculate sums from the filtered list, separating lost deals
    won_open_revenue = 0.0
    won_open_gp = 0.0
    lost_revenue = 0.0
    lost_gp = 0.0

    for deal in filtered_deals:
        if deal.stage == 'Closed Lost':
            lost_revenue += deal.revenue or 0.0
            lost_gp += deal.gross_profit or 0.0
        else:
            won_open_revenue += deal.revenue or 0.0
            won_open_gp += deal.gross_profit or 0.0

    # --- DEBUG PRINT --- 
    print("--- DEBUG: Recent Activities for Dashboard ---")
    for act in activities_pagination.items:
        cust_name = act.customer.name if act.customer else 'None'
        print(f"Activity ID: {act.id}, Type: {act.activity_type}, Customer Name: {cust_name}")
    print("--- END DEBUG ---")
    # --- END DEBUG PRINT ---

    return render_template(
        'dashboard.html',
        # Activities data (unchanged)
        activities_pagination=activities_pagination,
        current_act_per_page=act_per_page_str,
        # New Deals data
        filtered_deals=filtered_deals,
        # Updated totals
        won_open_revenue=won_open_revenue,
        won_open_gp=won_open_gp,
        lost_revenue=lost_revenue,
        lost_gp=lost_gp,
        # Filter selections and options for the form
        selected_year=selected_year,
        selected_quarter=selected_quarter,
        selected_status=selected_status,
        year_options=year_options
    )


@app.route('/log_activity', methods=['GET', 'POST'])
@login_required
def log_activity():
    now = datetime.now() # Get current time for pre-filling date
    if request.method == 'POST':
        activity_type = request.form.get('activity_type')
        activity_date_str = request.form.get('activity_date')
        description = request.form.get('notes')
        deal_id_str = request.form.get('deal_id')
        contact_name = request.form.get('contact_name')
        company_name = request.form.get('company_name')

        # --- Basic Validation ---
        if not activity_type or not activity_date_str:
            flash('Activity type and date are required.', 'danger')
            # Rerender form with pagination info if validation fails
            page = request.args.get('page', 1, type=int)
            per_page_str = request.args.get('per_page', '10') # Default 10 for dashboard
            deals = Deal.query.filter_by(user_id=current_user.id).order_by(Deal.name).all()
            activities_query = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.date.desc())
            if per_page_str.lower() == 'all':
                per_page = activities_query.count()
                if per_page == 0: per_page = 1
                activities_pagination = activities_query.paginate(page=1, per_page=per_page, error_out=False)
            else:
                per_page = int(per_page_str)
                activities_pagination = activities_query.paginate(page=page, per_page=per_page, error_out=False)
            return render_template('log_activity.html', deals=deals, activities_pagination=activities_pagination, now=now, current_per_page=per_page_str)

        # --- Date Parsing ---
        try:
            activity_date = datetime.strptime(activity_date_str, '%Y-%m-%d').date()
            activity_datetime = datetime.combine(activity_date, datetime.min.time())
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'warning')
            # Rerender form with pagination info if date parse fails
            page = request.args.get('page', 1, type=int)
            per_page_str = request.args.get('per_page', '10') # Default 10 for dashboard
            deals = Deal.query.filter_by(user_id=current_user.id).order_by(Deal.name).all()
            activities_query = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.date.desc())
            if per_page_str.lower() == 'all':
                per_page = activities_query.count()
                if per_page == 0: per_page = 1
                activities_pagination = activities_query.paginate(page=1, per_page=per_page, error_out=False)
            else:
                per_page = int(per_page_str)
                activities_pagination = activities_query.paginate(page=page, per_page=per_page, error_out=False)
            return render_template('log_activity.html', deals=deals, activities_pagination=activities_pagination, now=now, current_per_page=per_page_str)

        deal_id = int(deal_id_str) if deal_id_str and deal_id_str.isdigit() else None

        customer_id = None
        if company_name:
            customer = Customer.query.filter(func.lower(Customer.name) == func.lower(company_name)).first()
            if not customer:
                customer = Customer(name=company_name)
                db.session.add(customer)
                db.session.flush() # Get ID
            customer_id = customer.id

        # --- Database Operation ---
        try:
            new_activity = Activity(
                activity_type=activity_type,
                date=activity_datetime,
                description=description,
                deal_id=deal_id,
                user_id=current_user.id,
                contact_name=contact_name,
                customer_id=customer_id
            )
            db.session.add(new_activity)
            db.session.commit()
            flash('Activity logged successfully!', 'success')
            # Redirect to the same page (or page 1) after successful POST
            return redirect(url_for('log_activity'))
        except Exception as e:
            db.session.rollback()
            print(f"Error saving activity: {e}")
            flash(f'Error saving activity. Please try again. Details: {e}', 'danger')
            # Rerender form with pagination info if commit fails
            page = request.args.get('page', 1, type=int)
            per_page_str = request.args.get('per_page', '10') # Default 10 for dashboard
            deals = Deal.query.filter_by(user_id=current_user.id).order_by(Deal.name).all()
            activities_query = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.date.desc())
            if per_page_str.lower() == 'all':
                per_page = activities_query.count()
                if per_page == 0: per_page = 1
                activities_pagination = activities_query.paginate(page=1, per_page=per_page, error_out=False)
            else:
                per_page = int(per_page_str)
                activities_pagination = activities_query.paginate(page=page, per_page=per_page, error_out=False)
            return render_template('log_activity.html', deals=deals, activities_pagination=activities_pagination, now=now, current_per_page=per_page_str)

    # --- GET Request Handling ---
    else:
        page = request.args.get('page', 1, type=int)
        per_page_str = request.args.get('per_page', '10') # Default to 10

        deals = Deal.query.filter_by(user_id=current_user.id).order_by(Deal.name).all()
        activities_query = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.date.desc())

        # Handle 'all' case
        if per_page_str.lower() == 'all':
            per_page = activities_query.count()
            if per_page == 0: per_page = 1 # Avoid division by zero if no activities exist
            # Always show page 1 when 'all' is selected
            activities_pagination = activities_query.paginate(page=1, per_page=per_page, error_out=False)
        else:
            try:
                per_page = int(per_page_str)
                if per_page <= 0:
                    per_page = 10 # Default to 10 if invalid number <= 0
            except ValueError:
                per_page = 10 # Default to 10 if not a valid integer or 'all'
            activities_pagination = activities_query.paginate(page=page, per_page=per_page, error_out=False)

        return render_template('log_activity.html', deals=deals, activities_pagination=activities_pagination, now=now, current_per_page=per_page_str)


@app.route('/activity/add/<int:deal_id>', methods=['GET', 'POST'], endpoint='add_activity_for_deal') # Added specific endpoint
@app.route('/activity/edit/<int:activity_id>', methods=['GET', 'POST'])
@login_required
def add_edit_activity(deal_id=None, activity_id=None):
    now = datetime.now() # Get current time for pre-filling date

    # --- Add Activity Logic ---
    if deal_id:
        # Ensure the deal exists and belongs to the current user
        deal = Deal.query.get_or_404(deal_id)
        if deal.user_id != current_user.id:
            flash("You don't have permission to log an activity for this deal.", "danger")
            return redirect(url_for('index'))

        if request.method == 'POST':
            activity_type = request.form.get('activity_type')
            activity_date_str = request.form.get('activity_date')
            description = request.form.get('description')
            contact_name = request.form.get('contact_name')
            company_name = request.form.get('company_name')

            # --- Basic Validation ---
            if not activity_type or not activity_date_str:
                flash('Activity type and date are required.', 'danger')
                return render_template('log_activity.html', deal=deal, now=now)

            # --- Date Parsing ---
            try:
                activity_date = datetime.strptime(activity_date_str, '%Y-%m-%d').date()
                activity_datetime = datetime.combine(activity_date, datetime.min.time())
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.', 'warning')
                return render_template('log_activity.html', deal=deal, now=now)

            customer_id = None
            if company_name:
                customer = Customer.query.filter(func.lower(Customer.name) == func.lower(company_name)).first()
                if not customer:
                    customer = Customer(name=company_name)
                    db.session.add(customer)
                    db.session.flush() # Get ID
                customer_id = customer.id

            # --- Database Operation ---
            try:
                new_activity = Activity(
                    activity_type=activity_type,
                    date=activity_datetime,
                    description=description,
                    deal_id=deal_id,
                    user_id=current_user.id,
                    contact_name=contact_name,
                    customer_id=customer_id
                )
                db.session.add(new_activity)
                db.session.commit()
                flash('Activity logged successfully!', 'success')
                # Redirect to the same page (or page 1) after successful POST
                return redirect(url_for('log_activity'))
            except Exception as e:
                db.session.rollback()
                print(f"Error saving activity: {e}")
                flash(f'Error saving activity. Please try again. Details: {e}', 'danger')
                return render_template('log_activity.html', deal=deal, now=now)

        # GET request: Show the add form pre-filled with deal data
        return render_template('log_activity.html', deal=deal, now=now)

    # --- Edit Activity Logic ---
    elif activity_id:
        activity = Activity.query.get_or_404(activity_id)
        # Ensure the current user owns the activity
        if activity.user_id != current_user.id:
            flash("You don't have permission to edit this activity.", "danger")
            return redirect(url_for('index'))

        if request.method == 'POST':
            # Get data from form
            activity.activity_type = request.form.get('activity_type') # Correct field name
            activity.description = request.form.get('description')       # Correct field name
            activity.contact_name = request.form.get('contact_name')
            company_name = request.form.get('company_name') # Keep form name for now

            customer_id = None
            if company_name:
                customer = Customer.query.filter(func.lower(Customer.name) == func.lower(company_name)).first()
                if not customer:
                    customer = Customer(name=company_name)
                    db.session.add(customer)
                    db.session.flush() # Get ID
                customer_id = customer.id
            activity.customer_id = customer_id # Update the customer_id

            # Handle deal_id potentially being empty/None
            deal_id_str = request.form.get('deal_id')
            activity.deal_id = int(deal_id_str) if deal_id_str and deal_id_str.isdigit() else None
            # Date handling (assuming you want to update the date)
            date_str = request.form.get('date')
            try:
                activity.date = datetime.strptime(date_str, '%Y-%m-%d') if date_str else datetime.utcnow()
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.', 'warning')
                deals = current_user.deals.order_by(Deal.name).all()
                return render_template('log_activity.html', activity=activity, deals=deals, now=now)

            # Basic validation
            if not activity.activity_type: # Check correct field name
                flash('Activity Type is required.', 'warning')
                deals = current_user.deals.order_by(Deal.name).all()
                return render_template('log_activity.html', activity=activity, deals=deals, now=now)

            try:
                db.session.commit()
                flash('Activity updated successfully!', 'success')
                return redirect(url_for('dashboard')) # Redirect back to the dashboard
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred while updating the activity: {e}', 'danger')
                deals = current_user.deals.order_by(Deal.name).all()
                return render_template('log_activity.html', activity=activity, deals=deals, now=now)

        # GET request: Show the edit form pre-filled with activity data
        deals = current_user.deals.order_by(Deal.name).all()
        return render_template('log_activity.html', activity=activity, deals=deals, now=now)

    # If neither deal_id nor activity_id is provided, redirect to the log activity page
    else:
        return redirect(url_for('log_activity'))


# Route to delete an activity
@app.route('/activity/<int:activity_id>/delete', methods=['POST'])
@login_required
def delete_activity(activity_id):
    activity = Activity.query.get_or_404(activity_id)
    if activity.user_id != current_user.id:
        flash("You don't have permission to delete this activity.", "danger")
        return redirect(url_for('dashboard'))

    db.session.delete(activity)
    db.session.commit()
    flash('Activity deleted successfully.', 'success')
    return redirect(url_for('dashboard'))


# --- Deals Routes ---
@app.route('/deals', methods=['GET', 'POST'])
@login_required
def deals():
    if request.method == 'POST':
        name = request.form.get('deal_name')
        stage = request.form.get('stage')
        revenue_str = request.form.get('revenue')
        gross_profit_str = request.form.get('gross_profit')
        expected_close_date_str = request.form.get('expected_close_date')
        metrics = request.form.get('metrics')
        economic_buyer = request.form.get('economic_buyer')
        decision_criteria = request.form.get('decision_criteria')
        decision_process = request.form.get('decision_process')
        paper_process = request.form.get('paper_process')
        identify_pain = request.form.get('identify_pain')
        champion = request.form.get('champion')
        customer_name = request.form.get('customer') # Get customer name

        if not name or not stage or not customer_name: # Check for customer_name
            flash('Deal Name, Stage, and Customer Name are required.', 'warning')
            # Redirect back to the form or render the template again with existing data
            # Depending on how you want to handle validation errors
            deals_query = Deal.query.order_by(Deal.name).all()
            return render_template('deals.html', title='Deals Management', deals=deals_query)
        else:
            revenue_str = request.form.get('revenue')
            gross_profit_str = request.form.get('gross_profit')
            expected_close_date_str = request.form.get('expected_close_date')
            deal_revenue = float(revenue_str) if revenue_str else 0.0
            deal_gross_profit = float(gross_profit_str) if gross_profit_str else 0.0
            close_date = datetime.strptime(expected_close_date_str, '%Y-%m-%d').date() if expected_close_date_str else None
            # Find or Create Customer (Case-insensitive search)
            customer = Customer.query.filter(func.lower(Customer.name) == func.lower(customer_name)).first()
            if not customer:
                customer = Customer(name=customer_name)
                db.session.add(customer)
                db.session.flush() # Ensure customer gets an ID before association
            new_deal = Deal(
                name=name, stage=stage, revenue=deal_revenue, gross_profit=deal_gross_profit,
                expected_close_date=close_date, user_id=current_user.id,
                metrics=metrics, economic_buyer=economic_buyer, decision_criteria=decision_criteria,
                decision_process=decision_process, paper_process=paper_process,
                identify_pain=identify_pain, champion=champion, customer_id=customer.id # Use customer.id
            )
            try:
                db.session.add(new_deal)
                db.session.commit()
                flash(f'Deal "{new_deal.name}" created successfully!', 'success')
                return redirect(url_for('deals', page=1)) # Redirect to first page after creation
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error creating deal: {e}")
                flash('An error occurred while creating the deal.', 'danger')
                # Re-render form on error
                deals_query = Deal.query.order_by(Deal.name).all() # Fetch deals again for template context
                return render_template('deals.html', title='Deals Management', deals=deals_query)

    # --- GET request: Display deals with pagination and sorting ---
    page = request.args.get('page', 1, type=int)
    per_page_str = request.args.get('per_page', '10') # Default to 10
    sort_by = request.args.get('sort_by', 'name') # Default sort
    sort_order = request.args.get('sort_order', 'asc') # Default order

    # Base query
    deals_query = Deal.query.filter_by(user_id=current_user.id)

    # Sorting logic
    sort_column = getattr(Deal, sort_by, Deal.name) # Default to name if invalid
    if sort_order == 'desc':
        deals_query = deals_query.order_by(sort_column.desc())
    else:
        deals_query = deals_query.order_by(sort_column.asc())

    # Pagination logic
    if per_page_str.lower() == 'all':
        per_page = deals_query.count()
        if per_page == 0: per_page = 1
        deals_pagination = deals_query.paginate(page=1, per_page=per_page, error_out=False)
    else:
        try:
            per_page = int(per_page_str)
            if per_page <= 0:
                per_page = 10 # Default to 10 if invalid number <= 0
        except ValueError:
            per_page = 10 # Default to 10 if not a valid integer or 'all'
        deals_pagination = deals_query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('deals.html', 
                           deals_pagination=deals_pagination, 
                           current_per_page=per_page_str, 
                           sort_by=sort_by, 
                           sort_order=sort_order)

# Route to view details of a specific deal
@app.route('/deal/<int:deal_id>')
@login_required
def deal_detail(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    # Ensure the current user owns this deal
    if deal.user_id != current_user.id:
        flash("You don't have permission to view this deal.", "danger")
        return redirect(url_for('deals'))
    now = datetime.now() # Get current datetime
    return render_template('deal_detail.html', deal=deal, now=now) # Pass 'now' to template

@app.route('/deal/<int:deal_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_deal(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    if deal.owner != current_user and current_user.role not in ['admin', 'manager']:
        flash('You do not have permission to edit this deal.', 'danger')
        return redirect(url_for('deals'))

    # Instantiate forms
    # For GET, populate DealForm with existing data using obj=deal
    # For POST, DealForm will be populated from request.form
    # Note: obj=deal works for most fields, but we handle customer_name_input manually in GET
    deal_form = DealForm(request.form if request.method == 'POST' else None, obj=deal)
    attachment_form = DealAttachmentForm() # Attachment form is always fresh or populated by its own POST

    # --- Handle Deal Edit Form Submission --- 
    # Use validate_on_submit for the specific form, checking its submit button
    if deal_form.submit_deal_changes.data and deal_form.validate_on_submit(): 
        # Find or Create Customer (Case-insensitive search)
        customer_name = deal_form.customer_name_input.data # Use renamed field
        customer = Customer.query.filter(func.lower(Customer.name) == func.lower(customer_name)).first()
        if not customer:
            customer = Customer(name=customer_name)
            db.session.add(customer)
            db.session.flush() # Ensure customer gets an ID before association
        
        # Populate deal object from form data manually, skipping specific fields
        for name, field in deal_form._fields.items():
            # Skip fields handled manually or not part of the Deal model attributes
            if name not in ['customer_name_input', 'submit_deal_changes', 'csrf_token']:
                 # Check if the deal object has this attribute before setting
                 # This prevents errors if the form has fields not on the model
                 if hasattr(deal, name):
                    field.populate_obj(deal, name)

        # Manually assign customer_id after lookup/creation
        deal.customer_id = customer.id 
        # Ensure gross_profit is updated (populate_obj should handle this if names match)
        # Explicitly: deal.gross_profit = deal_form.gross_profit.data

        try:
            db.session.commit()
            flash('Deal updated successfully!', 'success')
            # Redirect to detail page after saving deal changes
            # Use view_deal as detail page might not exist or be desired
            return redirect(url_for('view_deal', deal_id=deal.id)) 
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating deal: {str(e)}', 'danger')
            # If save fails, fall through to render the edit form again with errors
            
    # --- Handle Attachment Form Submission --- 
    # Use attachment_form.validate_on_submit() and check its submit button
    # Note: validate_on_submit() checks if it's a POST and validates.
    elif attachment_form.submit_attachment.data and attachment_form.validate_on_submit():
        file = attachment_form.attachment_file.data
        file_type = attachment_form.attachment_type.data # data gives the enum member
        
        if file:
            original_filename = secure_filename(file.filename)
            timestamp = int(datetime.utcnow().timestamp())
            unique_filename = f"{deal.id}_{timestamp}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            try:
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(filepath)
                
                new_attachment = DealAttachment(
                    deal_id=deal.id,
                    filename=original_filename,
                    filepath=unique_filename,
                    file_type=file_type # Store enum member
                )
                db.session.add(new_attachment)
                db.session.commit()
                flash('Attachment uploaded successfully!', 'success')
                # Redirect to the SAME edit page to show the new attachment and clear the form
                # Prevent re-submission on refresh
                return redirect(url_for('edit_deal', deal_id=deal.id)) 
            except Exception as e:
                db.session.rollback()
                flash(f'Error uploading attachment: {str(e)}', 'danger')
                # Fall through to render the edit page again

    # --- Handle GET Request --- 
    if request.method == 'GET':
        # Pre-populate customer name field if deal has a customer
        # We do this manually because form field name != model attribute name
        if deal.customer:
            deal_form.customer_name_input.data = deal.customer.name # Use renamed field
        # Dates need careful pre-population if using obj=deal doesn't work perfectly
        if deal.expected_close_date:
            deal_form.expected_close_date.data = deal.expected_close_date

    # Always fetch attachments to display
    attachments = DealAttachment.query.filter_by(deal_id=deal.id).order_by(DealAttachment.uploaded_at.desc()).all()
    
    # Pass both forms and attachments to the template
    return render_template('edit_deal.html', title='Edit Deal', deal=deal, 
                           deal_form=deal_form, attachment_form=attachment_form, 
                           attachments=attachments)


# Route to delete a deal
@app.route('/deal/<int:deal_id>/delete', methods=['POST'])
@login_required
def delete_deal(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    if deal.owner != current_user and current_user.role not in ['admin', 'manager']:
        flash("You don't have permission to delete this deal.", "danger")
        return redirect(url_for('deals')) # Or dashboard

    # Optional: Handle related activities? Decide if they should be deleted or unlinked.
    # For now, SQLAlchemy might raise an error if activities reference this deal,
    # depending on cascade settings. Let's assume we want to delete the deal directly.
    # If issues arise, we might need to handle activities (e.g., set deal_id to null or delete them).

    db.session.delete(deal)
    db.session.commit()
    flash('Deal deleted successfully.', 'success')
    return redirect(url_for('dashboard')) # Redirect to dashboard list after deletion

# --- View Deal Route (Read-Only) ---
@app.route('/deal/<int:deal_id>/view')
@login_required
def view_deal(deal_id):
    # Ensure only managers or admins can access this view
    if current_user.role not in ['manager', 'admin']:
        flash('You do not have permission to view this page.', 'danger')
        # Redirect to user's own dashboard if they don't have permission
        return redirect(url_for('dashboard'))

    deal = Deal.query.get_or_404(deal_id)
    # Optionally, you might want to verify if the manager should only see deals
    # belonging to their team, but for now, allow viewing any deal if manager/admin.

    # Fetch associated activities
    activities = Activity.query.filter_by(deal_id=deal.id).order_by(Activity.date.desc()).all()

    # Fetch associated attachments
    attachments = DealAttachment.query.filter_by(deal_id=deal.id).order_by(DealAttachment.uploaded_at.desc()).all()

    return render_template('view_deal.html',
                           title=f"View Deal: {deal.customer.name}",
                           deal=deal,
                           activities=activities,
                           attachments=attachments)

# --- View Activity Route (Read-Only) ---
@app.route('/activity/<int:activity_id>/view')
@login_required
def view_activity(activity_id):
    # Ensure only managers or admins can access this view
    if current_user.role not in ['manager', 'admin']:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    activity = Activity.query.options(joinedload(Activity.deal), joinedload(Activity.author)).get_or_404(activity_id)
    # Allow owner, admin, or manager to view
    if (activity.author != current_user and 
        current_user.role not in ['admin', 'manager'] and 
        (not activity.deal or activity.deal.owner != current_user)):
        flash('You do not have permission to view this activity.', 'danger')
        return redirect(url_for('index'))
    return render_template('view_activity.html', title='View Activity', activity=activity)

# --- Email Report Routes ---

@app.route('/email_activity_report', methods=['POST'])
@login_required
def email_activity_report():
    period = request.form.get('activity_period') # 'week' or 'month'
    recipient_email_string = request.form.get('recipient_email', '').strip() # Get recipient emails string
    today = date.today()
    start_date = None
    end_date = None
    period_desc = ""

    if period == 'week':
        start_date = today - timedelta(days=today.weekday())
        end_date = start_date + timedelta(days=6)
        period_desc = "this week"
    elif period == 'month':
        start_date = today.replace(day=1)
        end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        period_desc = "this month"
    else:
        flash('Invalid time period selected.', 'warning')
        return redirect(url_for('dashboard'))

    recipient_emails_raw = [email.strip() for email in recipient_email_string.split(',')]
    recipient_emails = [email for email in recipient_emails_raw if email] # Remove empty strings

    # Validate emails
    invalid_emails = [email for email in recipient_emails if '@' not in email]
    if invalid_emails:
        flash(f'Invalid email address(es) found: {", ".join(invalid_emails)}. Please check and try again.', 'warning')
        return redirect(url_for('dashboard'))

    if not recipient_emails:
        flash('Please provide at least one recipient email address.', 'warning')
        return redirect(url_for('dashboard'))

    activities = Activity.query.filter(
        Activity.user_id == current_user.id,
        Activity.date >= start_date,
        Activity.date <= end_date
    ).order_by(Activity.date.desc()).all()

    subject = f"Activity Report: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"

    # Generate Plain Text Body
    activity_body = f"Activity Report for {current_user.email} ({period_desc.lower()}: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})\n\n"
    if activities:
        for activity in activities:
            activity_date_str = activity.date.strftime("%Y-%m-%d")
            deal_name = activity.deal.name if activity.deal else "N/A"
            contact_name = activity.contact_name or "N/A"
            company_name = activity.customer.name if activity.customer else "N/A"
            description = activity.description or "N/A"
            activity_body += f"- {activity_date_str}: {activity.activity_type} - {description}\n"
    else:
        activity_body += f"No activities found for {period_desc.lower()}.\n"

    # Generate HTML Body with a Table
    html_table_rows = ""
    if activities:
        for activity in activities:
            activity_date_str = activity.date.strftime("%Y-%m-%d")
            deal_name = activity.deal.name if activity.deal else "N/A"
            contact_name = activity.contact_name or "N/A"
            company_name = activity.customer.name if activity.customer else "N/A"
            description = activity.description or "N/A"
            html_table_rows += f"""
            <tr>
                <td style='border: 1px solid #ddd; padding: 8px;'>{activity.activity_type}</td>
                <td style='border: 1px solid #ddd; padding: 8px;'>{activity_date_str}</td>
                <td style='border: 1px solid #ddd; padding: 8px;'>{description}</td>
                <td style='border: 1px solid #ddd; padding: 8px;'>{deal_name}</td>
                <td style='border: 1px solid #ddd; padding: 8px;'>{contact_name}</td>
                <td style='border: 1px solid #ddd; padding: 8px;'>{company_name}</td>
            </tr>
            """

    html_body = f"""
    <html>
    <head>
        <style>
            table {{{{ ' border-collapse: collapse; width: 100%; ' }}}}
            th, td {{{{ ' border: 1px solid #ddd; padding: 8px; text-align: left; ' }}}}
            th {{{{ ' background-color: #f2f2f2; ' }}}}
            tr:nth-child(even) {{{{ ' background-color: #f9f9f9; ' }}}}
        </style>
    </head>
    <body>
        <h2>Activity Report ({period_desc}) for {current_user.email}</h2>
        {'<table><thead><tr><th>Type</th><th>Date</th><th>Notes</th><th>Related Deal</th><th>Contact</th><th>Company</th></tr></thead><tbody>' + html_table_rows + '</tbody></table>' if activities else f'<p>No activities found for {period_desc.lower()}.</p>'}
    </body>
    </html>
    """

    # Use the list of recipient_emails
    recipient_display_str = ", ".join(recipient_emails)
    if send_email(to=recipient_emails, subject=subject, body=activity_body, html_body=html_body): # Pass html_body
        flash(f'Activity report for {period_desc.lower()} sent to {recipient_display_str}.', 'success')
    else:
        flash(f'Failed to send activity report for {period_desc.lower()} to {recipient_display_str}.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/email_deal_report', methods=['POST'])
@login_required
def email_deal_report():
    from datetime import date, timedelta, datetime
    import calendar
    status = request.form.get('deal_status') # 'Open', 'Closed Won', 'Closed Lost', 'All'
    time_period = request.form.get('time_period', 'all') # 'all', 'current_quarter', 'current_year'
    recipient_email_string = request.form.get('recipient_email', '').strip()

    deals_query = Deal.query.filter(Deal.user_id == current_user.id)
    status_desc = status # Use the selected status directly
    time_desc = "All Time"
    start_date = None
    end_date = None
    today = date.today()

    # Calculate date range based on time_period
    if time_period == 'current_quarter':
        time_desc = "Current Quarter"
        current_quarter_first_month = ((today.month - 1) // 3) * 3 + 1
        start_date = date(today.year, current_quarter_first_month, 1)
        end_month = current_quarter_first_month + 2
        end_day = calendar.monthrange(today.year, end_month)[1]
        end_date = date(today.year, end_month, end_day)
    elif time_period == 'current_year':
        time_desc = "Current Fiscal Year"
        start_date = date(today.year, 1, 1) # Fiscal year starts Jan 1
        end_date = date(today.year, 12, 31)

    # Apply Status Filter
    if status == 'Open':
        deals_query = deals_query.filter(~Deal.stage.in_(['Closed Won', 'Closed Lost']))
    elif status == 'Closed Won':
        deals_query = deals_query.filter(Deal.stage == 'Closed Won')
    elif status == 'Closed Lost':
        deals_query = deals_query.filter(Deal.stage == 'Closed Lost')
    elif status == 'All':
        pass # No status filter needed for 'All'
    else:
        flash('Invalid deal status selected.', 'warning')
        return redirect(url_for('dashboard'))

    # Apply Date Filter if applicable
    if start_date and end_date:
        # Filter by expected_close_date being within the range
        # Handles cases where expected_close_date might be None by excluding them implicitly
        deals_query = deals_query.filter(
            Deal.expected_close_date >= start_date,
            Deal.expected_close_date <= end_date
        )

    deals = deals_query.order_by(Deal.expected_close_date.asc()).all()

    # Calculate totals for the filtered deals, EXCLUDING 'Closed Lost'
    total_revenue = sum(d.revenue for d in deals if d.revenue and d.stage != 'Closed Lost') or 0
    total_gp = sum(d.gross_profit for d in deals if d.gross_profit and d.stage != 'Closed Lost') or 0

    recipient_emails_raw = [email.strip() for email in recipient_email_string.split(',')]
    recipient_emails = [email for email in recipient_emails_raw if email]

    invalid_emails = [email for email in recipient_emails if '@' not in email]
    if invalid_emails:
        flash(f'Invalid email address(es) found: {", ".join(invalid_emails)}. Please check and try again.', 'warning')
        return redirect(url_for('dashboard'))

    if not recipient_emails:
        flash('Please provide at least one recipient email address.', 'warning')
        return redirect(url_for('dashboard'))

    report_desc = f"{status_desc} ({time_desc})"
    subject = f"{report_desc} Deals Report"

    # Generate Plain Text Body
    body = f"{report_desc} Deals Report for {current_user.email}\n\n"
    if deals:
        for deal in deals:
            close_date = deal.expected_close_date.strftime('%Y-%m-%d') if deal.expected_close_date else 'N/A'
            revenue_str = f"${(deal.revenue or 0.0):,.2f}"
            gross_profit_str = f"${(deal.gross_profit or 0.0):,.2f}"
            lost_indicator = " (Lost)" if deal.stage == 'Closed Lost' else ""
            body += f"- {deal.name} ({deal.stage}{lost_indicator}): Revenue {revenue_str}, Gross Profit {gross_profit_str}, Close Date: {close_date}\n"
        # Add totals to plain text body (reflects exclusion of lost deals)
        body += f"\nTotal Revenue (excluding Lost): ${total_revenue:,.2f}"
        body += f"\nTotal Gross Profit (excluding Lost): ${total_gp:,.2f}"
    else:
        body += f"No {status} deals found for {time_desc}.\n"

    # Generate HTML Body with a Table and Totals Footer
    html_table_rows = ""
    if deals:
        for deal in deals:
            is_lost = deal.stage == 'Closed Lost'
            cell_style = "style='border: 1px solid #ddd; padding: 8px; text-decoration: line-through;'" if is_lost else "style='border: 1px solid #ddd; padding: 8px;'"
            cell_style_numeric = "style='border: 1px solid #ddd; padding: 8px; text-align: right; text-decoration: line-through;'" if is_lost else "style='border: 1px solid #ddd; padding: 8px; text-align: right;'"

            close_date_str = deal.expected_close_date.strftime("%Y-%m-%d") if deal.expected_close_date else "N/A"
            revenue_html = f"${(deal.revenue or 0.0):,.2f}"
            gross_profit_html = f"${(deal.gross_profit or 0.0):,.2f}"
            html_table_rows += f"""
            <tr>
                <td {cell_style}>{deal.name}</td>
                <td {cell_style}>{deal.stage}</td>
                <td {cell_style_numeric}>{revenue_html}</td>
                <td {cell_style_numeric}>{gross_profit_html}</td>
                <td {cell_style}>{close_date_str}</td>
            </tr>
            """

    # Add Totals Row for HTML
    totals_row_html = ""
    if deals:
        formatted_total_revenue = f"${total_revenue:,.2f}"
        formatted_total_gp = f"${total_gp:,.2f}"
        # Using implicit string concatenation with f-strings
        totals_row_html = (
            f"<tfoot style='font-weight: bold; background-color: #f2f2f2;'>"
            f"<tr>"
            f"<td style='border: 1px solid #ddd; padding: 8px;' colspan='2'>Totals ({status_desc}, excluding Lost):</td>" 
            f"<td style='border: 1px solid #ddd; padding: 8px; text-align: right;'>{formatted_total_revenue}</td>"
            f"<td style='border: 1px solid #ddd; padding: 8px; text-align: right;'>{formatted_total_gp}</td>"
            f"<td style='border: 1px solid #ddd; padding: 8px;'></td>"
            f"</tr>"
            f"</tfoot>"
        )

    # Generate the table content or 'no deals' message
    table_html_content = ""
    if deals:
        # Construct the table with header, body, and footer
        table_html_content = f"""
        <table>
            <thead>
                <tr><th>Name</th><th>Stage</th><th>Revenue</th><th>Gross Profit</th><th>Close Date</th></tr>
            </thead>
            <tbody>
                {html_table_rows}
            </tbody>
            {totals_row_html}
        </table>
        """
    else:
        table_html_content = f"<p>No {status} deals found for {time_desc}.</p>"

    # Final HTML Body construction
    html_body = f"""
    <html>
    <head>
        <style>
            table {{{{ ' border-collapse: collapse; width: 100%; ' }}}}
            th, td {{{{ ' border: 1px solid #ddd; padding: 8px; text-align: left; ' }}}}
            th {{{{ ' background-color: #f2f2f2; ' }}}}
            tr:nth-child(even) {{{{ ' background-color: #f9f9f9; ' }}}}
            tfoot td {{{{ ' border-top: 2px solid #aaa; ' }}}}
        </style>
    </head>
    <body>
        <h2>{report_desc} Deals Report for {current_user.email}</h2>
        {table_html_content}
    </body>
    </html>
    """

    recipient_display_str = ", ".join(recipient_emails)
    if send_email(to=recipient_emails, subject=subject, body=body, html_body=html_body):
        flash(f'{report_desc} Deals report sent to {recipient_display_str}.', 'success')
    else:
        flash(f'Failed to send {report_desc} Deals report to {recipient_display_str}.', 'danger')

    return redirect(url_for('dashboard'))


# --- Manager Dashboard Route --- #
@app.route('/manager_dashboard')
@login_required
def manager_dashboard():
    # Ensure only managers or admins can access
    if current_user.role not in ['manager', 'admin']:
        flash('You do not have permission to access the Manager Dashboard.', 'danger')
        return redirect(url_for('dashboard'))

    # --- Get Filters --- #
    # Get raw user_id, could be None or empty string ''
    raw_user_id = request.args.get('user_id') 
    # Treat None or empty string as 'all'
    selected_user_id = raw_user_id if raw_user_id else 'all' 

    selected_user = None
    if selected_user_id != 'all':
        # Attempt to get user only if selected_user_id is not 'all'
        # Assume IDs are integers, convert here
        try:
            selected_user = User.query.get(int(selected_user_id)) 
        except ValueError:
             flash('Invalid user ID selected.', 'warning')
             selected_user_id = 'all' # Fallback safely

    # Use the explicitly imported 'date' here
    selected_year = request.args.get('year', str(date.today().year)) 
    selected_quarter = request.args.get('quarter', 'All')
    selected_status = request.args.get('status', 'Open') # Default to Open

    # --- Dynamic Year Options --- #
    # Calculate available years dynamically based on deals associated with the selected user
    available_years = db.session.query(db.extract('year', Deal.expected_close_date)).distinct().order_by(db.desc(db.extract('year', Deal.expected_close_date))) 
    if selected_user:
        available_years = available_years.filter(Deal.user_id == selected_user.id)
    elif selected_user_id != 'all': # Handle case where user_id is provided but user not found
        available_years = available_years.filter(Deal.user_id == selected_user_id)
    
    year_options = [str(year[0]) for year in available_years.all() if year[0]]
    # Use the explicitly imported 'date' here as well
    current_year_str = str(date.today().year) 
    if current_year_str not in year_options:
        year_options.insert(0, current_year_str) # Ensure current year is always an option
    if 'All' not in year_options:
        year_options.append('All')
    # Correct selected_year if it's not valid
    if selected_year not in year_options and selected_year != 'All':
        selected_year = current_year_str if current_year_str in year_options else 'All'

    # --- User Filtering --- #
    users = User.query.order_by(User.email).all()

    # --- Deal Filtering & Summarization (Copied & Adapted from /dashboard) --- #
    # Base query - Eagerly load customer and owner
    deals_base_query = Deal.query.options(joinedload(Deal.customer), joinedload(Deal.owner))

    # Apply user filter if a user is selected
    if selected_user:
        deals_base_query = deals_base_query.filter(Deal.user_id == selected_user.id)

    # Start with the base query (potentially user-filtered)
    deals_query = deals_base_query 
    
    # Apply year filter (Chain from deals_query)
    if selected_year != 'All':
        try:
            # Apply to the current deals_query
            deals_query = deals_query.filter(extract('year', Deal.expected_close_date) == int(selected_year)) 
        except ValueError:
            flash(f"Invalid year format: {selected_year}. Showing all years.", 'warning')
            selected_year = 'All'

    # Apply quarter filter (Chain from deals_query)
    if selected_quarter != 'All':
        quarter_map = {'Q1': (1, 3), 'Q2': (4, 6), 'Q3': (7, 9), 'Q4': (10, 12)}
        if selected_quarter in quarter_map:
            start_month, end_month = quarter_map[selected_quarter]
            # Apply to the current deals_query
            deals_query = deals_query.filter( 
                extract('month', Deal.expected_close_date) >= start_month,
                extract('month', Deal.expected_close_date) <= end_month
            )
        else:
             flash(f"Invalid quarter selected: {selected_quarter}. Showing all quarters.", 'warning')
             selected_quarter = 'All'

    # Apply status filter (Chain from deals_query)
    if selected_status != 'All':
        # If 'Open', filter for stages that are not 'Closed Won' or 'Closed Lost'
        if selected_status == 'Open':
             # Apply to the current deals_query
             deals_query = deals_query.filter( 
                Deal.stage.notin_(['Closed Won', 'Closed Lost'])
            )
        # Handle 'Closed Won', 'Closed Lost' directly
        elif selected_status in ['Closed Won', 'Closed Lost']:
            # Apply to the current deals_query
            deals_query = deals_query.filter(Deal.stage == selected_status) 
        else:
            flash(f"Invalid status selected: {selected_status}. Showing all statuses.", 'warning')
            selected_status = 'All'

    # Final filtered deals list
    filtered_deals = deals_query.order_by(Deal.expected_close_date.desc()).all()

    # Calculate Summaries (Based on the FINAL filtered list)
    won_open_revenue = sum(d.revenue for d in filtered_deals if d.revenue and d.stage in ['Closed Won', 'Open']) or 0
    won_open_gp = sum(d.gross_profit for d in filtered_deals if d.gross_profit and d.stage in ['Closed Won', 'Open']) or 0
    lost_revenue = sum(d.revenue for d in filtered_deals if d.revenue and d.stage == 'Closed Lost') or 0
    lost_gp = sum(d.gross_profit for d in filtered_deals if d.gross_profit and d.stage == 'Closed Lost') or 0

    # --- Activity Filtering (Keep existing logic) --- #
    activities_query = Activity.query.options(joinedload(Activity.author), joinedload(Activity.deal), joinedload(Activity.customer))
    if selected_user:
        activities_query = activities_query.filter(Activity.user_id == selected_user.id)
    all_activities = activities_query.order_by(Activity.date.desc()).all()
    
    print(f"--- DEBUG: Manager Dashboard Deals (User: {selected_user_id}, Year: {selected_year}, Q: {selected_quarter}, Status: {selected_status}) ---")
    print(f"Filtered Deals Count: {len(filtered_deals)}")
    # Optionally print the deals themselves if the list is small
    # print(filtered_deals)
    print("--- END DEBUG ---")
    
    return render_template('manager_dashboard.html',
                           activities=all_activities,
                           # Deal related variables
                           filtered_deals=filtered_deals,
                           won_open_revenue=won_open_revenue,
                           won_open_gp=won_open_gp,
                           lost_revenue=lost_revenue,
                           lost_gp=lost_gp,
                           year_options=year_options,
                           selected_year=selected_year,
                           selected_quarter=selected_quarter,
                           selected_status=selected_status,
                           # User filter variables
                           all_users=users,
                           selected_user=selected_user,
                           title="Manager Dashboard")


# --- Attachment Routes ---
@app.route('/attachments/<int:attachment_id>/download')
@login_required
def download_attachment(attachment_id):
    attachment = DealAttachment.query.get_or_404(attachment_id)
    deal = attachment.deal # Get the associated deal

    # Permission check: Only deal owner or admin/manager can download
    if deal.owner != current_user and current_user.role not in ['admin', 'manager']:
        flash('You do not have permission to download this file.', 'danger')
        # Redirect to the deal detail page or another appropriate location
        return redirect(url_for('deal_detail', deal_id=deal.id)) 

    # Ensure the upload folder path is absolute
    upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
    
    try:
        # send_from_directory needs the directory path and the filename separately
        # attachment.filepath stores the unique filename, attachment.filename stores the original
        return send_from_directory(upload_folder, 
                                   attachment.filepath, 
                                   as_attachment=True, 
                                   download_name=attachment.filename) # Use original filename for download prompt
    except FileNotFoundError:
        flash('File not found on server.', 'danger')
        # Log the error for investigation
        app.logger.error(f"Attachment file not found: ID={attachment.id}, Path={os.path.join(upload_folder, attachment.filepath)}")
        return redirect(url_for('edit_deal', deal_id=deal.id)) # Redirect back to edit page
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'danger')
        app.logger.error(f"Error downloading attachment ID {attachment_id}: {e}")
        return redirect(url_for('edit_deal', deal_id=deal.id))

# Route to delete an attachment
@app.route('/attachments/<int:attachment_id>/delete', methods=['POST'])
@login_required
def delete_attachment(attachment_id):
    attachment = DealAttachment.query.get_or_404(attachment_id)
    deal = attachment.deal # Get the associated deal for permission check and redirect

    # Permission check: Only deal owner or admin/manager can delete
    if deal.owner != current_user and current_user.role not in ['admin', 'manager']:
        flash('You do not have permission to delete this attachment.', 'danger')
        return redirect(url_for('edit_deal', deal_id=deal.id))

    # Construct the full path to the file
    upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
    filepath = os.path.join(upload_folder, attachment.filepath)

    try:
        # 1. Delete the file from the filesystem
        if os.path.exists(filepath):
            os.remove(filepath)
        else:
             # Log if file was already missing, but proceed to delete DB record
            app.logger.warning(f"Attempted to delete non-existent attachment file: ID={attachment.id}, Path={filepath}")

        # 2. Delete the record from the database
        db.session.delete(attachment)
        db.session.commit()
        flash('Attachment deleted successfully!', 'success')

    except OSError as e:
        # File system error during deletion
        db.session.rollback() # Rollback DB change if file deletion failed unexpectedly
        flash(f'Error deleting file from server: {str(e)}', 'danger')
        app.logger.error(f"Error deleting attachment file: ID={attachment.id}, Path={filepath}, Error: {e}")
    except Exception as e:
        # Database or other error
        db.session.rollback()
        flash(f'Error deleting attachment record: {str(e)}', 'danger')
        app.logger.error(f"Error deleting attachment record ID {attachment_id}: {e}")

    # Redirect back to the edit deal page regardless of outcome (flash message indicates status)
    return redirect(url_for('edit_deal', deal_id=deal.id))


# --- Main Execution ---
if __name__ == '__main__':
    # Ensure the instance folder exists
    # Removed redundant db.create_all() here, use 'flask init-db' instead
    app.run(debug=True, port=5001) # Run on port 5001 with debug enabled
