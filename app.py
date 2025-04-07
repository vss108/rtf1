import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from datetime import datetime
import re

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_SECURE"] = True  # Use HTTPS in production
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes session timeout

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    service = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Validation functions
def validate_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]{4,20}$', username))

def validate_password(password):
    return len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password)

# Routes
@app.route("/")
def home():
    return render_template("main.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("doctors"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        
        if not validate_username(username):
            flash("Invalid username format", "danger")
            return render_template("login.html")
            
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session.permanent = True
            session.modified = True
            flash("Login successful!", "success")
            return redirect(url_for("doctors"))
        else:
            flash("Invalid credentials", "danger")
    
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("doctors"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not validate_username(username):
            flash("Invalid username format", "danger")
            return render_template("signup.html")
        
        if not validate_password(password):
            flash("Password must have at least 8 characters, an uppercase letter, and a number", "danger")
            return render_template("signup.html")
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return render_template("signup.html")
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully!", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/book", methods=["GET", "POST"])
def book():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        service = request.form["service"].strip()
        date_str = request.form["date"].strip()
        date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")

        # Validate booking time (9 AM - 9 PM)
        if date.hour < 9 or date.hour > 21:
            flash("Bookings allowed only between 9 AM and 9 PM", "danger")
            return render_template("booknow.html")

        if date < datetime.now():
            flash("Cannot book for past dates", "danger")
            return render_template("booknow.html")
            
        new_booking = Booking(user_id=session["user_id"], service=service, date=date)
        db.session.add(new_booking)
        db.session.commit()
        flash("Booking successful!", "success")
        return redirect(url_for("pay"))

    return render_template("booknow.html")

# Handle 404 errors
@app.errorhandler(404)
def page_not_found(error):
    flash("Page not found. Redirecting to login.", "warning")
    return redirect(url_for("login"))

# Global error handling
@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {str(error)}")
    return render_template("500.html"), 500

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
