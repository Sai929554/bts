from flask import Flask, request, render_template, redirect, url_for, session, flash, send_from_directory
import pandas as pd
import smtplib
import os
import random
import spacy
import subprocess
from flask_caching import Cache
from flask_cors import CORS  # Added CORS for cross-origin access
from gamil import process_resumes_for_job  # Updated function name to avoid input() issue

# Ensure Spacy Model is Installed
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("Downloading Spacy model at runtime...")
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv('SECRET_KEY', 'your_default_secret_key')  # Use environment variable for security

# Enable CORS to allow access from your company website
CORS(app, origins=["https://www.iitlabs.us"], supports_credentials=True)

# Set up caching (in-memory cache for simplicity)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Temporary storage for OTPs (use a database in production)
otp_storage = {}

# Allowed users (Replace with a database in production)
ALLOWED_USERS = {
    "maneeshaupender30@gmail.com": "Chawoo@30",
    "saicharan.rajampeta@iitlabs.us": "Db2@Admin",
    "rakeshthallapalli7@gmail.com": "7799590053"
}

# Temporary password for password reset
TEMP_PASSWORD = "Reset@123"

# Function to send reset password email
def send_reset_email(user_email):
    sender_email = os.getenv("EMAIL_USER")  # Get email from environment variable
    sender_password = os.getenv("EMAIL_PASS")  # Get password from environment variable
    subject = "Password Reset Request"
    message = f"Your temporary password is: {TEMP_PASSWORD}. Please log in and change it immediately."
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, f"Subject: {subject}\n\n{message}")
        server.quit()
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

# Route to serve images
@app.route('/static/images/<filename>')
def serve_image(filename):
    return send_from_directory("static/images", filename)

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "ALLOW-FROM https://www.iitlabs.us"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'self' https://www.iitlabs.us;"
    return response

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/', methods=['POST'])
def login_post():
    email = request.form['email']
    password = request.form['password']
    if email in ALLOWED_USERS and ALLOWED_USERS[email] == password:
        session['user'] = email  # Set session for the logged-in user
        session['logged_in'] = True  # Ensure session is properly set
        return redirect(url_for('index'))
    else:
        flash("Invalid credentials. Please try again.", "danger")
        return redirect(url_for('login'))

@app.route("/dashboard", methods=["GET", "POST"])
def index():
    if 'logged_in' not in session or not session['logged_in']:
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))
    if request.method == "POST":
        job_id = request.form.get("job_id")  # Get Job ID from form input
        if not job_id:
            flash("Please enter a valid Job ID", "warning")
            return redirect(url_for("index"))
        df = process_resumes_for_job(job_id)  # Call function without input()
        if df.empty:
            flash(f"No resumes found for Job ID: {job_id}", "warning")
            return render_template("index.html", tables=[])
        df_cleaned = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
        return render_template("index.html", tables=[df_cleaned.to_html(classes='table table-bordered', index=False)])
    return render_template("index.html")

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
