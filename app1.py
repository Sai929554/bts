from flask import Flask, request, render_template, redirect, url_for, session, flash
import pandas as pd
import smtplib
import imaplib
import time
import email
import os
import random
import spacy
import subprocess
from flask_caching import Cache
from gamil import process_resumes_for_job  # Updated function name to avoid input() issue


# Ensure Spacy Model is Installed
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("Downloading Spacy model at runtime...")
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")


app = Flask(__name__, template_folder="templates")

app.secret_key = os.getenv('SECRET_KEY', 'your_default_secret_key')  # Use environment variable for security

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

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/forgot_password', methods=['POST'])
def send_otp():
    email = request.form['email']
    otp = str(random.randint(100000, 999999))
    otp_storage[email] = otp  # Store OTP temporarily
    print(f"OTP for {email}: {otp}")  # Debugging purposes
    flash("OTP sent to your email.", "success")
    return redirect(url_for('confirm_otp'))

@app.route('/confirm_otp')
def confirm_otp():
    return render_template('confirm_otp.html')

@app.route('/confirm_otp', methods=['POST'])
def verify_otp():
    email = request.form.get('email')
    otp = request.form['otp']
    if email in otp_storage and otp_storage[email] == otp:
        session['reset_email'] = email
        return redirect(url_for('reset_password'))
    else:
        flash("Invalid OTP. Please try again.", "danger")
        return redirect(url_for('confirm_otp'))

@app.route('/reset_password')
def reset_password():
    return render_template('reset_password.html')

@app.route('/reset_password', methods=['POST'])
def reset_password_post():
    if 'reset_email' not in session:
        return redirect(url_for('login'))
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if new_password == confirm_password:
        flash("Password reset successfully. Please log in.", "success")
        return redirect(url_for('login'))
    else:
        flash("Passwords do not match. Try again.", "danger")
        return redirect(url_for('reset_password'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
