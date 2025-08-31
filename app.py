import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

# --- App & DB ---
app = Flask(__name__)
app.config.from_object("config.Config")
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# --- Models ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student','recruiter','admin'
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    resume_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    jobs = db.relationship("Job", backref="recruiter", lazy=True, cascade="all, delete")

    def set_password(self, pwd): self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd): return check_password_hash(self.password_hash, pwd)

class Job(db.Model):
    __tablename__ = "jobs"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(120))
    job_type = db.Column(db.String(80))
    description = db.Column(db.Text)
    requirements = db.Column(db.Text)
    salary_min = db.Column(db.Integer) # New
    salary_max = db.Column(db.Integer) # New
    posted_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    deadline = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    applications = db.relationship("Application", backref="job", lazy=True, cascade="all, delete")

class Application(db.Model):
    __tablename__ = "applications"
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    cover_note = db.Column(db.Text)
    status = db.Column(db.String(20), default="applied")
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    student = db.relationship("User", backref="applications", lazy=True, foreign_keys=[student_id])

# --- Init DB (first run) ---
with app.app_context():
    db.create_all()

# --- Helpers ---
def login_required(role=None):
    def wrapper(fn):
        from functools import wraps
        @wraps(fn)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "warning"); return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Unauthorized.", "danger"); return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return decorated
    return wrapper

def allowed_file(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in app.config["ALLOWED_EXTENSIONS"]

# --- Auth Routes ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, password, role = request.form["name"].strip(), request.form["email"].strip().lower(), request.form["password"], request.form["role"]
        if role not in ("student", "recruiter"):
            flash("Select a valid role.", "danger"); return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger"); return redirect(url_for("register"))
        user = User(name=name, email=email, role=role)
        user.set_password(password)
        if role == "student":
            user.is_approved = True
            flash_message = "Registration successful. Please log in."
        else:
            flash_message = "Recruiter account created. It will be active after admin approval."
        db.session.add(user); db.session.commit()
        flash(flash_message, "success")
        return redirect(url_for("login"))
    return render_template("auth_register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form["email"].strip().lower(), request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if user.role == "recruiter" and not user.is_approved:
                flash("Your account is pending approval.", "warning"); return redirect(url_for("login"))
            session["user_id"], session["role"], session["name"] = user.id, user.role, user.name
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("auth_login.html")

@app.route("/logout")
def logout():
    session.clear(); flash("Logged out.", "info"); return redirect(url_for("login"))

# --- Dashboards ---
@app.route("/")
@login_required()
def dashboard():
    role = session.get("role")
    if role == "recruiter":
        my_jobs = Job.query.filter_by(posted_by=session["user_id"]).order_by(Job.created_at.desc()).all()
        total_apps = sum(len(j.applications) for j in my_jobs)
        return render_template("dashboard_recruiter.html", jobs=my_jobs, total_apps=total_apps)
    if role == "admin":
        pending_recruiters = User.query.filter_by(role="recruiter", is_approved=False).all()
        approved_recruiters = User.query.filter_by(role="recruiter", is_approved=True).order_by(User.name).all()
        all_applications = Application.query.order_by(Application.applied_at.desc()).all()
        return render_template("dashboard_admin.html", pending=pending_recruiters, recruiters=approved_recruiters, applications=all_applications)
    # student
    my_apps = Application.query.filter_by(student_id=session["user_id"]).order_by(Application.applied_at.desc()).all()
    return render_template("dashboard_student.html", applications=my_apps)

# --- Admin Actions ---
@app.route("/admin/approve/<int:user_id>", methods=["POST"])
@login_required("admin")
def approve_recruiter(user_id):
    recruiter = User.query.get_or_404(user_id)
    if recruiter.role == "recruiter":
        recruiter.is_approved = True
        db.session.commit(); flash(f"{recruiter.name}'s account has been approved.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/delete_recruiter/<int:user_id>", methods=["POST"])
@login_required("admin")
def delete_recruiter(user_id):
    recruiter = User.query.get_or_404(user_id)
    if recruiter.role == "recruiter":
        db.session.delete(recruiter)
        db.session.commit(); flash(f"Recruiter {recruiter.name} has been deleted.", "info")
    return redirect(url_for("dashboard"))

@app.route("/admin/delete_application/<int:app_id>", methods=["POST"])
@login_required("admin")
def delete_application(app_id):
    application = Application.query.get_or_404(app_id)
    db.session.delete(application)
    db.session.commit(); flash("Application has been deleted.", "info")
    return redirect(url_for("dashboard"))

# --- Recruiter actions on applications ---
@app.route("/application/<int:app_id>/update_status", methods=["POST"])
@login_required("recruiter")
def update_application_status(app_id):
    application = Application.query.get_or_404(app_id)
    if application.job.posted_by != session["user_id"]: abort(403)
    new_status = request.form.get("status")
    if new_status in ["accepted", "rejected"]:
        application.status = new_status
        db.session.commit(); flash(f"Application status updated to {new_status}.", "success")
    return redirect(url_for("applicants", job_id=application.job.id))

# --- Profile Management ---
@app.route("/profile", methods=["GET", "POST"])
@login_required()
def profile():
    user = User.query.get_or_404(session["user_id"])
    if request.method == "POST":
        if "update_details" in request.form:
            user.name = request.form["name"].strip()
            db.session.commit(); session["name"] = user.name
            flash("Profile updated.", "success")
        elif "upload_resume" in request.form and user.role == "student":
            file = request.files.get("resume")
            if file and allowed_file(file.filename):
                fname = f"resume_user{user.id}_{secure_filename(file.filename)}"
                path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
                file.save(path); user.resume_path = fname
                db.session.commit(); flash("Resume uploaded.", "success")
            else:
                flash("Select a valid PDF file.", "danger")
        elif "delete_resume" in request.form and user.role == "student":
            if user.resume_path:
                path = os.path.join(app.config["UPLOAD_FOLDER"], user.resume_path)
                if os.path.exists(path): os.remove(path)
                user.resume_path = None
                db.session.commit(); flash("Resume deleted.", "info")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

@app.route("/uploads/<path:filename>")
@login_required()
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# --- Job Routes ---
# In app.py

# --- Job Routes ---
@app.route("/jobs")
@login_required()
def jobs_list():
    # Get the page number from URL query string, default to 1
    page = request.args.get('page', 1, type=int)
    
    q, jt = request.args.get("q", "").strip(), request.args.get("type", "").strip()
    query = Job.query
    if q: 
        query = query.filter(db.or_(Job.title.ilike(f"%{q}%"), Job.company.ilike(f"%{q}%"), Job.location.ilike(f"%{q}%")))
    if jt: 
        query = query.filter_by(job_type=jt)
    
    # Instead of .all(), use .paginate(). 
    # This fetches only the jobs for the current page.
    jobs_pagination = query.order_by(Job.created_at.desc()).paginate(
        page=page, per_page=8, error_out=False
    )
    
    # Pass the pagination object to the template
    return render_template("jobs_list.html", jobs=jobs_pagination, q=q, jt=jt)

@app.route("/jobs/<int:job_id>")
@login_required()
def job_detail(job_id):
    job = Job.query.get_or_404(job_id)
    already_applied, co_joiners = None, None
    if session.get("role") == "student":
        application = Application.query.filter_by(job_id=job.id, student_id=session["user_id"]).first()
        if application:
            already_applied = True
            if application.status == 'accepted':
                co_joiners = Application.query.filter(
                    Application.job_id == job.id,
                    Application.status == 'accepted',
                    Application.student_id != session["user_id"]
                ).all()
    return render_template("job_detail.html", job=job, already=already_applied, co_joiners=co_joiners)

@app.route("/jobs/new", methods=["GET", "POST"])
@login_required("recruiter")
def job_new():
    if request.method == "POST":
        job = Job(posted_by=session["user_id"])
        job.title = request.form["title"].strip()
        job.company = request.form["company"].strip()
        job.location = request.form.get("location", "").strip()
        job.job_type = request.form.get("job_type", "").strip()
        job.description = request.form.get("description", "").strip()
        job.requirements = request.form.get("requirements", "").strip()
        job.salary_min = int(request.form.get("salary_min")) if request.form.get("salary_min") else None
        job.salary_max = int(request.form.get("salary_max")) if request.form.get("salary_max") else None
        deadline = request.form.get("deadline") or None
        job.deadline = datetime.strptime(deadline, "%Y-%m-%d").date() if deadline else None
        db.session.add(job); db.session.commit()
        flash("Job posted.", "success"); return redirect(url_for("dashboard"))
    return render_template("job_form.html", job=None)

@app.route("/jobs/<int:job_id>/edit", methods=["GET", "POST"])
@login_required("recruiter")
def job_edit(job_id):
    job = Job.query.get_or_404(job_id)
    if job.posted_by != session["user_id"]: abort(403)
    if request.method == "POST":
        job.title = request.form["title"].strip()
        job.company = request.form["company"].strip()
        job.location = request.form.get("location", "").strip()
        job.job_type = request.form.get("job_type", "").strip()
        job.description = request.form.get("description", "").strip()
        job.requirements = request.form.get("requirements", "").strip()
        job.salary_min = int(request.form.get("salary_min")) if request.form.get("salary_min") else None
        job.salary_max = int(request.form.get("salary_max")) if request.form.get("salary_max") else None
        deadline = request.form.get("deadline") or None
        job.deadline = datetime.strptime(deadline, "%Y-%m-%d").date() if deadline else None
        db.session.commit(); flash("Job updated.", "success"); return redirect(url_for("dashboard"))
    return render_template("job_form.html", job=job)

@app.route("/jobs/<int:job_id>/delete", methods=["POST"])
@login_required("recruiter")
def job_delete(job_id):
    job = Job.query.get_or_404(job_id)
    if job.posted_by != session["user_id"]: abort(403)
    db.session.delete(job); db.session.commit()
    flash("Job deleted.", "info"); return redirect(url_for("dashboard"))

@app.route("/jobs/<int:job_id>/apply", methods=["POST"])
@login_required("student")
def apply(job_id):
    student = User.query.get(session["user_id"])
    if not student.resume_path:
        flash("Upload your resume before applying.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))
    if Application.query.filter_by(job_id=job_id, student_id=student.id).first():
        flash("You already applied.", "info")
        return redirect(url_for("job_detail", job_id=job_id))
    appn = Application(job_id=job_id, student_id=student.id, cover_note=request.form.get("cover_note", "").strip())
    db.session.add(appn); db.session.commit()
    flash("Application submitted!", "success"); return redirect(url_for("dashboard"))

@app.route("/recruiter/jobs/<int:job_id>/applicants")
@login_required("recruiter")
def applicants(job_id):
    job = Job.query.get_or_404(job_id)
    if job.posted_by != session["user_id"]: abort(403)
    apps = Application.query.filter_by(job_id=job.id).order_by(Application.applied_at.desc()).all()
    return render_template("applicants_list.html", job=job, applications=apps)

# --- Error Handlers & Seed ---
@app.errorhandler(403)
def err403(e): return render_template("base.html", content="403 Unauthorized"), 403

@app.errorhandler(404)
def err404(e): return render_template("base.html", content="404 Not Found"), 404

# --- THIS IS THE CORRECTED SEED FUNCTION ---
@app.route("/seed")
def seed():
    # Check if data already exists to prevent duplicates
    if User.query.filter_by(email="admin@portal.com").first() is None:
        # Create Users
        admin = User(name="Admin", email="admin@portal.com", role="admin", is_approved=True)
        admin.set_password("admin123")
        
        recruiter = User(name="ACME HR", email="recruiter@acme.com", role="recruiter", is_approved=True)
        recruiter.set_password("test123")
        
        student = User(name="John Student", email="student@example.com", role="student", is_approved=True)
        student.set_password("test123")
        
        db.session.add_all([admin, recruiter, student])
        db.session.commit() # Commit users to get their IDs
        
        # Create Jobs
        j1 = Job(title="Backend Intern", company="ACME Corp", location="Remote",
                 job_type="Internship", description="Work on cool APIs.", 
                 requirements="Python, SQL", posted_by=recruiter.id)
                 
        j2 = Job(title="Frontend Developer", company="ACME Corp", location="Vadodara",
                 job_type="Full-time", description="Build beautiful UIs with React.", 
                 requirements="JavaScript, CSS, React", salary_min=800000, salary_max=1200000, 
                 posted_by=recruiter.id)
                 
        db.session.add_all([j1, j2])
        db.session.commit()
        
        return "Database seeded with default users and jobs."
        
    return "Database already seeded."