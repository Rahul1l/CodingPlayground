import os
import sys
import subprocess
import tempfile
import traceback
import json
import csv
import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from io import BytesIO, StringIO

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, send_file
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, 
           template_folder='.')  # Look for templates in current directory

# Configure app
app.config.from_object(Config)
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False
)
app.secret_key = os.getenv("SECRET_KEY", Config.SECRET_KEY)

# Enable CORS for all routes (allow credentials for session cookies)
CORS(app, supports_credentials=True)

# MongoDB Setup - Following working Feedback-App-V2 pattern
try:
    print("Connecting to MongoDB...")
    # Try the exact same pattern as working app
    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("✅ MongoDB connected successfully")
    
    db = client[Config.DATABASE_NAME]
    admins_col = db["admins"]
    users_col = db["users"]
    classroom_col = db["classrooms"]
    activities_col = db["activities"]
    tests_col = db["tests"]
    submissions_col = db["submissions"]
    
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    print("Trying alternative connection method...")
    
    # Try with explicit SSL context (sometimes needed on AWS EC2)
    try:
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        client = MongoClient(
            Config.MONGO_URI, 
            serverSelectionTimeoutMS=10000,
            ssl_context=ssl_context
        )
        client.admin.command('ping')
        print("✅ MongoDB connected successfully with SSL context")
        
        db = client[Config.DATABASE_NAME]
        admins_col = db["admins"]
        users_col = db["users"]
        classroom_col = db["classrooms"]
        activities_col = db["activities"]
        tests_col = db["tests"]
        submissions_col = db["submissions"]
        
    except Exception as e2:
        print(f"❌ Alternative MongoDB connection also failed: {e2}")
        print("App cannot start without MongoDB connection")
        exit(1)

# OpenAI Client - Following working Feedback-App-V2 pattern exactly
import openai

# Simple initialization like working app - no proxy clearing, no test calls
api_key = os.getenv("OPENAI_API_KEY")
if api_key:
    openai.api_key = api_key
    print(f"OpenAI API key set: {api_key[:10]}...")
else:
    print("Warning: OPENAI_API_KEY not found in environment variables")


def require_admin():
	if not session.get("admin_username"):
		return redirect(url_for("login"))
	return None


def require_user():
	if not session.get("user_username"):
		return redirect(url_for("login"))
	return None


@app.route("/")
def index():
	# Check if already logged in
	if "admin_username" in session:
		return redirect(url_for("admin_dashboard"))
	if "user_username" in session:
		return redirect(url_for("user_home"))
	# Otherwise redirect to unified login
	return redirect(url_for("login"))

@app.route('/health', methods=['GET'])
def health_check():
	"""Health check endpoint"""
	return jsonify({
		'status': 'healthy',
		'message': 'Coding Playground API is running',
		'version': '1.0.0',
		'mongodb': 'Connected' if users_col is not None else 'Disconnected'
	})

# All CSS and JavaScript are now embedded in index.html

@app.route("/test-mongodb")
def test_mongodb():
	"""Test MongoDB Atlas connection"""
	try:
		# Try to insert a test document
		test_doc = {"test": True, "timestamp": datetime.now()}
		result = users_col.insert_one(test_doc)
		
		# Try to find the document
		found = users_col.find_one({"_id": result.inserted_id})
		
		# Clean up test document
		users_col.delete_one({"_id": result.inserted_id})
		
		return jsonify({
			"status": "success", 
			"message": "MongoDB Atlas connection working",
			"test_id": str(result.inserted_id),
			"database_type": "MongoDB Atlas"
		})
	except Exception as e:
		return jsonify({"status": "error", "message": f"MongoDB Atlas test failed: {str(e)}"})


@app.route("/login", methods=["GET", "POST"])
def login():
	"""Unified login for both admin and users"""
	if request.method == "POST":
		username = request.form.get("username", "").strip()
		password = request.form.get("password", "")
		
		# Check if admin credentials (hardcoded: Ayushman / ayushman9277)
		if username == "Ayushman" and password == "ayushman9277":
			session["admin_username"] = "Ayushman"
			return redirect(url_for("admin_dashboard"))
		
		# Check existing admin in database
		admin = admins_col.find_one({"username": username})
		if admin and check_password_hash(admin.get("password_hash", ""), password):
			session["admin_username"] = username
			return redirect(url_for("admin_dashboard"))
		
		# Check regular user
		user = users_col.find_one({"username": username})
		if user and check_password_hash(user.get("password_hash", ""), password):
			session["user_username"] = username
			session["user_role"] = user.get("role")
			return redirect(url_for("user_home"))
		
		# Invalid credentials
		return render_template("index.html", view="login", error="Invalid username or password")
	
	return render_template("index.html", view="login")


@app.route("/admin/logout")
def admin_logout():
	session.pop("admin_username", None)
	return redirect(url_for("login"))




@app.route("/admin/dashboard")
def admin_dashboard():
	redir = require_admin()
	if redir:
		return redir
	# Basic counts for display
	user_count = users_col.count_documents({})
	# Count unique classroom IDs from activities (more accurate than separate classroom collection)
	classroom_count = len(activities_col.distinct("classroom_id"))
	test_count = tests_col.count_documents({})
	# Get recent users for display
	recent_users = list(users_col.find({}, {"username": 1, "role": 1, "classroom_id": 1, "test_id": 1, "created_at": 1}).sort("created_at", -1).limit(10))
	return render_template("index.html", view="admin_dashboard", user_count=user_count, classroom_count=classroom_count, test_count=test_count, recent_users=recent_users)


@app.route("/admin/create_user", methods=["POST"])  # Admin creates user for classroom or test
def admin_create_user():
	redir = require_admin()
	if redir:
		return redir
	username = request.form.get("username", "").strip()
	password = request.form.get("password", "")
	university = request.form.get("university", "").strip()
	role = request.form.get("role", "").strip()  # 'classroom', 'test', or 'both'
	classroom_id = request.form.get("classroom_id", "").strip() or None
	test_id = request.form.get("test_id", "").strip() or None
	if not username or not password or not university or role not in ("classroom", "test", "both"):
		return jsonify({"ok": False, "error": "username, password, university, and valid role required"}), 400
	if role == "both" and (not classroom_id or not test_id):
		return jsonify({"ok": False, "error": "both classroom_id and test_id required for 'both' role"}), 400
	# Check if password already exists (passwords must be unique)
	if users_col.find_one({"password_plain": password}):
		return jsonify({"ok": False, "error": "This password is already in use. Please use a different password."}), 409
	users_col.insert_one({
		"username": username,
		"password_hash": generate_password_hash(password),
		"password_plain": password,  # Store plain password for admin viewing (in production, use encryption)
		"university": university,
		"role": role,
		"classroom_id": classroom_id,
		"test_id": test_id,
		"created_at": datetime.now(timezone.utc)
	})
	return redirect(url_for("admin_dashboard"))


@app.route("/admin/bulk_create_users", methods=["POST"])
def admin_bulk_create_users():
	redir = require_admin()
	if redir:
		return redir
	
	# Check if file was uploaded
	if 'csv_file' not in request.files:
		return jsonify({"ok": False, "error": "No CSV file uploaded"}), 400
	
	file = request.files['csv_file']
	if file.filename == '':
		return jsonify({"ok": False, "error": "No file selected"}), 400
	
	if not file.filename.endswith('.csv'):
		return jsonify({"ok": False, "error": "File must be a CSV file"}), 400
	
	try:
		# Read CSV file
		stream = StringIO(file.stream.read().decode("UTF-8"), newline=None)
		csv_reader = csv.DictReader(stream)
		
		# Validate headers
		required_headers = ['username', 'password', 'university']
		optional_headers = ['role', 'classroom_id', 'test_id']
		
		if not all(header in csv_reader.fieldnames for header in required_headers):
			return jsonify({"ok": False, "error": f"CSV must contain headers: {', '.join(required_headers)}. Optional: {', '.join(optional_headers)}"}), 400
		
		created_users = []
		skipped_users = []
		errors = []
		
		for row_num, row in enumerate(csv_reader, start=2):  # start=2 because row 1 is header
			username = row.get('username', '').strip()
			password = row.get('password', '').strip()
			university = row.get('university', '').strip()
			classroom_id = row.get('classroom_id', '').strip() or None
			test_id = row.get('test_id', '').strip() or None
			role = row.get('role', '').strip().lower()
			
			# Skip empty rows
			if not username:
				continue
			
			# Validate required fields
			if not password or not university:
				errors.append(f"Row {row_num}: Missing password or university for user '{username}'")
				continue
			
			# Auto-detect role if not specified or invalid
			if role not in ('classroom', 'test', 'both'):
				if classroom_id and test_id:
					role = 'both'
				elif classroom_id:
					role = 'classroom'
				elif test_id:
					role = 'test'
				else:
					errors.append(f"Row {row_num}: Cannot determine role for user '{username}'. No classroom_id or test_id provided.")
					continue
			
			# Validate role requirements
			if role == 'classroom' and not classroom_id:
				errors.append(f"Row {row_num}: User '{username}' has role 'classroom' but no classroom_id")
				continue
			if role == 'test' and not test_id:
				errors.append(f"Row {row_num}: User '{username}' has role 'test' but no test_id")
				continue
			if role == 'both' and (not classroom_id or not test_id):
				errors.append(f"Row {row_num}: User '{username}' has role 'both' but missing classroom_id or test_id")
				continue
			
			# Check if password already exists (passwords must be unique)
			if users_col.find_one({"password_plain": password}):
				skipped_users.append(f"{username} - password already in use")
				continue
			
			# Create user (usernames can be duplicate)
			try:
				users_col.insert_one({
					"username": username,
					"password_hash": generate_password_hash(password),
					"password_plain": password,
					"university": university,
					"role": role,
					"classroom_id": classroom_id,
					"test_id": test_id,
					"created_at": datetime.now(timezone.utc)
				})
				created_users.append(f"{username} ({university})")
			except Exception as e:
				errors.append(f"Row {row_num}: Failed to create user '{username}': {str(e)}")
		
		# Prepare response
		response = {
			"ok": True,
			"created": len(created_users),
			"skipped": len(skipped_users),
			"errors": len(errors),
			"details": {
				"created_users": created_users,
				"skipped_users": skipped_users,
				"errors": errors
			}
		}
		
		return jsonify(response), 200
		
	except Exception as e:
		return jsonify({"ok": False, "error": f"Failed to process CSV: {str(e)}"}), 500


@app.route("/admin/users")
def admin_users():
	redir = require_admin()
	if redir:
		return redir
	
	# Get all users grouped by university
	users = list(users_col.find({}, {"username": 1, "role": 1, "classroom_id": 1, "test_id": 1, "university": 1, "password_plain": 1, "created_at": 1}).sort("university", 1).sort("created_at", -1))
	
	# Group users by university
	universities = {}
	for user in users:
		university = user.get("university", "Unknown")
		if university not in universities:
			universities[university] = []
		universities[university].append(user)
	
	total_users = len(users)
	
	return render_template("index.html", view="admin_users", universities=universities, total_users=total_users)


@app.route("/admin/users/export")
def admin_export_users():
	redir = require_admin()
	if redir:
		return redir
	
	try:
		# Get all users
		users = list(users_col.find({}, {"username": 1, "role": 1, "classroom_id": 1, "test_id": 1, "university": 1, "password_plain": 1, "created_at": 1}).sort("created_at", -1))
		
		# Create CSV file in memory
		output = StringIO()
		writer = csv.writer(output)
		
		# Write header
		writer.writerow(['Username', 'Password', 'Role', 'University', 'Classroom ID', 'Test ID', 'Created At'])
		
		# Write data
		for user in users:
			created_at = user.get('created_at', '').strftime('%Y-%m-%d %H:%M:%S') if user.get('created_at') else ''
			writer.writerow([
				user.get('username', ''),
				user.get('password_plain', ''),
				user.get('role', ''),
				user.get('university', ''),
				user.get('classroom_id', ''),
				user.get('test_id', ''),
				created_at
			])
		
		output.seek(0)
		return send_file(
			BytesIO(output.getvalue().encode('utf-8')),
			mimetype='text/csv',
			as_attachment=True,
			download_name=f'users_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
		)
		
	except Exception as e:
		print(f"Export error: {e}")
		return jsonify({"success": False, "error": f"Export failed: {str(e)}"})


@app.route("/admin/users/export/<university>")
def admin_export_university_users(university):
	redir = require_admin()
	if redir:
		return redir
	
	try:
		# Get users for specific university
		users = list(users_col.find({"university": university}, {"username": 1, "role": 1, "classroom_id": 1, "test_id": 1, "university": 1, "password_plain": 1, "created_at": 1}).sort("created_at", -1))
		
		if not users:
			return jsonify({"error": f"No users found for {university}"}), 404
		
		# Create CSV file in memory
		output = StringIO()
		writer = csv.writer(output)
		
		# Write header
		writer.writerow(['Username', 'Password', 'Role', 'University', 'Classroom ID', 'Test ID', 'Created At'])
		
		# Write data
		for user in users:
			created_at = user.get('created_at', '').strftime('%Y-%m-%d %H:%M:%S') if user.get('created_at') else ''
			writer.writerow([
				user.get('username', ''),
				user.get('password_plain', ''),
				user.get('role', ''),
				user.get('university', ''),
				user.get('classroom_id', ''),
				user.get('test_id', ''),
				created_at
			])
		
		output.seek(0)
		return send_file(
			BytesIO(output.getvalue().encode('utf-8')),
			mimetype='text/csv',
			as_attachment=True,
			download_name=f'{university}_users_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
		)
		
	except Exception as e:
		print(f"Export error: {e}")
		return jsonify({"success": False, "error": f"Export failed: {str(e)}"})


@app.route("/admin/users/delete/<username>", methods=["POST"])
def admin_delete_user(username):
	redir = require_admin()
	if redir:
		return redir
	
	# Delete user
	result = users_col.delete_one({"username": username})
	if result.deleted_count > 0:
		return jsonify({"ok": True, "message": f"User {username} deleted successfully"})
	else:
		return jsonify({"ok": False, "message": "User not found"}), 404


@app.route("/admin/classroom-activities")
def admin_classroom_activities():
	redir = require_admin()
	if redir:
		return redir
	
	# Get all activities created by admin
	activities = list(activities_col.find({}, {"activity_id": 1, "subject": 1, "classroom_id": 1, "created_at": 1, "generated": 1}).sort("created_at", -1))
	
	return render_template("index.html", view="admin_classroom_activities", activities=activities)


@app.route("/admin/classroom-activities/<activity_id>")
def admin_attempt_activity(activity_id: str):
	redir = require_admin()
	if redir:
		return redir
	
	# Get the activity
	activity = activities_col.find_one({"activity_id": activity_id})
	if not activity:
		abort(404)
	
	# Parse questions from generated content
	questions = []
	try:
		import json
		generated_data = json.loads(activity.get("generated", "{}"))
		questions = generated_data.get("questions", [])
	except Exception as e:
		print(f"Error parsing activity JSON: {e}")
		questions = []
	
	return render_template("index.html", view="admin_attempt_activity", activity=activity, questions=questions)


@app.route("/admin/question/execute", methods=["POST"])
def admin_execute_question():
	redir = require_admin()
	if redir:
		return redir
	
	code = request.form.get("code", "").strip()
	question_text = request.form.get("question_text", "")
	
	if not code:
		return jsonify({"success": False, "error": "No code provided"})
	
	try:
		# Execute the code
		result = execute_python_code(code)
		
		# Get AI validation if OpenAI is available
		validation = ""
		if openai.api_key:
			try:
				trainer_role = """You are an Expert Code Reviewer for educational purposes.

Your approach:
- Technical but accessible
- Identify both strengths and issues
- Provide specific, actionable advice
- Consider best practices
- Help admins understand student performance"""
				
				validation_prompt = f"""Review this student solution from an educational assessment perspective.

**Question:** {question_text}

**Student's Code:**
```python
{code}
```

**Execution Result:**
{result['output'] if result['success'] else 'Error: ' + result['error']}

**Provide Assessment:**

✅ **Correctness:** (Correct / Partially Correct / Incorrect) - Brief explanation

💪 **Strengths:** What the student did well

⚠️ **Issues:** Specific problems or concerns

💡 **Improvement Suggestions:** Concrete advice

🎓 **Teaching Note:** Key concepts this reveals about student understanding"""
				
				validation = _ai_generate(validation_prompt, trainer_role)
			except Exception as e:
				print(f"AI validation error: {e}")
				validation = "AI validation temporarily unavailable"
		
		return jsonify({
			"success": result['success'],
			"output": result['output'],
			"error": result['error'],
			"validation": validation
		})
		
	except Exception as e:
		return jsonify({"success": False, "error": f"Execution error: {str(e)}"})


@app.route("/admin/activities")
def admin_activities():
	redir = require_admin()
	if redir:
		return redir
	# Get all activities with pagination
	page = int(request.args.get('page', 1))
	per_page = 20
	skip = (page - 1) * per_page
	
	activities = list(activities_col.find({}).sort("created_at", -1).skip(skip).limit(per_page))
	total_activities = activities_col.count_documents({})
	total_pages = (total_activities + per_page - 1) // per_page
	
	return render_template("index.html", view="admin_activities", activities=activities, page=page, total_pages=total_pages, total_activities=total_activities)


@app.route("/admin/activities/delete/<activity_id>", methods=["POST"])
def admin_delete_activity(activity_id):
	redir = require_admin()
	if redir:
		return redir
	
	# Get the activity first to check its classroom_id
	activity = activities_col.find_one({"activity_id": activity_id})
	if not activity:
		return jsonify({"ok": False, "message": "Activity not found"}), 404
	
	classroom_id = activity.get("classroom_id")
	
	# Delete activity
	result = activities_col.delete_one({"activity_id": activity_id})
	if result.deleted_count > 0:
		# Check if there are any more activities for this classroom
		remaining_activities = activities_col.count_documents({"classroom_id": classroom_id})
		if remaining_activities == 0:
			# Remove the classroom entry if no more activities exist
			classroom_col.delete_one({"classroom_id": classroom_id})
		
		return jsonify({"ok": True, "message": f"Activity {activity_id} deleted successfully"})
	else:
		return jsonify({"ok": False, "message": "Activity not found"}), 404


@app.route("/admin/tests")
def admin_tests():
	redir = require_admin()
	if redir:
		return redir
	# Get all tests with pagination
	page = int(request.args.get('page', 1))
	per_page = 20
	skip = (page - 1) * per_page
	
	tests = list(tests_col.find({}).sort("created_at", -1).skip(skip).limit(per_page))
	total_tests = tests_col.count_documents({})
	total_pages = (total_tests + per_page - 1) // per_page
	
	# Convert UTC times to local time for display
	timezone_offset = timedelta(hours=Config.TIMEZONE_OFFSET_HOURS, minutes=Config.TIMEZONE_OFFSET_MINUTES)
	for test in tests:
		if test.get("start_time"):
			test["start_time"] = test["start_time"] + timezone_offset
		if test.get("end_time"):
			test["end_time"] = test["end_time"] + timezone_offset
		if test.get("scheduled_at"):
			test["scheduled_at"] = test["scheduled_at"] + timezone_offset
	
	return render_template("index.html", view="admin_tests", tests=tests, page=page, total_pages=total_pages, total_tests=total_tests)


@app.route("/admin/tests/delete/<test_id>", methods=["POST"])
def admin_delete_test(test_id):
	redir = require_admin()
	if redir:
		return redir
	
	# Delete test
	result = tests_col.delete_one({"test_id": test_id})
	if result.deleted_count > 0:
		# Also delete any submissions related to this test
		submissions_col.delete_many({"test_id": test_id})
		return jsonify({"ok": True, "message": f"Test {test_id} deleted successfully"})
	else:
		return jsonify({"ok": False, "message": "Test not found"}), 404


@app.route("/admin/submissions")
def admin_submissions():
	redir = require_admin()
	if redir:
		return redir
	
	# Get filter parameters
	filter_context = request.args.get('context', 'all')  # all, test, test_violation, classroom
	filter_test = request.args.get('test_id', 'all')
	filter_user = request.args.get('username', 'all')
	page = int(request.args.get('page', 1))
	per_page = 50
	skip = (page - 1) * per_page
	
	# Build query
	query = {}
	if filter_context != 'all':
		query['context'] = filter_context
	if filter_test != 'all':
		query['test_id'] = filter_test
	if filter_user != 'all':
		query['username'] = filter_user
	
	# Get submissions
	submissions = list(submissions_col.find(query).sort("created_at", -1).skip(skip).limit(per_page))
	total_submissions = submissions_col.count_documents(query)
	total_pages = (total_submissions + per_page - 1) // per_page
	
	# Get unique values for filters
	all_tests = submissions_col.distinct("test_id")
	all_users = submissions_col.distinct("username")
	
	# Get statistics
	stats = {
		'total_submissions': submissions_col.count_documents({}),
		'total_violations': submissions_col.count_documents({'context': 'test_violation'}),
		'total_test_submissions': submissions_col.count_documents({'context': 'test'}),
		'total_test_completions': submissions_col.count_documents({'context': 'test_complete'}),
		'total_classroom_submissions': submissions_col.count_documents({'context': 'classroom'}),
		'unique_users': len(all_users),
		'unique_tests': len([t for t in all_tests if t])
	}
	
	# Get violation breakdown
	violation_pipeline = [
		{"$match": {"context": "test_violation"}},
		{"$group": {"_id": "$violation_type", "count": {"$sum": 1}}},
		{"$sort": {"count": -1}}
	]
	violation_stats = list(submissions_col.aggregate(violation_pipeline))
	
	# Get users with most violations
	user_violation_pipeline = [
		{"$match": {"context": "test_violation"}},
		{"$group": {"_id": "$username", "count": {"$sum": 1}}},
		{"$sort": {"count": -1}},
		{"$limit": 10}
	]
	user_violations = list(submissions_col.aggregate(user_violation_pipeline))
	
	return render_template("index.html", view="admin_submissions", 
		submissions=submissions, page=page, total_pages=total_pages, total_submissions=total_submissions,
		filter_context=filter_context, filter_test=filter_test, filter_user=filter_user,
		all_tests=all_tests, all_users=all_users, stats=stats, 
		violation_stats=violation_stats, user_violations=user_violations)


@app.route("/admin/submissions/export")
def admin_export_submissions():
	redir = require_admin()
	if redir:
		return redir
	
	# Get filter parameters
	filter_context = request.args.get('context', 'all')
	filter_test = request.args.get('test_id', 'all')
	filter_user = request.args.get('username', 'all')
	
	# Build query
	query = {}
	if filter_context != 'all':
		query['context'] = filter_context
	if filter_test != 'all':
		query['test_id'] = filter_test
	if filter_user != 'all':
		query['username'] = filter_user
	
	try:
		# Get all submissions matching filters
		submissions = list(submissions_col.find(query).sort("created_at", -1))
		
		# Create CSV file in memory
		output = StringIO()
		writer = csv.writer(output)
		
		# Write header
		writer.writerow(['Username', 'Context', 'Test ID', 'Violation Type', 'Warning Number', 'Created At', 'Details'])
		
		# Write data
		for sub in submissions:
			created_at = sub.get('created_at', '').strftime('%Y-%m-%d %H:%M:%S') if sub.get('created_at') else ''
			details = ''
			
			if sub.get('context') == 'test_violation':
				details = f"Violation: {sub.get('violation_type', 'N/A')}"
			elif sub.get('context') == 'test':
				details = f"Question: {sub.get('question_index', 'N/A')}"
			
			writer.writerow([
				sub.get('username', ''),
				sub.get('context', ''),
				sub.get('test_id', ''),
				sub.get('violation_type', ''),
				sub.get('warning_number', ''),
				created_at,
				details
			])
		
		output.seek(0)
		filename = f'submissions_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
		if filter_test != 'all':
			filename += f'_{filter_test}'
		if filter_context != 'all':
			filename += f'_{filter_context}'
		filename += '.csv'
		
		return send_file(
			BytesIO(output.getvalue().encode('utf-8')),
			mimetype='text/csv',
			as_attachment=True,
			download_name=filename
		)
		
	except Exception as e:
		print(f"Export error: {e}")
		return jsonify({"success": False, "error": f"Export failed: {str(e)}"})


@app.route("/admin/submissions/<submission_id>")
def admin_submission_detail(submission_id):
	redir = require_admin()
	if redir:
		return redir
	
	from bson.objectid import ObjectId
	try:
		submission = submissions_col.find_one({"_id": ObjectId(submission_id)})
		if not submission:
			abort(404)
		
		return render_template("index.html", view="admin_submission_detail", submission=submission)
	except:
		abort(404)


def execute_python_code(code: str, timeout: int = 5) -> dict:
	"""Safely execute Python code and return output"""
	try:
		# Create a temporary file to store the code
		with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
			f.write(code)
			temp_file = f.name
		
		# Execute the code with timeout
		result = subprocess.run(
			[sys.executable, temp_file],
			capture_output=True,
			text=True,
			timeout=timeout,
			cwd=tempfile.gettempdir()  # Run in temp directory for safety
		)
		
		# Clean up the temporary file
		os.unlink(temp_file)
		
		return {
			"success": True,
			"output": result.stdout,
			"error": result.stderr,
			"return_code": result.returncode
		}
		
	except subprocess.TimeoutExpired:
		# Clean up if timeout
		try:
			os.unlink(temp_file)
		except:
			pass
		return {
			"success": False,
			"output": "",
			"error": f"Code execution timed out after {timeout} seconds",
			"return_code": -1
		}
	except Exception as e:
		# Clean up on any error
		try:
			os.unlink(temp_file)
		except:
			pass
		return {
			"success": False,
			"output": "",
			"error": f"Execution error: {str(e)}",
			"return_code": -1
		}


def _ai_generate(prompt: str, system_role: str = "You are an expert coding instructor.") -> str:
	# Check if OpenAI API key is available
	if not openai.api_key:
		print("OpenAI API key not available, using mock response")
		return '''{
	"questions": [
		{
			"question_type": "mcq",
			"difficulty": "easy",
			"title": "Python Basics - Variables",
			"description": "What is the correct way to assign a value to a variable in Python?",
			"options": ["A) var x = 5", "B) x = 5", "C) set x to 5", "D) x := 5"],
			"correct_answer": "B",
			"explanation": "In Python, variables are assigned using the = operator: x = 5"
		},
		{
			"question_type": "coding",
			"difficulty": "medium_plus",
			"title": "Sum of Numbers",
			"description": "Write a function that takes a list of numbers and returns their sum.",
			"input_format": "A list of integers",
			"output_format": "The sum of all integers",
			"sample_input": "[1, 2, 3, 4, 5]",
			"sample_output": "15",
			"test_cases": [
				{"input": "[1, 2, 3]", "expected_output": "6"},
				{"input": "[10, 20]", "expected_output": "30"}
			]
		}
	]
}'''
	
	try:
		print(f"Making OpenAI API call with model: {os.getenv('OPENAI_MODEL', 'gpt-4')}")
		
		# Use the exact same pattern as working Feedback-App-V2
		response = openai.chat.completions.create(
			model=os.getenv("OPENAI_MODEL", "gpt-4"),
			messages=[
				{"role": "system", "content": system_role},
				{"role": "user", "content": prompt}
			],
			temperature=0.4,
			max_tokens=2000,
			timeout=30
		)
		
		print("OpenAI API call successful")
		return response.choices[0].message.content
		
	except Exception as e:
		error_message = str(e)
		print(f"OpenAI API error: {error_message}")
		print(f"Error type: {type(e)}")
		
		# Check if it's a quota error
		if "quota" in error_message.lower() or "429" in error_message:
			print("⚠️ OpenAI API quota exceeded! Using fallback questions.")
		
		# Return valid fallback JSON with proper structure
		return '''{
	"questions": [
		{
			"question_type": "mcq",
			"difficulty": "easy",
			"title": "Sample MCQ Question",
			"description": "This is a sample question because OpenAI API is unavailable (quota exceeded or API error). Please check your OpenAI API key and billing status.",
			"options": ["A) Option 1", "B) Option 2", "C) Option 3", "D) Option 4"],
			"correct_answer": "A",
			"explanation": "This is a sample question generated due to API unavailability."
		},
		{
			"question_type": "coding",
			"difficulty": "medium_plus",
			"title": "Sample Coding Question",
			"description": "Write a simple function. Note: This is a placeholder question due to OpenAI API unavailability.",
			"input_format": "Any input",
			"output_format": "Any output",
			"sample_input": "test",
			"sample_output": "result",
			"test_cases": [
				{"input": "test1", "expected_output": "result1"},
				{"input": "test2", "expected_output": "result2"}
			]
		}
	]
}'''


def _ai_generate_classroom_activity(subject: str, toc: str, num_questions: int) -> str:
	"""Generate classroom activities with varied difficulty and question types"""
	trainer_role = """You are an expert Educational Content Designer and Assessment Specialist with 15+ years of experience in creating comprehensive, pedagogically sound assessments. 

Your expertise includes:
- Designing questions that test different cognitive levels (Bloom's Taxonomy)
- Creating realistic, industry-relevant case studies
- Balancing theoretical knowledge with practical application
- Writing clear, unambiguous MCQs with effective distractors
- Crafting coding problems that assess problem-solving and algorithmic thinking
- Ensuring questions are aligned with learning objectives and difficulty levels

You create assessments that are fair, challenging, and educational."""
	
	prompt = f"""Create {num_questions} high-quality practice questions for: **{subject}**

🎯 **TOPIC/CONTENT GUIDANCE:**
{toc if toc else "Cover fundamental to advanced concepts in " + subject}

📋 **QUESTION DISTRIBUTION (distribute questions across these types):**

**1. EASY (25% of questions) - Foundational MCQs:**
   - Test basic concepts, definitions, and fundamental principles
   - 4 well-crafted options with clear correct answer
   - Options should be distinct and plausible
   - Time: 2-3 minutes each
   - Topics: Core terminology, simple recall, basic understanding

**2. MEDIUM (35% of questions) - Application-Based MCQs:**
   - Short scenario or case study (2-3 paragraphs)
   - Requires applying concepts to solve problems
   - 4 options with subtle differences
   - Time: 5-7 minutes each
   - Topics: Problem-solving, analysis, practical application

**3. HARD (25% of questions) - Complex Case-Based MCQs:**
   - Detailed scenario/case study (4-6 paragraphs)
   - Multi-faceted problem requiring deep analysis
   - 4 options requiring careful consideration
   - Time: 8-10 minutes each
   - Topics: Critical thinking, evaluation, complex decision-making

**4. MEDIUM+ HEAVY (15% of questions) - Coding Challenges:**
   - Real-world algorithmic or programming problems
   - Must be solvable in Python
   - Focus on logic, not syntax memorization
   - Provide comprehensive test cases
   - Time: 15-20 minutes each
   - Topics: Data structures, algorithms, problem-solving

📝 **STRICT JSON FORMAT (return ONLY JSON, no markdown):**
{{
  "questions": [
    {{
      "question_type": "mcq",
      "difficulty": "easy",
      "title": "Concise, descriptive title based on {subject}",
      "description": "Complete question. For cases: include realistic scenario with context.",
      "options": [
        "A) First plausible option",
        "B) Common misconception option",
        "C) Correct answer",
        "D) Another plausible distractor"
      ],
      "correct_answer": "C",
      "explanation": "Why C is correct and why A, B, D are wrong. Include key concepts from {subject}.",
      "hints": ["Helpful hint 1", "Helpful hint 2"],
      "learning_objectives": ["What student should learn"]
    }},
    {{
      "question_type": "coding",
      "difficulty": "medium_plus",
      "title": "Clear problem title related to {subject}",
      "description": "Complete problem statement with context and requirements related to {toc if toc else subject}",
      "input_format": "Format with examples: e.g., 'First line: integer n, Second line: n space-separated integers'",
      "output_format": "Expected output format with examples",
      "sample_input": "3\\n1 2 3",
      "sample_output": "6",
      "test_cases": [
        {{"input": "basic test", "expected_output": "result"}},
        {{"input": "edge case", "expected_output": "edge result"}},
        {{"input": "complex test", "expected_output": "complex result"}}
      ],
      "hints": ["Algorithm hint", "Edge case hint"],
      "learning_objectives": ["Data structure knowledge", "Algorithm application"]
    }}
  ]
}}

✅ **QUALITY REQUIREMENTS:**
1. **Topic Focus**: Every question must directly relate to "{subject}" and topics in: {toc if toc else "fundamental to advanced " + subject + " concepts"}
2. **Randomization**: Mix difficulties - DON'T group by difficulty level
3. **MCQs**: All 4 options plausible, no obvious answers, equal-length options, include explanation
4. **Coding**: Solvable in time limit, minimum 3 test cases with edges, clear I/O specs
5. **Educational**: Each question teaches something valuable about {subject}

⚠️ **CRITICAL**: Return PURE JSON only. No markdown blocks, no extra text."""
	
	return _ai_generate(prompt, trainer_role)


def _ai_generate_test(subject: str, toc: str, num_questions: int) -> str:
	"""Generate tests with varied difficulty and question types"""
	trainer_role = """You are a Senior Examination Designer and Assessment Expert with expertise in creating fair, comprehensive, and academically rigorous tests.

Your qualifications:
- PhD in Educational Assessment and Measurement
- 20+ years designing standardized tests and professional certifications
- Expert in psychometrics and item response theory
- Specialist in computer science and programming assessments
- Known for creating challenging yet fair exam questions

You design tests that:
- Accurately measure student knowledge and skills
- Cover the full spectrum of difficulty levels
- Test both theoretical understanding and practical application
- Use realistic scenarios from industry and research
- Have clear, unambiguous correct answers
- Provide comprehensive evaluation of student competency"""
	
	prompt = f"""Create {num_questions} rigorous test questions for: **{subject}** (EXAM MODE - Higher Standards)

🎯 **SUBJECT/TOPIC COVERAGE:**
{toc if toc else "Comprehensive coverage of " + subject + " from fundamentals to advanced topics"}

⚠️ **EXAM STANDARDS:** These are formal test questions - higher difficulty and rigor than practice questions.

📋 **QUESTION DISTRIBUTION:**

**1. EASY (25%) - Foundation Assessment:**
   - Test essential concepts and core principles
   - 4 carefully designed options (3 plausible distractors)
   - No "freebie" questions - require understanding, not just recall
   - Time: 2-3 minutes
   - Purpose: Verify baseline competency

**2. MEDIUM (35%) - Applied Knowledge:**
   - Realistic scenarios (2-3 paragraph case studies)
   - Test ability to apply concepts to new situations
   - Options require careful analysis
   - Time: 5-7 minutes
   - Purpose: Assess problem-solving and analysis skills

**3. HARD (25%) - Advanced Analysis:**
   - Complex, multi-layered case studies (4-6 paragraphs)
   - Requires synthesis of multiple concepts
   - All options should seem plausible at first glance
   - Time: 8-10 minutes
   - Purpose: Distinguish excellent from good students

**4. MEDIUM+ HEAVY (15%) - Coding Proficiency:**
   - Industry-relevant algorithmic challenges
   - Must demonstrate mastery of data structures and algorithms
   - Comprehensive test cases including corner cases
   - Time: 15-20 minutes
   - Purpose: Evaluate practical coding skills and logical thinking

REQUIRED JSON FORMAT:
{{
  "questions": [
    {{
      "question_type": "mcq" OR "coding",
      "difficulty": "easy" OR "medium" OR "hard" OR "medium_plus",
      "title": "Clear question title",
      "description": "Full question text with case study if applicable",
      "options": ["A) ...", "B) ...", "C) ...", "D) ..."],  // Only for MCQs
      "correct_answer": "A" OR "B" OR "C" OR "D",  // Only for MCQs
      "explanation": "Why this answer is correct",  // Only for MCQs
      "input_format": "...",  // Only for coding
      "output_format": "...",  // Only for coding
      "sample_input": "...",  // Only for coding
      "sample_output": "...",  // Only for coding
      "test_cases": [  // Only for coding
        {{"input": "...", "expected_output": "..."}},
        {{"input": "...", "expected_output": "..."}},
        {{"input": "...", "expected_output": "..."}}
      ],
      "constraints": "Any limitations",  // Only for coding
      "time_limit_minutes": <number>,
      "points": <number>,
      "hints": ["Hint 1", "Hint 2"],
      "learning_objectives": ["Objective 1", "Objective 2"]
    }}
  ]
}}

✅ **EXAM STANDARDS (Stricter than practice):**
1. **Topic Focus**: All questions test "{subject}" - Coverage: {toc if toc else "Full " + subject + " curriculum"}
2. **Randomization**: Mix difficulty levels - NO grouping by difficulty
3. **MCQs**: All options plausible, thorough explanations, one correct answer
4. **Coding**: Test FUNCTIONALITY not exact output, include edge cases, clear specs
5. **Rigor**: Exam-level difficulty - more challenging than practice questions
6. **Clarity**: Zero ambiguity in questions or answers

⚠️ **CRITICAL**: Return PURE JSON. No markdown (no ```json), no extra text."""
	
	return _ai_generate(prompt, trainer_role)


@app.route("/admin/create_classroom_activity", methods=["POST"])  # Generate activities via OpenAI
def admin_create_classroom_activity():
	redir = require_admin()
	if redir:
		return redir
	subject = request.form.get("subject", "").strip()
	toc = request.form.get("toc", "").strip()
	num_questions = int(request.form.get("num_questions", "3") or 3)
	classroom_id = request.form.get("classroom_id", "").strip()
	if not subject or not classroom_id or num_questions < 1:
		return jsonify({"ok": False, "error": "subject, classroom_id, >=1 questions required"}), 400
	try:
		content = _ai_generate_classroom_activity(subject, toc, num_questions)
		
		# Clean and validate JSON before storing
		import re
		json_content = content
		
		# Check if content is wrapped in markdown code blocks
		if "```json" in content or "```" in content:
			match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
			if match:
				json_content = match.group(1)
				print("Cleaned: Extracted JSON from markdown code block")
		
		# Try to find JSON object if there's extra text
		if not json_content.strip().startswith('{'):
			match = re.search(r'\{.*\}', content, re.DOTALL)
			if match:
				json_content = match.group(0)
				print("Cleaned: Extracted JSON object from text")
		
		# Validate JSON
		import json
		try:
			parsed = json.loads(json_content)
			if "questions" not in parsed:
				return jsonify({"ok": False, "error": "Generated content missing 'questions' array"}), 500
			content = json_content  # Use the cleaned version
		except json.JSONDecodeError as e:
			print(f"JSON validation failed: {e}")
			print(f"Content: {json_content[:500]}")
			return jsonify({"ok": False, "error": f"AI generated invalid JSON: {str(e)}"}), 500
			
	except Exception as e:
		return jsonify({"ok": False, "error": str(e)}), 500
	activity_id = str(uuid4())
	activities_col.insert_one({
		"activity_id": activity_id,
		"classroom_id": classroom_id,
		"subject": subject,
		"toc": toc,
		"num_questions": num_questions,
		"generated": content,
		"created_at": datetime.now(timezone.utc)
	})
	# Track classroom → activities
	classroom_col.update_one({"classroom_id": classroom_id}, {"$setOnInsert": {"classroom_id": classroom_id, "created_at": datetime.now(timezone.utc)}}, upsert=True)
	return redirect(url_for("admin_dashboard"))


@app.route("/admin/create_test", methods=["POST"])  # Generate test; scheduled
def admin_create_test():
	redir = require_admin()
	if redir:
		return redir
	subject = request.form.get("subject", "").strip()
	toc = request.form.get("toc", "").strip()
	num_questions = int(request.form.get("num_questions", "3") or 3)
	test_id = request.form.get("test_id", "").strip()
	start_datetime = request.form.get("start_datetime", "").strip()  # datetime-local input
	end_datetime = request.form.get("end_datetime", "").strip()  # datetime-local input
	if not subject or not test_id or num_questions < 1 or not start_datetime or not end_datetime:
		return jsonify({"ok": False, "error": "subject, test_id, start_datetime, end_datetime, >=1 questions required"}), 400
	try:
		# Parse datetime-local inputs (YYYY-MM-DDTHH:MM format)
		# These give us naive datetimes in local time
		start_time = datetime.fromisoformat(start_datetime)
		end_time = datetime.fromisoformat(end_datetime)
		
		# Validate that end time is after start time
		if end_time <= start_time:
			return jsonify({"ok": False, "error": "End time must be after start time"}), 400
		
		# Convert from local time to UTC using configurable timezone offset
		from datetime import timedelta
		timezone_offset = timedelta(hours=Config.TIMEZONE_OFFSET_HOURS, minutes=Config.TIMEZONE_OFFSET_MINUTES)
		start_time = start_time - timezone_offset  # Convert to UTC
		start_time = start_time.replace(tzinfo=timezone.utc)
		end_time = end_time - timezone_offset  # Convert to UTC
		end_time = end_time.replace(tzinfo=timezone.utc)
	except Exception as e:
		return jsonify({"ok": False, "error": f"Invalid datetime: {str(e)}"}), 400
	try:
		content = _ai_generate_test(subject, toc, num_questions)
		
		# Clean and validate JSON before storing
		import re
		json_content = content
		
		# Check if content is wrapped in markdown code blocks
		if "```json" in content or "```" in content:
			match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
			if match:
				json_content = match.group(1)
				print("Cleaned: Extracted JSON from markdown code block")
		
		# Try to find JSON object if there's extra text
		if not json_content.strip().startswith('{'):
			match = re.search(r'\{.*\}', content, re.DOTALL)
			if match:
				json_content = match.group(0)
				print("Cleaned: Extracted JSON object from text")
		
		# Validate JSON
		import json
		try:
			parsed = json.loads(json_content)
			if "questions" not in parsed:
				return jsonify({"ok": False, "error": "Generated content missing 'questions' array"}), 500
			content = json_content  # Use the cleaned version
		except json.JSONDecodeError as e:
			print(f"JSON validation failed: {e}")
			print(f"Content: {json_content[:500]}")
			return jsonify({"ok": False, "error": f"AI generated invalid JSON: {str(e)}"}), 500
			
	except Exception as e:
		return jsonify({"ok": False, "error": str(e)}), 500
	tests_col.insert_one({
		"test_id": test_id,
		"subject": subject,
		"toc": toc,
		"num_questions": num_questions,
		"generated": content,
		"start_time": start_time,
		"end_time": end_time,
		"created_at": datetime.now(timezone.utc)
	})
	return redirect(url_for("admin_dashboard"))


@app.route("/user/logout")
def user_logout():
	session.pop("user_username", None)
	session.pop("user_role", None)
	session.pop("test_progress", None)
	session.pop("test_warnings", None)
	session.pop("test_violations", None)
	return redirect(url_for("login"))


@app.route("/home")
def user_home():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	role = user.get("role")
	if role == "classroom":
		return redirect(url_for("classroom"))
	elif role == "test":
		return redirect(url_for("test"))
	elif role == "both":
		return render_template("index.html", view="user_selection", user=user)
	return redirect(url_for("index"))


@app.route("/classroom")
def classroom():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("classroom", "both"):
		abort(403)
	cid = user.get("classroom_id")
	acts = list(activities_col.find({"classroom_id": cid}).sort("created_at", -1))
	return render_template("index.html", view="classroom", activities=acts, classroom_id=cid)


@app.route("/activity/<activity_id>")
def activity(activity_id: str):
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("classroom", "both"):
		abort(403)
	act = activities_col.find_one({"activity_id": activity_id})
	if not act or act.get("classroom_id") != user.get("classroom_id"):
		abort(404)
	
	# Parse the generated JSON to extract questions
	questions = []
	try:
		import json
		generated_data = json.loads(act.get("generated", "{}"))
		questions = generated_data.get("questions", [])
	except Exception as e:
		print(f"Error parsing activity JSON: {e}")
		questions = []
	
	return render_template("index.html", view="activity", activity=act, questions=questions)


@app.route("/classroom/validate", methods=["POST"])  # Validate code via AI (classroom only)
def classroom_validate():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") != "classroom":
		abort(403)
	question_text = request.form.get("question_text", "")
	user_code = request.form.get("user_code", "")
	if not question_text or not user_code:
		return jsonify({"ok": False, "error": "question_text and user_code required"}), 400
	trainer_role = """You are a Patient and Encouraging Coding Mentor with a passion for teaching.

Your philosophy:
- **Student-Centered**: Every student learns at their own pace
- **Growth Mindset**: Mistakes are learning opportunities
- **Constructive**: Always find something positive first
- **Practical**: Give actionable, specific advice
- **Supportive**: Build confidence while identifying areas for growth
- **Clear**: Explain concepts simply without talking down to students

Your experience:
- 10+ years mentoring students from beginner to advanced levels
- Expert in breaking down complex concepts into understandable chunks
- Known for patient, encouraging feedback that motivates students
- Skilled at identifying common pitfalls and explaining why they happen
- Passionate about helping students develop good coding habits early"""
	
	prompt = f"""Review this student's practice code submission and provide encouraging, educational feedback.

🎯 **PROBLEM:**
{question_text}

💻 **STUDENT'S CODE:**
```python
{user_code}
```

📝 **YOUR FEEDBACK SHOULD INCLUDE:**

1. **Initial Encouragement** (Start positive!)
   - Acknowledge their effort and any correct approaches
   - Highlight what they're doing right

2. **Correctness Assessment**
   - ✅ Correct: Solution works perfectly
   - ⚠️ Partially Correct: Works for some cases but not all
   - ❌ Needs Work: Has significant issues
   - Explain which test cases it would pass/fail

3. **What Works Well**
   - Specific code elements they did correctly
   - Good practices they're using
   - Right concepts they've applied

4. **Areas for Improvement**
   - Specific issues in the code (be gentle!)
   - Explain WHY it's an issue (help them understand)
   - Show the impact (what goes wrong because of this)

5. **Learning Points**
   - Key concepts relevant to this problem
   - Common mistakes to avoid
   - Helpful patterns or approaches

6. **Step-by-Step Guidance**
   - How to fix the main issues
   - Better approaches they could try
   - Example of what improved code might look like (hints, not full solution)

7. **Next Steps**
   - What to focus on for improvement
   - Practice suggestions
   - Resources or topics to study

8. **Encouragement** (End positive!)
   - Motivate them to keep learning
   - Remind them that coding is a journey

⚠️ **TONE GUIDELINES:**
- 🎓 **Educational**: Teach, don't just correct
- 💚 **Kind**: Be gentle, especially about mistakes
- 🎯 **Specific**: Give concrete examples, not vague advice
- ✨ **Encouraging**: Build confidence
- 🔍 **Thorough**: Cover main issues but don't overwhelm

Format your response as clear, friendly text (not JSON). Use emojis sparingly to make it engaging. Write as if you're sitting next to the student explaining everything patiently."""
	
	try:
		suggestions = _ai_generate(prompt, trainer_role)
	except Exception as e:
		return jsonify({"ok": False, "error": str(e)}), 500
	submissions_col.insert_one({
		"username": user["username"],
		"context": "classroom",
		"question_text": question_text,
		"user_code": user_code,
		"ai_feedback": suggestions,
		"created_at": datetime.now(timezone.utc)
	})
	return jsonify({"ok": True, "feedback": suggestions})


@app.route("/classroom/complete", methods=["POST"])  # Simple completion hook
def classroom_complete():
	redir = require_user()
	if redir:
		return redir
	return redirect(url_for("classroom"))


@app.route("/test")
def test():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("test", "both"):
		abort(403)
	test_doc = tests_col.find_one({"test_id": user.get("test_id")})
	if not test_doc:
		return render_template("index.html", view="test", error="No test assigned" )
	
	# Check if user has already completed this test
	test_id = user.get("test_id")
	already_completed = submissions_col.find_one({
		"username": user["username"],
		"context": "test_complete",
		"test_id": test_id
	})
	
	if already_completed:
		return render_template("index.html", view="test", error="You have already completed this test. You cannot attempt it again.", 
			test=test_doc, already_completed=True,
			completion_time=already_completed.get("created_at"))
	
	now = datetime.now(timezone.utc)
	
	# Get start and end times (new format) or fallback to scheduled_at (old format)
	start_time = test_doc.get("start_time")
	end_time = test_doc.get("end_time")
	scheduled_at = test_doc.get("scheduled_at")  # For backward compatibility
	
	# Ensure times are timezone-aware for comparison
	if start_time and start_time.tzinfo is None:
		start_time = start_time.replace(tzinfo=timezone.utc)
	if end_time and end_time.tzinfo is None:
		end_time = end_time.replace(tzinfo=timezone.utc)
	if scheduled_at and scheduled_at.tzinfo is None:
		scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
	
	# Convert UTC times to local time for display
	timezone_offset = timedelta(hours=Config.TIMEZONE_OFFSET_HOURS, minutes=Config.TIMEZONE_OFFSET_MINUTES)
	start_time_local = start_time + timezone_offset if start_time else None
	end_time_local = end_time + timezone_offset if end_time else None
	scheduled_at_local = scheduled_at + timezone_offset if scheduled_at else None
	
	# Determine test status
	test_status = "not_scheduled"
	test_open = False
	test_expired = False
	
	if start_time and end_time:
		# New format with start and end times
		if now < start_time:
			test_status = "not_started"
		elif now >= start_time and now <= end_time:
			test_status = "open"
			test_open = True
		else:
			test_status = "expired"
			test_expired = True
	elif scheduled_at:
		# Old format with only scheduled_at
		if now >= scheduled_at:
			test_status = "open"
			test_open = True
		else:
			test_status = "not_started"
	else:
		test_status = "not_scheduled"
	
	# Initialize progress
	if session.get("test_progress") is None:
		session["test_progress"] = 0
	
	# Always show test info, but with different UI based on test status
	return render_template("index.html", view="test", test=test_doc, progress=session["test_progress"], 
		test_open=test_open, test_expired=test_expired, test_status=test_status,
		start_time=start_time_local, end_time=end_time_local, scheduled_at=scheduled_at_local, current_time=now + timezone_offset) 


@app.route("/debug/test/<test_id>")  # Debug route to check test content
def debug_test(test_id):
	"""Debug endpoint to view test structure and content"""
	test_doc = tests_col.find_one({"test_id": test_id})
	if not test_doc:
		return f"Test '{test_id}' not found", 404
	
	import json
	generated_content = test_doc.get("generated", "")
	
	debug_info = {
		"test_id": test_id,
		"subject": test_doc.get("subject"),
		"num_questions": test_doc.get("num_questions"),
		"content_type": type(generated_content).__name__,
		"content_length": len(generated_content) if generated_content else 0,
		"content_preview": generated_content[:500] if generated_content else "Empty",
	}
	
	# Try to parse as JSON
	try:
		parsed = json.loads(generated_content)
		debug_info["json_valid"] = True
		debug_info["has_questions_key"] = "questions" in parsed
		if "questions" in parsed:
			debug_info["questions_count"] = len(parsed.get("questions", []))
			debug_info["first_question"] = parsed["questions"][0] if parsed["questions"] else None
		else:
			debug_info["top_level_keys"] = list(parsed.keys())
	except json.JSONDecodeError as e:
		debug_info["json_valid"] = False
		debug_info["json_error"] = str(e)
	except Exception as e:
		debug_info["error"] = str(e)
	
	return f"""
	<html>
	<head><title>Test Debug: {test_id}</title></head>
	<body style="font-family: monospace; padding: 20px; background: #1a1a1a; color: #e0e0e0;">
		<h1>Test Debug Information</h1>
		<h2>Test: {test_id}</h2>
		
		<h3>Metadata:</h3>
		<pre>{json.dumps({k: v for k, v in debug_info.items() if k not in ['content_preview', 'first_question']}, indent=2)}</pre>
		
		<h3>Content Preview (first 500 chars):</h3>
		<pre style="background: #2a2a2a; padding: 10px; border-radius: 5px; white-space: pre-wrap;">{debug_info.get('content_preview', 'N/A')}</pre>
		
		<h3>First Question (if available):</h3>
		<pre style="background: #2a2a2a; padding: 10px; border-radius: 5px; white-space: pre-wrap;">{json.dumps(debug_info.get('first_question'), indent=2) if debug_info.get('first_question') else 'N/A'}</pre>
		
		<h3>Full Raw Content:</h3>
		<details>
			<summary>Click to expand full content</summary>
			<pre style="background: #2a2a2a; padding: 10px; border-radius: 5px; white-space: pre-wrap; max-height: 600px; overflow: auto;">{generated_content}</pre>
		</details>
		
		<br>
		<a href="/admin/tests" style="color: #60a5fa;">← Back to Tests Management</a>
	</body>
	</html>
	"""

@app.route("/debug/time")  # Debug route to check timezone handling
def debug_time():
	now_utc = datetime.now(timezone.utc)
	timezone_offset = timedelta(hours=Config.TIMEZONE_OFFSET_HOURS, minutes=Config.TIMEZONE_OFFSET_MINUTES)
	now_local = now_utc + timezone_offset
	
	# Get a test to show how times are stored and displayed
	sample_test = tests_col.find_one()
	test_info = ""
	if sample_test:
		test_info = f"""
		<br><strong>Sample Test Times:</strong><br>
		Test ID: {sample_test.get('test_id', 'N/A')}<br>
		"""
		if sample_test.get('start_time'):
			start_utc = sample_test['start_time']
			start_local = start_utc + timezone_offset if start_utc else None
			test_info += f"""
			Stored Start Time (UTC): {start_utc}<br>
			Display Start Time (Local): {start_local}<br>
			"""
		if sample_test.get('end_time'):
			end_utc = sample_test['end_time']
			end_local = end_utc + timezone_offset if end_utc else None
			test_info += f"""
			Stored End Time (UTC): {end_utc}<br>
			Display End Time (Local): {end_local}<br>
			"""
	
	return f"""
	<h2>Timezone Debug Information</h2>
	<strong>Current Times:</strong><br>
	Server UTC time: {now_utc}<br>
	Server Local time (UTC + offset): {now_local}<br>
	System local time: {datetime.now()}<br>
	<br>
	<strong>Configuration:</strong><br>
	Configured timezone offset: UTC+{Config.TIMEZONE_OFFSET_HOURS}:{Config.TIMEZONE_OFFSET_MINUTES:02d}<br>
	<br>
	<strong>How it works:</strong><br>
	1. Admin enters time in datetime-local input (browser's local time)<br>
	2. Server converts to UTC by subtracting offset and stores in MongoDB<br>
	3. When displaying to users, server adds offset to convert back to local time<br>
	4. Users see times in their configured local timezone<br>
	{test_info}
	<br>
	<strong>To adjust timezone:</strong><br>
	Update your .env file with:<br>
	TIMEZONE_OFFSET_HOURS=5<br>
	TIMEZONE_OFFSET_MINUTES=30<br>
	(Adjust these values to match your actual timezone offset from UTC)
	"""


@app.route("/test/start")  # Start the actual test
def test_start():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("test", "both"):
		abort(403)
	test_doc = tests_col.find_one({"test_id": user.get("test_id")})
	if not test_doc:
		return render_template("index.html", view="test", error="No test assigned" )
	
	# Check if user has already completed this test
	test_id = user.get("test_id")
	already_completed = submissions_col.find_one({
		"username": user["username"],
		"context": "test_complete",
		"test_id": test_id
	})
	
	if already_completed:
		return render_template("index.html", view="test", error="You have already completed this test. You cannot attempt it again.", 
			test=test_doc, already_completed=True,
			completion_time=already_completed.get("created_at"))
	
	# Check if test is open
	now = datetime.now(timezone.utc)
	start_time = test_doc.get("start_time")
	end_time = test_doc.get("end_time")
	scheduled_at = test_doc.get("scheduled_at")  # For backward compatibility
	
	# Ensure times are timezone-aware for comparison
	if start_time and start_time.tzinfo is None:
		start_time = start_time.replace(tzinfo=timezone.utc)
	if end_time and end_time.tzinfo is None:
		end_time = end_time.replace(tzinfo=timezone.utc)
	if scheduled_at and scheduled_at.tzinfo is None:
		scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
	
	# Check test availability
	if start_time and end_time:
		# New format with start and end times
		if now < start_time:
			return render_template("index.html", view="test", error="Test not yet open. Please return at the scheduled start time." )
		elif now > end_time:
			return render_template("index.html", view="test", error="Test has expired. The test window has closed." )
	elif scheduled_at:
		# Old format with only scheduled_at
		if now < scheduled_at:
			return render_template("index.html", view="test", error="Test not yet open. Please return at the scheduled time." )
	else:
		return render_template("index.html", view="test", error="No test scheduled" )
	
	# Initialize progress and anti-cheat tracking
	if session.get("test_progress") is None:
		session["test_progress"] = 0
	if session.get("test_warnings") is None:
		session["test_warnings"] = 0
	if session.get("test_violations") is None:
		session["test_violations"] = []
	
	# Parse the generated JSON to extract questions
	questions = []
	current_question = None
	parse_error = None
	try:
		import json
		import re
		generated_content = test_doc.get("generated", "")
		print(f"Generated content type: {type(generated_content)}")
		print(f"Generated content preview: {generated_content[:200] if generated_content else 'Empty'}")
		
		# Try to extract JSON from markdown code blocks or text
		json_content = generated_content
		
		# Check if content is wrapped in markdown code blocks
		if "```json" in generated_content or "```" in generated_content:
			# Extract JSON from code blocks
			match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', generated_content, re.DOTALL)
			if match:
				json_content = match.group(1)
				print("Extracted JSON from markdown code block")
		
		# Try to find JSON object if there's extra text
		if not json_content.strip().startswith('{'):
			match = re.search(r'\{.*\}', generated_content, re.DOTALL)
			if match:
				json_content = match.group(0)
				print("Extracted JSON object from text")
		
		generated_data = json.loads(json_content)
		questions = generated_data.get("questions", [])
		print(f"Number of questions parsed: {len(questions)}")
		
		# Get current question based on progress
		progress = session["test_progress"]
		if progress < len(questions):
			current_question = questions[progress]
			print(f"Current question (progress {progress}): {current_question.get('title', 'No title') if current_question else 'None'}")
		else:
			print(f"Progress {progress} is beyond question count {len(questions)}")
	except json.JSONDecodeError as e:
		parse_error = f"JSON parsing error: {str(e)}"
		print(f"Error parsing test JSON: {e}")
		print(f"Generated content that failed to parse: {test_doc.get('generated', '')[:500]}")
	except Exception as e:
		parse_error = f"Error: {str(e)}"
		print(f"Unexpected error parsing test: {e}")
		import traceback
		traceback.print_exc()
	
	# Show the actual test interface
	return render_template("index.html", view="test_interface", test=test_doc, progress=session["test_progress"], 
		questions=questions, current_question=current_question, parse_error=parse_error, 
		warning_count=session.get("test_warnings", 0))


@app.route("/test/violation", methods=["POST"])  # Record test violations
def test_violation():
	"""Record anti-cheat violations during test"""
	redir = require_user()
	if redir:
		return jsonify({"ok": False, "error": "Not authenticated"}), 401
	
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("test", "both"):
		return jsonify({"ok": False, "error": "Not authorized"}), 403
	
	violation_type = request.json.get("type", "unknown")
	timestamp = datetime.now(timezone.utc)
	
	# Initialize warnings if not present
	if session.get("test_warnings") is None:
		session["test_warnings"] = 0
	if session.get("test_violations") is None:
		session["test_violations"] = []
	
	# Increment warning count
	session["test_warnings"] += 1
	warning_count = session["test_warnings"]
	
	# Record violation
	violation_record = {
		"type": violation_type,
		"timestamp": timestamp.isoformat(),
		"warning_number": warning_count
	}
	session["test_violations"].append(violation_record)
	session.modified = True
	
	# Log violation to database for audit
	test_id = user.get("test_id")
	submissions_col.insert_one({
		"username": user["username"],
		"context": "test_violation",
		"test_id": test_id,
		"violation_type": violation_type,
		"warning_number": warning_count,
		"created_at": timestamp
	})
	
	# Check if test should be auto-closed
	auto_close = warning_count >= 3
	
	return jsonify({
		"ok": True,
		"warning_count": warning_count,
		"auto_close": auto_close,
		"message": f"Warning {warning_count}/3: {violation_type}"
	})


@app.route("/test/submit", methods=["POST"])  # Sequential submission, no output displayed
def test_submit():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("test", "both"):
		abort(403)
	test_doc = tests_col.find_one({"test_id": user.get("test_id")})
	if not test_doc:
		abort(404)
	
	# Check if test is open
	now = datetime.now(timezone.utc)
	start_time = test_doc.get("start_time")
	end_time = test_doc.get("end_time")
	scheduled_at = test_doc.get("scheduled_at")  # For backward compatibility
	
	# Ensure times are timezone-aware for comparison
	if start_time and start_time.tzinfo is None:
		start_time = start_time.replace(tzinfo=timezone.utc)
	if end_time and end_time.tzinfo is None:
		end_time = end_time.replace(tzinfo=timezone.utc)
	if scheduled_at and scheduled_at.tzinfo is None:
		scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
	
	# Check test availability
	if start_time and end_time:
		# New format with start and end times
		if now < start_time:
			return jsonify({"ok": False, "error": "Test not yet open"}), 403
		elif now > end_time:
			return jsonify({"ok": False, "error": "Test has expired"}), 403
	elif scheduled_at:
		# Old format with only scheduled_at
		if now < scheduled_at:
			return jsonify({"ok": False, "error": "Test not yet open"}), 403
	else:
		return jsonify({"ok": False, "error": "No test scheduled"}), 403
	idx = int(session.get("test_progress", 0))
	answer_code = request.form.get("user_code", "")
	mcq_answer = request.form.get("mcq_answer", "")
	question_type = request.form.get("question_type", "coding")
	question_bank_json = test_doc.get("generated", "")
	
	# Get current question details
	try:
		import json
		generated_data = json.loads(question_bank_json)
		questions = generated_data.get("questions", [])
		current_question = questions[idx] if idx < len(questions) else None
	except:
		current_question = None
	
	# Evaluate based on question type
	if mcq_answer and question_type == "mcq" and current_question:
		# MCQ Evaluation
		correct_answer = current_question.get("correct_answer", "")
		is_correct = mcq_answer.strip().upper()[0] == correct_answer.strip().upper()[0] if correct_answer else False
		score = 1.0 if is_correct else 0.0
		
		grading = json.dumps({
			"score": score,
			"is_correct": is_correct,
			"student_answer": mcq_answer,
			"correct_answer": correct_answer,
			"explanation": current_question.get("explanation", ""),
			"question_type": "mcq",
			"reason": "Correct answer!" if is_correct else f"Incorrect. The correct answer is {correct_answer}."
		})
		
		submissions_col.insert_one({
			"username": user["username"],
			"context": "test",
			"test_id": test_doc.get("test_id"),
			"question_index": idx,
			"question_type": "mcq",
			"mcq_answer": mcq_answer,
			"correct_answer": correct_answer,
			"is_correct": is_correct,
			"ai_grading": grading,
			"created_at": datetime.now(timezone.utc)
		})
	elif answer_code and question_type == "coding":
		# Coding Question Evaluation
		trainer_role = """You are a Senior Software Engineering Evaluator and Computer Science Professor specializing in code assessment.

Your credentials:
- 15+ years teaching Data Structures & Algorithms
- Former Technical Interviewer at top tech companies (Google, Microsoft, Amazon)
- Expert in evaluating code for correctness, efficiency, and quality
- Published researcher in programming education and assessment
- Known for fair, thorough, and constructive code reviews

Your evaluation approach:
- Test-driven: Does the code pass all test cases?
- Correctness-focused: Does it solve the actual problem?
- Quality-aware: Is the code readable, maintainable, and well-structured?
- Efficiency-conscious: Is the algorithm optimal or reasonable?
- Edge-case minded: Does it handle boundary conditions?
- Fair but rigorous: Give credit for what works, note what doesn't"""
		
		prompt = f"""Evaluate this student's coding submission for an exam question. Be thorough and fair.

📋 **PROBLEM:**
{json.dumps(current_question, indent=2) if current_question else "N/A"}

💻 **STUDENT'S SUBMISSION:**
```python
{answer_code}
```

🎯 **EVALUATION CRITERIA:**

1. **Correctness (40%)**: Does the code solve the problem as specified?
   - Check against problem requirements
   - Verify logic and algorithm
   - Consider test case coverage

2. **Functionality (30%)**: Does it work properly?
   - Would it pass the provided test cases?
   - Does it handle edge cases (empty input, large input, special cases)?
   - Are there any runtime errors or logical bugs?

3. **Code Quality (20%)**: Is it well-written?
   - Readability and clarity
   - Proper naming conventions
   - Logical structure and organization
   - Comments if needed for complex logic

4. **Efficiency (10%)**: Is the approach reasonable?
   - Time complexity appropriate for problem
   - Space usage reasonable
   - Unnecessary inefficiencies avoided

📊 **REQUIRED JSON RESPONSE:**
{{
  "score": <0.0 to 1.0>,
  "functionality_score": <0.0 to 1.0>,
  "code_quality_score": <0.0 to 1.0>,
  "efficiency_score": <0.0 to 1.0>,
  "passes_test_cases": true/false,
  "reason": "Comprehensive explanation: what works, what doesn't, why this score",
  "strengths": "Specific things the student did well (be encouraging)",
  "weaknesses": "Specific issues found (be constructive)",
  "suggestions": "Actionable advice for improvement",
  "test_case_analysis": "Which test cases would pass/fail and why"
}}

⭐ **SCORING RUBRIC:**
- **1.0 (Perfect)**: Correct solution, passes all tests, excellent code quality, optimal approach
- **0.9**: Correct solution, minor code quality issues, passes all tests
- **0.8**: Correct solution, some quality issues or slightly inefficient
- **0.7**: Solution works for most cases, misses one edge case, decent quality
- **0.6**: Partial solution, works for basic cases, has logical issues
- **0.5**: Attempts the problem, has the right idea, but significant bugs
- **0.4**: Some correct logic, but doesn't work for most cases
- **0.3**: Shows understanding of problem, but implementation is largely incorrect
- **0.2**: Minimal correct code, mostly wrong approach
- **0.1**: Attempted but fundamentally wrong
- **0.0**: Empty, completely incorrect, or unrelated code

⚠️ **BE FAIR**: Give credit for partially correct solutions. If logic is right but has a small bug, don't give 0."""
		
		try:
			grading = _ai_generate(prompt, trainer_role)
		except Exception as e:
			grading = json.dumps({"score": 0, "reason": f"AI error: {e}", "suggestions": "Please try again"})
		
		submissions_col.insert_one({
			"username": user["username"],
			"context": "test",
			"test_id": test_doc.get("test_id"),
			"question_index": idx,
			"question_type": "coding",
			"user_code": answer_code,
			"ai_grading": grading,
			"created_at": datetime.now(timezone.utc)
		})
	# Move to next question
	idx += 1
	session["test_progress"] = idx
	if idx >= int(test_doc.get("num_questions", 0)):
		return redirect(url_for("test_complete"))
	return redirect(url_for("test"))


@app.route("/test/complete")
def test_complete():
	redir = require_user()
	if redir:
		return redir
	user = users_col.find_one({"username": session["user_username"]})
	if user.get("role") not in ("test", "both"):
		abort(403)
	test_id = user.get("test_id")
	test_doc = tests_col.find_one({"test_id": test_id})
	
	# Calculate score but don't show to user
	submissions = list(submissions_col.find({"username": user["username"], "context": "test", "test_id": test_id}))
	score_sum = 0.0
	total = 0
	import json
	for s in submissions:
		try:
			data = json.loads(s.get("ai_grading", "{}"))
			score_sum += float(data.get("score", 0))
			total += 1
		except Exception:
			continue
	final_score = 0.0 if total == 0 else round((score_sum / total) * 100.0, 2)
	
	# Store final score in database for admin viewing
	submissions_col.insert_one({
		"username": user["username"],
		"context": "test_complete",
		"test_id": test_id,
		"final_score": final_score,
		"total_questions": total,
		"created_at": datetime.now(timezone.utc)
	})
	
	# Reset progress and warnings
	session.pop("test_progress", None)
	session.pop("test_warnings", None)
	session.pop("test_violations", None)
	
	# Don't pass score to template - user won't see it
	return render_template("index.html", view="test_result", 
		test=test_doc, total_questions=total, show_score=False)


@app.route("/compiler")
def compiler():
	"""Python compiler page"""
	redir = require_user()
	if redir:
		return redir
	return render_template("index.html", view="compiler")


@app.route("/compiler/execute", methods=["POST"])
def execute_code():
	"""Execute Python code safely"""
	redir = require_user()
	if redir:
		return redir
	
	code = request.form.get("code", "").strip()
	if not code:
		return jsonify({"success": False, "error": "No code provided"}), 400
	
	# Execute the code
	result = execute_python_code(code)
	return jsonify(result)


@app.route("/question/execute", methods=["POST"])
def execute_question_code():
	"""Execute Python code for a specific question with validation"""
	redir = require_user()
	if redir:
		return redir
	
	code = request.form.get("code", "").strip()
	question_text = request.form.get("question_text", "").strip()
	
	if not code:
		return jsonify({"success": False, "error": "No code provided"}), 400
	
	# Execute the code
	result = execute_python_code(code)
	
	# If execution was successful, validate against the question
	if result["success"] and question_text:
		try:
			# Use AI to validate the solution
			trainer_role = """You are a Helpful Coding Tutor focused on quick, actionable feedback.

Your style:
- Quick and concise (students are testing their code in real-time)
- Focused on what matters most
- Encouraging but honest
- Practical suggestions"""
			
			validation_prompt = f"""Quickly validate this student's code execution. Keep it concise.

**Question:** {question_text}

**Student's Code:**
```python
{code}
```

**Output Produced:**
```
{result.get('output', 'No output')}
```

**Provide Brief Feedback:**

✅ **Status:** (Correct / Partially Correct / Incorrect)

💡 **Quick Analysis:**
- What the code does
- Is it solving the problem correctly?
- Any obvious issues?

📝 **Main Suggestions:** (1-2 key improvements)

Keep it concise - the student is iterating on their solution."""
			
			try:
				validation = _ai_generate(validation_prompt, trainer_role)
				result["validation"] = validation
			except Exception as e:
				result["validation"] = f"Validation error: {str(e)}"
		except Exception as e:
			result["validation"] = f"Validation failed: {str(e)}"
	
	return jsonify(result)


# Security headers and minimal copy/paste restrictions for test page
@app.after_request
def add_security_headers(resp):
	resp.headers["X-Frame-Options"] = "DENY"
	resp.headers["X-Content-Type-Options"] = "nosniff"
	resp.headers["Referrer-Policy"] = "no-referrer"
	return resp


# Error handlers
@app.errorhandler(404)
def not_found(error):
	"""Handle 404 errors"""
	return jsonify({
		'success': False,
		'message': 'Endpoint not found'
	}), 404

@app.errorhandler(405)
def method_not_allowed(error):
	"""Handle 405 errors"""
	return jsonify({
		'success': False,
		'message': 'Method not allowed'
	}), 405

@app.errorhandler(500)
def internal_error(error):
	"""Handle 500 errors"""
	logger.error(f"Internal server error: {error}")
	return jsonify({
		'success': False,
		'message': 'Internal server error'
	}), 500

if __name__ == "__main__":
	# Hardcoded production settings for AWS EC2
	host = "0.0.0.0"  # Listen on all interfaces
	port = 5000       # Hardcoded port
	debug = False     # Production mode
	
	# For production, use threaded=True for better performance
	app.run(host=host, port=port, debug=debug, threaded=True)
