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
           template_folder='.',  # Look for templates in current directory
           static_folder='.',   # Look for static files in current directory
           static_url_path='')  # Serve static files from root

# Configure app
app.config.from_object(Config)
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False
)
app.secret_key = os.getenv("SECRET_KEY", Config.SECRET_KEY)

# Enable CORS for all routes (allow credentials for session cookies)
CORS(app, supports_credentials=True)

# MongoDB Setup - Simple and working approach
try:
    print("Connecting to MongoDB...")
    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("✅ MongoDB connected successfully")
    
    db = client[Config.MONGO_DB]
    admins_col = db["admins"]
    users_col = db["users"]
    classroom_col = db["classrooms"]
    activities_col = db["activities"]
    tests_col = db["tests"]
    submissions_col = db["submissions"]
    
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    print("App cannot start without MongoDB connection")
    exit(1)

# OpenAI Client - Simple and working approach
import openai
openai.api_key = os.getenv("OPENAI_API_KEY")


def require_admin():
	if not session.get("admin_username"):
		return redirect(url_for("admin_login"))
	return None


def require_user():
	if not session.get("user_username"):
		return redirect(url_for("user_login"))
	return None


@app.route("/")
def index():
	# Debug: Check if template exists and MongoDB status
	try:
		mongodb_status = "Connected" if users_col is not None else "Disconnected"
		return render_template("index.html", view="home", mongodb_status=mongodb_status)
	except Exception as e:
		print(f"Template error: {e}")
		return f"Template error: {e}<br>Current directory: {os.getcwd()}<br>MongoDB: {'Connected' if users_col is not None else 'Disconnected'}"

@app.route('/health', methods=['GET'])
def health_check():
	"""Health check endpoint"""
	return jsonify({
		'status': 'healthy',
		'message': 'Coding Playground API is running',
		'version': '1.0.0',
		'mongodb': 'Connected' if users_col is not None else 'Disconnected'
	})

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


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
	# Hardcoded admin credentials: Ayushman / ayushman9277
	# App URL: http://3.80.74.243:5000
	if request.method == "POST":
		username = request.form.get("username", "").strip()
		password = request.form.get("password", "")
		
		# Check if this is the first admin login attempt
		if username == "Ayushman" and password == "ayushman9277" and admins_col.count_documents({}) == 0:
			# Create the first admin
			admins_col.insert_one({
				"username": "Ayushman",
				"password_hash": generate_password_hash("ayushman9277"),
				"created_at": datetime.now(timezone.utc)
			})
			session["admin_username"] = "Ayushman"
			return redirect(url_for("admin_dashboard"))
		
		# Check existing admin
		admin = admins_col.find_one({"username": username})
		if admin and check_password_hash(admin.get("password_hash", ""), password):
			session["admin_username"] = username
			return redirect(url_for("admin_dashboard"))
		return render_template("index.html", view="admin_login", error="Invalid credentials")
	return render_template("index.html", view="admin_login")


@app.route("/admin/logout")
def admin_logout():
	session.pop("admin_username", None)
	return redirect(url_for("index"))




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
	if users_col.find_one({"username": username}):
		return jsonify({"ok": False, "error": "username already exists"}), 409
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
				validation = _ai_generate(f"""As a coding trainer, validate this student's solution for the following question:

Question: {question_text}

Student's Code:
```python
{code}
```

Student's Output:
{result['output'] if result['success'] else 'Error: ' + result['error']}

Please provide:
1. Whether the solution is correct
2. What the student did well
3. Areas for improvement
4. Suggestions for better approaches

Be encouraging but constructive in your feedback.""", "You are a helpful coding trainer who provides constructive feedback to students.")
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
	if not openai.api_key:
		print("OpenAI API key not available, using mock response")
		return f'{{"questions": [{{"title": "Sample Question", "description": "This is a sample coding question generated for testing. The actual OpenAI integration is not working properly.", "input_format": "Input format here", "output_format": "Output format here", "sample_input": "sample input", "sample_output": "sample output"}}]}}'
	
	try:
		completion = openai.chat.completions.create(
			model=os.getenv("OPENAI_MODEL", "gpt-4"),
			messages=[{"role": "system", "content": system_role}, {"role": "user", "content": prompt}],
			temperature=0.4,
		)
		return completion.choices[0].message.content
	except Exception as e:
		print(f"OpenAI API error: {e}")
		# Fallback response
		return f'{{"questions": [{{"title": "Sample Question", "description": "This is a sample coding question. OpenAI API error: {str(e)}", "input_format": "Input format here", "output_format": "Output format here", "sample_input": "sample input", "sample_output": "sample output"}}]}}'


def _ai_generate_classroom_activity(subject: str, toc: str, num_questions: int) -> str:
	"""Generate classroom activities with trainer role and ToC integration"""
	trainer_role = """You are a trainer and you will design set of coding based activities for the number of questions mentioned and the questions will vary in difficulty from simple to hard and you will validate entries for each activity and display output and display suggestions as well."""
	
	prompt = f"""Create {num_questions} case-study based coding activities for subject '{subject}'.

Table of Contents (ToC) Guidance:
{toc}

Requirements:
- Design activities that vary in difficulty from simple to hard
- Each activity should be practical and hands-on
- Include clear validation criteria for each activity
- Provide expected outputs and suggestions for improvement
- Make activities engaging and educational

For each activity, provide:
- title: Clear, descriptive title
- description: Detailed problem statement with context
- difficulty: "easy", "medium", or "hard"
- input_format: How input should be provided
- output_format: Expected output format
- sample_input: Example input
- sample_output: Expected output for sample input
- validation_criteria: How to validate the solution
- suggestions: Tips and hints for students
- learning_objectives: What students will learn

Respond in JSON format with an array 'questions' containing all activities."""
	
	return _ai_generate(prompt, trainer_role)


def _ai_generate_test(subject: str, toc: str, num_questions: int) -> str:
	"""Generate tests with trainer role and ToC integration"""
	trainer_role = """You are a trainer and you will design set of coding based activities for the number of questions mentioned and the questions will vary in difficulty from simple to hard and you will validate entries for each activity and display output and display suggestions as well."""
	
	prompt = f"""Create a rigorous coding test with {num_questions} questions for subject '{subject}'.

Table of Contents (ToC) Guidance:
{toc}

Requirements:
- Design questions that vary in difficulty from simple to hard
- Each question should test practical coding skills
- Include comprehensive test cases for validation
- Questions should be challenging but fair
- Focus on problem-solving and implementation skills

For each question, provide:
- title: Clear, descriptive title
- description: Detailed problem statement
- difficulty: "easy", "medium", or "hard"
- input_format: How input should be provided
- output_format: Expected output format
- sample_input: Example input
- sample_output: Expected output for sample input
- test_cases: Array of hidden test cases for validation
- constraints: Any limitations or constraints
- time_limit: Suggested time limit in minutes

Respond in JSON format with an array 'questions' containing all test questions."""
	
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


@app.route("/user/login", methods=["GET", "POST"])  # User login
def user_login():
	if request.method == "POST":
		username = request.form.get("username", "").strip()
		password = request.form.get("password", "")
		user = users_col.find_one({"username": username})
		if user and check_password_hash(user.get("password_hash", ""), password):
			session["user_username"] = username
			session["user_role"] = user.get("role")
			return redirect(url_for("user_home"))
		return render_template("index.html", view="user_login", error="Invalid credentials")
	return render_template("index.html", view="user_login")


@app.route("/user/logout")
def user_logout():
	session.pop("user_username", None)
	session.pop("user_role", None)
	return redirect(url_for("index"))


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
	trainer_role = """You are a trainer and you will design set of coding based activities for the number of questions mentioned and the questions will vary in difficulty from simple to hard and you will validate entries for each activity and display output and display suggestions as well."""
	
	prompt = f"""As a trainer, evaluate the student's code submission and provide helpful feedback.

Problem Statement:
{question_text}

Student's Code:
{user_code}

Please provide:
1. Validation of the code (correct/incorrect/partially correct)
2. Expected vs actual output if the code is runnable
3. Specific suggestions for improvement
4. Learning points and tips
5. Encouragement and constructive feedback

Format your response in a clear, educational manner that helps the student learn and improve."""
	
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
		start_time=start_time, end_time=end_time, scheduled_at=scheduled_at, current_time=now) 


@app.route("/debug/time")  # Debug route to check timezone handling
def debug_time():
	now = datetime.now(timezone.utc)
	from datetime import timedelta
	timezone_offset = timedelta(hours=Config.TIMEZONE_OFFSET_HOURS, minutes=Config.TIMEZONE_OFFSET_MINUTES)
	return f"""
	Current UTC time: {now}<br>
	Current local time: {datetime.now()}<br>
	Configured timezone offset: UTC+{Config.TIMEZONE_OFFSET_HOURS}:{Config.TIMEZONE_OFFSET_MINUTES:02d}<br>
	If you scheduled for local time, it should be stored as: {now - timezone_offset}<br>
	<br>
	To fix timezone issues, update your .env file with:<br>
	TIMEZONE_OFFSET_HOURS=5<br>
	TIMEZONE_OFFSET_MINUTES=30<br>
	(Adjust these values to your actual timezone)
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
	
	# Initialize progress
	if session.get("test_progress") is None:
		session["test_progress"] = 0
	
	# Parse the generated JSON to extract questions
	questions = []
	current_question = None
	try:
		import json
		generated_data = json.loads(test_doc.get("generated", "{}"))
		questions = generated_data.get("questions", [])
		
		# Get current question based on progress
		progress = session["test_progress"]
		if progress < len(questions):
			current_question = questions[progress]
	except Exception as e:
		print(f"Error parsing test JSON: {e}")
		questions = []
	
	# Show the actual test interface
	return render_template("index.html", view="test_interface", test=test_doc, progress=session["test_progress"], 
		questions=questions, current_question=current_question)


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
	question_bank_json = test_doc.get("generated", "")
	# Background-like evaluation (sync here for simplicity), but do not show output
	if answer_code:
		trainer_role = """You are a trainer and you will design set of coding based activities for the number of questions mentioned and the questions will vary in difficulty from simple to hard and you will validate entries for each activity and display output and display suggestions as well."""
		
		prompt = f"""As a trainer, evaluate the student's test submission and provide a score with detailed feedback.

Question Set: {question_bank_json}
Question Index: {idx}
Student's Code: {answer_code}

Please evaluate the code and respond in JSON format:
{{
  "score": <0.0 to 1.0>,
  "reason": "Detailed explanation of the score and what the student did well or needs to improve",
  "suggestions": "Specific suggestions for improvement",
  "learning_points": "Key concepts the student should focus on"
}}

Score guidelines:
- 1.0: Perfect solution, excellent code quality
- 0.8-0.9: Very good solution with minor issues
- 0.6-0.7: Good solution with some problems
- 0.4-0.5: Partially correct with significant issues
- 0.2-0.3: Mostly incorrect but shows some understanding
- 0.0-0.1: Incorrect or no meaningful attempt"""
		
		try:
			grading = _ai_generate(prompt, trainer_role)
		except Exception as e:
			grading = str({"score": 0, "reason": f"AI error: {e}", "suggestions": "Please try again", "learning_points": "Review the problem statement"})
		submissions_col.insert_one({
			"username": user["username"],
			"context": "test",
			"test_id": test_doc.get("test_id"),
			"question_index": idx,
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
	submissions = list(submissions_col.find({"username": user["username"], "context": "test", "test_id": test_id}))
	# Extract scores if present (simple parsing, robust against non-JSON text)
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
	# Reset progress
	session.pop("test_progress", None)
	return render_template("index.html", view="test_result", score=final_score, total=total)


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
			trainer_role = """You are a trainer and you will design set of coding based activities for the number of questions mentioned and the questions will vary in difficulty from simple to hard and you will validate entries for each activity and display output and display suggestions as well."""
			
			validation_prompt = f"""As a trainer, validate the student's solution for this coding question.

Question: {question_text}

Student's Code:
{code}

Code Output:
{result.get('output', 'No output')}

Please provide:
1. Is the solution correct? (Yes/No/Partially)
2. What the code actually does
3. Expected behavior vs actual behavior
4. Suggestions for improvement
5. Learning points

Format your response clearly and helpfully."""
			
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
