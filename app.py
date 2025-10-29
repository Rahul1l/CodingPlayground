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

app = Flask(__name__, template_folder='.')

# Configure app
app.config.from_object(Config)
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False
)
app.secret_key = os.getenv("SECRET_KEY", Config.SECRET_KEY)

# Enable CORS
CORS(app, supports_credentials=True)

# MongoDB Setup
try:
    print("Connecting to MongoDB...")
    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("✅ MongoDB connected successfully")
    
    db = client[Config.DATABASE_NAME]
    admins_col = db["admins"]
    users_col = db["users"]
    activities_col = db["activities"]
    submissions_col = db["submissions"]
    
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    sys.exit(1)

# OpenAI Setup
import openai
openai.api_key = os.getenv("OPENAI_API_KEY")

def _ai_generate(prompt: str, system_role: str = "You are a helpful assistant.") -> str:
    """Call OpenAI API"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_role},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return f"Error generating content: {str(e)}"

def require_admin():
    if "admin_username" not in session:
        return redirect(url_for("login"))
    return None

def require_user():
    if "user_username" not in session:
        return redirect(url_for("user_login"))
    return None

# ============================================================================
# ROUTES
# ============================================================================

@app.route("/")
def index():
    if "admin_username" in session:
        return redirect(url_for("admin_dashboard"))
    elif "user_username" in session:
        return redirect(url_for("user_dashboard"))
    return redirect(url_for("login"))

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        admin = admins_col.find_one({"username": username})
        
        if admin and check_password_hash(admin["password"], password):
            session["admin_username"] = username
            return redirect(url_for("admin_dashboard"))
        return render_template("index.html", view="login", error="Invalid credentials")
    
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
    
    # Get statistics
    users_count = users_col.count_documents({})
    activities_count = activities_col.count_documents({})
    submissions_count = submissions_col.count_documents({})
    recent_users = list(users_col.find().sort("created_at", -1).limit(5))
    
    return render_template("index.html", 
                         view="admin_dashboard",
                         users_count=users_count,
                         activities_count=activities_count,
                         submissions_count=submissions_count,
                         recent_users=recent_users)

@app.route("/admin/create_user", methods=["POST"])
def admin_create_user():
    redir = require_admin()
    if redir:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    classroom_id = request.form.get("classroom_id", "").strip()
    university = request.form.get("university", "").strip()
    
    if not all([username, password, classroom_id]):
        return jsonify({"ok": False, "error": "All fields required"}), 400
    
    # Check if user exists
    if users_col.find_one({"username": username}):
        return jsonify({"ok": False, "error": "Username already exists"}), 400
    
    # Create user
    users_col.insert_one({
        "username": username,
        "password": password,
        "password_plain": password,
        "role": "classroom",
        "classroom_id": classroom_id,
        "university": university or "Unknown",
        "created_at": datetime.now(timezone.utc)
    })
    
    return jsonify({"ok": True})

@app.route("/admin/users")
def admin_users():
    redir = require_admin()
    if redir:
        return redir
    
    users = list(users_col.find().sort("created_at", -1))
    return render_template("index.html", view="admin_users", users=users)

@app.route("/admin/users/delete/<username>", methods=["POST"])
def admin_delete_user(username):
    redir = require_admin()
    if redir:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    result = users_col.delete_one({"username": username})
    if result.deleted_count > 0:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "User not found"}), 404

@app.route("/admin/activities")
def admin_activities():
    redir = require_admin()
    if redir:
        return redir
    
    activities = list(activities_col.find().sort("created_at", -1))
    return render_template("index.html", view="admin_classroom_activities", activities=activities)

@app.route("/admin/create_activity", methods=["POST"])
def admin_create_activity():
    redir = require_admin()
    if redir:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    subject = request.form.get("subject", "").strip()
    toc = request.form.get("toc", "").strip()
    num_mcq = int(request.form.get("num_mcq", "0") or 0)
    num_coding = int(request.form.get("num_coding", "0") or 0)
    classroom_id = request.form.get("classroom_id", "").strip()
    
    if not subject or not classroom_id:
        return jsonify({"ok": False, "error": "Subject and classroom_id required"}), 400
    
    if num_mcq + num_coding < 1:
        return jsonify({"ok": False, "error": "At least one question required"}), 400
    
    # Generate questions with AI
    try:
        content = _ai_generate_classroom_activity(subject, toc, num_mcq, num_coding)
        
        # Clean JSON
        import re
        if "```json" in content or "```" in content:
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
            if match:
                content = match.group(1)
        
        # Validate
        parsed = json.loads(content)
        if "questions" not in parsed:
            return jsonify({"ok": False, "error": "Generated content missing questions"}), 500
        
        # Save activity
        activity_id = str(uuid4())[:8]
        activities_col.insert_one({
            "activity_id": activity_id,
            "subject": subject,
            "toc": toc,
            "classroom_id": classroom_id,
            "num_questions": num_mcq + num_coding,
            "num_mcq": num_mcq,
            "num_coding": num_coding,
            "generated": content,
            "created_at": datetime.now(timezone.utc)
        })
        
        return jsonify({"ok": True, "activity_id": activity_id})
        
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

def _ai_generate_classroom_activity(subject: str, toc: str, num_mcq: int, num_coding: int) -> str:
    """Generate classroom activity questions"""
    num_questions = num_mcq + num_coding
    
    system_role = """You are an Expert Educational Content Creator specializing in creating engaging, pedagogically sound learning materials."""
    
    prompt = f"""Create EXACTLY {num_questions} high-quality practice questions for: **{subject}**

Table of Contents Focus:
{toc if toc else "General curriculum topics"}

**Requirements:**
- **{num_mcq} MCQ Questions** (Multiple Choice with 4 options)
- **{num_coding} Coding Questions** (Programming problems)

**Total: {num_questions} questions**

**MCQ GUIDELINES:**
- 4 options (A, B, C, D)
- One correct answer
- Include explanation
- Include hints

**CODING GUIDELINES:**
- Clear problem statement
- Input/output format
- Sample test cases
- Constraints

Return valid JSON:
{{
  "questions": [
    {{
      "question_type": "mcq",
      "difficulty": "easy/medium/hard",
      "title": "Question Title",
      "description": "Question text",
      "options": ["A) ...", "B) ...", "C) ...", "D) ..."],
      "correct_answer": "A",
      "explanation": "Why this is correct",
      "hints": ["Hint 1", "Hint 2"]
    }},
    {{
      "question_type": "coding",
      "difficulty": "medium_plus",
      "title": "Problem Title",
      "description": "Problem description",
      "input_format": "Input description",
      "output_format": "Output description",
      "sample_input": "Example input",
      "sample_output": "Example output",
      "constraints": "Constraints",
      "hints": ["Hint 1"]
    }}
  ]
}}

Generate EXACTLY {num_mcq} MCQ and {num_coding} coding questions."""
    
    return _ai_generate(prompt, system_role)

@app.route("/admin/classroom-activities/<activity_id>")
def admin_attempt_activity(activity_id):
    redir = require_admin()
    if redir:
        return redir
    
    activity = activities_col.find_one({"activity_id": activity_id})
    if not activity:
        abort(404)
    
    # Load questions
    questions = []
    try:
        import json
        generated_data = json.loads(activity.get("generated", "{}"))
        all_questions = generated_data.get("questions", [])
        
        num_mcq = activity.get("num_mcq", None)
        num_coding = activity.get("num_coding", None)
        
        if num_mcq is not None and num_coding is not None and (num_mcq > 0 or num_coding > 0):
            mcq_questions = [q for q in all_questions if q.get("question_type") == "mcq"]
            coding_questions = [q for q in all_questions if q.get("question_type") == "coding"]
            questions = mcq_questions[:num_mcq] + coding_questions[:num_coding]
        else:
            questions = all_questions
    except:
        questions = []
    
    return render_template("index.html", view="admin_attempt_activity", activity=activity, questions=questions)

@app.route("/admin/submissions")
def admin_submissions():
    redir = require_admin()
    if redir:
        return redir
    
    filter_context = request.args.get("context", "")
    filter_university = request.args.get("university", "")
    
    query = {}
    if filter_context:
        query["context"] = filter_context
    if filter_university:
        query["university"] = filter_university
    
    submissions = list(submissions_col.find(query).sort("created_at", -1))
    
    # Get universities
    all_universities = submissions_col.distinct("university")
    
    return render_template("index.html", 
                         view="admin_submissions",
                         submissions=submissions,
                         all_universities=all_universities,
                         filter_context=filter_context,
                         filter_university=filter_university)

@app.route("/admin/submissions/<submission_id>")
def admin_submission_detail(submission_id):
    redir = require_admin()
    if redir:
        return redir
    
    try:
        from bson.objectid import ObjectId
        submission = submissions_col.find_one({"_id": ObjectId(submission_id)})
        if submission:
            submission["_id"] = str(submission["_id"])
            return render_template("index.html", view="submission_detail", submission=submission)
    except:
        pass
    
    return render_template("index.html", view="submission_detail", error="Submission not found")

@app.route("/admin/submissions/delete/<submission_id>", methods=["POST"])
def admin_delete_submission(submission_id):
    redir = require_admin()
    if redir:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    try:
        from bson.objectid import ObjectId
        result = submissions_col.delete_one({"_id": ObjectId(submission_id)})
        if result.deleted_count > 0:
            return jsonify({"ok": True})
    except:
        pass
    
    return jsonify({"ok": False, "error": "Submission not found"}), 404

# ============================================================================
# USER ROUTES
# ============================================================================

@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = users_col.find_one({"username": username})
        
        if user and user["password"] == password:
            session["user_username"] = username
            return redirect(url_for("user_dashboard"))
        return render_template("index.html", view="user_login", error="Invalid credentials")
    
    return render_template("index.html", view="user_login")

@app.route("/user/logout")
def user_logout():
    session.pop("user_username", None)
    return redirect(url_for("user_login"))

@app.route("/user/dashboard")
def user_dashboard():
    redir = require_user()
    if redir:
        return redir
    
    user = users_col.find_one({"username": session["user_username"]})
    return render_template("index.html", view="user_dashboard", user=user)

@app.route("/classroom")
def classroom():
    redir = require_user()
    if redir:
        return redir
    
    user = users_col.find_one({"username": session["user_username"]})
    classroom_id = user.get("classroom_id")
    
    activities = list(activities_col.find({"classroom_id": classroom_id}).sort("created_at", -1))
    return render_template("index.html", view="classroom", classroom_id=classroom_id, activities=activities)

@app.route("/activity/<activity_id>")
def activity(activity_id: str):
    redir = require_user()
    if redir:
        return redir
    
    user = users_col.find_one({"username": session["user_username"]})
    act = activities_col.find_one({"activity_id": activity_id})
    
    if not act or act.get("classroom_id") != user.get("classroom_id"):
        abort(404)
    
    # Load questions
    questions = []
    try:
        import json
        generated_data = json.loads(act.get("generated", "{}"))
        all_questions = generated_data.get("questions", [])
        
        num_mcq = act.get("num_mcq", None)
        num_coding = act.get("num_coding", None)
        
        if num_mcq is not None and num_coding is not None and (num_mcq > 0 or num_coding > 0):
            mcq_questions = [q for q in all_questions if q.get("question_type") == "mcq"]
            coding_questions = [q for q in all_questions if q.get("question_type") == "coding"]
            questions = mcq_questions[:num_mcq] + coding_questions[:num_coding]
        else:
            questions = all_questions
    except:
        questions = []
    
    return render_template("index.html", view="activity", activity=act, questions=questions)

@app.route("/classroom/submit_all", methods=["POST"])
def classroom_submit_all():
    redir = require_user()
    if redir:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    
    user = users_col.find_one({"username": session["user_username"]})
    data = request.json
    activity_id = data.get("activity_id")
    answers = data.get("answers", [])
    
    # Evaluate answers
    results = []
    correct_count = 0
    total_questions = len(answers)
    
    for answer in answers:
        question_type = answer.get("question_type")
        
        if question_type == "mcq":
            selected_answer = answer.get("selected_answer")
            correct_answer = answer.get("question_data", {}).get("correct_answer", "")
            is_correct = selected_answer and correct_answer and selected_answer.strip().upper()[0] == correct_answer.strip().upper()[0]
            if is_correct:
                correct_count += 1
            results.append({
                "question_index": answer.get("question_index"),
                "question_type": "mcq",
                "question_title": answer.get("question_data", {}).get("title", ""),
                "selected_answer": selected_answer,
                "correct_answer": correct_answer,
                "explanation": answer.get("question_data", {}).get("explanation", ""),
                "is_correct": is_correct
            })
        elif question_type == "coding":
            # AI evaluation
            user_code = answer.get("user_code")
            question_data = answer.get("question_data", {})
            ai_feedback = "Code submitted successfully."
            score = 0.7
            is_correct = True
            
            if user_code and openai.api_key:
                try:
                    trainer_role = """You are a Patient and Encouraging Coding Mentor focused on helping students learn."""
                    prompt = f"""Evaluate this student's code. Return JSON with score (0.0-1.0), is_correct (bool), feedback (string).
                    
Problem: {question_data.get('description', 'N/A')}

Student's Code:
```python
{user_code}
```"""
                    response_text = _ai_generate(prompt, trainer_role)
                    import re
                    json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                    if json_match:
                        feedback_data = json.loads(json_match.group())
                        score = float(feedback_data.get("score", 0.7))
                        is_correct = feedback_data.get("is_correct", score >= 0.7)
                        ai_feedback = feedback_data.get("feedback", "Code submitted successfully.")
                except:
                    pass
            
            if is_correct:
                correct_count += 1
            
            results.append({
                "question_index": answer.get("question_index"),
                "question_type": "coding",
                "question_title": question_data.get("title", ""),
                "user_code": user_code,
                "ai_feedback": ai_feedback,
                "is_correct": is_correct,
                "score": score
            })
    
    percentage = round((correct_count / total_questions * 100), 2) if total_questions > 0 else 0
    
    # Save submission
    submissions_col.insert_one({
        "username": user["username"],
        "university": user.get("university", "Unknown"),
        "activity_id": activity_id,
        "context": "classroom_complete",
        "total_questions": total_questions,
        "correct_count": correct_count,
        "score": f"{correct_count}/{total_questions}",
        "percentage": percentage,
        "details": results,
        "created_at": datetime.now(timezone.utc)
    })
    
    return jsonify({
        "ok": True,
        "total_questions": total_questions,
        "correct_count": correct_count,
        "percentage": percentage,
        "details": results
    })

@app.route("/compiler")
def compiler():
    if "admin_username" in session:
        return render_template("index.html", view="compiler")
    elif "user_username" in session:
        return render_template("index.html", view="compiler")
    return redirect(url_for("login"))

@app.route("/question/execute", methods=["POST"])
def execute_code():
    code = request.json.get("code", "")
    if not code:
        return jsonify({"ok": False, "error": "No code provided"}), 400
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        result = subprocess.run(
            [sys.executable, temp_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        os.unlink(temp_file)
        
        return jsonify({
            "ok": True,
            "output": result.stdout,
            "error": result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Execution timeout"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
