# Coding Playground Flask App

A Flask application for coding classroom activities and scheduled tests with MongoDB Atlas and OpenAI integration.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file in the project root with the following variables:
```env
# MongoDB Configuration
MONGO_URI=<your-mongodb-atlas-uri>
MONGO_DB=coding_playground

# OpenAI Configuration
OPENAI_API_KEY=<your-openai-api-key>
OPENAI_MODEL=gpt-4

# Flask Configuration
SECRET_KEY=<your-secret-key>
DEBUG=True
HOST=0.0.0.0
PORT=5000

# Security Configuration (for production)
SESSION_COOKIE_SECURE=False
```

3. Run the application:
```bash
python app.py
```

## Features

- **Admin Panel**: Create users, generate classroom activities, and schedule tests
- **Classroom Activities**: AI-generated coding exercises with validation
- **Scheduled Tests**: Time-restricted tests with copy/paste restrictions
- **User Management**: Separate login for classroom and test users
- **MongoDB Integration**: All data stored in MongoDB Atlas
- **OpenAI Integration**: GPT-4 for content generation and code validation

## First Time Setup

1. Create the first admin by making a POST request to `/admin/bootstrap`:
```bash
curl -X POST http://localhost:5000/admin/bootstrap \
  -d "username=admin&password=yourpassword"
```

2. Login at `/admin/login` and start creating users and activities.

## Deployment

For production deployment on EC2:
1. Set `DEBUG=False` and `SESSION_COOKIE_SECURE=True` in your `.env`
2. Use a WSGI server like Gunicorn:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```
3. Configure Nginx as a reverse proxy
4. Set up SSL certificates for HTTPS
