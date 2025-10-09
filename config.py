import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # MongoDB Configuration - Try environment first, then hardcoded fallback
    MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://ayushmang99_db_user:ayushman_g99@codingclass.e6mq5te.mongodb.net/?retryWrites=true&w=majority&appName=CodingClass")
    MONGO_DB = os.getenv("MONGO_DB", "coding_playground")
    
    # Debug: Print which URI source is being used
    if os.getenv("MONGO_URI"):
        print(f"🔧 Config: Using MONGO_URI from environment: {MONGO_URI[:50]}...")
    else:
        print(f"⚠️  Config: No MONGO_URI in environment, using hardcoded: {MONGO_URI[:50]}...")
    
    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
    
    # Flask Configuration
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24).hex())
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))
    
    # Security Configuration
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    
    # Timezone Configuration - adjust this to your local timezone
    TIMEZONE_OFFSET_HOURS = int(os.getenv("TIMEZONE_OFFSET_HOURS", "5"))  # Default: UTC+5
    TIMEZONE_OFFSET_MINUTES = int(os.getenv("TIMEZONE_OFFSET_MINUTES", "30"))  # Default: +30 minutes
    
    @staticmethod
    def validate_config():
        """Validate that required configuration is present"""
        errors = []
        
        if not Config.MONGO_URI:
            errors.append("MONGO_URI is required")
        
        if not Config.OPENAI_API_KEY:
            errors.append("OPENAI_API_KEY is required")
        
        if errors:
            raise RuntimeError(f"Configuration errors: {', '.join(errors)}")
        
        return True

# Validate configuration on import
Config.validate_config()
