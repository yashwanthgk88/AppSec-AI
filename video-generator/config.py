"""
Configuration for the Secure Dev AI demo video generator.
Update these values before running.
"""

# App URLs (update if your app runs on different ports)
APP_BASE_URL = "https://frontend-production-838e.up.railway.app"
API_BASE_URL = "https://frontend-production-838e.up.railway.app"

# Demo credentials
DEMO_EMAIL = "admin@example.com"
DEMO_PASSWORD = "admin123"

# ElevenLabs settings
ELEVENLABS_API_KEY = "sk_4c4ae5eeff59baff5641e7f5e93e465d9310ab8555f6a283"
ELEVENLABS_VOICE_ID = "onwK4e9ZLuTAKqWW03F9"  # "Daniel" - professional male voice
ELEVENLABS_MODEL = "eleven_multilingual_v2"

# Video settings
VIDEO_WIDTH = 1920
VIDEO_HEIGHT = 1080
FPS = 30

# Output paths
OUTPUT_DIR = "output"
AUDIO_DIR = "output/audio"
SCREENSHOTS_DIR = "output/screenshots"
RECORDINGS_DIR = "output/recordings"
FINAL_VIDEO = "output/SecureDevAI_Demo.mp4"

# Timing (seconds to pause on each screen for visual clarity)
DEFAULT_PAUSE = 2.0
LONG_PAUSE = 4.0
SHORT_PAUSE = 1.0

# Demo project ID (will be auto-detected or set manually after seeding)
DEMO_PROJECT_ID = 5
