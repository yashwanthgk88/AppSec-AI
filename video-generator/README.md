# Secure Dev AI — Automated Demo Video Generator

Generates a complete product demo video with professional AI voiceover automatically.

## Pipeline

```
VOICEOVER_SCRIPT.txt → ElevenLabs API → Audio per scene
                                              ↓
Browser (Playwright) → Screen recording → Full session video
                                              ↓
                              FFmpeg → Final MP4 (video + audio)
```

## Quick Start

### 1. Install dependencies

```bash
cd video-generator

# Python deps
pip install -r requirements.txt

# Playwright browser
playwright install chromium

# FFmpeg (for video assembly)
brew install ffmpeg
```

### 2. Set your ElevenLabs API key

```bash
export ELEVENLABS_API_KEY="your-key-here"
```

Get a free key at [elevenlabs.io](https://elevenlabs.io) (free tier = ~10 min of audio).

### 3. Start your app

```bash
cd ../
docker-compose up -d

# Seed demo data
curl -X POST http://localhost:8000/api/seed-demo
```

### 4. Generate the video

```bash
# Full pipeline (audio → record → assemble)
python generate_demo.py

# Or run steps individually:
python generate_demo.py --step audio      # Generate voiceover only
python generate_demo.py --step record     # Record browser only
python generate_demo.py --step assemble   # Combine video + audio
```

## Output

```
output/
├── audio/              # Individual voiceover MP3 per scene
│   ├── 01_opening.mp3
│   ├── 02_dashboard.mp3
│   └── ...
├── recordings/         # Playwright screen recording
│   └── full_session.webm
├── combined_audio.mp3  # All scenes concatenated
└── SecureDevAI_Demo.mp4  # FINAL VIDEO
```

## Configuration

Edit `config.py` to customize:

| Setting | Default | Description |
|---------|---------|-------------|
| `APP_BASE_URL` | `http://localhost:5173` | Frontend URL |
| `API_BASE_URL` | `http://localhost:8000` | Backend URL |
| `ELEVENLABS_VOICE_ID` | `onwK4e9ZLuTAKqWW03F9` | Voice (Daniel) |
| `VIDEO_WIDTH` | 1920 | Recording width |
| `VIDEO_HEIGHT` | 1080 | Recording height |
| `DEMO_PROJECT_ID` | 1 | Project to showcase |

### Changing the voice

Popular ElevenLabs voice IDs:
- `onwK4e9ZLuTAKqWW03F9` — Daniel (professional male)
- `pNInz6obpgDQGcFmaJgB` — Adam (deep male)
- `21m00Tcm4TlvDq8ikWAM` — Rachel (professional female)
- `EXAVITQu4vr4xnSDxMaL` — Bella (warm female)

## VS Code Extension Scene

Scene 15 (VS Code Extension) shows the settings page where the extension is downloadable. For a richer VS Code demo, record VS Code separately using OBS/Loom and splice it into the final video using your video editor.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ELEVENLABS_API_KEY not set` | `export ELEVENLABS_API_KEY="..."` |
| `App not reachable` | Start app: `docker-compose up` |
| `ffmpeg not found` | `brew install ffmpeg` |
| `playwright not found` | `pip install playwright && playwright install chromium` |
| Audio already exists | Delete `output/audio/` to regenerate |
| Video too short/long | Adjust `DEFAULT_PAUSE` / `LONG_PAUSE` in `config.py` |
