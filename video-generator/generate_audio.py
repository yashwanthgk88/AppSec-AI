"""
Step 1: Generate voiceover audio for each scene using ElevenLabs API.
Outputs individual MP3 files per scene into output/audio/.
"""

import os
import sys
from pathlib import Path

from config import (
    ELEVENLABS_API_KEY, ELEVENLABS_VOICE_ID, ELEVENLABS_MODEL,
    AUDIO_DIR
)
from scenes import get_scenes


def generate_audio():
    api_key = os.environ.get("ELEVENLABS_API_KEY", ELEVENLABS_API_KEY)
    if not api_key:
        print("ERROR: Set ELEVENLABS_API_KEY environment variable or update config.py")
        sys.exit(1)

    from elevenlabs import ElevenLabs

    client = ElevenLabs(api_key=api_key)
    scenes = get_scenes()

    os.makedirs(AUDIO_DIR, exist_ok=True)

    for scene in scenes:
        output_path = os.path.join(AUDIO_DIR, f"{scene['id']}.mp3")

        if os.path.exists(output_path):
            print(f"  [SKIP] {scene['id']} — audio already exists")
            continue

        print(f"  [GENERATING] {scene['id']}: {scene['title']}...")

        audio_generator = client.text_to_speech.convert(
            voice_id=ELEVENLABS_VOICE_ID,
            model_id=ELEVENLABS_MODEL,
            text=scene["voiceover"],
            output_format="mp3_44100_128",
        )

        # Write the audio stream to file
        with open(output_path, "wb") as f:
            for chunk in audio_generator:
                f.write(chunk)

        file_size = os.path.getsize(output_path)
        print(f"  [DONE] {scene['id']} — {file_size / 1024:.0f} KB")

    print(f"\nAll audio files saved to {AUDIO_DIR}/")
    print("Review the audio files before proceeding to screen recording.")


if __name__ == "__main__":
    print("=" * 60)
    print("STEP 1: Generating ElevenLabs Voiceover Audio")
    print("=" * 60)
    generate_audio()
