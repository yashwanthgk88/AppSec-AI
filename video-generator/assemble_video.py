"""
Step 3: Assemble final video by combining screen recording with voiceover audio.
Uses FFmpeg to merge video + audio tracks and add transitions.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

from config import (
    RECORDINGS_DIR, AUDIO_DIR, FINAL_VIDEO, OUTPUT_DIR, FPS
)
from scenes import get_scenes


def get_duration(file_path: str) -> float:
    """Get media file duration using ffprobe."""
    result = subprocess.run(
        ["ffprobe", "-v", "quiet", "-print_format", "json",
         "-show_format", file_path],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    return float(data["format"]["duration"])


def check_ffmpeg():
    """Verify ffmpeg and ffprobe are installed."""
    for cmd in ["ffmpeg", "ffprobe"]:
        result = subprocess.run(["which", cmd], capture_output=True)
        if result.returncode != 0:
            print(f"ERROR: {cmd} not found. Install with: brew install ffmpeg")
            sys.exit(1)


def concatenate_audio():
    """Concatenate all scene audio files into one track."""
    scenes = get_scenes()
    concat_list = os.path.join(OUTPUT_DIR, "audio_concat.txt")
    combined_audio = os.path.join(OUTPUT_DIR, "combined_audio.mp3")

    if os.path.exists(combined_audio):
        print("  [SKIP] Combined audio already exists")
        return combined_audio

    # Build FFmpeg concat file
    with open(concat_list, "w") as f:
        for scene in scenes:
            audio_path = os.path.abspath(os.path.join(AUDIO_DIR, f"{scene['id']}.mp3"))
            if not os.path.exists(audio_path):
                print(f"  ERROR: Missing audio: {audio_path}")
                sys.exit(1)
            # Add a small silence gap between scenes (0.8s)
            f.write(f"file '{audio_path}'\n")
            silence = os.path.abspath(os.path.join(OUTPUT_DIR, "silence.mp3"))
            if not os.path.exists(silence):
                # Generate 0.8s silence
                subprocess.run([
                    "ffmpeg", "-y", "-f", "lavfi", "-i",
                    "anullsrc=r=44100:cl=stereo", "-t", "0.8",
                    "-q:a", "9", silence
                ], capture_output=True)
            f.write(f"file '{silence}'\n")

    # Concatenate
    subprocess.run([
        "ffmpeg", "-y", "-f", "concat", "-safe", "0",
        "-i", concat_list, "-c", "copy", combined_audio
    ], capture_output=True)

    duration = get_duration(combined_audio)
    print(f"  [DONE] Combined audio: {duration:.1f}s")
    return combined_audio


def assemble():
    """Combine screen recording video with voiceover audio."""
    check_ffmpeg()

    print("\n--- Concatenating audio tracks ---")
    combined_audio = concatenate_audio()

    recording = os.path.join(RECORDINGS_DIR, "full_session.webm")
    if not os.path.exists(recording):
        print(f"ERROR: Screen recording not found at {recording}")
        print("Run record_screens.py first.")
        sys.exit(1)

    audio_duration = get_duration(combined_audio)
    video_duration = get_duration(recording)

    print(f"\n--- Assembling final video ---")
    print(f"  Video duration: {video_duration:.1f}s")
    print(f"  Audio duration: {audio_duration:.1f}s")

    # Use the shorter duration to avoid black frames or silence
    target_duration = min(audio_duration, video_duration)

    # Assemble: video + audio, trim to match, encode as H.264/AAC MP4
    subprocess.run([
        "ffmpeg", "-y",
        "-i", recording,
        "-i", combined_audio,
        "-t", str(target_duration),
        "-map", "0:v:0",
        "-map", "1:a:0",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "20",
        "-r", str(FPS),
        "-c:a", "aac",
        "-b:a", "192k",
        "-pix_fmt", "yuv420p",
        "-movflags", "+faststart",
        FINAL_VIDEO
    ], check=True)

    final_size = os.path.getsize(FINAL_VIDEO) / (1024 * 1024)
    print(f"\n  FINAL VIDEO: {FINAL_VIDEO}")
    print(f"  Duration: {target_duration:.1f}s | Size: {final_size:.1f} MB")


if __name__ == "__main__":
    print("=" * 60)
    print("STEP 3: Assembling Final Demo Video")
    print("=" * 60)
    assemble()
