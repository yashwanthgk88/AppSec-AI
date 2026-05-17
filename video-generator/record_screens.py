"""
Step 2: Record browser screen for each scene using Playwright.
Navigates through the app and captures video per scene.
Audio duration is used to time each scene's recording length.
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

from config import (
    VIDEO_WIDTH, VIDEO_HEIGHT, RECORDINGS_DIR, AUDIO_DIR,
    APP_BASE_URL, DEFAULT_PAUSE
)
from scenes import get_scenes


def get_audio_duration(audio_path: str) -> float:
    """Get duration of an MP3 file using ffprobe."""
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_format", audio_path],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        return float(data["format"]["duration"])
    except Exception:
        return 30.0


def safe_wait(page, ms):
    """Wait in small chunks to avoid TargetClosedError on long waits."""
    chunk = 5000  # 5 second chunks
    remaining = ms
    while remaining > 0:
        wait = min(remaining, chunk)
        try:
            page.wait_for_timeout(wait)
        except Exception:
            time.sleep(wait / 1000)
        remaining -= wait


def execute_actions(page, actions, total_duration: float):
    """Execute browser actions, then pad remaining time to match audio duration."""
    import time as _time
    start = _time.time()

    if not actions:
        safe_wait(page, int(total_duration * 1000))
        return

    for action in actions:
        wait_ms = int(action.get("wait", DEFAULT_PAUSE) * 1000)
        action_type = action["type"]

        try:
            if action_type == "goto":
                page.goto(action["url"], wait_until="networkidle", timeout=30000)
            elif action_type == "click":
                element = page.query_selector(action["selector"])
                if element:
                    element.click()
            elif action_type == "fill":
                element = page.query_selector(action["selector"])
                if element:
                    element.fill(action["value"])
            elif action_type == "scroll":
                page.evaluate(f"window.scrollTo({{top: {action['y']}, behavior: 'smooth'}})")
            elif action_type == "hover":
                element = page.query_selector(action["selector"])
                if element:
                    element.hover()
        except Exception as e:
            print(f"    [WARN] Action '{action_type}' failed: {e}")

        safe_wait(page, max(wait_ms, 500))

    # Pad remaining time with slow scrolling to fill audio duration
    elapsed = _time.time() - start
    remaining_ms = int((total_duration - elapsed) * 1000)
    if remaining_ms > 1000:
        # Slowly scroll up and down to keep the screen visually active
        scroll_steps = max(1, remaining_ms // 4000)
        per_step = remaining_ms // max(scroll_steps * 2, 1)
        for i in range(scroll_steps):
            try:
                page.evaluate(f"window.scrollTo({{top: {300 + i * 200}, behavior: 'smooth'}})")
            except Exception:
                pass
            safe_wait(page, per_step)
            try:
                page.evaluate(f"window.scrollTo({{top: {100 + i * 100}, behavior: 'smooth'}})")
            except Exception:
                pass
            safe_wait(page, per_step)


def record_scenes():
    scenes = get_scenes()
    os.makedirs(RECORDINGS_DIR, exist_ok=True)

    # Clean old recordings
    for f in Path(RECORDINGS_DIR).glob("*.webm"):
        f.unlink()

    # Check audio files exist
    missing_audio = []
    for scene in scenes:
        audio_path = os.path.join(AUDIO_DIR, f"{scene['id']}.mp3")
        if not os.path.exists(audio_path):
            missing_audio.append(scene["id"])

    if missing_audio:
        print(f"ERROR: Missing audio for scenes: {', '.join(missing_audio)}")
        print("Run generate_audio.py first.")
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = browser.new_context(
            viewport={"width": VIDEO_WIDTH, "height": VIDEO_HEIGHT},
            record_video_dir=RECORDINGS_DIR,
            record_video_size={"width": VIDEO_WIDTH, "height": VIDEO_HEIGHT},
            color_scheme="dark",
            no_viewport=False,
        )
        # Prevent timeouts from closing the page
        context.set_default_timeout(60000)

        page = context.new_page()

        for i, scene in enumerate(scenes):
            audio_path = os.path.join(AUDIO_DIR, f"{scene['id']}.mp3")
            duration = get_audio_duration(audio_path)

            print(f"  [{i+1}/{len(scenes)}] Recording: {scene['title']} ({duration:.1f}s)")

            try:
                execute_actions(page, scene["actions"], duration)
            except Exception as e:
                print(f"    [ERROR] Scene failed: {e}")
                print(f"    [RECOVERING] Continuing to next scene...")
                try:
                    page.goto(APP_BASE_URL, wait_until="networkidle", timeout=15000)
                except Exception:
                    pass

        # Close and save video
        print("\n  Finalizing recording...")
        page.close()
        context.close()
        browser.close()

    # Playwright saves a single video for the full session — find and rename it
    video_files = sorted(Path(RECORDINGS_DIR).glob("*.webm"))
    if video_files:
        final_recording = os.path.join(RECORDINGS_DIR, "full_session.webm")
        if os.path.exists(final_recording):
            os.remove(final_recording)
        video_files[-1].rename(final_recording)
        size_mb = os.path.getsize(final_recording) / (1024 * 1024)
        print(f"\n  Full session recording: {final_recording} ({size_mb:.1f} MB)")
    else:
        print("\n  WARN: No video files found.")

    print("  Screen recording complete.")


if __name__ == "__main__":
    print("=" * 60)
    print("STEP 2: Recording Browser Screens with Playwright")
    print("=" * 60)

    import urllib.request
    try:
        urllib.request.urlopen(APP_BASE_URL, timeout=5)
    except Exception:
        print(f"ERROR: App not reachable at {APP_BASE_URL}")
        print("Start your app first: cd ../  &&  docker-compose up")
        sys.exit(1)

    record_scenes()
