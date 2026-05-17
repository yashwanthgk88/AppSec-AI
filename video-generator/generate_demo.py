#!/usr/bin/env python3
"""
Secure Dev AI — Automated Demo Video Generator

One-command pipeline that:
  1. Generates voiceover audio via ElevenLabs API
  2. Records browser walkthrough via Playwright
  3. Assembles final MP4 with FFmpeg

Usage:
  # Run the full pipeline
  python generate_demo.py

  # Run individual steps
  python generate_demo.py --step audio
  python generate_demo.py --step record
  python generate_demo.py --step assemble

Prerequisites:
  pip install -r requirements.txt
  playwright install chromium
  brew install ffmpeg
  export ELEVENLABS_API_KEY="your-key-here"

  # Make sure your app is running:
  cd ../ && docker-compose up
"""

import argparse
import sys

from generate_audio import generate_audio
from record_screens import record_scenes
from assemble_video import assemble


def main():
    parser = argparse.ArgumentParser(
        description="Secure Dev AI — Automated Demo Video Generator"
    )
    parser.add_argument(
        "--step",
        choices=["audio", "record", "assemble", "all"],
        default="all",
        help="Which step to run (default: all)"
    )
    args = parser.parse_args()

    print()
    print("╔════════════════════════════════════════════════════╗")
    print("║   Secure Dev AI — Demo Video Generator            ║")
    print("╚════════════════════════════════════════════════════╝")
    print()

    if args.step in ("audio", "all"):
        print("=" * 60)
        print("STEP 1/3: Generating Voiceover Audio (ElevenLabs)")
        print("=" * 60)
        generate_audio()
        print()

    if args.step in ("record", "all"):
        print("=" * 60)
        print("STEP 2/3: Recording Browser Walkthrough (Playwright)")
        print("=" * 60)
        record_scenes()
        print()

    if args.step in ("assemble", "all"):
        print("=" * 60)
        print("STEP 3/3: Assembling Final Video (FFmpeg)")
        print("=" * 60)
        assemble()
        print()

    if args.step == "all":
        print("╔════════════════════════════════════════════════════╗")
        print("║   Demo video generation complete!                 ║")
        print("║   Output: output/SecureDevAI_Demo.mp4             ║")
        print("╚════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
