#!/usr/bin/env python3
"""Build audio, subtitles, and scene assets for the XRL-IDARS Open Day 2026 video."""

from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
import edge_tts
import numpy as np
import scipy.io.wavfile as wavfile

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "open_day_2026"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Exact transition times matching the recorded clips:
# [0.0, 10.5, 20.0, 35.5, 57.77, 70.77, 81.77, 87.77]
SCENES = [
    {
        "id": 1,
        "name": "Introduction",
        "start_time": 0.50,
        "max_dur": 9.00,
        "text": "Every second, computer networks face cyber threats that can compromise sensitive information and disrupt critical services. Introducing XRL-IDARS, an explainable AI-powered intrusion detection and response system developed at JSS Academy of Technical Education, Bengaluru.",
    },
    {
        "id": 2,
        "name": "Problem & Solution",
        "start_time": 10.90,
        "max_dur": 8.20,
        "text": "Traditional intrusion detection systems can struggle to explain their decisions and respond intelligently. XRL-IDARS combines machine learning, explainable AI, deterministic security rules and reinforcement-learning-based response recommendations.",
    },
    {
        "id": 3,
        "name": "Architecture & Workflow",
        "start_time": 20.50,
        "max_dur": 13.50,
        "text": "Network traffic is converted into flows and processed using the matching feature pipeline. A trained Random Forest identifies suspicious activity, while independent security rules detect additional threats. TreeSHAP explains the models prediction, and a Dueling Deep Q-Network recommends a response. A deterministic safety gate checks every recommendation before it can proceed.",
    },
    {
        "id": 4,
        "name": "Live Demonstration",
        "start_time": 36.00,
        "max_dur": 19.50,
        "text": "Here is the live demonstration. First, normal traffic is processed. Next, we introduce suspicious traffic. The system evaluates the flow, identifies the threat, and displays the prediction with its feature-level explanation. The DQN then recommends an appropriate response, while the safety gate prevents unsafe actions. Every event can be inspected through the dashboard.",
    },
    {
        "id": 5,
        "name": "Benchmarks & Evaluation",
        "start_time": 58.20,
        "max_dur": 11.20,
        "text": "XRL-IDARS also includes a reproducible evaluation workbench. We compare Random Forest, LSTM and fusion models using a ten-thousand-record evaluation dataset. The results help us assess detection performance, explainability and computational efficiency.",
    },
    {
        "id": 6,
        "name": "Real-World Applications",
        "start_time": 71.20,
        "max_dur": 9.50,
        "text": "This technology can support enterprise networks, banking systems, healthcare infrastructure, educational institutions and cloud environments. By combining explainable detection with safety-controlled response recommendations, XRL-IDARS aims to help security teams understand threats and make more informed decisions.",
    },
    {
        "id": 7,
        "name": "Closing",
        "start_time": 82.20,
        "max_dur": 4.50,
        "text": "XRL-IDARS: making network security more intelligent, explainable and responsible. Thank you.",
    },
]

TOTAL_DURATION = 87.77
SAMPLE_RATE = 44100


def fmt_tc(s: float) -> str:
    hrs = int(s // 3600)
    mins = int((s % 3600) // 60)
    secs = int(s % 60)
    ms = int((s - int(s)) * 1000)
    return f"{hrs:02d}:{mins:02d}:{secs:02d},{ms:03d}"


async def generate_voiceover_and_subtitles():
    total_samples = int(TOTAL_DURATION * SAMPLE_RATE)
    master_voice = np.zeros(total_samples, dtype=np.float32)
    srt_entries = []

    print("[*] Generating voiceover clips using Edge-TTS (en-IN-PrabhatNeural)...")
    for item in SCENES:
        idx = item["id"]
        scene_name = item["name"]
        raw_mp3 = OUTPUT_DIR / f"raw_scene_{idx}.mp3"
        proc_wav = OUTPUT_DIR / f"proc_scene_{idx}.wav"

        comm = edge_tts.Communicate(item["text"], "en-IN-PrabhatNeural", rate="+15%")
        await comm.save(str(raw_mp3))

        # Check raw duration
        res = subprocess.run([str(REPO_ROOT / ".venv" / "bin" / "ffmpeg"), "-i", str(raw_mp3)], stderr=subprocess.PIPE, text=True)
        raw_dur = 0.0
        for line in res.stderr.splitlines():
            if "Duration:" in line:
                parts = line.split("Duration:")[1].split(",")[0].strip().split(":")
                raw_dur = float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
                break

        max_dur = item["max_dur"]
        speed = max(1.0, raw_dur / max_dur)

        # Apply subtle silence trim & tempo adjustment
        af_chain = f"silenceremove=stop_periods=-1:stop_duration=0.12:stop_threshold=-38dB:detection=peak,atempo={speed:.3f}"
        subprocess.run([
            str(REPO_ROOT / ".venv" / "bin" / "ffmpeg"), "-y", "-i", str(raw_mp3),
            "-af", af_chain,
            "-ar", str(SAMPLE_RATE), "-ac", "1",
            str(proc_wav)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        sr, audio_data = wavfile.read(str(proc_wav))
        audio_norm = audio_data.astype(np.float32) / 32767.0
        clip_dur = len(audio_norm) / SAMPLE_RATE

        start_sec = item["start_time"]
        end_sec = start_sec + clip_dur
        start_samp = int(start_sec * SAMPLE_RATE)
        end_samp = start_samp + len(audio_norm)

        if end_samp > total_samples:
            end_samp = total_samples
            audio_norm = audio_norm[:end_samp - start_samp]

        master_voice[start_samp:end_samp] += audio_norm
        print(f"  - Scene {idx} [{scene_name}]: {start_sec:.2f}s -> {end_sec:.2f}s (dur={clip_dur:.2f}s, speed={speed:.2f}x)")

        srt_entries.append((idx, fmt_tc(start_sec), fmt_tc(end_sec), item["text"]))

    # Save master voiceover WAV and MP3
    voice_wav = OUTPUT_DIR / "XRL_IDARS_Voiceover.wav"
    voice_mp3 = OUTPUT_DIR / "XRL_IDARS_Voiceover.mp3"
    wavfile.write(str(voice_wav), SAMPLE_RATE, (master_voice * 32767).astype(np.int16))

    subprocess.run([
        str(REPO_ROOT / ".venv" / "bin" / "ffmpeg"), "-y", "-i", str(voice_wav),
        "-codec:a", "libmp3lame", "-b:a", "192k",
        str(voice_mp3)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Master voiceover written to {voice_wav} and {voice_mp3}")

    # Write synchronized SRT
    srt_path = OUTPUT_DIR / "XRL_IDARS_Subtitles.srt"
    with open(srt_path, "w", encoding="utf-8") as f:
        for entry in srt_entries:
            f.write(f"{entry[0]}\n{entry[1]} --> {entry[2]}\n{entry[3]}\n\n")
    print(f"[+] Synchronized subtitles written to {srt_path}")

    # Mix with background music (-22 dB ducking under speech)
    bgm_path = OUTPUT_DIR / "background_music.wav"
    master_mix_wav = OUTPUT_DIR / "master_audio_mix.wav"
    
    print("[*] Mixing master audio track (Voiceover + Ambient Music at -22 dB)...")
    mix_cmd = [
        str(REPO_ROOT / ".venv" / "bin" / "ffmpeg"), "-y",
        "-i", str(voice_wav),
        "-i", str(bgm_path),
        "-filter_complex",
        "[0:a]volume=1.0[voice];[1:a]volume=0.08[bgm];[voice][bgm]amix=inputs=2:duration=first:dropout_transition=2[out]",
        "-map", "[out]",
        "-ar", str(SAMPLE_RATE),
        str(master_mix_wav)
    ]
    subprocess.run(mix_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Final master audio track written to {master_mix_wav}")


if __name__ == "__main__":
    asyncio.run(generate_voiceover_and_subtitles())
