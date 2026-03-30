#!/usr/bin/env python3
"""
Palimpsest - Metadata Forensics Toolkit v4.0
Video-first desktop application for analyzing metadata from
photos and videos, managing suspects, and building evidence packages.

v4.0: ENF (Electrical Network Frequency) analysis for geographic
region detection, AI vision frame analysis (Claude/GPT/Gemini),
batch metadata grouping for distribution chain mapping.

Pure Python. No external DLLs. Single-user local tool.

Part of the Project No More ecosystem.
https://ephemeradev.net | https://github.com/ephemera02
"""

import os, sys, json, hashlib, sqlite3, time, io, re, webbrowser, threading, struct, subprocess, shutil, base64
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False; print("[*] numpy not found. pip install numpy")

try:
    from scipy import signal as scipy_signal
    from scipy.io import wavfile as scipy_wav
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False; print("[*] scipy not found. pip install scipy")
from pathlib import Path
from contextlib import contextmanager

try:
    from flask import Flask, request, jsonify, send_from_directory, send_file
except ImportError:
    print("[!] Flask not found. Run: pip install flask"); sys.exit(1)

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False; print("[*] Pillow not found. pip install Pillow")

try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False; print("[*] imagehash not found. pip install imagehash")

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False; print("[*] opencv not found. pip install opencv-python-headless")

try:
    from hachoir.parser import createParser
    from hachoir.metadata import extractMetadata
    HAS_HACHOIR = True
except ImportError:
    HAS_HACHOIR = False; print("[*] hachoir not found. pip install hachoir")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False; print("[*] reportlab not found. pip install reportlab")

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "palimpsest.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
THUMB_DIR = os.path.join(BASE_DIR, "thumbnails")
FRAMES_DIR = os.path.join(BASE_DIR, "frames")
PREVIEW_DIR = os.path.join(BASE_DIR, "previews")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")
for d in (UPLOAD_DIR, THUMB_DIR, FRAMES_DIR, PREVIEW_DIR, EXPORT_DIR):
    os.makedirs(d, exist_ok=True)

IMAGE_EXTS = {".jpg",".jpeg",".png",".tiff",".tif",".bmp",".gif",".webp",".heic",".heif"}
VIDEO_EXTS = {".mp4",".avi",".mov",".mkv",".wmv",".flv",".webm",".m4v",".3gp",".ts",".mts",".m2ts"}

app = Flask(__name__, static_folder=None)
# No file size limit. This is a local tool, your machine, your rules.

# Limit concurrent background work (ffmpeg, frame extraction).
# Without this, batch processing 100 videos spawns 100 ffmpeg processes simultaneously.
BG_SEMAPHORE = threading.Semaphore(2)  # max 2 concurrent background jobs

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS suspects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, aliases TEXT DEFAULT '',
            platform TEXT DEFAULT '', notes TEXT DEFAULT '',
            threat_level TEXT DEFAULT 'unknown', status TEXT DEFAULT 'active',
            created_at TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS suspect_identifiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suspect_id INTEGER NOT NULL, id_type TEXT NOT NULL, id_value TEXT NOT NULL,
            FOREIGN KEY (suspect_id) REFERENCES suspects(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL, file_name TEXT NOT NULL,
            file_size INTEGER DEFAULT 0, media_type TEXT DEFAULT '',
            mime_type TEXT DEFAULT '', width INTEGER DEFAULT 0, height INTEGER DEFAULT 0,
            duration REAL DEFAULT 0, fps REAL DEFAULT 0, codec TEXT DEFAULT '',
            bitrate INTEGER DEFAULT 0, frame_count INTEGER DEFAULT 0,
            audio_codec TEXT DEFAULT '', audio_channels INTEGER DEFAULT 0,
            audio_sample_rate INTEGER DEFAULT 0,
            md5 TEXT DEFAULT '', sha256 TEXT DEFAULT '',
            phash TEXT DEFAULT '', dhash TEXT DEFAULT '',
            whash TEXT DEFAULT '', ahash TEXT DEFAULT '',
            has_exif INTEGER DEFAULT 0, has_gps INTEGER DEFAULT 0,
            gps_lat REAL DEFAULT NULL, gps_lon REAL DEFAULT NULL, gps_alt REAL DEFAULT NULL,
            camera_make TEXT DEFAULT '', camera_model TEXT DEFAULT '', software TEXT DEFAULT '',
            original_date TEXT DEFAULT '', modify_date TEXT DEFAULT '',
            creation_date TEXT DEFAULT '',
            metadata_json TEXT DEFAULT '{}',
            stripping_detected INTEGER DEFAULT 0, stripping_indicators TEXT DEFAULT '[]',
            frames_extracted INTEGER DEFAULT 0,
            suspect_id INTEGER DEFAULT NULL, tags TEXT DEFAULT '', notes TEXT DEFAULT '',
            added_at TEXT,
            FOREIGN KEY (suspect_id) REFERENCES suspects(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS extracted_frames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            frame_number INTEGER DEFAULT 0,
            timestamp_sec REAL DEFAULT 0,
            file_path TEXT NOT NULL,
            phash TEXT DEFAULT '',
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS comparisons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id_a INTEGER NOT NULL, evidence_id_b INTEGER NOT NULL,
            hash_similarity REAL DEFAULT 0, same_camera INTEGER DEFAULT 0,
            same_location INTEGER DEFAULT 0, same_date INTEGER DEFAULT 0,
            notes TEXT DEFAULT '', created_at TEXT,
            FOREIGN KEY (evidence_id_a) REFERENCES evidence(id) ON DELETE CASCADE,
            FOREIGN KEY (evidence_id_b) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ev_suspect ON evidence(suspect_id);
        CREATE INDEX IF NOT EXISTS idx_ev_phash ON evidence(phash);
        CREATE INDEX IF NOT EXISTS idx_ev_sha256 ON evidence(sha256);
        CREATE INDEX IF NOT EXISTS idx_ev_gps ON evidence(has_gps);
        CREATE INDEX IF NOT EXISTS idx_ident_val ON suspect_identifiers(id_value);
        CREATE INDEX IF NOT EXISTS idx_frames_ev ON extracted_frames(evidence_id);
        """)
init_db()

def init_forensic_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS forensic_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL, analysis_type TEXT NOT NULL,
            result_json TEXT DEFAULT '{}', flags TEXT DEFAULT '[]',
            score REAL DEFAULT 0, analyzed_at TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS audio_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            spectral_centroid TEXT DEFAULT '', mfcc_features TEXT DEFAULT '',
            duration REAL DEFAULT 0, sample_rate INTEGER DEFAULT 0,
            has_speech INTEGER DEFAULT 0, energy_profile TEXT DEFAULT '',
            fingerprint_hash TEXT DEFAULT '',
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS scene_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            color_histogram TEXT DEFAULT '', dominant_colors TEXT DEFAULT '',
            brightness_profile TEXT DEFAULT '', edge_density REAL DEFAULT 0,
            texture_hash TEXT DEFAULT '',
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_forensic_ev ON forensic_results(evidence_id);
        CREATE INDEX IF NOT EXISTS idx_audio_ev ON audio_fingerprints(evidence_id);
        CREATE INDEX IF NOT EXISTS idx_scene_ev ON scene_signatures(evidence_id);
        """)
init_forensic_db()

def init_v4_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS enf_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            detected_freq REAL DEFAULT 0,
            grid_region TEXT DEFAULT '',
            confidence REAL DEFAULT 0,
            enf_trace TEXT DEFAULT '[]',
            source TEXT DEFAULT '',
            flags TEXT DEFAULT '[]',
            analyzed_at TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            provider TEXT DEFAULT '',
            model TEXT DEFAULT '',
            frame_index INTEGER DEFAULT 0,
            result_json TEXT DEFAULT '{}',
            tokens_used INTEGER DEFAULT 0,
            cost_estimate REAL DEFAULT 0,
            analyzed_at TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            provider TEXT DEFAULT 'anthropic',
            api_key TEXT DEFAULT '',
            model TEXT DEFAULT '',
            custom_endpoint TEXT DEFAULT '',
            default_prompt TEXT DEFAULT '',
            total_tokens INTEGER DEFAULT 0,
            total_cost REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ocr_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            frame_index INTEGER DEFAULT 0,
            detected_text TEXT DEFAULT '',
            language TEXT DEFAULT '',
            confidence REAL DEFAULT 0,
            analyzed_at TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_enf_ev ON enf_results(evidence_id);
        CREATE INDEX IF NOT EXISTS idx_ai_ev ON ai_results(evidence_id);
        CREATE INDEX IF NOT EXISTS idx_ocr_ev ON ocr_results(evidence_id);
        """)
        existing = conn.execute("SELECT id FROM ai_settings WHERE id=1").fetchone()
        if not existing:
            default_prompt = ("You are a forensic analyst examining video frames from an investigation. "
                "Analyze this frame and return ONLY a JSON object (no markdown, no explanation) with these fields: "
                "outlet_type (power outlet type visible: Type A/B/C/F/G/I or none), "
                "visible_text (array of any readable text), "
                "text_language (detected language of visible text), "
                "room_features (description of flooring, walls, furniture), "
                "lighting (fluorescent/incandescent/natural/LED), "
                "vegetation (plants/trees visible through windows), "
                "objects (notable objects, tools, animals), "
                "environmental_clues (anything suggesting geographic region or time), "
                "confidence (0-100 confidence in geographic indicators), "
                "region_estimate (best guess at country/region)")
            conn.execute("INSERT INTO ai_settings (id, provider, model, default_prompt) VALUES (1, 'anthropic', 'claude-sonnet-4-5-20250514', ?)",
                (default_prompt,))
init_v4_db()

# AI provider configuration
AI_PROVIDERS = {
    "anthropic": {
        "name": "Anthropic (Claude)",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "models": [
            {"id": "claude-sonnet-4-5-20250514", "name": "Claude Sonnet 4.5", "input_cost": 3.0, "output_cost": 15.0},
            {"id": "claude-sonnet-4-6-20250725", "name": "Claude Sonnet 4.6", "input_cost": 3.0, "output_cost": 15.0},
            {"id": "claude-opus-4-5-20250410", "name": "Claude Opus 4.5", "input_cost": 15.0, "output_cost": 75.0},
            {"id": "claude-opus-4-6-20250710", "name": "Claude Opus 4.6", "input_cost": 15.0, "output_cost": 75.0},
        ],
        "format": "anthropic"
    },
    "openai": {
        "name": "OpenAI (GPT)",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "models": [
            {"id": "gpt-5.2", "name": "GPT-5.2", "input_cost": 2.5, "output_cost": 10.0},
            {"id": "gpt-5.3", "name": "GPT-5.3", "input_cost": 5.0, "output_cost": 15.0},
        ],
        "format": "openai"
    },
    "google": {
        "name": "Google (Gemini)",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "models": [
            {"id": "gemini-3.0-flash", "name": "Gemini 3.0 Flash", "input_cost": 0.075, "output_cost": 0.30},
            {"id": "gemini-3.1-flash", "name": "Gemini 3.1 Flash", "input_cost": 0.075, "output_cost": 0.30},
            {"id": "gemini-3.0-pro", "name": "Gemini 3.0 Pro", "input_cost": 1.25, "output_cost": 5.0},
            {"id": "gemini-3.1-pro", "name": "Gemini 3.1 Pro", "input_cost": 1.25, "output_cost": 5.0},
        ],
        "format": "google"
    },
    "openrouter": {
        "name": "OpenRouter",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "models": [
            {"id": "anthropic/claude-sonnet-4.5", "name": "Claude Sonnet 4.5 (via OR)", "input_cost": 3.0, "output_cost": 15.0},
            {"id": "openai/gpt-5.2", "name": "GPT-5.2 (via OR)", "input_cost": 2.5, "output_cost": 10.0},
            {"id": "google/gemini-3.0-flash", "name": "Gemini 3.0 Flash (via OR)", "input_cost": 0.075, "output_cost": 0.30},
        ],
        "format": "openai"
    },
    "custom": {
        "name": "Custom Endpoint",
        "endpoint": "",
        "models": [{"id": "custom", "name": "Custom Model", "input_cost": 1.0, "output_cost": 1.0}],
        "format": "openai"
    }
}

# Check for ffmpeg (needed for audio extraction)
# Look next to exe first (bundled), then PATH
_ffmpeg_bundled = os.path.join(BASE_DIR, "ffmpeg.exe")
if os.path.exists(_ffmpeg_bundled):
    FFMPEG_PATH = _ffmpeg_bundled
    HAS_FFMPEG = True
elif shutil.which("ffmpeg"):
    FFMPEG_PATH = "ffmpeg"
    HAS_FFMPEG = True
else:
    FFMPEG_PATH = None
    HAS_FFMPEG = False
    print("[*] ffmpeg not found. Audio extraction disabled. Install ffmpeg for full forensics.")

FIELD_EXPLAIN = {
    "Make":"Camera manufacturer (who made the device that took this)",
    "Model":"Camera/phone model name",
    "Software":"Software used to edit or process this file",
    "DateTime":"Date the file was last modified",
    "DateTimeOriginal":"Date the photo/video was originally captured",
    "DateTimeDigitized":"Date the media was digitized",
    "ExposureTime":"How long the shutter was open (seconds)",
    "FNumber":"Aperture (lower = wider opening = more light)",
    "ISOSpeedRatings":"Sensor light sensitivity (higher = grainier)",
    "FocalLength":"Lens focal length in mm",
    "FocalLengthIn35mmFilm":"Equivalent focal length on 35mm camera",
    "Flash":"Whether the flash fired",
    "WhiteBalance":"Color temperature correction mode",
    "ExposureProgram":"Camera shooting mode (auto, manual, etc.)",
    "MeteringMode":"How the camera measured light",
    "ColorSpace":"Color space of the image data",
    "ExifImageWidth":"Image width stored in EXIF",
    "ExifImageHeight":"Image height stored in EXIF",
    "Orientation":"How the image should be rotated for display",
    "GPSLatitude":"GPS latitude (north/south position)",
    "GPSLongitude":"GPS longitude (east/west position)",
    "GPSAltitude":"GPS altitude (meters above sea level)",
    "GPSTimeStamp":"Time recorded by GPS (UTC)",
    "GPSDateStamp":"Date recorded by GPS",
    "ImageDescription":"User-entered description in the file",
    "Artist":"Creator/photographer name",
    "Copyright":"Copyright notice in the file",
    "UserComment":"User comment embedded in the file",
    "BodySerialNumber":"Camera serial number (identifies specific device)",
    "LensModel":"Lens model used",
    "LensSerialNumber":"Lens serial number",
    "ImageUniqueID":"Unique identifier for this image",
}
VIDEO_FIELD_EXPLAIN = {
    "duration":"Total length of the video",
    "width":"Video frame width in pixels",
    "height":"Video frame height in pixels",
    "fps":"Frames per second (playback speed)",
    "codec":"Video compression format",
    "bitrate":"Data rate (higher = better quality, larger file)",
    "frame_count":"Total number of frames in the video",
    "audio_codec":"Audio compression format",
    "audio_channels":"Audio channels (1=mono, 2=stereo)",
    "audio_sample_rate":"Audio samples per second",
    "creation_date":"When the video was originally created",
    "comment":"Embedded comment or description",
    "encoder":"Software/hardware that encoded this video",
}

def compute_hashes(file_path):
    result = {"md5":"","sha256":"","phash":"","dhash":"","whash":"","ahash":""}
    md5 = hashlib.md5(); sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1048576)
            if not chunk: break
            md5.update(chunk); sha.update(chunk)
    result["md5"] = md5.hexdigest(); result["sha256"] = sha.hexdigest()
    if HAS_IMAGEHASH and HAS_PIL:
        try:
            img = Image.open(file_path)
            result["phash"]=str(imagehash.phash(img)); result["dhash"]=str(imagehash.dhash(img))
            result["whash"]=str(imagehash.whash(img)); result["ahash"]=str(imagehash.average_hash(img))
        except: pass
    return result

def compute_video_hashes(file_path):
    result = {"md5":"","sha256":"","phash":"","dhash":"","whash":"","ahash":""}
    md5 = hashlib.md5(); sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1048576)
            if not chunk: break
            md5.update(chunk); sha.update(chunk)
    result["md5"] = md5.hexdigest(); result["sha256"] = sha.hexdigest()
    if HAS_CV2 and HAS_IMAGEHASH and HAS_PIL:
        try:
            cap = cv2.VideoCapture(file_path)
            for _ in range(10): cap.read()
            ret, frame = cap.read(); cap.release()
            if ret:
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB); img = Image.fromarray(rgb)
                result["phash"]=str(imagehash.phash(img)); result["dhash"]=str(imagehash.dhash(img))
                result["whash"]=str(imagehash.whash(img)); result["ahash"]=str(imagehash.average_hash(img))
        except: pass
    return result

def extract_gps(exif_data):
    gps_info = {}
    for key, val in exif_data.items():
        if TAGS.get(key, key) == "GPSInfo":
            for gk, gv in val.items(): gps_info[GPSTAGS.get(gk, gk)] = gv
    if not gps_info: return None
    def to_deg(v):
        try: return float(v[0])+float(v[1])/60.0+float(v[2])/3600.0
        except: return None
    lat=to_deg(gps_info.get("GPSLatitude")); lon=to_deg(gps_info.get("GPSLongitude"))
    if lat is None or lon is None: return None
    if gps_info.get("GPSLatitudeRef","N")=="S": lat=-lat
    if gps_info.get("GPSLongitudeRef","E")=="W": lon=-lon
    alt=None
    try:
        alt=float(gps_info["GPSAltitude"])
        if gps_info.get("GPSAltitudeRef",b'\x00')==b'\x01': alt=-alt
    except: pass
    return {"lat":lat,"lon":lon,"alt":alt}

def detect_stripping_image(metadata, file_path):
    indicators = []
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in (".jpg",".jpeg",".png",".tiff",".tif"): return indicators
    if not metadata:
        indicators.append("No EXIF data found -- metadata may have been stripped before sharing"); return indicators
    has_cam=any(k in metadata for k in ["Make","Model"])
    has_dates=any(k in metadata for k in ["DateTimeOriginal","DateTimeDigitized"])
    if not has_cam and not has_dates:
        indicators.append("Missing camera info and timestamps (common after stripping tools)")
    elif has_cam and not has_dates:
        indicators.append("Camera info present but timestamps removed (possible selective strip)")
    sw=metadata.get("Software","")
    if sw:
        for tool in ["gimp","photoshop","snapseed","lightroom","paint","canva","pixlr"]:
            if tool in sw.lower(): indicators.append(f"Edited with {sw} -- metadata may have been modified")
    dt=metadata.get("DateTime",""); dto=metadata.get("DateTimeOriginal","")
    if dt and dto and dt!=dto:
        indicators.append(f"Modification date ({dt}) differs from original ({dto}) -- file was edited after capture")
    return indicators

def detect_stripping_video(metadata, file_path):
    indicators = []
    if not metadata or not metadata.get("raw"):
        indicators.append("No container metadata found -- video metadata may have been stripped"); return indicators
    raw=metadata.get("raw",{})
    if not metadata.get("dates",{}).get("original") and not metadata.get("dates",{}).get("modified"):
        indicators.append("No date information in video container -- timestamps may have been removed")
    if not raw.get("comment") and not raw.get("encoder") and not raw.get("creation_date"):
        indicators.append("Minimal container metadata -- video may have been re-encoded to strip data")
    return indicators

def extract_image_metadata(file_path):
    result = {"type":"image","fields":{},"fields_explained":{},"gps":None,
              "camera":{"make":"","model":"","software":""},
              "dates":{"original":"","modified":"","digitized":""},
              "dimensions":{"width":0,"height":0},
              "stripping":{"detected":False,"indicators":[]},"raw":{},"has_exif":False}
    if not HAS_PIL: return result
    try:
        img=Image.open(file_path); result["dimensions"]["width"]=img.size[0]; result["dimensions"]["height"]=img.size[1]
        exif_data=img._getexif()
        if not exif_data:
            ind=detect_stripping_image({},file_path); result["stripping"]["detected"]=len(ind)>0; result["stripping"]["indicators"]=ind; return result
        decoded={}
        for tag_id,value in exif_data.items():
            tag_name=TAGS.get(tag_id,str(tag_id))
            try: json.dumps(value); decoded[tag_name]=value
            except: decoded[tag_name]=str(value)
        result["raw"]=decoded; result["fields"]=decoded; result["has_exif"]=True
        for fn,expl in FIELD_EXPLAIN.items():
            if fn in decoded: result["fields_explained"][fn]={"value":decoded[fn],"explanation":expl}
        result["camera"]["make"]=decoded.get("Make",""); result["camera"]["model"]=decoded.get("Model",""); result["camera"]["software"]=decoded.get("Software","")
        result["dates"]["original"]=decoded.get("DateTimeOriginal",""); result["dates"]["modified"]=decoded.get("DateTime",""); result["dates"]["digitized"]=decoded.get("DateTimeDigitized","")
        gps=extract_gps(exif_data)
        if gps: result["gps"]=gps
        ind=detect_stripping_image(decoded,file_path); result["stripping"]["detected"]=len(ind)>0; result["stripping"]["indicators"]=ind
    except Exception as e: result["error"]=str(e)
    return result

def extract_video_metadata(file_path):
    result = {"type":"video","fields":{},"fields_explained":{},"gps":None,
              "camera":{"make":"","model":"","software":""},
              "dates":{"original":"","modified":"","creation":""},
              "dimensions":{"width":0,"height":0},
              "duration":0,"fps":0,"codec":"","bitrate":0,"frame_count":0,
              "audio":{"codec":"","channels":0,"sample_rate":0},
              "stripping":{"detected":False,"indicators":[]},"raw":{},"has_exif":False}
    file_size = os.path.getsize(file_path)
    # Skip hachoir for files over 500MB, it chokes on large files.
    # cv2 gets the important stuff (dimensions, fps, codec, duration) from headers only.
    use_hachoir = HAS_HACHOIR and file_size < 500 * 1024 * 1024
    if use_hachoir:
        try:
            import concurrent.futures
            def _parse_hachoir(fp):
                parser=createParser(fp)
                if not parser: return {}
                meta=extractMetadata(parser)
                if not meta:
                    try: parser.stream._input.close()
                    except: pass
                    return {}
                raw={}
                for item in meta:
                    for val in item.values: raw[item.key]=str(val.value) if hasattr(val,'value') else str(val)
                try: parser.stream._input.close()
                except: pass
                return raw
            with concurrent.futures.ThreadPoolExecutor() as ex:
                future = ex.submit(_parse_hachoir, file_path)
                try:
                    raw = future.result(timeout=15)
                except concurrent.futures.TimeoutError:
                    raw = {}
                    result.setdefault("warnings",[]).append("hachoir timed out (file may be very large or unusual format)")
            if raw:
                result["raw"]=raw
                if "duration" in raw: result["fields"]["Duration"]=raw["duration"]
                if "width" in raw:
                    try: result["dimensions"]["width"]=int(raw["width"].split()[0])
                    except: pass
                if "height" in raw:
                    try: result["dimensions"]["height"]=int(raw["height"].split()[0])
                    except: pass
                for dk in ("creation_date","last_modification","date_time_original"):
                    if dk in raw: result["dates"]["creation"]=raw[dk]; result["dates"]["original"]=raw[dk]; break
                for ck in ("compression","video_compression","codec","format_version"):
                    if ck in raw: result["codec"]=raw[ck]; result["fields"]["Codec"]=raw[ck]; break
                if "encoder" in raw: result["camera"]["software"]=raw["encoder"]; result["fields"]["Encoder"]=raw["encoder"]
                if "comment" in raw: result["fields"]["Comment"]=raw["comment"]
                if "producer" in raw: result["fields"]["Producer"]=raw["producer"]
                if "bit_rate" in raw:
                    result["fields"]["Bitrate"]=raw["bit_rate"]
                    try: result["bitrate"]=int(re.sub(r'[^\d]','',raw["bit_rate"]))
                    except: pass
                for ak in ("audio_compression","audio_codec"):
                    if ak in raw: result["audio"]["codec"]=raw[ak]; result["fields"]["AudioCodec"]=raw[ak]; break
                if "sample_rate" in raw:
                    try: result["audio"]["sample_rate"]=int(re.sub(r'[^\d]','',raw["sample_rate"]))
                    except: pass
                if "channel" in raw: result["fields"]["AudioChannels"]=raw["channel"]
                fmap={"Duration":"duration","Codec":"codec","Bitrate":"bitrate","Encoder":"encoder","Comment":"comment","AudioCodec":"audio_codec","AudioChannels":"audio_channels"}
                for dk,ek in fmap.items():
                    if dk in result["fields"] and ek in VIDEO_FIELD_EXPLAIN:
                        result["fields_explained"][dk]={"value":result["fields"][dk],"explanation":VIDEO_FIELD_EXPLAIN[ek]}
        except Exception as e:
            result.setdefault("warnings",[]).append(f"hachoir error: {e}")
    if HAS_CV2:
        try:
            cap=cv2.VideoCapture(file_path)
            if cap.isOpened():
                w=int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); h=int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                fps=cap.get(cv2.CAP_PROP_FPS); fc=int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                fourcc=int(cap.get(cv2.CAP_PROP_FOURCC))
                codec_str=struct.pack('<I',fourcc).decode('ascii',errors='replace').strip('\x00')
                result["dimensions"]["width"]=w; result["dimensions"]["height"]=h
                result["fps"]=round(fps,2) if fps else 0; result["frame_count"]=fc
                if fps and fc: result["duration"]=round(fc/fps,2)
                result["fields"]["Resolution"]=f"{w}x{h}"; result["fields"]["FrameRate"]=f"{fps:.2f} fps" if fps else "Unknown"
                result["fields"]["FrameCount"]=str(fc); result["fields"]["FourCC"]=codec_str
                if result["duration"]:
                    m=int(result["duration"]//60); s=result["duration"]%60; result["fields"]["Duration"]=f"{m}:{s:05.2f}"
                if not result["codec"]: result["codec"]=codec_str
                for dk,(ek,val) in {"Resolution":("width",f"{w}x{h}"),"FrameRate":("fps",f"{fps:.2f} fps"),"FrameCount":("frame_count",str(fc)),"FourCC":("codec",codec_str)}.items():
                    if ek in VIDEO_FIELD_EXPLAIN: result["fields_explained"][dk]={"value":val,"explanation":VIDEO_FIELD_EXPLAIN[ek]}
                cap.release()
        except: pass
    ind=detect_stripping_video(result,file_path); result["stripping"]["detected"]=len(ind)>0; result["stripping"]["indicators"]=ind
    return result

def extract_frames(file_path, evidence_id, count=8):
    if not HAS_CV2: return []
    frames=[]
    try:
        cap=cv2.VideoCapture(file_path)
        if not cap.isOpened(): return []
        total=int(cap.get(cv2.CAP_PROP_FRAME_COUNT)); fps=cap.get(cv2.CAP_PROP_FPS) or 30
        if total<count: count=max(total,1)
        interval=max(total//count,1)
        fdir=os.path.join(FRAMES_DIR,str(evidence_id)); os.makedirs(fdir,exist_ok=True)
        for i in range(count):
            fn=i*interval; cap.set(cv2.CAP_PROP_POS_FRAMES,fn)
            ret,frame=cap.read()
            if not ret: continue
            fname=f"frame_{i:04d}.jpg"; fpath=os.path.join(fdir,fname)
            cv2.imwrite(fpath,frame,[cv2.IMWRITE_JPEG_QUALITY,85])
            ts=fn/fps if fps else 0; phash=""
            if HAS_IMAGEHASH and HAS_PIL:
                try:
                    rgb=cv2.cvtColor(frame,cv2.COLOR_BGR2RGB); img=Image.fromarray(rgb)
                    phash=str(imagehash.phash(img))
                except: pass
            frames.append({"frame_number":fn,"timestamp_sec":round(ts,2),"file_path":f"{evidence_id}/{fname}","phash":phash})
        cap.release()
    except: pass
    return frames

def generate_thumbnail(file_path, evidence_id, media_type="image"):
    tp=os.path.join(THUMB_DIR,f"{evidence_id}.jpg")
    if media_type=="image" and HAS_PIL:
        try:
            img=Image.open(file_path); img.thumbnail((200,200))
            if img.mode in ("RGBA","P"): img=img.convert("RGB")
            img.save(tp,"JPEG",quality=80); return True
        except: return False
    elif media_type=="video" and HAS_CV2:
        try:
            cap=cv2.VideoCapture(file_path); total=int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            cap.set(cv2.CAP_PROP_POS_FRAMES,max(total//10,1))
            ret,frame=cap.read(); cap.release()
            if ret:
                h,w=frame.shape[:2]; scale=200/max(h,w)
                thumb=cv2.resize(frame,(int(w*scale),int(h*scale)))
                cv2.imwrite(tp,thumb,[cv2.IMWRITE_JPEG_QUALITY,80]); return True
        except: pass
    return False

def generate_preview(file_path, evidence_id):
    """Transcode video to browser-playable H.264 MP4 for universal playback.
    Keeps original untouched. Preview is for the player only."""
    if not HAS_FFMPEG: return None
    preview_path = os.path.join(PREVIEW_DIR, f"{evidence_id}.mp4")
    if os.path.exists(preview_path): return preview_path
    try:
        subprocess.run([
            FFMPEG_PATH, "-i", file_path,
            "-c:v", "libx264", "-preset", "fast", "-crf", "23",
            "-c:a", "aac", "-b:a", "128k",
            "-movflags", "+faststart",
            "-y", preview_path
        ], capture_output=True, timeout=600)
        if os.path.exists(preview_path) and os.path.getsize(preview_path) > 100:
            return preview_path
    except:
        pass
    return None

def classify_file(fn):
    ext=os.path.splitext(fn)[1].lower()
    if ext in IMAGE_EXTS: return "image"
    if ext in VIDEO_EXTS: return "video"
    return "other"

def save_and_hash(file_obj, save_path):
    """Save uploaded file to disk while computing MD5+SHA-256 in the same pass.
    Eliminates the need to re-read the entire file for hashing.
    For a 1.3GB file this cuts processing time roughly in half."""
    md5 = hashlib.md5(); sha = hashlib.sha256()
    with open(save_path, "wb") as out:
        while True:
            chunk = file_obj.read(1048576)  # 1MB chunks
            if not chunk: break
            out.write(chunk)
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()

def perceptual_hash_video(file_path):
    """Compute perceptual hashes from first meaningful frame. Fast, header-seek only."""
    result = {"phash":"","dhash":"","whash":"","ahash":""}
    if not HAS_CV2 or not HAS_IMAGEHASH or not HAS_PIL: return result
    try:
        cap = cv2.VideoCapture(file_path)
        for _ in range(10): cap.read()
        ret, frame = cap.read(); cap.release()
        if ret:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB); img = Image.fromarray(rgb)
            result["phash"]=str(imagehash.phash(img)); result["dhash"]=str(imagehash.dhash(img))
            result["whash"]=str(imagehash.whash(img)); result["ahash"]=str(imagehash.average_hash(img))
    except: pass
    return result

# ===========================================================================
# FORENSIC ANALYSIS MODULES
# ===========================================================================

def forensic_scene_analysis(file_path, evidence_id):
    """Analyze scene characteristics: color histograms, dominant colors,
    edge density, brightness profile. Used to match videos filmed in the
    same location."""
    result = {"dominant_colors":[],"brightness_avg":0,"edge_density":0,
              "color_histogram":[],"texture_hash":"","flags":[]}
    if not HAS_CV2 or not HAS_NUMPY: return result
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened(): return result
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        samples = min(10, max(total, 1))
        interval = max(total // samples, 1)
        histograms = []; brightnesses = []; edge_densities = []

        for i in range(samples):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i * interval)
            ret, frame = cap.read()
            if not ret: continue

            # Color histogram (HSV space, more robust to lighting)
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
            hist_h = cv2.calcHist([hsv],[0],None,[32],[0,180]).flatten()
            hist_s = cv2.calcHist([hsv],[1],None,[32],[0,256]).flatten()
            hist_h = hist_h / (hist_h.sum() + 1e-7)
            hist_s = hist_s / (hist_s.sum() + 1e-7)
            histograms.append(np.concatenate([hist_h, hist_s]))

            # Brightness
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            brightnesses.append(float(np.mean(gray)))

            # Edge density (indicates textures, objects, complexity)
            edges = cv2.Canny(gray, 50, 150)
            edge_densities.append(float(np.sum(edges > 0)) / edges.size)

            # Dominant colors via simple k-means-like binning
            if i == samples // 2:  # Middle frame
                pixels = frame.reshape(-1, 3).astype(np.float32)
                # Simple dominant color: most common color ranges
                for ch in range(3):
                    vals = pixels[:, ch]
                    hist_counts, _ = np.histogram(vals, bins=8, range=(0, 256))
                    peak_bin = int(np.argmax(hist_counts))
                    result["dominant_colors"].append(int(peak_bin * 32 + 16))

        cap.release()
        if histograms:
            avg_hist = np.mean(histograms, axis=0)
            result["color_histogram"] = avg_hist.tolist()
            # Texture hash: quantize histogram to create a comparable string
            quantized = (avg_hist * 100).astype(int)
            result["texture_hash"] = hashlib.md5(quantized.tobytes()).hexdigest()[:16]
        result["brightness_avg"] = float(np.mean(brightnesses)) if brightnesses else 0
        result["edge_density"] = float(np.mean(edge_densities)) if edge_densities else 0

        # Flags
        if result["brightness_avg"] < 40:
            result["flags"].append("Very dark scene (may be intentionally low-light)")
        if result["brightness_avg"] > 200:
            result["flags"].append("Very bright/overexposed scene")
        if result["edge_density"] < 0.02:
            result["flags"].append("Low detail scene (plain walls/floors, or blurred)")

    except Exception as e:
        result["error"] = str(e)
    return result


def forensic_scene_compare(sig_a, sig_b):
    """Compare two scene signatures. Returns similarity 0-100."""
    if not HAS_NUMPY: return 0
    try:
        hist_a = np.array(sig_a.get("color_histogram", []))
        hist_b = np.array(sig_b.get("color_histogram", []))
        if len(hist_a) == 0 or len(hist_b) == 0 or len(hist_a) != len(hist_b):
            return 0
        # Histogram correlation
        corr = float(cv2.compareHist(
            hist_a.astype(np.float32), hist_b.astype(np.float32),
            cv2.HISTCMP_CORREL
        ))
        # Brightness similarity
        b_diff = abs(sig_a.get("brightness_avg",0) - sig_b.get("brightness_avg",0))
        b_sim = max(0, 1 - b_diff / 128)
        # Edge density similarity
        e_diff = abs(sig_a.get("edge_density",0) - sig_b.get("edge_density",0))
        e_sim = max(0, 1 - e_diff / 0.2)
        # Weighted combo
        similarity = (corr * 0.6 + b_sim * 0.2 + e_sim * 0.2) * 100
        return round(max(0, min(100, similarity)), 1)
    except:
        return 0


def forensic_watermark_detection(file_path):
    """Detect potential watermarks/overlays in video frames.
    Looks for text-like regions in consistent positions across frames."""
    result = {"has_overlay":False,"overlay_regions":[],"flags":[],"overlay_frames":[]}
    if not HAS_CV2 or not HAS_NUMPY: return result
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened(): return result
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        # Check corners and edges for consistent bright/contrasting regions
        # (where watermarks typically appear)
        regions = {
            "top_left": (0, 0, w//4, h//8),
            "top_right": (3*w//4, 0, w, h//8),
            "bottom_left": (0, 7*h//8, w//4, h),
            "bottom_right": (3*w//4, 7*h//8, w, h),
            "bottom_center": (w//4, 7*h//8, 3*w//4, h),
            "top_center": (w//4, 0, 3*w//4, h//8),
        }

        samples = min(6, total)
        interval = max(total // samples, 1)
        region_scores = {k: [] for k in regions}

        for i in range(samples):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i * interval)
            ret, frame = cap.read()
            if not ret: continue
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            for name, (x1, y1, x2, y2) in regions.items():
                roi = gray[y1:y2, x1:x2]
                if roi.size == 0: continue
                # High contrast text detection: look for sharp edges in region
                edges = cv2.Canny(roi, 100, 200)
                edge_ratio = float(np.sum(edges > 0)) / edges.size
                # Text tends to have moderate-high edge density in small region
                region_scores[name].append(edge_ratio)

        cap.release()

        # A watermark appears consistently across frames in the same position
        for name, scores in region_scores.items():
            if len(scores) < 3: continue
            avg = np.mean(scores)
            std = np.std(scores)
            # High average edge density + low variance = consistent overlay
            if avg > 0.05 and std < 0.03:
                result["has_overlay"] = True
                result["overlay_regions"].append({
                    "position": name,
                    "confidence": round(min(avg * 10, 1.0) * 100),
                    "consistency": round((1 - min(std * 20, 1.0)) * 100)
                })

        if result["has_overlay"]:
            positions = [r["position"] for r in result["overlay_regions"]]
            result["flags"].append(f"Consistent overlay detected in: {', '.join(positions)}")
            result["flags"].append("This may be a channel watermark, bot stamp, or redistribution mark")

    except Exception as e:
        result["error"] = str(e)
    return result


def forensic_encoding_analysis(file_path, evidence_id):
    """Analyze encoding characteristics to detect re-encoding, generation loss,
    and compression artifacts."""
    result = {"is_original":None,"generation_estimate":"unknown",
              "compression_ratio":0,"flags":[],"details":{}}
    if not HAS_CV2 or not HAS_NUMPY: return result
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened(): return result
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fourcc = int(cap.get(cv2.CAP_PROP_FOURCC))
        codec = struct.pack('<I', fourcc).decode('ascii', errors='replace').strip('\x00')

        file_size = os.path.getsize(file_path)
        duration = total / fps if fps and total else 0
        bitrate_actual = (file_size * 8 / duration) if duration > 0 else 0

        result["details"]["resolution"] = f"{w}x{h}"
        result["details"]["fps"] = round(fps, 2) if fps else 0
        result["details"]["codec"] = codec
        result["details"]["bitrate_bps"] = int(bitrate_actual)
        result["details"]["bitrate_human"] = f"{bitrate_actual/1000:.0f} kbps"

        # Expected bitrate for resolution (rough heuristic)
        pixels = w * h
        # Typical bitrate ranges for common resolutions
        if pixels > 0:
            bpp = bitrate_actual / (pixels * (fps or 30))  # bits per pixel per frame
            result["details"]["bits_per_pixel_frame"] = round(bpp, 4)
            result["compression_ratio"] = round(bpp, 4)

            if bpp < 0.01:
                result["flags"].append("Extremely low bitrate for resolution (heavy re-compression likely)")
                result["generation_estimate"] = "3rd+ generation (heavily re-encoded)"
            elif bpp < 0.03:
                result["flags"].append("Low bitrate for resolution (probable re-encode)")
                result["generation_estimate"] = "2nd-3rd generation"
            elif bpp < 0.08:
                result["generation_estimate"] = "1st-2nd generation"
            else:
                result["generation_estimate"] = "likely original or 1st generation"

        # FPS analysis
        if fps:
            # Non-standard FPS often indicates screen recording or re-encoding
            standard_fps = [23.976, 24, 25, 29.97, 30, 50, 59.94, 60]
            closest = min(standard_fps, key=lambda x: abs(x - fps))
            if abs(fps - closest) > 0.5:
                result["flags"].append(f"Non-standard frame rate ({fps:.2f} fps) may indicate screen recording or re-encoding")

        # Resolution analysis
        standard_res = [(640,480),(720,480),(720,576),(1280,720),(1920,1080),(2560,1440),(3840,2160),
                        (720,1280),(1080,1920),(480,854),(360,640)]  # Include vertical
        is_standard = any(abs(w-sw)<=2 and abs(h-sh)<=2 for sw,sh in standard_res)
        if not is_standard and w > 100 and h > 100:
            result["flags"].append(f"Non-standard resolution ({w}x{h}) may indicate cropping, screen recording, or re-encoding")

        # Analyze quantization artifacts (blockiness)
        samples = min(5, total)
        interval = max(total // samples, 1)
        blockiness_scores = []
        for i in range(samples):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i * interval)
            ret, frame = cap.read()
            if not ret: continue
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float64)
            # Blockiness: measure discontinuities at 8x8 block boundaries
            if gray.shape[0] > 16 and gray.shape[1] > 16:
                h_blocks = gray[:, 7::8] - gray[:, 8::8]  # Horizontal boundaries
                v_blocks = gray[7::8, :] - gray[8::8, :]  # Vertical boundaries
                blockiness = (np.mean(np.abs(h_blocks)) + np.mean(np.abs(v_blocks))) / 2
                blockiness_scores.append(float(blockiness))

        cap.release()

        if blockiness_scores:
            avg_blockiness = np.mean(blockiness_scores)
            result["details"]["blockiness"] = round(avg_blockiness, 2)
            if avg_blockiness > 8:
                result["flags"].append(f"High blockiness ({avg_blockiness:.1f}) indicates heavy compression or multiple re-encodes")
            elif avg_blockiness > 4:
                result["flags"].append(f"Moderate blockiness ({avg_blockiness:.1f}) suggests at least one re-encode")

        result["is_original"] = len(result["flags"]) == 0

    except Exception as e:
        result["error"] = str(e)
    return result


def forensic_screen_recording_detection(file_path):
    """Detect whether a video is a screen recording rather than a camera capture."""
    result = {"is_screen_recording":False,"confidence":0,"indicators":[],"flags":[]}
    if not HAS_CV2 or not HAS_NUMPY: return result
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened(): return result
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        score = 0

        # Phone screen resolutions (common screen record sizes)
        phone_res = [(720,1280),(1080,1920),(1440,2560),(750,1334),(1125,2436),
                     (1170,2532),(1284,2778),(1080,2340),(1080,2400)]
        # Check both orientations
        for pw, ph in phone_res:
            if (abs(w-pw)<=4 and abs(h-ph)<=4) or (abs(w-ph)<=4 and abs(h-pw)<=4):
                score += 30
                result["indicators"].append(f"Resolution matches phone screen ({w}x{h})")
                break

        # Check for status bar (consistent bright strip at top)
        samples = min(5, total)
        interval = max(total // samples, 1)
        top_strip_consistency = []
        bottom_strip_consistency = []

        for i in range(samples):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i * interval)
            ret, frame = cap.read()
            if not ret: continue
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            # Status bar region (top 3% of frame)
            top_strip = gray[:max(h//30, 5), :]
            top_brightness = float(np.mean(top_strip))
            top_strip_consistency.append(top_brightness)

            # Navigation bar (bottom 5%)
            bottom_strip = gray[-max(h//20, 5):, :]
            bottom_brightness = float(np.mean(bottom_strip))
            bottom_strip_consistency.append(bottom_brightness)

        cap.release()

        # Consistent brightness at top = likely status bar
        if top_strip_consistency:
            top_std = np.std(top_strip_consistency)
            top_avg = np.mean(top_strip_consistency)
            if top_std < 5 and top_avg > 100:
                score += 25
                result["indicators"].append("Consistent bright strip at top (status bar)")
            if top_std < 5 and top_avg < 50:
                score += 15
                result["indicators"].append("Consistent dark strip at top (dark mode status bar)")

        # Bottom bar
        if bottom_strip_consistency:
            bot_std = np.std(bottom_strip_consistency)
            if bot_std < 5:
                score += 15
                result["indicators"].append("Consistent strip at bottom (navigation bar)")

        # Variable frame rate (screen recorders often have inconsistent fps)
        if fps and (fps < 20 or (fps > 30.5 and fps < 59)):
            score += 10
            result["indicators"].append(f"Unusual frame rate ({fps:.1f} fps)")

        # Portrait orientation (more common for phone screen recordings)
        if h > w * 1.3:
            score += 10
            result["indicators"].append("Portrait orientation (common for phone screen recording)")

        result["confidence"] = min(score, 100)
        result["is_screen_recording"] = score >= 40

        if result["is_screen_recording"]:
            result["flags"].append(f"Screen recording detected ({result['confidence']}% confidence)")
            result["flags"].append("This is likely someone recording their phone/app screen, not an original camera capture")

    except Exception as e:
        result["error"] = str(e)
    return result


def forensic_lighting_analysis(file_path):
    """Analyze lighting characteristics: natural vs artificial, brightness over time,
    potential time-of-day estimation."""
    result = {"lighting_type":"unknown","brightness_over_time":[],"color_temp":"unknown",
              "flags":[],"details":{}}
    if not HAS_CV2 or not HAS_NUMPY: return result
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened(): return result
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 30
        samples = min(20, max(total, 1))
        interval = max(total // samples, 1)

        brightnesses = []; color_temps = []; timestamps = []

        for i in range(samples):
            fn = i * interval
            cap.set(cv2.CAP_PROP_POS_FRAMES, fn)
            ret, frame = cap.read()
            if not ret: continue

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            b_avg = float(np.mean(gray))
            brightnesses.append(b_avg)
            timestamps.append(round(fn / fps, 1))

            # Color temperature estimation via blue/red ratio
            b_mean = float(np.mean(frame[:,:,0]))  # Blue
            r_mean = float(np.mean(frame[:,:,2]))  # Red
            if r_mean > 0:
                br_ratio = b_mean / r_mean
                color_temps.append(br_ratio)

        cap.release()

        result["brightness_over_time"] = [{"t": t, "b": round(b, 1)} for t, b in zip(timestamps, brightnesses)]

        if brightnesses:
            avg_b = np.mean(brightnesses)
            std_b = np.std(brightnesses)
            result["details"]["avg_brightness"] = round(avg_b, 1)
            result["details"]["brightness_variance"] = round(std_b, 1)

            if avg_b < 50:
                result["lighting_type"] = "very low light"
                result["flags"].append("Very low light conditions (nighttime or intentionally dark)")
            elif avg_b < 100:
                result["lighting_type"] = "low light"
            elif avg_b < 170:
                result["lighting_type"] = "normal"
            else:
                result["lighting_type"] = "bright"

            if std_b > 30:
                result["flags"].append("Significant brightness variation (lighting changes, movement, or flickering)")

        if color_temps:
            avg_ct = np.mean(color_temps)
            result["details"]["blue_red_ratio"] = round(avg_ct, 3)
            if avg_ct > 1.2:
                result["color_temp"] = "cool/blue (fluorescent or daylight)"
            elif avg_ct < 0.8:
                result["color_temp"] = "warm/orange (incandescent or sunset)"
            else:
                result["color_temp"] = "neutral"

    except Exception as e:
        result["error"] = str(e)
    return result


def forensic_audio_analysis(file_path, evidence_id):
    """Extract and analyze audio track. Requires ffmpeg in PATH."""
    result = {"has_audio":False,"duration":0,"flags":[],"details":{},
              "spectral_features":{},"fingerprint_hash":""}
    if not HAS_FFMPEG: result["flags"].append("ffmpeg not installed, audio analysis unavailable"); return result
    if not HAS_NUMPY: return result

    # Extract audio to temp WAV
    wav_path = os.path.join(FRAMES_DIR, f"audio_{evidence_id}.wav")
    try:
        subprocess.run([
            FFMPEG_PATH, "-i", file_path, "-vn", "-acodec", "pcm_s16le",
            "-ar", "16000", "-ac", "1", "-y", wav_path
        ], capture_output=True, timeout=120)

        if not os.path.exists(wav_path) or os.path.getsize(wav_path) < 100:
            result["flags"].append("No audio track found or audio extraction failed")
            return result

        result["has_audio"] = True

        if HAS_SCIPY:
            sr, audio = scipy_wav.read(wav_path)
            audio = audio.astype(np.float64)
            if audio.max() > 0:
                audio = audio / max(abs(audio.max()), abs(audio.min()))  # Normalize

            result["duration"] = round(len(audio) / sr, 2)
            result["details"]["sample_rate"] = sr
            result["details"]["samples"] = len(audio)

            # Energy profile (detect silence vs activity)
            chunk_size = sr  # 1-second chunks
            energies = []
            for j in range(0, len(audio) - chunk_size, chunk_size):
                chunk = audio[j:j+chunk_size]
                energy = float(np.sqrt(np.mean(chunk**2)))
                energies.append(round(energy, 4))
            result["details"]["energy_profile"] = energies

            # Silence detection
            if energies:
                silence_threshold = 0.01
                silence_chunks = sum(1 for e in energies if e < silence_threshold)
                silence_pct = silence_chunks / len(energies) * 100
                result["details"]["silence_percent"] = round(silence_pct, 1)
                if silence_pct > 80:
                    result["flags"].append(f"Mostly silent ({silence_pct:.0f}% silence)")
                elif silence_pct < 10:
                    result["flags"].append("Continuous audio (possible background noise or speech)")

            # Spectral analysis (simplified)
            if len(audio) > sr:
                # Spectral centroid (brightness of sound)
                fft = np.fft.rfft(audio[:sr*5] if len(audio) > sr*5 else audio)
                magnitude = np.abs(fft)
                freqs = np.fft.rfftfreq(len(audio[:sr*5] if len(audio) > sr*5 else audio), 1/sr)
                if magnitude.sum() > 0:
                    centroid = float(np.sum(freqs * magnitude) / magnitude.sum())
                    result["spectral_features"]["centroid_hz"] = round(centroid, 1)

                    if centroid < 500:
                        result["flags"].append("Low-frequency dominant audio (rumble, machinery, male voice)")
                    elif centroid > 3000:
                        result["flags"].append("High-frequency dominant audio (hissing, high-pitched sounds)")

            # Audio fingerprint hash (simplified: hash of energy profile + spectral shape)
            if energies:
                fp_data = np.array(energies[:60])  # First 60 seconds
                quantized = (fp_data * 1000).astype(int)
                result["fingerprint_hash"] = hashlib.md5(quantized.tobytes()).hexdigest()

    except subprocess.TimeoutExpired:
        result["flags"].append("Audio extraction timed out (file may be very large)")
    except Exception as e:
        result["error"] = str(e)
    finally:
        if os.path.exists(wav_path):
            try: os.remove(wav_path)
            except: pass
    return result


def forensic_enf_analysis(file_path, evidence_id):
    """Extract Electrical Network Frequency (ENF) from audio and video.
    ENF is the power grid frequency (50Hz or 60Hz) embedded in recordings
    through electromagnetic interference. Classifying 50 vs 60Hz narrows
    geographic region: 50Hz = Europe/Asia/Africa, 60Hz = Americas/parts of Asia.
    Court-accepted forensic technique."""
    result = {"detected_freq": 0, "grid_region": "", "confidence": 0,
              "enf_trace": [], "source": "", "flags": [], "details": {}}
    if not HAS_FFMPEG or not HAS_NUMPY or not HAS_SCIPY:
        result["flags"].append("ENF analysis requires ffmpeg, numpy, and scipy")
        return result

    wav_path = os.path.join(FRAMES_DIR, f"enf_{evidence_id}.wav")
    try:
        # Extract audio at high sample rate for ENF detection
        subprocess.run([
            FFMPEG_PATH, "-i", file_path, "-vn", "-acodec", "pcm_s16le",
            "-ar", "8000", "-ac", "1", "-y", wav_path
        ], capture_output=True, timeout=120)

        if not os.path.exists(wav_path) or os.path.getsize(wav_path) < 1000:
            result["flags"].append("No audio track or audio too short for ENF analysis")
            return result

        sr, audio = scipy_wav.read(wav_path)
        audio = audio.astype(np.float64)
        if audio.max() == 0:
            result["flags"].append("Silent audio track -- no ENF signal possible")
            return result
        audio = audio / max(abs(audio.max()), abs(audio.min()))

        duration = len(audio) / sr
        result["details"]["audio_duration"] = round(duration, 2)
        result["details"]["sample_rate"] = sr

        if duration < 2:
            result["flags"].append("Audio too short for reliable ENF analysis (need 2+ seconds)")
            return result

        # ---- ENF Detection via STFT ----
        # We analyze around both 50Hz and 60Hz (and their harmonics)
        # Using Short-Time Fourier Transform for time-varying frequency tracking

        # STFT parameters
        nperseg = min(sr * 2, len(audio))  # 2-second windows
        noverlap = nperseg // 2

        freqs, times, Zxx = scipy_signal.stft(audio, fs=sr, nperseg=nperseg, noverlap=noverlap)
        magnitude = np.abs(Zxx)

        # Find energy around 50Hz and 60Hz bands (with tolerance)
        def band_energy(center_freq, bandwidth=2.0):
            """Get average energy in a frequency band over time."""
            mask = (freqs >= center_freq - bandwidth) & (freqs <= center_freq + bandwidth)
            if not np.any(mask):
                return np.zeros(len(times)), 0
            band_mag = magnitude[mask, :]
            # Find the peak frequency in each time window
            peak_freqs = []
            energies = []
            for t_idx in range(band_mag.shape[1]):
                col = band_mag[:, t_idx]
                if col.max() > 0:
                    peak_idx = np.argmax(col)
                    peak_freq = freqs[mask][peak_idx]
                    peak_freqs.append(float(peak_freq))
                    energies.append(float(col[peak_idx]))
                else:
                    peak_freqs.append(center_freq)
                    energies.append(0)
            return np.array(energies), np.array(peak_freqs)

        # Analyze fundamental and 2nd harmonic for both grid types
        e50, pf50 = band_energy(50.0)
        e60, pf60 = band_energy(60.0)
        e100, pf100 = band_energy(100.0)  # 2nd harmonic of 50Hz
        e120, pf120 = band_energy(120.0)  # 2nd harmonic of 60Hz

        # Combined score: fundamental + harmonic
        score_50 = np.mean(e50) + np.mean(e100) * 0.5
        score_60 = np.mean(e60) + np.mean(e120) * 0.5

        # Noise floor estimate (energy at non-ENF frequencies)
        e_noise1, _ = band_energy(55.0, 1.0)  # Between 50 and 60
        e_noise2, _ = band_energy(45.0, 1.0)
        noise_floor = (np.mean(e_noise1) + np.mean(e_noise2)) / 2

        result["details"]["score_50hz"] = round(float(score_50), 6)
        result["details"]["score_60hz"] = round(float(score_60), 6)
        result["details"]["noise_floor"] = round(float(noise_floor), 6)

        # Signal-to-noise ratio
        snr_50 = score_50 / (noise_floor + 1e-10)
        snr_60 = score_60 / (noise_floor + 1e-10)

        result["details"]["snr_50hz"] = round(float(snr_50), 2)
        result["details"]["snr_60hz"] = round(float(snr_60), 2)

        # Classification
        if snr_50 < 1.5 and snr_60 < 1.5:
            result["flags"].append("No clear ENF signal detected (recording may be battery-powered or outdoors)")
            result["confidence"] = 0
            result["grid_region"] = "indeterminate"
        elif score_50 > score_60 * 1.3:
            result["detected_freq"] = 50.0
            result["grid_region"] = "50Hz grid (Europe, Asia, Africa, Oceania)"
            result["source"] = "audio"
            confidence = min(95, int(snr_50 * 10))
            result["confidence"] = confidence
            if confidence > 60:
                result["flags"].append(f"50Hz ENF detected with {confidence}% confidence -- recording likely from 50Hz power grid region")
            else:
                result["flags"].append(f"Weak 50Hz ENF signal ({confidence}% confidence) -- may be 50Hz grid region")
        elif score_60 > score_50 * 1.3:
            result["detected_freq"] = 60.0
            result["grid_region"] = "60Hz grid (Americas, parts of East Asia, Saudi Arabia)"
            result["source"] = "audio"
            confidence = min(95, int(snr_60 * 10))
            result["confidence"] = confidence
            if confidence > 60:
                result["flags"].append(f"60Hz ENF detected with {confidence}% confidence -- recording likely from 60Hz power grid region")
            else:
                result["flags"].append(f"Weak 60Hz ENF signal ({confidence}% confidence) -- may be 60Hz grid region")
        else:
            result["flags"].append("Both 50Hz and 60Hz signals present -- ambiguous (could be mixed environment or broadband noise)")
            result["grid_region"] = "ambiguous"
            result["confidence"] = max(0, int(max(snr_50, snr_60) * 5))

        # Build ENF trace over time for visualization
        if result["detected_freq"] == 50.0:
            trace_freqs = pf50
        elif result["detected_freq"] == 60.0:
            trace_freqs = pf60
        else:
            trace_freqs = pf50 if score_50 > score_60 else pf60

        if isinstance(trace_freqs, np.ndarray) and len(trace_freqs) > 0:
            enf_trace = []
            for i, t in enumerate(times):
                if i < len(trace_freqs):
                    enf_trace.append({
                        "t": round(float(t), 2),
                        "freq": round(float(trace_freqs[i]), 3)
                    })
            result["enf_trace"] = enf_trace

        # ---- Video luminance ENF (supplementary) ----
        # Indoor lighting under AC power flickers at the ENF frequency
        # This is harder to detect but provides corroboration
        if HAS_CV2:
            try:
                cap = cv2.VideoCapture(file_path)
                if cap.isOpened():
                    fps = cap.get(cv2.CAP_PROP_FPS)
                    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                    if fps >= 50 and total > fps * 2:  # Need high fps and 2+ seconds
                        # Sample luminance from superpixel grid
                        lum_values = []
                        max_frames = min(total, int(fps * 10))  # Max 10 seconds
                        for fi in range(max_frames):
                            ret, frame = cap.read()
                            if not ret: break
                            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                            lum_values.append(float(np.mean(gray)))
                        cap.release()

                        if len(lum_values) > fps:
                            lum = np.array(lum_values) - np.mean(lum_values)
                            # FFT of luminance
                            lum_fft = np.abs(np.fft.rfft(lum))
                            lum_freqs = np.fft.rfftfreq(len(lum), 1/fps)

                            # Check for peaks at 50 and 60 Hz
                            mask_50 = (lum_freqs >= 48) & (lum_freqs <= 52)
                            mask_60 = (lum_freqs >= 58) & (lum_freqs <= 62)
                            lum_50 = np.max(lum_fft[mask_50]) if np.any(mask_50) else 0
                            lum_60 = np.max(lum_fft[mask_60]) if np.any(mask_60) else 0

                            result["details"]["video_lum_50hz"] = round(float(lum_50), 4)
                            result["details"]["video_lum_60hz"] = round(float(lum_60), 4)

                            if lum_50 > lum_60 * 1.5 and lum_50 > np.median(lum_fft) * 3:
                                result["flags"].append("Video luminance also shows 50Hz flicker (corroborates audio ENF)")
                                result["source"] = "audio+video"
                                result["confidence"] = min(98, result["confidence"] + 15)
                            elif lum_60 > lum_50 * 1.5 and lum_60 > np.median(lum_fft) * 3:
                                result["flags"].append("Video luminance also shows 60Hz flicker (corroborates audio ENF)")
                                result["source"] = "audio+video"
                                result["confidence"] = min(98, result["confidence"] + 15)
                    else:
                        cap.release()
                        if fps < 50:
                            result["details"]["video_enf_note"] = f"Video fps ({fps:.1f}) too low for luminance ENF (need 50+)"
            except Exception as ve:
                result["details"]["video_enf_error"] = str(ve)

    except subprocess.TimeoutExpired:
        result["flags"].append("Audio extraction timed out")
    except Exception as e:
        result["error"] = str(e)
    finally:
        if os.path.exists(wav_path):
            try: os.remove(wav_path)
            except: pass
    return result


def forensic_run_all(file_path, evidence_id, media_type):
    """Run all applicable forensic analyses on a file."""
    results = {}
    if media_type == "video":
        results["scene"] = forensic_scene_analysis(file_path, evidence_id)
        results["watermark"] = forensic_watermark_detection(file_path)
        results["encoding"] = forensic_encoding_analysis(file_path, evidence_id)
        results["screen_recording"] = forensic_screen_recording_detection(file_path)
        results["lighting"] = forensic_lighting_analysis(file_path)
        results["audio"] = forensic_audio_analysis(file_path, evidence_id)
        results["enf"] = forensic_enf_analysis(file_path, evidence_id)
    elif media_type == "image":
        results["scene"] = forensic_scene_analysis(file_path, evidence_id)
        results["lighting"] = forensic_lighting_analysis(file_path)
    return results


# --- Routes ---
@app.route("/")
def index():
    ui=os.path.join(BASE_DIR,"palimpsest_ui.html")
    return send_file(ui) if os.path.exists(ui) else ("<h1>Palimpsest</h1><p>UI not found</p>",404)

@app.route("/thumbnails/<path:fn>")
def serve_thumb(fn): return send_from_directory(THUMB_DIR,fn)
@app.route("/uploads/<path:fn>")
def serve_upload(fn): return send_from_directory(UPLOAD_DIR,fn)
@app.route("/frames/<path:fn>")
def serve_frame(fn): return send_from_directory(FRAMES_DIR,fn)
@app.route("/previews/<path:fn>")
def serve_preview(fn): return send_from_directory(PREVIEW_DIR,fn)
@app.route("/exports/<path:fn>")
def serve_export(fn): return send_from_directory(EXPORT_DIR,fn)
@app.route("/favicon.ico")
def serve_favicon(): return send_from_directory(BASE_DIR,"palimpsest_icon.ico",mimetype="image/x-icon")
@app.route("/icon.ico")
def serve_icon(): return send_from_directory(BASE_DIR,"palimpsest_icon.ico",mimetype="image/x-icon")

@app.route("/api/dashboard")
def api_dashboard():
    with get_db() as c:
        ev=c.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        sus=c.execute("SELECT COUNT(*) FROM suspects").fetchone()[0]
        gps=c.execute("SELECT COUNT(*) FROM evidence WHERE has_gps=1").fetchone()[0]
        stripped=c.execute("SELECT COUNT(*) FROM evidence WHERE stripping_detected=1").fetchone()[0]
        imgs=c.execute("SELECT COUNT(*) FROM evidence WHERE media_type='image'").fetchone()[0]
        vids=c.execute("SELECT COUNT(*) FROM evidence WHERE media_type='video'").fetchone()[0]
        sz=c.execute("SELECT COALESCE(SUM(file_size),0) FROM evidence").fetchone()[0]
        dur=c.execute("SELECT COALESCE(SUM(duration),0) FROM evidence WHERE media_type='video'").fetchone()[0]
        recent=[dict(r) for r in c.execute("SELECT id,file_name,media_type,added_at,suspect_id,duration FROM evidence ORDER BY added_at DESC LIMIT 10").fetchall()]
        cams=[dict(r) for r in c.execute("SELECT camera_make||' '||camera_model as camera,COUNT(*) as count FROM evidence WHERE camera_make!='' GROUP BY camera ORDER BY count DESC LIMIT 10").fetchall()]
        codecs=[dict(r) for r in c.execute("SELECT codec,COUNT(*) as count FROM evidence WHERE codec!='' GROUP BY codec ORDER BY count DESC LIMIT 10").fetchall()]
    return jsonify({"evidence_count":ev,"suspect_count":sus,"gps_count":gps,"stripped_count":stripped,
        "image_count":imgs,"video_count":vids,"total_size":sz,"total_duration":dur,
        "recent":recent,"cameras":cams,"codecs":codecs})

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" not in request.files: return jsonify({"error":"No file"}),400
    f=request.files["file"]
    if not f.filename: return jsonify({"error":"Empty filename"}),400
    suspect_id=request.form.get("suspect_id") or None
    if suspect_id: suspect_id=int(suspect_id)
    tags=request.form.get("tags",""); notes=request.form.get("notes","")
    safe=re.sub(r'[^\w\-_\. ]','_',f.filename)
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    sn=f"{ts}_{safe}"; sp=os.path.join(UPLOAD_DIR,sn)
    # Stream save + hash in one pass (no double-read for large files)
    md5_hex, sha_hex = save_and_hash(f.stream, sp)
    fsz=os.path.getsize(sp); mt=classify_file(f.filename)
    if mt=="video":
        phashes = perceptual_hash_video(sp)
        hashes = {"md5":md5_hex,"sha256":sha_hex,**phashes}
    elif mt=="image":
        hashes = compute_hashes(sp)
        hashes["md5"]=md5_hex; hashes["sha256"]=sha_hex
    else:
        hashes = {"md5":md5_hex,"sha256":sha_hex,"phash":"","dhash":"","whash":"","ahash":""}
    meta=extract_image_metadata(sp) if mt=="image" else (extract_video_metadata(sp) if mt=="video" else {})
    now=datetime.now().isoformat(); gps=meta.get("gps")
    with get_db() as c:
        cur=c.execute("""INSERT INTO evidence (file_path,file_name,file_size,media_type,mime_type,
            width,height,duration,fps,codec,bitrate,frame_count,audio_codec,audio_channels,audio_sample_rate,
            md5,sha256,phash,dhash,whash,ahash,has_exif,has_gps,gps_lat,gps_lon,gps_alt,
            camera_make,camera_model,software,original_date,modify_date,creation_date,
            metadata_json,stripping_detected,stripping_indicators,suspect_id,tags,notes,added_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sn,f.filename,fsz,mt,f.content_type or "",
             meta.get("dimensions",{}).get("width",0),meta.get("dimensions",{}).get("height",0),
             meta.get("duration",0),meta.get("fps",0),meta.get("codec",""),
             meta.get("bitrate",0),meta.get("frame_count",0),
             meta.get("audio",{}).get("codec",""),meta.get("audio",{}).get("channels",0),
             meta.get("audio",{}).get("sample_rate",0),
             hashes["md5"],hashes["sha256"],hashes["phash"],hashes["dhash"],hashes["whash"],hashes["ahash"],
             1 if meta.get("has_exif") else 0, 1 if gps else 0,
             gps["lat"] if gps else None, gps["lon"] if gps else None, gps["alt"] if gps else None,
             meta.get("camera",{}).get("make",""),meta.get("camera",{}).get("model",""),
             meta.get("camera",{}).get("software",""),
             meta.get("dates",{}).get("original",""),meta.get("dates",{}).get("modified",""),
             meta.get("dates",{}).get("creation",""),
             json.dumps(meta.get("raw",{})),
             1 if meta.get("stripping",{}).get("detected") else 0,
             json.dumps(meta.get("stripping",{}).get("indicators",[])),
             suspect_id,tags,notes,now))
        eid=cur.lastrowid
    generate_thumbnail(sp,eid,mt)
    if mt=="video":
        # Heavy work in background so the response returns immediately
        def _background_video_work(file_path, evidence_id):
            with BG_SEMAPHORE:
                try:
                    frames=extract_frames(file_path, evidence_id, count=8)
                    if frames:
                        with get_db() as c:
                            for fr in frames: c.execute("INSERT INTO extracted_frames (evidence_id,frame_number,timestamp_sec,file_path,phash) VALUES (?,?,?,?,?)",(evidence_id,fr["frame_number"],fr["timestamp_sec"],fr["file_path"],fr["phash"]))
                            c.execute("UPDATE evidence SET frames_extracted=? WHERE id=?",(len(frames),evidence_id))
                    generate_preview(file_path, evidence_id)
                except Exception as e:
                    print(f"[!] Background video processing error for {evidence_id}: {e}")
        threading.Thread(target=_background_video_work, args=(sp,eid), daemon=True).start()
    return jsonify({"id":eid,"file_name":f.filename,"media_type":mt,"file_size":fsz,"hashes":hashes,"metadata":meta})

@app.route("/api/analyze/batch", methods=["POST"])
def api_analyze_batch():
    files=request.files.getlist("files")
    if not files: return jsonify({"error":"No files"}),400
    sid=request.form.get("suspect_id") or None
    if sid: sid=int(sid)
    results=[]
    for f in files:
        if not f.filename: continue
        safe=re.sub(r'[^\w\-_\. ]','_',f.filename)
        ts=datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        sn=f"{ts}_{safe}"; sp=os.path.join(UPLOAD_DIR,sn)
        md5_hex, sha_hex = save_and_hash(f.stream, sp)
        fsz=os.path.getsize(sp); mt=classify_file(f.filename)
        if mt=="video":
            phashes = perceptual_hash_video(sp)
            hashes = {"md5":md5_hex,"sha256":sha_hex,**phashes}
        elif mt=="image":
            hashes = compute_hashes(sp)
            hashes["md5"]=md5_hex; hashes["sha256"]=sha_hex
        else:
            hashes = {"md5":md5_hex,"sha256":sha_hex,"phash":"","dhash":"","whash":"","ahash":""}
        meta=extract_image_metadata(sp) if mt=="image" else (extract_video_metadata(sp) if mt=="video" else {})
        now=datetime.now().isoformat(); gps=meta.get("gps")
        with get_db() as c:
            cur=c.execute("""INSERT INTO evidence (file_path,file_name,file_size,media_type,mime_type,
                width,height,duration,fps,codec,bitrate,frame_count,audio_codec,audio_channels,audio_sample_rate,
                md5,sha256,phash,dhash,whash,ahash,has_exif,has_gps,gps_lat,gps_lon,gps_alt,
                camera_make,camera_model,software,original_date,modify_date,creation_date,
                metadata_json,stripping_detected,stripping_indicators,suspect_id,added_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sn,f.filename,fsz,mt,f.content_type or "",
                 meta.get("dimensions",{}).get("width",0),meta.get("dimensions",{}).get("height",0),
                 meta.get("duration",0),meta.get("fps",0),meta.get("codec",""),
                 meta.get("bitrate",0),meta.get("frame_count",0),
                 meta.get("audio",{}).get("codec",""),meta.get("audio",{}).get("channels",0),
                 meta.get("audio",{}).get("sample_rate",0),
                 hashes["md5"],hashes["sha256"],hashes["phash"],hashes["dhash"],hashes["whash"],hashes["ahash"],
                 1 if meta.get("has_exif") else 0, 1 if gps else 0,
                 gps["lat"] if gps else None, gps["lon"] if gps else None, gps["alt"] if gps else None,
                 meta.get("camera",{}).get("make",""),meta.get("camera",{}).get("model",""),
                 meta.get("camera",{}).get("software",""),
                 meta.get("dates",{}).get("original",""),meta.get("dates",{}).get("modified",""),
                 meta.get("dates",{}).get("creation",""),
                 json.dumps(meta.get("raw",{})),
                 1 if meta.get("stripping",{}).get("detected") else 0,
                 json.dumps(meta.get("stripping",{}).get("indicators",[])),
                 sid,now))
            eid=cur.lastrowid
        generate_thumbnail(sp,eid,mt)
        if mt=="video":
            _sp,_eid=sp,eid  # capture for closure
            def _bg_batch(fp,evid):
                with BG_SEMAPHORE:
                    try:
                        frames=extract_frames(fp,evid,count=8)
                        if frames:
                            with get_db() as c:
                                for fr in frames: c.execute("INSERT INTO extracted_frames (evidence_id,frame_number,timestamp_sec,file_path,phash) VALUES (?,?,?,?,?)",(evid,fr["frame_number"],fr["timestamp_sec"],fr["file_path"],fr["phash"]))
                                c.execute("UPDATE evidence SET frames_extracted=? WHERE id=?",(len(frames),evid))
                        generate_preview(fp, evid)
                    except Exception as e:
                        print(f"[!] Background batch processing error for {evid}: {e}")
            threading.Thread(target=_bg_batch, args=(_sp,_eid), daemon=True).start()
        results.append({"id":eid,"file_name":f.filename,"media_type":mt,"duration":meta.get("duration",0),"stripping_detected":meta.get("stripping",{}).get("detected",False)})
    return jsonify({"results":results,"count":len(results)})

@app.route("/api/evidence")
def api_evidence_list():
    with get_db() as c:
        page=int(request.args.get("page",1)); pp=int(request.args.get("per_page",50))
        w=[]; p=[]
        if request.args.get("suspect_id"): w.append("suspect_id=?"); p.append(int(request.args["suspect_id"]))
        if request.args.get("media_type"): w.append("media_type=?"); p.append(request.args["media_type"])
        if request.args.get("has_gps")=="1": w.append("has_gps=1")
        if request.args.get("stripped")=="1": w.append("stripping_detected=1")
        q=request.args.get("q","")
        if q: w.append("(file_name LIKE ? OR tags LIKE ? OR notes LIKE ?)"); p.extend([f"%{q}%"]*3)
        ws=(" WHERE "+" AND ".join(w)) if w else ""
        total=c.execute(f"SELECT COUNT(*) FROM evidence{ws}",p).fetchone()[0]
        rows=[dict(r) for r in c.execute(f"SELECT * FROM evidence{ws} ORDER BY added_at DESC LIMIT ? OFFSET ?",p+[pp,(page-1)*pp]).fetchall()]
    return jsonify({"items":rows,"total":total,"page":page,"per_page":pp})

@app.route("/api/evidence/<int:eid>")
def api_evidence_detail(eid):
    with get_db() as c:
        r=c.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone()
        if not r: return jsonify({"error":"Not found"}),404
        d=dict(r); d["metadata_json"]=json.loads(d.get("metadata_json","{}")); d["stripping_indicators"]=json.loads(d.get("stripping_indicators","[]"))
        d["frames"]=[dict(f) for f in c.execute("SELECT * FROM extracted_frames WHERE evidence_id=? ORDER BY frame_number",(eid,)).fetchall()]
        return jsonify(d)

@app.route("/api/evidence/<int:eid>", methods=["PUT"])
def api_evidence_update(eid):
    data=request.json; sets=[]; params=[]
    for f in ("suspect_id","tags","notes"):
        if f in data: sets.append(f"{f}=?"); params.append(data[f])
    if sets: params.append(eid); 
    with get_db() as c: c.execute(f"UPDATE evidence SET {','.join(sets)} WHERE id=?",params)
    return jsonify({"ok":True})

@app.route("/api/evidence/<int:eid>", methods=["DELETE"])
def api_evidence_delete(eid):
    with get_db() as c:
        r=c.execute("SELECT file_path FROM evidence WHERE id=?",(eid,)).fetchone()
        if r:
            fp=os.path.join(UPLOAD_DIR,r["file_path"])
            if os.path.exists(fp): os.remove(fp)
            tp=os.path.join(THUMB_DIR,f"{eid}.jpg")
            if os.path.exists(tp): os.remove(tp)
            fd=os.path.join(FRAMES_DIR,str(eid))
            if os.path.isdir(fd): import shutil; shutil.rmtree(fd,ignore_errors=True)
            pp=os.path.join(PREVIEW_DIR,f"{eid}.mp4")
            if os.path.exists(pp): os.remove(pp)
            c.execute("DELETE FROM extracted_frames WHERE evidence_id=?",(eid,))
            c.execute("DELETE FROM evidence WHERE id=?",(eid,))
    return jsonify({"ok":True})

@app.route("/api/suspects", methods=["GET","POST"])
def api_suspects():
    if request.method=="GET":
        with get_db() as c:
            rows=[dict(r) for r in c.execute("SELECT s.*,COUNT(e.id) as evidence_count FROM suspects s LEFT JOIN evidence e ON e.suspect_id=s.id GROUP BY s.id ORDER BY s.created_at DESC").fetchall()]
            for row in rows: row["identifiers"]=[dict(i) for i in c.execute("SELECT * FROM suspect_identifiers WHERE suspect_id=?",(row["id"],)).fetchall()]
        return jsonify(rows)
    data=request.json; now=datetime.now().isoformat()
    with get_db() as c:
        cur=c.execute("INSERT INTO suspects (name,aliases,platform,notes,threat_level,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (data.get("name",""),data.get("aliases",""),data.get("platform",""),data.get("notes",""),data.get("threat_level","unknown"),data.get("status","active"),now,now))
        sid=cur.lastrowid
        for ident in data.get("identifiers",[]): c.execute("INSERT INTO suspect_identifiers (suspect_id,id_type,id_value) VALUES (?,?,?)",(sid,ident.get("type",""),ident.get("value","")))
    return jsonify({"id":sid})

@app.route("/api/suspects/<int:sid>", methods=["GET","PUT","DELETE"])
def api_suspect_detail(sid):
    if request.method=="GET":
        with get_db() as c:
            r=c.execute("SELECT * FROM suspects WHERE id=?",(sid,)).fetchone()
            if not r: return jsonify({"error":"Not found"}),404
            d=dict(r)
            d["identifiers"]=[dict(i) for i in c.execute("SELECT * FROM suspect_identifiers WHERE suspect_id=?",(sid,)).fetchall()]
            d["evidence"]=[dict(e) for e in c.execute("SELECT id,file_name,media_type,added_at,has_gps,stripping_detected,duration FROM evidence WHERE suspect_id=? ORDER BY added_at DESC",(sid,)).fetchall()]
        return jsonify(d)
    if request.method=="PUT":
        data=request.json; now=datetime.now().isoformat()
        with get_db() as c:
            c.execute("UPDATE suspects SET name=?,aliases=?,platform=?,notes=?,threat_level=?,status=?,updated_at=? WHERE id=?",
                (data.get("name",""),data.get("aliases",""),data.get("platform",""),data.get("notes",""),data.get("threat_level","unknown"),data.get("status","active"),now,sid))
            c.execute("DELETE FROM suspect_identifiers WHERE suspect_id=?",(sid,))
            for ident in data.get("identifiers",[]): c.execute("INSERT INTO suspect_identifiers (suspect_id,id_type,id_value) VALUES (?,?,?)",(sid,ident.get("type",""),ident.get("value","")))
        return jsonify({"ok":True})
    if request.method=="DELETE":
        with get_db() as c:
            c.execute("UPDATE evidence SET suspect_id=NULL WHERE suspect_id=?",(sid,))
            c.execute("DELETE FROM suspects WHERE id=?",(sid,))
        return jsonify({"ok":True})

@app.route("/api/gps")
def api_gps_data():
    with get_db() as c: return jsonify([dict(r) for r in c.execute("SELECT id,file_name,gps_lat,gps_lon,gps_alt,camera_make,camera_model,original_date,suspect_id FROM evidence WHERE has_gps=1").fetchall()])

@app.route("/api/compare", methods=["POST"])
def api_compare():
    data=request.json; id_a=data.get("id_a"); id_b=data.get("id_b")
    if not id_a or not id_b: return jsonify({"error":"Need id_a and id_b"}),400
    with get_db() as c:
        a=dict(c.execute("SELECT * FROM evidence WHERE id=?",(id_a,)).fetchone())
        b=dict(c.execute("SELECT * FROM evidence WHERE id=?",(id_b,)).fetchone())
    hsim=0
    if HAS_IMAGEHASH and a.get("phash") and b.get("phash"):
        try: hsim=max(0,100-(imagehash.hex_to_hash(a["phash"])-imagehash.hex_to_hash(b["phash"]))*100/64)
        except: pass
    same_cam=a.get("camera_make")==b.get("camera_make") and a.get("camera_model")==b.get("camera_model") and a.get("camera_make","")!=""
    same_loc=False
    if a.get("has_gps") and b.get("has_gps"): same_loc=abs((a.get("gps_lat")or 0)-(b.get("gps_lat")or 0))<0.001 and abs((a.get("gps_lon")or 0)-(b.get("gps_lon")or 0))<0.001
    same_dt=a.get("original_date")==b.get("original_date") and a.get("original_date","")!=""
    same_codec=a.get("codec")==b.get("codec") and a.get("codec","")!=""
    same_res=a.get("width")==b.get("width") and a.get("height")==b.get("height") and a.get("width",0)>0
    now=datetime.now().isoformat()
    with get_db() as c: c.execute("INSERT INTO comparisons (evidence_id_a,evidence_id_b,hash_similarity,same_camera,same_location,same_date,created_at) VALUES (?,?,?,?,?,?,?)",(id_a,id_b,hsim,int(same_cam),int(same_loc),int(same_dt),now))
    return jsonify({"a":a,"b":b,"hash_similarity":round(hsim,1),"same_camera":same_cam,"same_location":same_loc,"same_date":same_dt,"same_codec":same_codec,"same_resolution":same_res,"hash_match":a.get("sha256")==b.get("sha256") and a.get("sha256","")!=""})

@app.route("/api/duplicates")
def api_duplicates():
    with get_db() as c:
        exact=[dict(r) for r in c.execute("SELECT sha256,COUNT(*) as count,GROUP_CONCAT(id) as ids,GROUP_CONCAT(file_name,' | ') as names FROM evidence WHERE sha256!='' GROUP BY sha256 HAVING count>1").fetchall()]
        all_h=c.execute("SELECT id,file_name,phash FROM evidence WHERE phash!=''").fetchall()
    near=[]
    if HAS_IMAGEHASH:
        items=[(r["id"],r["file_name"],r["phash"]) for r in all_h]; seen=set()
        for i,(ia,na,ha) in enumerate(items):
            for j,(ib,nb,hb) in enumerate(items[i+1:],i+1):
                key=(min(ia,ib),max(ia,ib))
                if key in seen: continue
                try:
                    d=imagehash.hex_to_hash(ha)-imagehash.hex_to_hash(hb)
                    if 0<d<=10: near.append({"id_a":ia,"name_a":na,"id_b":ib,"name_b":nb,"similarity":round(max(0,100-d*100/64),1),"distance":d}); seen.add(key)
                except: pass
    return jsonify({"exact":exact,"near":near})

@app.route("/api/export/json")
def export_json():
    sid=request.args.get("suspect_id")
    with get_db() as c:
        if sid: ev=[dict(r) for r in c.execute("SELECT * FROM evidence WHERE suspect_id=?",(int(sid),)).fetchall()]; sus=dict(c.execute("SELECT * FROM suspects WHERE id=?",(int(sid),)).fetchone())
        else: ev=[dict(r) for r in c.execute("SELECT * FROM evidence").fetchall()]; sus=None
    for e in ev: e["metadata_json"]=json.loads(e.get("metadata_json","{}")); e["stripping_indicators"]=json.loads(e.get("stripping_indicators","[]"))
    payload={"exported_at":datetime.now().isoformat(),"tool":"Palimpsest v4.0","suspect":sus,"evidence_count":len(ev),"evidence":ev}
    fn=f"palimpsest_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"; fp=os.path.join(EXPORT_DIR,fn)
    with open(fp,"w") as f: json.dump(payload,f,indent=2,default=str)
    return send_file(fp,as_attachment=True,download_name=fn)

@app.route("/api/export/pdf")
def export_pdf():
    if not HAS_REPORTLAB: return jsonify({"error":"reportlab not installed"}),500
    sid=request.args.get("suspect_id")
    with get_db() as c:
        if sid: ev=[dict(r) for r in c.execute("SELECT * FROM evidence WHERE suspect_id=? ORDER BY added_at",(int(sid),)).fetchall()]; sus=dict(c.execute("SELECT * FROM suspects WHERE id=?",(int(sid),)).fetchone())
        else: ev=[dict(r) for r in c.execute("SELECT * FROM evidence ORDER BY added_at").fetchall()]; sus=None
    fn=f"palimpsest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"; fp=os.path.join(EXPORT_DIR,fn)
    doc=SimpleDocTemplate(fp,pagesize=letter); styles=getSampleStyleSheet(); story=[]
    story.append(Paragraph("Palimpsest Evidence Report",ParagraphStyle('T',parent=styles['Title'],fontSize=24,spaceAfter=20)))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",styles['Normal']))
    story.append(Spacer(1,20))
    if sus:
        story.append(Paragraph(f"<b>Suspect:</b> {sus['name']}",styles['Heading2']))
        if sus.get("aliases"): story.append(Paragraph(f"<b>Aliases:</b> {sus['aliases']}",styles['Normal']))
        story.append(Spacer(1,12))
    story.append(Paragraph(f"<b>Total Evidence:</b> {len(ev)}",styles['Normal'])); story.append(Spacer(1,20))
    for i,e in enumerate(ev):
        story.append(Paragraph(f"Evidence #{i+1}: {e['file_name']}",styles['Heading3']))
        dur_str=""
        if e.get("duration"): m=int(e["duration"]//60); s=e["duration"]%60; dur_str=f"{m}:{s:05.2f}"
        data=[["Field","Value"],["Type",e.get("media_type","")],["Dimensions",f"{e.get('width',0)}x{e.get('height',0)}"],
              ["Duration",dur_str or "N/A"],["Codec",e.get("codec","") or "N/A"],
              ["SHA-256",e.get("sha256","")[:32]+"..."],["MD5",e.get("md5","")],
              ["Camera",f"{e.get('camera_make','')} {e.get('camera_model','')}".strip() or "N/A"],
              ["Date",e.get("original_date","") or e.get("creation_date","") or "N/A"],
              ["GPS",f"{e.get('gps_lat','N/A')}, {e.get('gps_lon','N/A')}" if e.get("has_gps") else "None"],
              ["Stripping","YES" if e.get("stripping_detected") else "No"]]
        t=Table(data,colWidths=[1.8*inch,4.2*inch])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor("#1c1f2e")),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('FONTSIZE',(0,0),(-1,-1),9),('GRID',(0,0),(-1,-1),0.5,colors.HexColor("#2a2e42")),
            ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#0f1117")),('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor("#e2e4ea"))]))
        story.append(t); story.append(Spacer(1,16))
    doc.build(story)
    return send_file(fp,as_attachment=True,download_name=fn)

def _get_export_data(suspect_id=None):
    """Helper: fetch evidence and optional suspect for export."""
    with get_db() as c:
        if suspect_id:
            ev=[dict(r) for r in c.execute("SELECT * FROM evidence WHERE suspect_id=? ORDER BY added_at",(int(suspect_id),)).fetchall()]
            sus=dict(c.execute("SELECT * FROM suspects WHERE id=?",(int(suspect_id),)).fetchone())
        else:
            ev=[dict(r) for r in c.execute("SELECT * FROM evidence ORDER BY added_at").fetchall()]
            sus=None
    for e in ev:
        e["metadata_json"]=json.loads(e.get("metadata_json","{}"))
        e["stripping_indicators"]=json.loads(e.get("stripping_indicators","[]"))
    return ev, sus

def _fmt_dur(s):
    if not s: return ""
    m=int(s//60); sec=int(s%60)
    return f"{m}:{sec:02d}"

@app.route("/api/export/csv")
def export_csv():
    sid=request.args.get("suspect_id")
    ev, sus = _get_export_data(sid)
    import csv as csvmod
    fn=f"palimpsest_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    fp=os.path.join(EXPORT_DIR,fn)
    fields=["id","file_name","media_type","file_size","width","height","duration","fps","codec",
            "md5","sha256","phash","dhash","camera_make","camera_model","software",
            "original_date","modify_date","creation_date",
            "has_gps","gps_lat","gps_lon","has_exif","stripping_detected","tags","notes","added_at"]
    with open(fp,"w",newline="",encoding="utf-8") as f:
        writer=csvmod.writer(f)
        writer.writerow(fields)
        for e in ev:
            writer.writerow([e.get(k,"") for k in fields])
    return send_file(fp,as_attachment=True,download_name=fn)

@app.route("/api/export/html")
def export_html_report():
    sid=request.args.get("suspect_id")
    ev, sus = _get_export_data(sid)
    fn=f"palimpsest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    fp=os.path.join(EXPORT_DIR,fn)
    html="""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Palimpsest Evidence Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0b10;color:#e2e4ea;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;padding:40px}
h1{font-size:28px;margin-bottom:4px}
h2{font-size:20px;margin:24px 0 12px;color:#4f8ff7}
h3{font-size:16px;margin:16px 0 8px}
.meta{color:#8b8fa3;font-size:13px;margin-bottom:20px}
.quote{border-left:3px solid #4f8ff7;padding:12px 20px;margin:20px 0;font-style:italic;color:#8b8fa3}
.quote .attr{font-style:normal;font-size:12px;margin-top:8px;font-family:monospace}
table{width:100%;border-collapse:collapse;margin:12px 0}
th{text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#5c6078;border-bottom:1px solid #2a2e42;background:#161822}
td{padding:8px 12px;border-bottom:1px solid #1c1f2e;font-size:13px}
tr:hover td{background:#1c1f2e}
.warn{color:#f87171;font-weight:600}
.ok{color:#34d399}
.hash{font-family:monospace;font-size:11px;word-break:break-all;color:#8b8fa3}
.card{background:#161822;border:1px solid #2a2e42;border-radius:8px;padding:16px;margin:12px 0}
.suspect-name{font-size:18px;font-weight:600;color:#4f8ff7}
a{color:#4f8ff7}
</style></head><body>
<h1>Palimpsest Evidence Report</h1>
<div class="meta">Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """ | Tool: Palimpsest v4.0 | ephemeradev.net</div>
<div class="quote">"Sorrow be damned and all your plans. Fuck the faithful, fuck the committed, the dedicated, the true believers; fuck all the sure and certain people prepared to maim and kill whoever got in their way; fuck every cause that ended in murder and a child screaming."<div class="attr">Iain Banks, Against a Dark Background</div></div>
"""
    if sus:
        html+=f'<div class="card"><div class="suspect-name">{sus["name"]}</div>'
        if sus.get("aliases"): html+=f'<div class="meta">Aliases: {sus["aliases"]}</div>'
        if sus.get("platform"): html+=f'<div class="meta">Platform: {sus["platform"]}</div>'
        if sus.get("notes"): html+=f'<p style="font-size:13px;margin-top:8px">{sus["notes"]}</p>'
        html+='</div>'
    html+=f'<h2>Evidence ({len(ev)} items)</h2>'
    html+='<table><thead><tr><th>#</th><th>File</th><th>Type</th><th>Size</th><th>Duration</th><th>Codec</th><th>Camera</th><th>Date</th><th>GPS</th><th>Stripped</th><th>SHA-256</th></tr></thead><tbody>'
    for i,e in enumerate(ev):
        cam=(e.get("camera_make","")+" "+e.get("camera_model","")).strip() or ""
        dt=e.get("original_date","") or e.get("creation_date","") or ""
        gps_str=f'{e.get("gps_lat",0):.4f}, {e.get("gps_lon",0):.4f}' if e.get("has_gps") else ""
        strip_cls="warn" if e.get("stripping_detected") else "ok"
        strip_txt="YES" if e.get("stripping_detected") else "No"
        sz=e.get("file_size",0)
        sz_str=f"{sz/1048576:.1f} MB" if sz>1048576 else f"{sz/1024:.0f} KB"
        html+=f'<tr><td>{i+1}</td><td>{e["file_name"]}</td><td>{e.get("media_type","")}</td><td>{sz_str}</td><td>{_fmt_dur(e.get("duration",0))}</td><td>{e.get("codec","")}</td><td>{cam}</td><td>{dt}</td><td>{gps_str}</td><td class="{strip_cls}">{strip_txt}</td><td class="hash">{e.get("sha256","")[:24]}...</td></tr>'
    html+='</tbody></table>'
    # Detail cards
    for i,e in enumerate(ev):
        html+=f'<div class="card"><h3>#{i+1}: {e["file_name"]}</h3>'
        html+=f'<div class="meta">{e.get("media_type","")} | {e.get("width",0)}x{e.get("height",0)}'
        if e.get("duration"): html+=f' | {_fmt_dur(e["duration"])}'
        if e.get("codec"): html+=f' | {e["codec"]}'
        html+='</div>'
        html+=f'<div class="hash">MD5: {e.get("md5","")}</div>'
        html+=f'<div class="hash">SHA-256: {e.get("sha256","")}</div>'
        if e.get("phash"): html+=f'<div class="hash">pHash: {e.get("phash","")}</div>'
        cam=(e.get("camera_make","")+" "+e.get("camera_model","")).strip()
        if cam: html+=f'<div>Camera: {cam}</div>'
        dt=e.get("original_date","") or e.get("creation_date","")
        if dt: html+=f'<div>Date: {dt}</div>'
        if e.get("has_gps"): html+=f'<div>GPS: {e.get("gps_lat",0):.6f}, {e.get("gps_lon",0):.6f} (<a href="https://www.google.com/maps?q={e.get("gps_lat",0)},{e.get("gps_lon",0)}" target="_blank">map</a>)</div>'
        if e.get("stripping_detected"):
            html+='<div class="warn">Metadata stripping detected:</div>'
            for ind in e.get("stripping_indicators",[]):
                html+=f'<div style="font-size:12px;color:#f87171;margin-left:12px">- {ind}</div>'
        if e.get("notes"): html+=f'<div style="margin-top:8px;font-size:13px">Notes: {e["notes"]}</div>'
        html+='</div>'
    html+='<div class="meta" style="margin-top:40px;text-align:center">Generated by Palimpsest v4.0 | <a href="https://ephemeradev.net">ephemeradev.net</a> | <a href="https://github.com/ephemera02">github.com/ephemera02</a></div>'
    html+='</body></html>'
    with open(fp,"w",encoding="utf-8") as f: f.write(html)
    return send_file(fp,as_attachment=True,download_name=fn)

@app.route("/api/export/markdown")
def export_markdown():
    sid=request.args.get("suspect_id")
    ev, sus = _get_export_data(sid)
    fn=f"palimpsest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    fp=os.path.join(EXPORT_DIR,fn)
    md=f"# Palimpsest Evidence Report\n\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    if sus:
        md+=f"## Suspect: {sus['name']}\n\n"
        if sus.get("aliases"): md+=f"Aliases: {sus['aliases']}\n\n"
        if sus.get("platform"): md+=f"Platform: {sus['platform']}\n\n"
        if sus.get("notes"): md+=f"{sus['notes']}\n\n"
    md+=f"## Evidence ({len(ev)} items)\n\n"
    md+="| # | File | Type | Duration | Codec | Camera | Date | GPS | Stripped | SHA-256 |\n"
    md+="|---|------|------|----------|-------|--------|------|-----|----------|--------|\n"
    for i,e in enumerate(ev):
        cam=(e.get("camera_make","")+" "+e.get("camera_model","")).strip() or "-"
        dt=e.get("original_date","") or e.get("creation_date","") or "-"
        gps_str=f'{e.get("gps_lat",0):.4f}, {e.get("gps_lon",0):.4f}' if e.get("has_gps") else "-"
        strip="YES" if e.get("stripping_detected") else "No"
        dur=_fmt_dur(e.get("duration",0)) or "-"
        md+=f'| {i+1} | {e["file_name"]} | {e.get("media_type","")} | {dur} | {e.get("codec","") or "-"} | {cam} | {dt} | {gps_str} | {strip} | `{e.get("sha256","")[:16]}...` |\n'
    md+="\n## Detail\n\n"
    for i,e in enumerate(ev):
        md+=f'### #{i+1}: {e["file_name"]}\n\n'
        md+=f'- Type: {e.get("media_type","")}\n'
        md+=f'- Dimensions: {e.get("width",0)}x{e.get("height",0)}\n'
        if e.get("duration"): md+=f'- Duration: {_fmt_dur(e["duration"])}\n'
        if e.get("codec"): md+=f'- Codec: {e["codec"]}\n'
        md+=f'- MD5: `{e.get("md5","")}`\n'
        md+=f'- SHA-256: `{e.get("sha256","")}`\n'
        if e.get("phash"): md+=f'- pHash: `{e.get("phash","")}`\n'
        cam=(e.get("camera_make","")+" "+e.get("camera_model","")).strip()
        if cam: md+=f'- Camera: {cam}\n'
        dt=e.get("original_date","") or e.get("creation_date","")
        if dt: md+=f'- Date: {dt}\n'
        if e.get("has_gps"): md+=f'- GPS: {e.get("gps_lat",0):.6f}, {e.get("gps_lon",0):.6f}\n'
        if e.get("stripping_detected"):
            md+='- **Stripping detected:**\n'
            for ind in e.get("stripping_indicators",[]): md+=f'  - {ind}\n'
        if e.get("notes"): md+=f'- Notes: {e["notes"]}\n'
        md+='\n'
    md+=f"\n---\n\nGenerated by Palimpsest v4.0 | ephemeradev.net | github.com/ephemera02\n"
    with open(fp,"w",encoding="utf-8") as f: f.write(md)
    return send_file(fp,as_attachment=True,download_name=fn)

@app.route("/api/import/palimpsest", methods=["POST"])
def import_palimpsest():
    """Import a Palimpsest JSON export into this instance."""
    if "file" not in request.files: return jsonify({"error":"No file"}),400
    f=request.files["file"]
    try:
        data=json.loads(f.read().decode("utf-8"))
    except:
        return jsonify({"error":"Invalid JSON file"}),400
    if "evidence" not in data: return jsonify({"error":"Not a Palimpsest export (no evidence key)"}),400
    imported=0; skipped=0
    now=datetime.now().isoformat()
    # Import suspect if present
    sus_map={}
    if data.get("suspect"):
        s=data["suspect"]
        with get_db() as c:
            # Check if suspect already exists by name
            existing=c.execute("SELECT id FROM suspects WHERE name=?",(s.get("name",""),)).fetchone()
            if existing:
                sus_map[s.get("id")]=existing["id"]
            else:
                cur=c.execute("INSERT INTO suspects (name,aliases,platform,notes,threat_level,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (s.get("name",""),s.get("aliases",""),s.get("platform",""),s.get("notes",""),s.get("threat_level","unknown"),s.get("status","active"),now,now))
                sus_map[s.get("id")]=cur.lastrowid
    for e in data["evidence"]:
        # Skip if SHA-256 already exists
        sha=e.get("sha256","")
        if sha:
            with get_db() as c:
                exists=c.execute("SELECT id FROM evidence WHERE sha256=?",(sha,)).fetchone()
                if exists: skipped+=1; continue
        # Map suspect ID
        old_sid=e.get("suspect_id")
        new_sid=sus_map.get(old_sid) if old_sid else None
        meta_json=e.get("metadata_json",{})
        if isinstance(meta_json,dict): meta_json=json.dumps(meta_json)
        strip_ind=e.get("stripping_indicators",[])
        if isinstance(strip_ind,list): strip_ind=json.dumps(strip_ind)
        with get_db() as c:
            c.execute("""INSERT INTO evidence (file_path,file_name,file_size,media_type,mime_type,
                width,height,duration,fps,codec,bitrate,frame_count,
                audio_codec,audio_channels,audio_sample_rate,
                md5,sha256,phash,dhash,whash,ahash,
                has_exif,has_gps,gps_lat,gps_lon,gps_alt,
                camera_make,camera_model,software,original_date,modify_date,creation_date,
                metadata_json,stripping_detected,stripping_indicators,
                suspect_id,tags,notes,added_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (e.get("file_path","imported"),e.get("file_name","unknown"),e.get("file_size",0),
                 e.get("media_type",""),e.get("mime_type",""),
                 e.get("width",0),e.get("height",0),e.get("duration",0),e.get("fps",0),
                 e.get("codec",""),e.get("bitrate",0),e.get("frame_count",0),
                 e.get("audio_codec",""),e.get("audio_channels",0),e.get("audio_sample_rate",0),
                 e.get("md5",""),e.get("sha256",""),e.get("phash",""),e.get("dhash",""),
                 e.get("whash",""),e.get("ahash",""),
                 e.get("has_exif",0),e.get("has_gps",0),
                 e.get("gps_lat"),e.get("gps_lon"),e.get("gps_alt"),
                 e.get("camera_make",""),e.get("camera_model",""),e.get("software",""),
                 e.get("original_date",""),e.get("modify_date",""),e.get("creation_date",""),
                 meta_json,e.get("stripping_detected",0),strip_ind,
                 new_sid,e.get("tags",""),e.get("notes",""),now))
        imported+=1
    return jsonify({"imported":imported,"skipped":skipped,"total":len(data["evidence"]),
                     "message":f"Imported {imported} items, skipped {skipped} duplicates"})

@app.route("/api/hash_lookup")
def api_hash_lookup():
    h=request.args.get("hash","")
    if not h: return jsonify([])
    with get_db() as c: return jsonify([dict(r) for r in c.execute("SELECT * FROM evidence WHERE md5=? OR sha256=? OR phash=?",(h,h,h)).fetchall()])

@app.route("/api/timeline")
def api_timeline():
    with get_db() as c:
        return jsonify([dict(r) for r in c.execute("""SELECT id,file_name,media_type,original_date,creation_date,modify_date,
            camera_make,camera_model,suspect_id,duration,has_gps,stripping_detected
            FROM evidence WHERE original_date!='' OR creation_date!='' OR modify_date!=''
            ORDER BY COALESCE(NULLIF(original_date,''),NULLIF(creation_date,''),modify_date)""").fetchall()])

@app.route("/api/forensics/run/<int:eid>", methods=["POST"])
def api_forensics_run(eid):
    """Run all forensic analyses on a single evidence item."""
    with get_db() as c:
        r = c.execute("SELECT file_path, media_type FROM evidence WHERE id=?", (eid,)).fetchone()
        if not r: return jsonify({"error":"Not found"}),404
    fp = os.path.join(UPLOAD_DIR, r["file_path"])
    if not os.path.exists(fp): return jsonify({"error":"File not found on disk"}),404
    results = forensic_run_all(fp, eid, r["media_type"])
    now = datetime.now().isoformat()
    all_flags = []
    with get_db() as c:
        c.execute("DELETE FROM forensic_results WHERE evidence_id=?", (eid,))
        c.execute("DELETE FROM scene_signatures WHERE evidence_id=?", (eid,))
        c.execute("DELETE FROM audio_fingerprints WHERE evidence_id=?", (eid,))
        c.execute("DELETE FROM enf_results WHERE evidence_id=?", (eid,))
        for atype, data in results.items():
            flags = data.get("flags", [])
            all_flags.extend(flags)
            c.execute("INSERT INTO forensic_results (evidence_id,analysis_type,result_json,flags,analyzed_at) VALUES (?,?,?,?,?)",
                (eid, atype, json.dumps(data, default=str), json.dumps(flags), now))
            if atype == "scene" and data.get("color_histogram"):
                c.execute("INSERT INTO scene_signatures (evidence_id,color_histogram,dominant_colors,brightness_profile,edge_density,texture_hash) VALUES (?,?,?,?,?,?)",
                    (eid, json.dumps(data["color_histogram"]), json.dumps(data.get("dominant_colors",[])),
                     json.dumps(data.get("brightness_over_time",[])), data.get("edge_density",0), data.get("texture_hash","")))
            if atype == "audio" and data.get("fingerprint_hash"):
                c.execute("INSERT INTO audio_fingerprints (evidence_id,duration,has_speech,fingerprint_hash,energy_profile,spectral_centroid) VALUES (?,?,?,?,?,?)",
                    (eid, data.get("duration",0), 0, data.get("fingerprint_hash",""),
                     json.dumps(data.get("details",{}).get("energy_profile",[])),
                     json.dumps(data.get("spectral_features",{}))))
            if atype == "enf" and data.get("detected_freq", 0) > 0:
                c.execute("INSERT INTO enf_results (evidence_id,detected_freq,grid_region,confidence,enf_trace,source,flags,analyzed_at) VALUES (?,?,?,?,?,?,?,?)",
                    (eid, data.get("detected_freq",0), data.get("grid_region",""),
                     data.get("confidence",0), json.dumps(data.get("enf_trace",[])),
                     data.get("source",""), json.dumps(data.get("flags",[])), now))
    return jsonify({"evidence_id":eid,"results":results,"total_flags":len(all_flags),"flags":all_flags})

@app.route("/api/forensics/results/<int:eid>")
def api_forensics_results(eid):
    with get_db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM forensic_results WHERE evidence_id=? ORDER BY analysis_type", (eid,)).fetchall()]
        for r in rows:
            r["result_json"] = json.loads(r.get("result_json","{}"))
            r["flags"] = json.loads(r.get("flags","[]"))
    return jsonify(rows)

@app.route("/api/forensics/scene_matches")
def api_forensics_scene_matches():
    """Find evidence items that were likely filmed in the same location."""
    with get_db() as c:
        sigs = [dict(r) for r in c.execute("SELECT s.*, e.file_name, e.media_type FROM scene_signatures s JOIN evidence e ON e.id=s.evidence_id").fetchall()]
    matches = []
    seen = set()
    for i, a in enumerate(sigs):
        for j, b in enumerate(sigs[i+1:], i+1):
            key = (min(a["evidence_id"],b["evidence_id"]), max(a["evidence_id"],b["evidence_id"]))
            if key in seen: continue
            sig_a = {"color_histogram":json.loads(a.get("color_histogram","[]")),"brightness_avg":0,"edge_density":a.get("edge_density",0)}
            sig_b = {"color_histogram":json.loads(b.get("color_histogram","[]")),"brightness_avg":0,"edge_density":b.get("edge_density",0)}
            sim = forensic_scene_compare(sig_a, sig_b)
            if sim > 65:
                matches.append({"id_a":a["evidence_id"],"name_a":a["file_name"],"id_b":b["evidence_id"],"name_b":b["file_name"],"similarity":sim})
                seen.add(key)
    matches.sort(key=lambda x: -x["similarity"])
    return jsonify(matches)

@app.route("/api/forensics/audio_matches")
def api_forensics_audio_matches():
    """Find evidence items with similar audio environments."""
    with get_db() as c:
        fps = [dict(r) for r in c.execute("SELECT a.*, e.file_name FROM audio_fingerprints a JOIN evidence e ON e.id=a.evidence_id WHERE a.fingerprint_hash!=''").fetchall()]
    matches = []
    seen = set()
    for i, a in enumerate(fps):
        for j, b in enumerate(fps[i+1:], i+1):
            key = (min(a["evidence_id"],b["evidence_id"]), max(a["evidence_id"],b["evidence_id"]))
            if key in seen: continue
            if a["fingerprint_hash"] == b["fingerprint_hash"]:
                matches.append({"id_a":a["evidence_id"],"name_a":a["file_name"],"id_b":b["evidence_id"],"name_b":b["file_name"],"match":"exact audio fingerprint"})
                seen.add(key)
    return jsonify(matches)

@app.route("/api/forensics/batch", methods=["POST"])
def api_forensics_batch():
    """Run forensics on all evidence that hasn't been analyzed yet."""
    with get_db() as c:
        analyzed = set(r[0] for r in c.execute("SELECT DISTINCT evidence_id FROM forensic_results").fetchall())
        all_ev = [dict(r) for r in c.execute("SELECT id, file_path, media_type FROM evidence").fetchall()]
    pending = [e for e in all_ev if e["id"] not in analyzed]
    results = []
    for e in pending:
        fp = os.path.join(UPLOAD_DIR, e["file_path"])
        if not os.path.exists(fp): continue
        res = forensic_run_all(fp, e["id"], e["media_type"])
        now = datetime.now().isoformat()
        all_flags = []
        with get_db() as c:
            for atype, data in res.items():
                flags = data.get("flags", [])
                all_flags.extend(flags)
                c.execute("INSERT INTO forensic_results (evidence_id,analysis_type,result_json,flags,analyzed_at) VALUES (?,?,?,?,?)",
                    (e["id"], atype, json.dumps(data, default=str), json.dumps(flags), now))
                if atype == "scene" and data.get("color_histogram"):
                    c.execute("INSERT INTO scene_signatures (evidence_id,color_histogram,dominant_colors,brightness_profile,edge_density,texture_hash) VALUES (?,?,?,?,?,?)",
                        (e["id"], json.dumps(data["color_histogram"]), json.dumps(data.get("dominant_colors",[])),
                         json.dumps(data.get("brightness_over_time",[])), data.get("edge_density",0), data.get("texture_hash","")))
                if atype == "audio" and data.get("fingerprint_hash"):
                    c.execute("INSERT INTO audio_fingerprints (evidence_id,duration,has_speech,fingerprint_hash,energy_profile,spectral_centroid) VALUES (?,?,?,?,?,?)",
                        (e["id"], data.get("duration",0), 0, data.get("fingerprint_hash",""),
                         json.dumps(data.get("details",{}).get("energy_profile",[])),
                         json.dumps(data.get("spectral_features",{}))))
                if atype == "enf" and data.get("detected_freq", 0) > 0:
                    c.execute("INSERT INTO enf_results (evidence_id,detected_freq,grid_region,confidence,enf_trace,source,flags,analyzed_at) VALUES (?,?,?,?,?,?,?,?)",
                        (e["id"], data.get("detected_freq",0), data.get("grid_region",""),
                         data.get("confidence",0), json.dumps(data.get("enf_trace",[])),
                         data.get("source",""), json.dumps(data.get("flags",[])), now))
        results.append({"id":e["id"],"flags":len(all_flags)})
    return jsonify({"analyzed":len(results),"pending_before":len(pending),"results":results})

# ===== V4.0 API ROUTES =====

@app.route("/api/enf/results")
def api_enf_results():
    """Get ENF analysis results across all evidence."""
    with get_db() as c:
        rows = [dict(r) for r in c.execute("""
            SELECT e.id as evidence_id, e.file_name, e.duration, e.codec,
                   enf.detected_freq, enf.grid_region, enf.confidence, enf.source,
                   enf.enf_trace, enf.flags, enf.analyzed_at
            FROM enf_results enf
            JOIN evidence e ON e.id = enf.evidence_id
            ORDER BY enf.confidence DESC
        """).fetchall()]
        for r in rows:
            r["enf_trace"] = json.loads(r.get("enf_trace", "[]"))
            r["flags"] = json.loads(r.get("flags", "[]"))
    return jsonify(rows)

@app.route("/api/enf/matches")
def api_enf_matches():
    """Find videos with matching ENF traces (recorded at the same time on the same grid)."""
    with get_db() as c:
        enfs = [dict(r) for r in c.execute("""
            SELECT enf.*, e.file_name FROM enf_results enf
            JOIN evidence e ON e.id = enf.evidence_id
            WHERE enf.confidence > 30
        """).fetchall()]
    matches = []
    seen = set()
    for i, a in enumerate(enfs):
        for j, b in enumerate(enfs[i+1:], i+1):
            key = (min(a["evidence_id"], b["evidence_id"]), max(a["evidence_id"], b["evidence_id"]))
            if key in seen: continue
            # Same grid type
            if a["detected_freq"] == b["detected_freq"] and a["detected_freq"] > 0:
                matches.append({
                    "id_a": a["evidence_id"], "name_a": a["file_name"],
                    "id_b": b["evidence_id"], "name_b": b["file_name"],
                    "freq": a["detected_freq"],
                    "grid": a["grid_region"],
                    "confidence_a": a["confidence"], "confidence_b": b["confidence"]
                })
                seen.add(key)
    return jsonify(matches)

@app.route("/api/enf/summary")
def api_enf_summary():
    """Summary stats for ENF results."""
    with get_db() as c:
        total = c.execute("SELECT COUNT(*) FROM enf_results").fetchone()[0]
        hz50 = c.execute("SELECT COUNT(*) FROM enf_results WHERE detected_freq=50").fetchone()[0]
        hz60 = c.execute("SELECT COUNT(*) FROM enf_results WHERE detected_freq=60").fetchone()[0]
        ambig = c.execute("SELECT COUNT(*) FROM enf_results WHERE grid_region='ambiguous' OR grid_region='indeterminate'").fetchone()[0]
        avg_conf = c.execute("SELECT AVG(confidence) FROM enf_results WHERE confidence > 0").fetchone()[0] or 0
    return jsonify({"total": total, "hz50": hz50, "hz60": hz60, "ambiguous": ambig,
                    "avg_confidence": round(avg_conf, 1)})

@app.route("/api/metadata/groups")
def api_metadata_groups():
    """Group all evidence by metadata fields to map the distribution pipeline."""
    with get_db() as c:
        all_ev = [dict(r) for r in c.execute("""
            SELECT id, file_name, file_size, media_type, width, height, duration, fps, codec,
                   bitrate, audio_codec, audio_channels, audio_sample_rate,
                   creation_date, metadata_json
            FROM evidence ORDER BY file_name
        """).fetchall()]

    # Parse raw metadata for comment and encoder fields
    for e in all_ev:
        raw = json.loads(e.get("metadata_json", "{}"))
        e["comment"] = raw.get("comment", "")
        e["encoder"] = raw.get("encoder", "")

    # Group by comment
    comment_groups = {}
    for e in all_ev:
        key = e["comment"] or "(no comment)"
        comment_groups.setdefault(key, []).append({"id": e["id"], "file_name": e["file_name"]})

    # Group by encoder
    encoder_groups = {}
    for e in all_ev:
        key = e["encoder"] or "(no encoder)"
        encoder_groups.setdefault(key, []).append({"id": e["id"], "file_name": e["file_name"]})

    # Group by codec + resolution + fps (distribution chain fingerprint)
    pipeline_groups = {}
    for e in all_ev:
        key = f"{e['codec'] or '?'} | {e['width']}x{e['height']} | {e['fps']}fps"
        pipeline_groups.setdefault(key, []).append({"id": e["id"], "file_name": e["file_name"]})

    # Group by file size range
    size_groups = {}
    for e in all_ev:
        sz = e.get("file_size", 0)
        if sz < 1048576: bucket = "< 1 MB"
        elif sz < 10485760: bucket = "1-10 MB"
        elif sz < 52428800: bucket = "10-50 MB"
        elif sz < 104857600: bucket = "50-100 MB"
        elif sz < 524288000: bucket = "100-500 MB"
        else: bucket = "500+ MB"
        size_groups.setdefault(bucket, []).append({"id": e["id"], "file_name": e["file_name"]})

    return jsonify({
        "comment": {k: {"count": len(v), "items": v[:20]} for k, v in sorted(comment_groups.items(), key=lambda x: -len(x[1]))},
        "encoder": {k: {"count": len(v), "items": v[:20]} for k, v in sorted(encoder_groups.items(), key=lambda x: -len(x[1]))},
        "pipeline": {k: {"count": len(v), "items": v[:20]} for k, v in sorted(pipeline_groups.items(), key=lambda x: -len(x[1]))},
        "size": {k: {"count": len(v), "items": v[:20]} for k, v in sorted(size_groups.items(), key=lambda x: -len(x[1]))}
    })

# ===== AI VISION ANALYSIS ROUTES =====

@app.route("/api/ai/providers")
def api_ai_providers():
    """Return available AI providers and their models."""
    return jsonify(AI_PROVIDERS)

@app.route("/api/ai/settings", methods=["GET", "PUT"])
def api_ai_settings():
    if request.method == "GET":
        with get_db() as c:
            row = c.execute("SELECT * FROM ai_settings WHERE id=1").fetchone()
            if row:
                d = dict(row)
                # Mask API key for display
                key = d.get("api_key", "")
                d["api_key_masked"] = key[:8] + "..." + key[-4:] if len(key) > 12 else ("set" if key else "")
                d["api_key"] = key  # Frontend needs it for API calls
                return jsonify(d)
        return jsonify({"provider": "anthropic", "model": "claude-sonnet-4-5-20250514", "api_key": "", "api_key_masked": ""})
    else:
        data = request.json
        with get_db() as c:
            c.execute("""UPDATE ai_settings SET provider=?, api_key=?, model=?,
                custom_endpoint=?, default_prompt=? WHERE id=1""",
                (data.get("provider", "anthropic"), data.get("api_key", ""),
                 data.get("model", ""), data.get("custom_endpoint", ""),
                 data.get("default_prompt", "")))
        return jsonify({"ok": True})

@app.route("/api/ai/estimate/<int:eid>")
def api_ai_estimate(eid):
    """Estimate cost of running AI vision analysis on an evidence item's frames."""
    with get_db() as c:
        ev = c.execute("SELECT id, file_name, frames_extracted FROM evidence WHERE id=?", (eid,)).fetchone()
        if not ev: return jsonify({"error": "Not found"}), 404
        frames = c.execute("SELECT COUNT(*) FROM extracted_frames WHERE evidence_id=?", (eid,)).fetchall()
        frame_count = frames[0][0] if frames else 0
        settings = c.execute("SELECT * FROM ai_settings WHERE id=1").fetchone()

    if frame_count == 0:
        return jsonify({"error": "No frames extracted. Run file analysis first.", "frame_count": 0})

    provider = dict(settings).get("provider", "anthropic") if settings else "anthropic"
    model_id = dict(settings).get("model", "") if settings else ""

    # Find cost rates
    input_cost = 3.0; output_cost = 15.0  # defaults
    prov_info = AI_PROVIDERS.get(provider, {})
    for m in prov_info.get("models", []):
        if m["id"] == model_id:
            input_cost = m["input_cost"]; output_cost = m["output_cost"]
            break

    # Estimate: each 360p frame ~ 1500 tokens input, prompt ~ 500 tokens, response ~ 800 tokens
    tokens_per_frame_in = 2000
    tokens_per_frame_out = 800
    total_in = frame_count * tokens_per_frame_in
    total_out = frame_count * tokens_per_frame_out
    cost = (total_in / 1_000_000 * input_cost) + (total_out / 1_000_000 * output_cost)

    return jsonify({
        "evidence_id": eid,
        "frame_count": frame_count,
        "provider": prov_info.get("name", provider),
        "model": model_id,
        "estimated_tokens_in": total_in,
        "estimated_tokens_out": total_out,
        "estimated_cost": round(cost, 4),
        "cost_display": f"${cost:.4f}"
    })

def _call_ai_vision(provider, model, api_key, prompt, image_b64, custom_endpoint=""):
    """Call an AI vision API with a frame image. Returns parsed response text."""
    prov_info = AI_PROVIDERS.get(provider, {})
    fmt = prov_info.get("format", "openai")
    endpoint = custom_endpoint if provider == "custom" and custom_endpoint else prov_info.get("endpoint", "")

    if fmt == "anthropic":
        body = json.dumps({
            "model": model,
            "max_tokens": 1500,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                    {"type": "text", "text": prompt}
                ]
            }]
        }).encode("utf-8")
        req = Request(endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", api_key)
        req.add_header("anthropic-version", "2023-06-01")

    elif fmt == "google":
        endpoint = endpoint.replace("{model}", model) + f"?key={api_key}"
        body = json.dumps({
            "contents": [{"parts": [
                {"inlineData": {"mimeType": "image/jpeg", "data": image_b64}},
                {"text": prompt}
            ]}]
        }).encode("utf-8")
        req = Request(endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")

    else:  # openai / openrouter / custom
        body = json.dumps({
            "model": model,
            "max_tokens": 1500,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}},
                    {"type": "text", "text": prompt}
                ]
            }]
        }).encode("utf-8")
        req = Request(endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")
        if provider == "openrouter":
            req.add_header("HTTP-Referer", "https://ephemeradev.net")
            req.add_header("X-Title", "Palimpsest")

    try:
        resp = urlopen(req, timeout=60)
        data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return {"error": f"API error {e.code}: {error_body[:500]}", "tokens": 0}
    except URLError as e:
        return {"error": f"Connection error: {str(e)}", "tokens": 0}
    except Exception as e:
        return {"error": str(e), "tokens": 0}

    # Parse response based on format
    text = ""
    tokens = 0
    if fmt == "anthropic":
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        usage = data.get("usage", {})
        tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
    elif fmt == "google":
        for cand in data.get("candidates", []):
            for part in cand.get("content", {}).get("parts", []):
                text += part.get("text", "")
        tokens = data.get("usageMetadata", {}).get("totalTokenCount", 0)
    else:
        for choice in data.get("choices", []):
            msg = choice.get("message", {})
            text += msg.get("content", "")
        usage = data.get("usage", {})
        tokens = usage.get("total_tokens", 0)

    # Try to parse JSON from text
    parsed = {}
    try:
        # Strip markdown code fences if present
        clean = text.strip()
        if clean.startswith("```"): clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
        if clean.endswith("```"): clean = clean[:-3]
        clean = clean.strip()
        if clean.startswith("json"): clean = clean[4:].strip()
        parsed = json.loads(clean)
    except:
        parsed = {"raw_text": text}

    return {"result": parsed, "tokens": tokens}

@app.route("/api/ai/analyze/<int:eid>", methods=["POST"])
def api_ai_analyze(eid):
    """Run AI vision analysis on extracted frames for an evidence item."""
    with get_db() as c:
        ev = c.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        if not ev: return jsonify({"error": "Not found"}), 404
        frames = [dict(r) for r in c.execute(
            "SELECT * FROM extracted_frames WHERE evidence_id=? ORDER BY frame_number", (eid,)).fetchall()]
        settings = dict(c.execute("SELECT * FROM ai_settings WHERE id=1").fetchone())

    if not frames:
        return jsonify({"error": "No frames extracted. Analyze the file first."}), 400

    api_key = settings.get("api_key", "")
    if not api_key:
        return jsonify({"error": "No API key configured. Go to AI Settings to add one."}), 400

    provider = settings.get("provider", "anthropic")
    model = settings.get("model", "")
    prompt = settings.get("default_prompt", "Analyze this frame.")
    custom_endpoint = settings.get("custom_endpoint", "")

    # Find cost rates
    input_cost_rate = 3.0; output_cost_rate = 15.0
    prov_info = AI_PROVIDERS.get(provider, {})
    for m in prov_info.get("models", []):
        if m["id"] == model:
            input_cost_rate = m["input_cost"]; output_cost_rate = m["output_cost"]
            break

    results = []
    total_tokens = 0
    total_cost = 0.0
    now = datetime.now().isoformat()

    # Clear previous AI results for this evidence
    with get_db() as c:
        c.execute("DELETE FROM ai_results WHERE evidence_id=?", (eid,))

    for i, frame in enumerate(frames):
        frame_path = os.path.join(FRAMES_DIR, frame["file_path"])
        if not os.path.exists(frame_path):
            results.append({"frame": i, "error": "Frame file not found"})
            continue

        # Read and base64 encode
        with open(frame_path, "rb") as f:
            image_b64 = base64.b64encode(f.read()).decode("ascii")

        resp = _call_ai_vision(provider, model, api_key, prompt, image_b64, custom_endpoint)

        if "error" in resp and "result" not in resp:
            results.append({"frame": i, "error": resp["error"]})
            continue

        tokens = resp.get("tokens", 0)
        # Rough cost estimate (input heavy for images)
        est_cost = (tokens * 0.7 / 1_000_000 * input_cost_rate) + (tokens * 0.3 / 1_000_000 * output_cost_rate)
        total_tokens += tokens
        total_cost += est_cost

        result_data = resp.get("result", {})
        results.append({"frame": i, "result": result_data, "tokens": tokens})

        # Store in DB
        with get_db() as c:
            c.execute("""INSERT INTO ai_results (evidence_id, provider, model, frame_index,
                result_json, tokens_used, cost_estimate, analyzed_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (eid, provider, model, i, json.dumps(result_data, default=str),
                 tokens, round(est_cost, 6), now))

    # Update cumulative cost tracking
    with get_db() as c:
        c.execute("UPDATE ai_settings SET total_tokens = total_tokens + ?, total_cost = total_cost + ? WHERE id=1",
            (total_tokens, total_cost))

    return jsonify({
        "evidence_id": eid, "frames_analyzed": len(results),
        "total_tokens": total_tokens, "total_cost": round(total_cost, 4),
        "results": results
    })

@app.route("/api/ai/results/<int:eid>")
def api_ai_results(eid):
    """Get AI analysis results for an evidence item."""
    with get_db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM ai_results WHERE evidence_id=? ORDER BY frame_index", (eid,)).fetchall()]
        for r in rows:
            r["result_json"] = json.loads(r.get("result_json", "{}"))
    return jsonify(rows)

@app.route("/api/ai/test", methods=["POST"])
def api_ai_test():
    """Test AI provider connection with a simple text prompt."""
    data = request.json
    provider = data.get("provider", "anthropic")
    api_key = data.get("api_key", "")
    model = data.get("model", "")
    custom_endpoint = data.get("custom_endpoint", "")

    if not api_key:
        return jsonify({"error": "No API key provided"}), 400

    prov_info = AI_PROVIDERS.get(provider, {})
    fmt = prov_info.get("format", "openai")
    endpoint = custom_endpoint if provider == "custom" and custom_endpoint else prov_info.get("endpoint", "")

    try:
        if fmt == "anthropic":
            body = json.dumps({"model": model, "max_tokens": 50,
                "messages": [{"role": "user", "content": "Reply with exactly: CONNECTION OK"}]}).encode("utf-8")
            req = Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("x-api-key", api_key)
            req.add_header("anthropic-version", "2023-06-01")
        elif fmt == "google":
            ep = endpoint.replace("{model}", model) + f"?key={api_key}"
            body = json.dumps({"contents": [{"parts": [{"text": "Reply with exactly: CONNECTION OK"}]}]}).encode("utf-8")
            req = Request(ep, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
        else:
            body = json.dumps({"model": model, "max_tokens": 50,
                "messages": [{"role": "user", "content": "Reply with exactly: CONNECTION OK"}]}).encode("utf-8")
            req = Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", f"Bearer {api_key}")

        resp = urlopen(req, timeout=15)
        result = json.loads(resp.read().decode("utf-8"))
        return jsonify({"ok": True, "response": str(result)[:500]})
    except HTTPError as e:
        return jsonify({"ok": False, "error": f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:300]}"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200

@app.route("/api/enf/run/<int:eid>", methods=["POST"])
def api_enf_run_single(eid):
    """Run ENF analysis on a single evidence item (without full forensics)."""
    with get_db() as c:
        r = c.execute("SELECT file_path, media_type FROM evidence WHERE id=?", (eid,)).fetchone()
        if not r: return jsonify({"error": "Not found"}), 404
    fp = os.path.join(UPLOAD_DIR, r["file_path"])
    if not os.path.exists(fp): return jsonify({"error": "File not found on disk"}), 404
    result = forensic_enf_analysis(fp, eid)
    now = datetime.now().isoformat()
    with get_db() as c:
        c.execute("DELETE FROM enf_results WHERE evidence_id=?", (eid,))
        if result.get("detected_freq", 0) > 0:
            c.execute("INSERT INTO enf_results (evidence_id,detected_freq,grid_region,confidence,enf_trace,source,flags,analyzed_at) VALUES (?,?,?,?,?,?,?,?)",
                (eid, result["detected_freq"], result.get("grid_region",""), result.get("confidence",0),
                 json.dumps(result.get("enf_trace",[])), result.get("source",""), json.dumps(result.get("flags",[])), now))
    return jsonify(result)

@app.route("/api/info")
def api_info():
    return jsonify({"version":"4.0.0","name":"Palimpsest","pil":HAS_PIL,"imagehash":HAS_IMAGEHASH,
                     "cv2":HAS_CV2,"hachoir":HAS_HACHOIR,"reportlab":HAS_REPORTLAB,
                     "numpy":HAS_NUMPY,"scipy":HAS_SCIPY,"ffmpeg":HAS_FFMPEG})

def open_browser():
    time.sleep(1.2); webbrowser.open("http://127.0.0.1:7700")

if __name__ == "__main__":
    print(r"""
    ____        ___
   / __ \____ _/ (_)___ ___  ____  ________  _____/ /_
  / /_/ / __ `/ / / __ `__ \/ __ \/ ___/ _ \/ ___/ __/
 / ____/ /_/ / / / / / / / / /_/ (__  )  __(__  ) /_
/_/    \__,_/_/_/_/ /_/ /_/ .___/____/\___/____/\__/
                         /_/
    Metadata Forensics Toolkit v4.0
    https://ephemeradev.net | github.com/ephemera02
    """)
    print(f"[*] Database: {DB_PATH}")
    print(f"[*] Pillow: {'OK' if HAS_PIL else 'MISSING'} | imagehash: {'OK' if HAS_IMAGEHASH else 'MISSING'}")
    print(f"[*] OpenCV: {'OK' if HAS_CV2 else 'MISSING'} | hachoir: {'OK' if HAS_HACHOIR else 'MISSING'}")
    print(f"[*] numpy: {'OK' if HAS_NUMPY else 'MISSING'} | scipy: {'OK' if HAS_SCIPY else 'MISSING'}")
    print(f"[*] ffmpeg: {'OK' if HAS_FFMPEG else 'NOT FOUND (audio analysis disabled)'}")
    print(f"[*] reportlab: {'OK' if HAS_REPORTLAB else 'MISSING'}")
    print(f"[*] No file size limit.")
    print(f"[*] http://127.0.0.1:7700")
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=7700, debug=False)
