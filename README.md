# 🔍 P A L I M P S E S T 🔍

**Metadata Forensics Toolkit**

*by Eph at ephemeradev.net · est. 2026 · Open Source 💜*

---

A desktop app that rips the hidden data out of photos and videos, runs forensic analysis, tracks suspects, and builds evidence packages. Video-first. Built for investigators and advocacy communities documenting abuse networks.

The name comes from a palimpsest: a manuscript where the original writing has been scraped off and written over, but traces of the old text remain underneath. Just like metadata. You can try to erase it, but traces often remain.

Built by a mentally ill untrained aegosexual who got tired of watching these networks operate unchecked.

The Cat still supervised.

---

> *"Sorrow be damned and all your plans. Fuck the faithful, fuck the committed, the dedicated, the true believers; fuck all the sure and certain people prepared to maim and kill whoever got in their way; fuck every cause that ended in murder and a child screaming."*
>
> Iain Banks, Against a Dark Background

---

## ✦ Features

**File Analyzer**

> Drop any video or image. Palimpsest extracts every piece of hidden data: camera model, GPS coordinates, timestamps, editing software, hashes, codec info, everything. Simple Mode explains each field in plain English. Advanced Mode shows raw technical data. No file size limit.

**Video-First Design**

> Videos are the primary material. Full H.264 transcoding via ffmpeg for universal playback of any format (MP4, AVI, MOV, MKV, WebM, MTS, you name it). Automatic frame extraction. Frame-by-frame stepping. Videos are not second-class citizens here.

**Forensic Video Player**

> Zoom up to 32x with mouse wheel, slider, or preset buttons. Drag to pan at any zoom level. Brightness, contrast, saturation, hue rotation, and gamma sliders. Color inversion. Frame-by-frame navigation. All controls work on images too. Because sometimes you need to see what's in the dark corner of a frame.

**Forensic Suite**

> Six analysis modules that go deeper than basic metadata:
>
> → **Scene Analysis**: Color/brightness/texture fingerprinting. Finds videos filmed in the same room.
> → **Watermark Detection**: Finds channel stamps, bot overlays, and redistribution marks. Reveals the sharing chain.
> → **Encoding Chain Analysis**: Estimates whether a file is an original or a re-encoded copy. Measures generation loss.
> → **Screen Recording Detection**: Identifies Telegram screen grabs vs original camera captures. Checks for status bars, nav bars, phone resolutions.
> → **Lighting Analysis**: Natural vs artificial, color temperature, brightness patterns over time.
> → **Audio Fingerprinting**: Spectral analysis and energy profiling. Matches videos by ambient sound. Same room = same background noise.

**Scene Matching**

> Cross-references scene fingerprints across your whole evidence library. Same floor tiles, same wall color, same lighting setup? Flagged. Even if the camera angle is completely different.

**Audio Matching**

> Cross-references audio fingerprints. Same ambient hum, same background noise profile. Connects videos to the same physical location through sound.

**Multi-Algorithm Hashing**

> MD5, SHA-256 (exact identity), pHash, dHash, wHash, aHash (visual fingerprints). Perceptual hashes survive re-encoding, cropping, and compression. Track the same content across platforms even after re-upload.

**Batch Processing**

> Got a folder of 200 files from a Telegram dump? Drop them all in. Each one gets fully analyzed, hashed, thumbnailed, and frame-extracted. Link them all to a suspect at once.

**Suspect Management**

> Create profiles with names, aliases, platform info, threat levels, and typed identifiers (Telegram handles, crypto wallets, emails, phone numbers, Discord tags). Link evidence to suspects. Build case files.

**5 Export Formats**

> → **JSON**: Machine-readable, importable into another Palimpsest instance
> → **PDF**: Formatted evidence report for law enforcement handoff
> → **CSV**: Opens in Excel or Google Sheets, shareable with anyone
> → **HTML**: Standalone dark-themed report, opens in any browser, no software needed
> → **Markdown**: Clean text, paste into Discord, docs, or GitHub
>
> All filterable by suspect.

**Import**

> Load evidence from someone else's Palimpsest JSON export into your own instance. Suspects are imported too. Duplicates (same SHA-256) are skipped automatically. This is how your team shares data.

**Side-by-Side Comparison**

> Pick any two evidence items. Checks same camera, same location, same date, same codec, same resolution, and visual similarity.

**Duplicate Detection**

> Exact copies (identical SHA-256) and near-duplicates (visually similar via perceptual hashing). Works across videos and images. Finds re-uploads.

**Timeline**

> All dated evidence sorted chronologically. Useful for establishing event sequences and activity patterns.

**GPS Map**

> Files with embedded GPS coordinates plotted on an interactive map. Click markers for details.

**Interactive Tutorial**

> 15-step walkthrough that takes you through the entire app. Also a full Help page with written docs.

**61 Tooltips**

> Hover over basically anything for an explanation. Designed to be usable by people who have never touched forensic software before.

**No File Size Limit**

> It's your machine. Your rules.

**2,730 Lines of Code**

> One developer. One cat. Pure Python. No external DLLs. A lot of anger at the right things.

---

## 🚀 Installation & Setup

### Option A: Download the .exe

Go to [**Releases**](../../releases), download the zip, extract, double-click `Palimpsest.exe`. Done.

The exe bundles everything including ffmpeg. Nothing else to install. Three files total: `Palimpsest.exe`, `palimpsest_ui.html`, `palimpsest_icon.ico`.

### Option B: Run from Source

1. Install Python 3.10+ from [python.org](https://python.org)
   * ⚠️ **CHECK "Add Python to PATH"** during install.
2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```
3. Install ffmpeg from [ffmpeg.org](https://ffmpeg.org/download.html) and add to PATH (needed for audio forensics)
4. Run it:

   ```
   python palimpsest.py
   ```
5. Opens in your browser at `http://127.0.0.1:7700`

### Option C: Build the .exe Yourself

1. Do Option B first to make sure it works
2. Run the build script:

   ```
   build.bat
   ```
3. Your exe lands in `dist/`. Copy `palimpsest_ui.html` and `palimpsest_icon.ico` next to it.

Note: `pyinstaller` might not be on your PATH. If `build.bat` fails, use the full path:
```
& "C:\Users\YOU\AppData\Roaming\Python\PythonXXX\Scripts\pyinstaller.exe" ...
```

---

## 📁 Project Structure

| File | What It Does |
| --- | --- |
| `palimpsest.py` | The whole backend. Flask API, metadata extraction, forensic modules, database. 1,747 lines. |
| `palimpsest_ui.html` | The whole frontend. Single-page app with 59 functions. 983 lines. |
| `palimpsest_icon.ico` | App icon. Browser tab, sidebar, taskbar, file explorer. |
| `requirements.txt` | Python dependencies. All pip-installable. |
| `build.bat` | One-click Windows exe builder. Bundles ffmpeg. |
| `README.md` | You're reading it. |

---

## 🔧 Dependencies

All pip-installable. No external DLLs.

| Package | What It Does |
| --- | --- |
| Flask | Runs the local web UI |
| Pillow | Image EXIF extraction |
| imagehash | Perceptual hashing (pHash, dHash, wHash, aHash) |
| opencv-python-headless | Video analysis, frame extraction, thumbnails, forensic vision |
| hachoir | Video container metadata (creation dates, codecs, encoder info) |
| numpy | Numerical processing for forensic analysis |
| scipy | Audio spectral analysis and signal processing |
| reportlab | PDF report generation |

Plus **ffmpeg** (separate install from [ffmpeg.org](https://ffmpeg.org/download.html)) for audio extraction and video transcoding. Bundled into the exe automatically by `build.bat`.

---

## ✦ Forensic Modules Explained

**Scene Analysis**

> Samples frames throughout a video. Builds HSV color histograms, measures brightness profiles and edge density, generates a texture hash. Scene Matching then cross-references these fingerprints across your library. Same floor, same walls, same light? Connected.

**Watermark/Overlay Detection**

> Checks six standard overlay positions (four corners + top/bottom center) across multiple frames. Consistent high-contrast edges in the same position across the whole video = a channel stamp, bot watermark, or redistribution mark. Reports confidence and consistency percentages.

**Encoding Chain Analysis**

> Calculates bits-per-pixel-per-frame ratios, measures 8x8 block boundary artifacts (JPEG/H.264 compression grid), checks for non-standard resolutions and frame rates. Outputs: "likely original," "1st-2nd generation," "2nd-3rd generation," or "3rd+ generation (heavily re-encoded)." Originals are the most valuable for investigation.

**Screen Recording Detection**

> Checks resolution against known phone screen sizes, analyzes top/bottom frame strips for status bar and navigation bar patterns, checks FPS and orientation. Identifies Telegram screen grabs vs original camera captures. Outputs a confidence percentage.

**Lighting Analysis**

> Brightness and color temperature over time, visualized. Blue/red ratio for natural vs artificial classification. Flags very dark scenes, significant brightness changes, and unusual color temperatures.

**Audio Fingerprinting**

> Extracts audio via ffmpeg, normalizes to 16kHz mono. Computes spectral centroid, per-second energy profile, silence percentage. Generates a hash from the energy profile. Audio Matching then finds videos with the same ambient sound signature.

---

## ⚠️ Disclaimers

**Evidence Integrity**

> Original files are never modified. Palimpsest stores copies and generates previews/thumbnails alongside the originals. Hashes are computed on the original bytes.

**Forensic Accuracy**

> The forensic modules use heuristics. Scene matching, screen recording detection, and encoding analysis are probabilistic, not definitive. They flag connections worth investigating. They don't prove anything on their own.

**No Warranty**

> This software is provided as-is. It works on my machine. If it breaks on yours, open an issue with details.

**Privacy**

> Palimpsest collects nothing. No telemetry, no analytics, no tracking. Everything stays on your machine. Nothing phones home.

---

## 🐾 FAQ

**"What's this for?"**

> Documenting and investigating abuse networks. Specifically organized animal torture operations that share material through Telegram channels and encrypted platforms. But the forensic tools are general-purpose. Use them for whatever needs investigating.

**"Why video-first?"**

> Because the material we're analyzing is primarily video. The metadata, encoding chains, and frame analysis matter more than photo EXIF in this context.

**"Can law enforcement use the exports?"**

> That's the goal. PDF reports are formatted for handoff. JSON exports contain all metadata and hashes in a structured format. Evidence integrity is maintained (originals untouched, hashes verified).

**"Can my team share data?"**

> Yes. Export as JSON from one Palimpsest, import into another. Suspects come along for the ride. Duplicates are auto-skipped by SHA-256. CSV and HTML exports work for people who don't have Palimpsest at all.

**"The forensics say 'screen recording detected' but it's not"**

> It's a confidence score, not a verdict. False positives happen. Portrait video at phone screen resolution with consistent top/bottom strips will trigger it. Use it as one signal among many.

**"Something is broken"**

> Open an issue. Include what you were doing, what happened, and what you expected. The Cat will review it with the gravity it deserves.

---

## 💬 Links

🌐 **Website:** [ephemeradev.net](https://ephemeradev.net)

🐾 **Other projects:** [SillyLoreSmith](https://github.com/ephemera02/SillyLoreSmith) - AI lorebook builder, [GeoScout](https://github.com/ephemera02/GeoScout) - satellite image search

💜 **Project No More:** [projectnomore.net](https://projectnomore.net) - the advocacy work this tool supports

---

## Credits

**Created by Eph at Ephemera**

Built with the assistance of Claude (Anthropic), who ran the forensic math and didn't flinch at the subject matter.

Mascot: The Cat, who remains unbothered.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Use it. Modify it. Build on it. If it helps take down even one of these networks, that's all that matters.

---

*"She believed she could build a forensic toolkit and she actually did."*

🐾
