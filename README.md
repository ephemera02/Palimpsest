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

## ✦ What's New in v4.0

**ENF Analysis** ⚡

> Your power grid snitches on you. Every AC grid in the world runs at either 50Hz (Europe, Asia, Africa, Oceania) or 60Hz (Americas, parts of East Asia), and that frequency gets embedded in every recording made near a power source. Through electromagnetic interference in audio and flicker in indoor lighting. You can strip every byte of metadata and ENF still tells me what continent you're on. Court-accepted forensic science. Welcome to physics being on our side for once.

**AI Vision Analysis** 🧠

> Send extracted frames to Claude, GPT, Gemini, or whatever model you want. It identifies power outlet types (narrows your country real fast when you're using Type I plugs and claiming you're in Kansas), visible text and what language it's in, room features, vegetation through windows, lighting fixtures. Shows cost estimate before running because surprise API bills are their own kind of violence. Supports Anthropic, OpenAI, Google, OpenRouter, and custom endpoints.

**Metadata Groups** 📊

> Maps the distribution pipeline. Groups all your evidence by comment field, encoder, codec+resolution+fps, and file size. Same comment on 701 files? Same encoder? Same exact chain? Congratulations, you just fingerprinted whoever processed the batch. Who recorded, who re-encoded, who distributed. The pipeline has seams and this finds them.

---

## ✦ Features

**File Analyzer**

> Drop any video or image. Palimpsest extracts every piece of hidden data: camera model, GPS coordinates, timestamps, editing software, hashes, codec info, everything. Simple Mode explains each field in plain English. Advanced Mode shows raw technical data. No file size limit.

**Video-First Design**

> Videos are the primary material. Full H.264 transcoding via ffmpeg for universal playback of any format (MP4, AVI, MOV, MKV, WebM, MTS, you name it). Automatic frame extraction. Frame-by-frame stepping. Videos are not second-class citizens here.

**Forensic Video Player**

> Zoom up to 32x with mouse wheel, slider, or preset buttons. Drag to pan at any zoom level. Brightness, contrast, saturation, hue rotation, and gamma sliders. Color inversion. Frame-by-frame navigation. All controls work on images too. Because sometimes you need to see what's in the dark corner of a frame.

**Forensic Suite**

> Eight analysis modules that go deeper than basic metadata:
>
> → **Scene Analysis**: Color/brightness/texture fingerprinting. Finds videos filmed in the same room.
> → **Watermark Detection**: Finds channel stamps, bot overlays, and redistribution marks. Reveals the sharing chain.
> → **Encoding Chain Analysis**: Estimates whether a file is an original or a re-encoded copy. Measures generation loss.
> → **Screen Recording Detection**: Identifies Telegram screen grabs vs original camera captures. Checks for status bars, nav bars, phone resolutions.
> → **Lighting Analysis**: Natural vs artificial, color temperature, brightness patterns over time.
> → **Audio Fingerprinting**: Spectral analysis and energy profiling. Matches videos by ambient sound. Same room = same background noise.
> → **ENF Extraction**: Power grid frequency from audio (STFT bandpass) and video luminance (FFT). 50Hz or 60Hz. Geography from physics.
> → **AI Vision**: Frame-by-frame analysis via vision models. Outlet types, text, objects, regional clues.

**Scene Matching**

> Cross-references scene fingerprints across your whole evidence library. Same floor tiles, same wall color, same lighting setup? Flagged. Even if the camera angle is completely different.

**Audio Matching**

> Cross-references audio fingerprints. Same ambient hum, same background noise profile. Connects videos to the same physical location through sound.

**ENF Matching**

> Cross-references ENF traces. Same grid frequency, same fluctuation pattern? Recorded on the same power grid. Maybe at the same time. The grid doesn't care about your VPN.

**AI Vision Analysis**

> Pick an evidence item, see the cost estimate, click go. Each extracted frame gets sent to your configured AI provider with a forensic prompt. Results come back structured: outlet type, visible text, language, room features, lighting, objects, vegetation, region estimate, confidence score. Stored per-frame, viewable anytime.

**Metadata Groups**

> Four grouping modes: comment field (same recording tool), encoder (same encoding software), codec+resolution+fps chain (same batch processing), file size range (same parameters). Reveals the production and distribution pipeline behind a content network.

**Multi-Algorithm Hashing**

> MD5, SHA-256 (exact identity), pHash, dHash, wHash, aHash (visual fingerprints). Perceptual hashes survive re-encoding, cropping, and compression. Track the same content across platforms even after re-upload.

**Batch Processing**

> Got a folder of 700 files from an IPFS dump? Drop them all in. Each one gets fully analyzed, hashed, thumbnailed, and frame-extracted. Link them all to a suspect at once. BG_SEMAPHORE keeps it from spawning 700 ffmpeg processes and turning your machine into a space heater.

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

**61+ Tooltips**

> Hover over basically anything for an explanation. Designed to be usable by people who have never touched forensic software before.

**No File Size Limit**

> It's your machine. Your rules.

**4,163 Lines of Code**

> One developer. One cat. Pure Python. No external DLLs. Even more anger at the right things.

---

## 🚀 Installation & Setup

### Option A: Download the .exe

Go to [**Releases**](https://github.com/ephemera02/Palimpsest/releases), download the zip, extract, double-click `Palimpsest.exe`. Done.

The exe bundles everything including ffmpeg. Nothing else to install. Three files total: `Palimpsest.exe`, `palimpsest_ui.html`, `palimpsest_icon.ico`.

### Option B: Run from Source

1. Install Python 3.10+ from [python.org](https://python.org)

   * ⚠️ **CHECK "Add Python to PATH"** during install. I will not troubleshoot this for you.

2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Install ffmpeg from [ffmpeg.org](https://ffmpeg.org/download.html) and add to PATH (needed for audio forensics and ENF analysis)

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

PowerShell users: yes you need the `&` prefix. No I will not explain why. Blame Microsoft.

---

## 📁 Project Structure

| File | What It Does |
|------|------|
| `palimpsest.py` | The whole backend. Flask API, metadata extraction, forensic modules, ENF analysis, AI integration, database. 2,614 lines. |
| `palimpsest_ui.html` | The whole frontend. Single-page app with 70+ functions. 1,560 lines. |
| `palimpsest_icon.ico` | App icon. Browser tab, sidebar, taskbar, file explorer. |
| `requirements.txt` | Python dependencies. All pip-installable. |
| `build.bat` | One-click Windows exe builder. Bundles ffmpeg. |
| `README.md` | You're reading it. |

---

## 🔧 Dependencies

All pip-installable. No external DLLs.

| Package | What It Does |
|---------|------|
| Flask | Runs the local web UI |
| Pillow | Image EXIF extraction |
| imagehash | Perceptual hashing (pHash, dHash, wHash, aHash) |
| opencv-python-headless | Video analysis, frame extraction, thumbnails, forensic vision |
| hachoir | Video container metadata (creation dates, codecs, encoder info) |
| numpy | Numerical processing for forensic analysis |
| scipy | Audio spectral analysis, signal processing, ENF extraction |
| reportlab | PDF report generation |

Plus **ffmpeg** (separate install from [ffmpeg.org](https://ffmpeg.org/download.html)) for audio extraction, video transcoding, and ENF analysis. Bundled into the exe automatically by `build.bat`.

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

**ENF Extraction**

> Extracts audio at 8kHz, runs Short-Time Fourier Transform to isolate energy around 50Hz and 60Hz plus their 2nd harmonics at 100Hz and 120Hz. Computes signal-to-noise ratios against the noise floor between those frequencies. For high-framerate video (50+ fps), also extracts luminance FFT to detect AC lighting flicker as corroboration. Outputs: detected frequency, grid region classification, confidence percentage, source (audio, video, or both), and an ENF trace showing frequency fluctuations over time. The power grid is the world's largest unintentional tracking device.

**AI Vision Frame Analysis**

> Reads each extracted frame via a vision model API. Provider abstraction layer supports Anthropic (Claude Sonnet/Opus 4.5-4.6), OpenAI (GPT 5.2-5.3), Google (Gemini 3.0-3.1 Flash/Pro), OpenRouter, and custom OpenAI-compatible endpoints. Returns structured JSON: outlet type, visible text, text language, room features, lighting type, vegetation, objects, environmental clues, region estimate, confidence score. Shows cost estimate before running. Tracks cumulative spend. Your API key stays local.

---

## ⚠️ Disclaimers

**Evidence Integrity**

> Original files are never modified. Palimpsest stores copies and generates previews/thumbnails alongside the originals. Hashes are computed on the original bytes.

**Forensic Accuracy**

> The forensic modules use heuristics. Scene matching, screen recording detection, encoding analysis, and ENF classification are probabilistic, not definitive. They flag connections worth investigating. They don't prove anything on their own. ENF is court-accepted science but confidence levels vary with recording quality.

**No Warranty**

> This software is provided as-is. It works on my machine. If it breaks on yours, open an issue with details.

**Privacy**

> Palimpsest collects nothing. No telemetry, no analytics, no tracking. Everything stays on your machine. Nothing phones home. The only exception: if you use AI Vision analysis, extracted frames are sent to whichever AI provider you configured. Your API key is stored locally and only transmitted to the endpoint you chose. No frames leave your machine without you explicitly clicking "Run AI Analysis."

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

**"The ENF says indeterminate"**

> The recording was probably made on battery power away from the grid, or outdoors, or the audio is too noisy for a clean signal. ENF needs electromagnetic interference from nearby power lines or indoor lighting flicker to work. It's physics, not magic. Close though.

**"The AI Vision analysis is expensive"**

> That's why there's a cost estimator. Click "Estimate Cost" before running. At 360p with 8 frames per video, most providers run $0.02-0.08 per video. Gemini Flash is cheapest. For 700 videos that's $14-56 total. You can also just run it on the interesting ones.

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

Built with the assistance of Claude (Anthropic), who ran the forensic math, built the ENF extraction pipeline, and still didn't flinch at the subject matter.

Mascot: The Cat, who remains unbothered by your power grid frequency.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Use it. Modify it. Build on it. If it helps take down even one of these networks, that's all that matters.

---

*"She taught the power grid to snitch and honestly? Iconic."*

🐾
