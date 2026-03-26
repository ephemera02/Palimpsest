@echo off
REM Palimpsest v3.0 - Build Script
REM https://ephemeradev.net | github.com/ephemera02

echo [*] Installing dependencies...
pip install -r requirements.txt

echo [*] Building executable...
REM Bundle ffmpeg.exe so end users don't need to install it
set FFMPEG_PATH=C:\ffmpeg\bin\ffmpeg.exe
if not exist "%FFMPEG_PATH%" (
    echo [!] ffmpeg.exe not found at %FFMPEG_PATH%. Audio forensics will require manual ffmpeg install.
    set FFMPEG_FLAG=
) else (
    echo [*] Bundling ffmpeg.exe into build...
    set FFMPEG_FLAG=--add-binary "C:\ffmpeg\bin\ffmpeg.exe;."
)

pyinstaller --onefile --noconsole --name Palimpsest ^
    --icon "palimpsest_icon.ico" ^
    --add-data "palimpsest_ui.html;." ^
    --add-data "palimpsest_icon.ico;." ^
    %FFMPEG_FLAG% ^
    --hidden-import=flask ^
    --hidden-import=PIL ^
    --hidden-import=imagehash ^
    --hidden-import=cv2 ^
    --hidden-import=hachoir ^
    --hidden-import=hachoir.parser ^
    --hidden-import=hachoir.metadata ^
    --hidden-import=numpy ^
    --hidden-import=scipy ^
    --hidden-import=scipy.signal ^
    --hidden-import=scipy.io ^
    --hidden-import=reportlab ^
    palimpsest.py

echo.
echo [*] Done! Executable: dist\Palimpsest.exe
echo [*] Copy palimpsest_ui.html and palimpsest_icon.ico next to the exe.
echo [*] ffmpeg is bundled. Users just run the exe. Nothing else to install.
pause
