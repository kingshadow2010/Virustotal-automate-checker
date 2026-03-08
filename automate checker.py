import os
import sys
import json
import winreg
import webbrowser
import subprocess
import hashlib
import multiprocessing
from tkinter import Tk, messagebox, StringVar, Label, Button, Entry, Frame, X, BOTTOM

# --- STRICT CONFIGURATION ---
# We store the config and icon in a permanent AppData folder so they don't vanish
APPDATA_DIR = os.path.join(os.environ["APPDATA"], "VTScannerPro")
CONFIG_FILE = os.path.join(APPDATA_DIR, "config.json")
ICON_FILE = os.path.join(APPDATA_DIR, "vt.ico")

if not os.path.exists(APPDATA_DIR):
    os.makedirs(APPDATA_DIR)

# --- GET PERMANENT PATHS ---
def get_main_path():
    """
    Returns the permanent path to this program.
    If running as EXE, sys.executable points to the actual .exe file.
    If running as .py, it points to the script.
    """
    return os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)

def get_api_key():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f).get("api_key")
        except: 
            return None
    return None

def save_api_key(key):
    with open(CONFIG_FILE, "w") as f:
        json.dump({"api_key": key}, f)

def ensure_requests_installed():
    """Forces installation of requests if running as script. EXEs usually bundle it."""
    try:
        import requests
        return True
    except ImportError:
        try:
            # Install silently
            subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"], 
                                   creationflags=0x08000000)
            return True
        except Exception as e:
            messagebox.showerror("Dependency Error", f"Missing 'requests' library.\nError: {e}")
            return False

def download_icon_robust():
    """Saves the VT icon to a permanent location in AppData."""
    if os.path.exists(ICON_FILE):
        return True
    if not ensure_requests_installed():
        return False
    import requests
    url = "https://www.virustotal.com/gui/images/favicon.ico"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            with open(ICON_FILE, "wb") as f:
                f.write(response.content)
            return True
    except:
        pass
    return False

def nuke_old_registry_entries():
    """Wipes out all previous/broken registry attempts."""
    bad_keys = ["Scan with VirusTotal", "ScanWithVirusTotal", "ScanWithVT", "VirusTotal", "Scan_with_VirusTotal"]
    for key_name in bad_keys:
        reg_path = f"HKCU\\Software\\Classes\\*\\shell\\{key_name}"
        subprocess.run(["reg", "delete", reg_path, "/f"], 
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                       creationflags=0x08000000)

def register_context_menu():
    """Points the context menu to the permanent EXE or script location."""
    if not get_api_key():
        messagebox.showwarning("Hold On", "You need to save your API Key first!")
        return

    nuke_old_registry_entries()
    has_icon = download_icon_robust()

    main_path = get_main_path()
    
    # Logic: If it's a script, we need pythonw. If it's an EXE, we call the EXE directly.
    if main_path.lower().endswith(".py"):
        python_exe = sys.executable.replace("python.exe", "pythonw.exe")
        command = f'"{python_exe}" "{main_path}" "%1"'
    else:
        # This is the fix for your "could not find file" error:
        # It now uses the actual location of your compiled EXE.
        command = f'"{main_path}" "%1"'
    
    try:
        key_path = r"Software\Classes\*\shell\ScanWithVirusTotal"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "Scan with VirusTotal")
            if has_icon and os.path.exists(ICON_FILE):
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, ICON_FILE)
                
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path + r"\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, command)
            
        messagebox.showinfo("Success", f"Registry Fixed!\nPointing to: {main_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Registry Error: {e}")

# --- SCANNER LOGIC ---
def perform_upload_and_scan(filepath):
    """The logic that runs when you right-click a file."""
    api_key = get_api_key()
    if not api_key or not os.path.exists(filepath):
        return

    import requests

    # 1. Local Hash
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # 2. Upload
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            requests.post("https://www.virustotal.com/api/v3/files", 
                          headers={"x-apikey": api_key}, 
                          files=files, timeout=30)
        
        # 3. Redirect to Results
        webbrowser.open(f"https://www.virustotal.com/gui/file/{file_hash}")
    except Exception as e:
        # Since this runs without a console, we use a hidden TK window for errors
        root = Tk(); root.withdraw()
        messagebox.showerror("Scan Error", str(e))

def main_gui():
    root = Tk()
    root.title("VT Setup Pro")
    root.geometry("400x230")
    
    # Try to set the icon for the setup window
    if download_icon_robust() and os.path.exists(ICON_FILE):
        try: root.iconbitmap(ICON_FILE)
        except: pass

    Label(root, text="VirusTotal File Scanner Setup", font=("Arial", 12, "bold")).pack(pady=15)
    
    api_frame = Frame(root); api_frame.pack(fill=X, padx=20)
    Label(api_frame, text="API Key:").pack(side="left")
    api_var = StringVar(value=get_api_key() or "")
    Entry(api_frame, textvariable=api_var, show="*").pack(side="left", fill=X, expand=True, padx=5)
    
    def on_save():
        save_api_key(api_var.get().strip())
        messagebox.showinfo("Saved", "API Key saved to AppData.")

    Button(root, text="1. Save API Key", command=on_save, width=25).pack(pady=10)
    Button(root, text="2. Add to context menu", command=register_context_menu, width=25, bg="#005fb8", fg="white").pack(pady=5)
    
    Label(root, text="Move this EXE to a permanent folder before clicking add to context menu.", fg="red", font=("Arial", 8)).pack(side=BOTTOM, pady=5)
    root.mainloop()

if __name__ == "__main__":
    # Required for Windows EXEs to avoid crashes
    multiprocessing.freeze_support()
    
    if len(sys.argv) > 1:
        # Run scan if a file was passed as an argument
        perform_upload_and_scan(sys.argv[1])
    else:
        # Otherwise, show the setup UI
        main_gui()