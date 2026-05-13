import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from datetime import datetime
from typing import Callable, Optional, Dict
import os
import time
import sys
import subprocess
import platform

# Import your backend class
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wifiwpa import crackwifi

# ============================================================================
# COLOR SCHEME - Cybersecurity Command Center Design System
# ============================================================================
class Colors:
    """Cybersecurity-themed color palette"""
    BACKGROUND = "#0c0f0a"
    SURFACE = "#141e12"
    SURFACE_HIGH = "#1a2a18"
    SURFACE_HIGHER = "#223020"
    BORDER = "#3b4b37"
    
    PRIMARY = "#00ff41"
    PRIMARY_DIM = "#00cc33"
    PRIMARY_DARK = "#008822"
    
    ACCENT = "#00e5ff"
    ACCENT_DIM = "#00b8d4"
    
    ON_SURFACE = "#e0e8d8"
    ON_SURFACE_VARIANT = "#b0c0a8"
    ON_BACKGROUND = "#d0d8c8"
    
    ERROR = "#ff5252"
    WARNING = "#ffd740"
    SUCCESS = "#69f0ae"
    INFO = "#40c4ff"
    
    TERM_BG = "#0a0f08"
    TERM_FG = "#00ff41"
    TERM_SUCCESS = "#69f0ae"
    TERM_ERROR = "#ff5252"
    TERM_WARNING = "#ffd740"
    TERM_INFO = "#40c4ff"

# ============================================================================
# GLOBAL STATE
# ============================================================================
class AppState:
    """Global application state"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.password = None
            self.monitor_mode_active = False
            self.scanned_networks = {}
            self.current_scan_results = []
            self.cracker = None
            self.handshake_captured = False
            self.crack_target: Optional[Dict[str, str]] = None
            self._initialized = True
    
    def set_password(self, password: str):
        self.password = password
        self.cracker = crackwifi(password)
    
    def get_password(self) -> str | None:
        return self.password
    
    def get_cracker(self):
        return self.cracker

# ============================================================================
# BACKEND INTERFACE
# ============================================================================
class BackendInterface:
    """Interface for connecting to crackwifi backend"""
    
    @staticmethod
    def initialize_system(callback: Callable) -> None:
        def init_thread():
            try:
                cracker = AppState().get_cracker()
                if not cracker:
                    callback({"status": "error", "message": "Password not set"})
                    return
                
                callback({"status": "progress", "message": "Checking WiFi compatibility..."})
                result = cracker.check_wifi_compatibility()
                
                if not result:
                    callback({"status": "error", "message": "WiFi compatibility check failed"})
                    return
                
                callback({"status": "progress", "message": "Starting monitor mode..."})
                cracker.starting_monitor_mode()
                AppState().monitor_mode_active = True
                
                callback({
                    "status": "success",
                    "message": "System initialized. Monitor mode active on wlan0mon"
                })
            except Exception as e:
                callback({
                    "status": "error",
                    "message": f"Initialization failed: {str(e)}"
                })
        
        threading.Thread(target=init_thread, daemon=True).start()
    
    @staticmethod
    def start_monitor_mode(callback: Callable) -> None:
        """Start monitor mode only (without full initialization)"""
        def start_thread():
            try:
                cracker = AppState().get_cracker()
                if not cracker:
                    callback({"status": "error", "message": "Password not set"})
                    return
                
                callback({"status": "progress", "message": "Starting monitor mode..."})
                cracker.starting_monitor_mode()
                AppState().monitor_mode_active = True
                
                callback({
                    "status": "success",
                    "message": "Monitor mode enabled on wlan0mon"
                })
            except Exception as e:
                callback({
                    "status": "error",
                    "message": f"Failed to start monitor mode: {str(e)}"
                })
        
        threading.Thread(target=start_thread, daemon=True).start()
    
    @staticmethod
    def start_network_scan(callback: Callable, scan_time: int = 20) -> None:
        def scan_thread():
            try:
                cracker = AppState().get_cracker()
                if not cracker:
                    callback({"status": "error", "message": "System not initialized"})
                    return
                
                if not AppState().monitor_mode_active:
                    callback({"status": "error", "message": "Monitor mode not active. Initialize system first."})
                    return
                
                callback({"status": "progress", "message": f"Scanning for networks ({scan_time}s)..."})
                
                networks = cracker.get_target_visible_terminal(scan_time=scan_time)
                
                if not networks:
                    callback({"status": "error", "message": "No networks found or scan failed"})
                    return
                
                AppState().scanned_networks = networks
                formatted_networks = []
                for name, info in networks.items():
                    formatted_networks.append({
                        "name": name,
                        "ssid": info.get('essid', '<Hidden>'),
                        "bssid": info.get('bssid', 'Unknown'),
                        "channel": info.get('channel', 'Unknown'),
                        "signal": "N/A",
                        "security": "WPA/WPA2"
                    })
                
                AppState().current_scan_results = formatted_networks
                
                callback({
                    "status": "success",
                    "networks": formatted_networks,
                    "raw_data": networks
                })
            except Exception as e:
                callback({"status": "error", "message": f"Scan failed: {str(e)}"})
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    @staticmethod
    def capture_handshake(network_info: dict, deauth_count: int, callback: Callable) -> None:
        def capture_thread():
            try:
                cracker = AppState().get_cracker()
                if not cracker:
                    callback({"status": "error", "message": "System not initialized"})
                    return
                
                if not AppState().monitor_mode_active:
                    callback({"status": "error", "message": "Monitor mode not active"})
                    return
                
                bssid = network_info.get('bssid', '')
                essid = network_info.get('ssid', '') or network_info.get('essid', '')
                channel = int(network_info.get('channel', 1))
                
                callback({"status": "progress", "message": f"Target: {essid} ({bssid})"})
                callback({"status": "progress", "message": f"Channel: {channel}"})
                callback({"status": "progress", "message": f"Sending {deauth_count} deauth packets..."})
                callback({"status": "progress", "message": "Capturing handshake..."})
                
                success = cracker.get_handshake(bssid, channel, essid, deauth_count)
                
                if success:
                    AppState().handshake_captured = True
                    callback({
                        "status": "success",
                        "message": "Handshake captured successfully!",
                        "essid": essid,
                        "bssid": bssid,
                        "channel": channel
                    })
                else:
                    callback({
                        "status": "error",
                        "message": "Failed to capture handshake. Try increasing deauth packets."
                    })
            except Exception as e:
                callback({"status": "error", "message": f"Capture failed: {str(e)}"})
        
        threading.Thread(target=capture_thread, daemon=True).start()
    

    @staticmethod
    def crack_password(callback: Callable, wordlist_path: Optional[str] = None) -> None:
        """Crack captured handshake"""
        def crack_thread(wl_path):
            try:
                cracker = AppState().get_cracker()
                if not cracker:
                    callback({"status": "error", "message": "System not initialized"})
                    return
                
                if not wl_path:
                    wl_path = '/usr/share/wordlists/rockyou.txt'
                
                # Search for capture file
                possible_paths = [
                    os.path.join(os.getcwd(), 'handshakes', 'capture-01.cap'),
                    os.path.join(os.getcwd(), 'capture-01.cap'),
                    '/tmp/capture-01.cap',
                ]
                
                cap_path = None
                for path in possible_paths:
                    if os.path.exists(path):
                        cap_path = path
                        break
                
                if not cap_path:
                    callback({"status": "error", "message": "No capture file found!"})
                    return
                
                if not os.path.exists(wl_path):
                    callback({"status": "error", "message": f"Wordlist not found: {wl_path}"})
                    return
                
                callback({"status": "progress", "message": "Starting cracking..."})
                
                # Progress callback - just forwards to UI
                def on_progress(update):
                    callback(update)
                
                # Call crack_handshake with original return format
                result = cracker.crack_handshake(wl_path, cap_path, progress_callback=on_progress)
                
                if result.get('password'):
                    callback({
                        "status": "success",
                        "message": "Password cracked!",
                        "password": result['password'],
                        "progress": "100%"
                    })
                else:
                    callback({
                        "status": "error",
                        "message": "Password not found in wordlist."
                    })
            except Exception as e:
                callback({"status": "error", "message": f"Cracking error: {str(e)}"})
        
        threading.Thread(target=crack_thread, args=(wordlist_path,), daemon=True).start()
            
    @staticmethod
    def shutdown_system(callback: Callable) -> None:
        def shutdown_thread():
            try:
                cracker = AppState().get_cracker()
                if not cracker:
                    callback({"status": "error", "message": "System not initialized"})
                    return
                
                if AppState().monitor_mode_active:
                    callback({"status": "progress", "message": "Stopping monitor mode..."})
                    cracker.stop_monitor_mode()
                    AppState().monitor_mode_active = False
                    callback({
                        "status": "success",
                        "message": "System shutdown complete. Network services restored."
                    })
                else:
                    callback({
                        "status": "success",
                        "message": "System already shut down"
                    })
            except Exception as e:
                callback({
                    "status": "error",
                    "message": f"Shutdown failed: {str(e)}"
                })
        
        threading.Thread(target=shutdown_thread, daemon=True).start()

    @staticmethod
    def check_aircrack_installed(callback: Callable) -> Dict[str, any]: # type: ignore
        """Check if aircrack-ng is installed"""
        def check_thread():
            try:
                # Try to run aircrack-ng --version
                import subprocess
                result = subprocess.run(
                    ["which", "aircrack-ng"],
                    capture_output=True,
                    timeout=5
                )
                
                installed = result.returncode == 0
                
                callback({
                    "status": "success",
                    "installed": installed
                })
                
                return {"installed": installed}
            except Exception as e:
                callback({
                    "status": "error",
                    "installed": False,
                    "error": str(e)
                })
                return {"installed": False, "error": str(e)}
        threading.Thread(target=check_thread, daemon=True).start()
        return check_thread()

    @staticmethod
    def install_aircrack(callback: Callable) -> None:
        """Install aircrack-ng using system package manager"""
        def install_thread():
            try:
                
                
                
                callback({"status": "progress", "message": "Starting installation..."})
                
                system = platform.system().lower()
                
                if "linux" in system:
                    callback({"status": "progress", "message": "Updating package lists..."})
                    
                    # Update package manager
                    subprocess.run(
                        ["sudo", "apt-get", "update"],
                        check=False,
                        timeout=60
                    )
                    
                    callback({"status": "progress", "message": "Installing aircrack-ng..."})
                    
                    # Install aircrack-ng
                    result = subprocess.run(
                        ["sudo", "apt-get", "install", "-y", "aircrack-ng"],
                        capture_output=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        callback({
                            "status": "success",
                            "message": "Aircrack-ng installed successfully!"
                        })
                    else:
                        error = result.stderr.decode() if result.stderr else "Installation failed"
                        callback({
                            "status": "error",
                            "message": error
                        })
                else:
                    callback({
                        "status": "error",
                        "message": f"Automatic installation not supported on {system}. Please install aircrack-ng manually."
                    })
            
            except subprocess.TimeoutExpired:
                callback({
                    "status": "error",
                    "message": "Installation timed out. Check your sudo password and try again."
                })
            except Exception as e:
                callback({
                    "status": "error",
                    "message": f"Installation failed: {str(e)}"
                })
        
        threading.Thread(target=install_thread, daemon=True).start()



# ============================================================================
# CUSTOM WIDGETS
# ============================================================================
class StyledButton(tk.Button):
    """Custom button styled for cybersecurity theme"""
    def __init__(self, parent, text="", command=None, variant="default", **kwargs):
        colors_map = {
            "default": (Colors.SURFACE_HIGHER, Colors.PRIMARY),
            "primary": (Colors.PRIMARY_DARK, "#000000"),
            "danger": (Colors.ERROR, "#ffffff"),
            "success": (Colors.SUCCESS, "#000000"),
        }
        bg, fg = colors_map.get(variant, colors_map["default"])
        
        # Get custom padding if provided, otherwise use defaults
        custom_padx = kwargs.pop('padx', 16)
        custom_pady = kwargs.pop('pady', 8)
        
        super().__init__(
            parent,
            text=text,
            command=command, # type: ignore
            bg=bg,
            fg=fg,
            font=("Inter", 10, "bold"),
            activebackground=Colors.PRIMARY_DIM,
            activeforeground="#000000",
            relief=tk.FLAT,
            padx=custom_padx,
            pady=custom_pady,
            cursor="hand2",
            bd=0,
            highlightthickness=0,
            **kwargs
        )
        self._default_bg = bg
        self._default_fg = fg
        self.bind("<Enter>", self.on_hover)
        self.bind("<Leave>", self.on_leave)
    
    def on_hover(self, event):
        if self['state'] != tk.DISABLED:
            self.config(bg=Colors.PRIMARY, fg="#000000")
    
    def on_leave(self, event):
        if self['state'] != tk.DISABLED:
            self.config(bg=self._default_bg, fg=self._default_fg)

class TerminalPanel(tk.Frame):
    """Styled terminal/console panel"""
    def __init__(self, parent, title="TERMINAL", height=10, **kwargs):
        super().__init__(parent, bg=Colors.SURFACE_HIGH, **kwargs)
        
        header = tk.Frame(self, bg=Colors.SURFACE_HIGH)
        header.pack(fill=tk.X, padx=1, pady=(1, 0))
        
        tk.Label(
            header,
            text=f"◆ {title} ▶",
            bg=Colors.SURFACE_HIGH,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9, "bold")
        ).pack(side=tk.LEFT, padx=8, pady=4)
        
        StyledButton(
            header,
            text="CLEAR",
            command=self.clear,
            variant="default"
        ).pack(side=tk.RIGHT, padx=4, pady=2)
        
        self.output = scrolledtext.ScrolledText(
            self,
            bg=Colors.TERM_BG,
            fg=Colors.TERM_FG,
            font=("JetBrains Mono", 9),
            height=height,
            relief=tk.FLAT,
            insertbackground=Colors.PRIMARY,
            selectbackground=Colors.PRIMARY_DIM,
            selectforeground="#000000",
            wrap=tk.WORD
        )
        self.output.pack(fill=tk.BOTH, expand=True, padx=1, pady=(0, 1))
        self.output.config(state=tk.DISABLED)
        
        tag_colors = {
            "info": Colors.TERM_FG,
            "success": Colors.TERM_SUCCESS,
            "error": Colors.TERM_ERROR,
            "warning": Colors.TERM_WARNING,
            "primary": Colors.PRIMARY,
            "accent": Colors.ACCENT,
        }
        for tag_name, color in tag_colors.items():
            self.output.tag_configure(tag_name, foreground=color)
    
    def add_line(self, text: str, tag: str = "info"):
        self.output.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {text}\n"
        self.output.insert(tk.END, line, tag)
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)
    
    def clear(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete(1.0, tk.END)
        self.output.config(state=tk.DISABLED)

class NetworkCard(tk.Frame):
    """Card widget displaying network information - CLICKABLE"""
    def __init__(self, parent, network: dict, on_select: Callable, **kwargs):
        super().__init__(parent, bg=Colors.SURFACE, cursor="hand2", **kwargs)
        self.network = network
        self.on_select = on_select
        self.selected = False
        
        self.bind("<Button-1>", self._on_click)
        
        content = tk.Frame(self, bg=Colors.SURFACE, padx=12, pady=8)
        content.pack(fill=tk.BOTH, expand=True)
        content.bind("<Button-1>", self._on_click)
        
        ssid = network.get('ssid', 'Unknown')
        if len(ssid) > 25:
            ssid = ssid[:22] + "..."
        
        self.ssid_label = tk.Label(
            content,
            text=ssid,
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 11, "bold"),
            anchor="w"
        )
        self.ssid_label.pack(fill=tk.X)
        self.ssid_label.bind("<Button-1>", self._on_click)
        
        details_frame = tk.Frame(content, bg=Colors.SURFACE)
        details_frame.pack(fill=tk.X, pady=(4, 0))
        details_frame.bind("<Button-1>", self._on_click)
        
        self.ch_label = tk.Label(
            details_frame,
            text=f"CH: {network.get('channel', '?')}",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 8)
        )
        self.ch_label.pack(side=tk.LEFT, padx=(0, 12))
        self.ch_label.bind("<Button-1>", self._on_click)
        
        self.sec_label = tk.Label(
            details_frame,
            text=f"{network.get('security', 'WPA2')}",
            bg=Colors.SURFACE,
            fg=Colors.WARNING,
            font=("JetBrains Mono", 8)
        )
        self.sec_label.pack(side=tk.LEFT)
        self.sec_label.bind("<Button-1>", self._on_click)
        
        self.bssid_label = tk.Label(
            details_frame,
            text=network.get('bssid', ''),
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        )
        self.bssid_label.pack(side=tk.RIGHT)
        self.bssid_label.bind("<Button-1>", self._on_click)
        
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        
        self._all_widgets = [self, content, details_frame,
                            self.ssid_label, self.ch_label,
                            self.sec_label, self.bssid_label]
    
    def _on_click(self, event):
        self.on_select(self)
        return "break"
    
    def _on_enter(self, event):
        if not self.selected:
            for widget in self._all_widgets:
                try:
                    widget.config(bg=Colors.SURFACE_HIGH)
                except:
                    pass
    
    def _on_leave(self, event):
        if not self.selected:
            for widget in self._all_widgets:
                try:
                    widget.config(bg=Colors.SURFACE)
                except:
                    pass
    
    def set_selected(self, selected: bool):
        self.selected = selected
        new_bg = Colors.PRIMARY_DARK if selected else Colors.SURFACE
        for widget in self._all_widgets:
            try:
                widget.config(bg=new_bg)
            except:
                pass

class StatusBar(tk.Frame):
    """Status bar widget"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Colors.SURFACE_HIGH, height=30, **kwargs)
        self.pack_propagate(False)
        
        self.status_label = tk.Label(
            self,
            text="● SYSTEM READY",
            bg=Colors.SURFACE_HIGH,
            fg=Colors.SUCCESS,
            font=("JetBrains Mono", 9)
        )
        self.status_label.pack(side=tk.LEFT, padx=12, pady=4)
        
        self.mode_label = tk.Label(
            self,
            text="MONITOR: OFF",
            bg=Colors.SURFACE_HIGH,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 9)
        )
        self.mode_label.pack(side=tk.RIGHT, padx=12, pady=4)
    
    def set_status(self, text: str, color: str = Colors.SUCCESS):
        self.status_label.config(text=text, fg=color)
    
    def set_monitor_mode(self, active: bool):
        if active:
            self.mode_label.config(text="MONITOR: ON", fg=Colors.PRIMARY)
        else:
            self.mode_label.config(text="MONITOR: OFF", fg=Colors.ON_SURFACE_VARIANT)

# ============================================================================
# SCREENS
# ============================================================================
class AircrackCheckScreen(tk.Frame):
    """Check if aircrack-ng is installed, prompt to install if not"""
    def __init__(self, parent, on_aircrack_ready: Callable, **kwargs):
        super().__init__(parent, bg=Colors.BACKGROUND, **kwargs)
        self.on_aircrack_ready = on_aircrack_ready
        
        center = tk.Frame(self, bg=Colors.BACKGROUND)
        center.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        
        tk.Label(
            center,
            text="WiFi Auditor Suite v2.0",
            bg=Colors.BACKGROUND,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 16, "bold")
        ).pack(pady=(0, 5))
        
        tk.Label(
            center,
            text="System Dependency Check",
            bg=Colors.BACKGROUND,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("Inter", 10)
        ).pack(pady=(0, 30))
        
        check_frame = tk.Frame(center, bg=Colors.SURFACE, padx=20, pady=20)
        check_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            check_frame,
            text="◆ CHECKING DEPENDENCIES",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 10, "bold")
        ).pack(anchor="w", pady=(0, 15))
        
        # Aircrack-ng check item
        check_item_frame = tk.Frame(check_frame, bg=Colors.SURFACE)
        check_item_frame.pack(anchor="w", fill=tk.X, pady=8)
        
        self.aircrack_status_label = tk.Label(
            check_item_frame,
            text="⟳ aircrack-ng",
            bg=Colors.SURFACE,
            fg=Colors.WARNING,
            font=("JetBrains Mono", 9)
        )
        self.aircrack_status_label.pack(side=tk.LEFT)
        
        self.aircrack_result_label = tk.Label(
            check_item_frame,
            text="Checking...",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 8)
        )
        self.aircrack_result_label.pack(side=tk.RIGHT)
        
        self.progress = ttk.Progressbar(
            check_frame,
            length=300,
            mode='indeterminate',
            style='Cyber.Horizontal.TProgressbar'
        )
        self.progress.pack(pady=(15, 0))
        self.progress.start()
        
        self.status_label = tk.Label(
            center,
            text="",
            bg=Colors.BACKGROUND,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9)
        )
        self.status_label.pack(pady=(20, 0))
        
        # Buttons frame (initially hidden)
        self.button_frame = tk.Frame(center, bg=Colors.BACKGROUND)
        self.button_frame.pack(pady=(20, 0))
        
        self.install_button = StyledButton(
            self.button_frame,
            text="▶ INSTALL AIRCRACK-NG",
            command=self.install_aircrack,
            variant="primary"
        )
        self.install_button.pack(side=tk.LEFT, padx=4)
        self.install_button.config(state=tk.DISABLED)
        
        self.continue_button = StyledButton(
            self.button_frame,
            text="▶ CONTINUE",
            command=self.on_aircrack_ready,
            variant="success"
        )
        self.continue_button.pack(side=tk.LEFT, padx=4)
        self.continue_button.config(state=tk.DISABLED)
        
        tk.Label(
            center,
            text="Build 2024.1 | Linux Edition",
            bg=Colors.BACKGROUND,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        ).pack(pady=(30, 0))
        
        # Start checking
        self.check_dependencies()
    
    def check_dependencies(self):
        """Check if aircrack-ng is installed"""
        def check_thread():
            try:
                # Try to import/check aircrack-ng
                result = BackendInterface.check_aircrack_installed(lambda x: None)
                self.after(0, lambda: self._on_check_complete(result))
            except Exception as e:
                self.after(0, lambda: self._on_check_complete({"installed": False, "error": str(e)}))
        
        threading.Thread(target=check_thread, daemon=True).start()
    
    def _on_check_complete(self, result):
        """Handle check completion"""
        self.progress.stop()
        self.progress.pack_forget()
        
        if result.get("installed"):
            # Aircrack-ng is installed
            self.aircrack_status_label.config(text="✓ aircrack-ng", fg=Colors.SUCCESS)
            self.aircrack_result_label.config(
                text="Installed",
                fg=Colors.SUCCESS
            )
            self.status_label.config(text="All dependencies ready!", fg=Colors.SUCCESS)
            self.continue_button.config(state=tk.NORMAL)
        else:
            # Aircrack-ng is NOT installed
            self.aircrack_status_label.config(text="✗ aircrack-ng", fg=Colors.ERROR)
            self.aircrack_result_label.config(
                text="Not installed",
                fg=Colors.ERROR
            )
            self.status_label.config(
                text="Please install aircrack-ng to continue",
                fg=Colors.ERROR
            )
            self.install_button.config(state=tk.NORMAL)
    
    def install_aircrack(self):
        """Start aircrack-ng installation"""
        response = messagebox.askyesno(
            "Install Aircrack-ng",
            "This will install aircrack-ng and its dependencies.\n\n"
            "You may be prompted for your sudo password.\n\n"
            "Continue with installation?"
        )
        
        if not response:
            return
        
        self.install_button.config(state=tk.DISABLED, text="INSTALLING...")
        self.status_label.config(text="Installing aircrack-ng...", fg=Colors.WARNING)
        
        def on_install_complete(result):
            if result.get("status") == "success":
                self.status_label.config(
                    text="✓ Aircrack-ng installed successfully!",
                    fg=Colors.SUCCESS
                )
                self.aircrack_status_label.config(text="✓ aircrack-ng", fg=Colors.SUCCESS)
                self.aircrack_result_label.config(text="Installed", fg=Colors.SUCCESS)
                self.continue_button.config(state=tk.NORMAL)
                self.install_button.config(state=tk.DISABLED)
                self.after(1500, self.on_aircrack_ready)
            else:
                self.install_button.config(state=tk.NORMAL, text="▶ INSTALL AIRCRACK-NG")
                error_msg = result.get("message", "Installation failed")
                self.status_label.config(text=f"✗ {error_msg}", fg=Colors.ERROR)
                messagebox.showerror("Installation Failed", error_msg)
        
        BackendInterface.install_aircrack(on_install_complete)



class SplashScreen(tk.Frame):
    """Splash/initialization screen with password entry"""
    def __init__(self, parent, on_continue: Callable, **kwargs):
        super().__init__(parent, bg=Colors.BACKGROUND, **kwargs)
        self.on_continue = on_continue
        
        center = tk.Frame(self, bg=Colors.BACKGROUND)
        center.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        
        tk.Label(
            center,
            text="WiFi Auditor Suite v2.0",
            bg=Colors.BACKGROUND,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 16, "bold")
        ).pack(pady=(0, 5))
        
        tk.Label(
            center,
            text="Cybersecurity Command Center",
            bg=Colors.BACKGROUND,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("Inter", 10)
        ).pack(pady=(0, 30))
        
        password_frame = tk.Frame(center, bg=Colors.SURFACE, padx=20, pady=20)
        password_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            password_frame,
            text="ENTER SUDO PASSWORD",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 10, "bold")
        ).pack(anchor="w", pady=(0, 10))
        
        tk.Label(
            password_frame,
            text="Required for monitor mode and network operations",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("Inter", 8)
        ).pack(anchor="w", pady=(0, 10))
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="•",
            bg=Colors.TERM_BG,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 12),
            insertbackground=Colors.PRIMARY,
            relief=tk.FLAT,
            width=30
        )
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.password_entry.focus()
        self.password_entry.bind("<Return>", lambda e: self.initialize())
        
        self.error_label = tk.Label(
            password_frame,
            text="",
            bg=Colors.SURFACE,
            fg=Colors.ERROR,
            font=("Inter", 8)
        )
        self.error_label.pack(anchor="w")
        
        self.init_button = StyledButton(
            center,
            text="▶ INITIALIZE SYSTEM",
            command=self.initialize,
            variant="primary"
        )
        self.init_button.pack(pady=(20, 10))
        
        self.progress = ttk.Progressbar(
            center,
            length=300,
            mode='indeterminate',
            style='Cyber.Horizontal.TProgressbar'
        )
        
        self.status_label = tk.Label(
            center,
            text="",
            bg=Colors.BACKGROUND,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9)
        )
        self.status_label.pack(pady=(10, 0))
        
        tk.Label(
            center,
            text="Build 2024.1 | Linux Edition",
            bg=Colors.BACKGROUND,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        ).pack(pady=(30, 0))
    
    def initialize(self):
        password = self.password_var.get().strip()
        
        if not password:
            self.error_label.config(text="⚠ Password cannot be empty")
            return
        
        AppState().set_password(password)
        self.error_label.config(text="")
        
        self.password_entry.config(state=tk.DISABLED)
        self.init_button.config(state=tk.DISABLED, text="INITIALIZING...")
        
        self.progress.pack(pady=(10, 0))
        self.progress.start()
        self.status_label.config(text="Checking WiFi compatibility...")
        
        def on_init_complete(results):
            self.progress.stop()
            self.progress.pack_forget()
            
            if results.get("status") == "success":
                self.status_label.config(text="✓ " + results.get("message"))
                AppState().monitor_mode_active = True
                self.after(1500, self.on_continue)
            elif results.get("status") == "progress":
                self.status_label.config(text="⟳ " + results.get("message"))
            else:
                self.status_label.config(text="✗ " + results.get("message"))
                self.init_button.config(state=tk.NORMAL, text="RETRY")
                self.password_entry.config(state=tk.NORMAL)
                self.error_label.config(text="⚠ " + results.get("message"))
        
        BackendInterface.initialize_system(on_init_complete)


class DashboardScreen(tk.Frame):
    """Main dashboard with tabbed navigation"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Colors.BACKGROUND, **kwargs)
        
        self._cracking = False
        self._crack_start_time = 0
        
        self.create_top_bar()
        self.create_tab_navigation()
        
        self.content_frame = tk.Frame(self, bg=Colors.BACKGROUND)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        
        self.pages = {}
        self.create_scan_page()
        self.create_crack_page()
        self.create_settings_page()
        self.create_logs_page()
        
        self.status_bar = StatusBar(self)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_bar.set_monitor_mode(True)
        
        self.show_page("scan")
    
    def create_top_bar(self):
        top_bar = tk.Frame(self, bg=Colors.SURFACE_HIGH, height=50)
        top_bar.pack(fill=tk.X, side=tk.TOP)
        top_bar.pack_propagate(False)
        
        tk.Label(
            top_bar,
            text="◆ CYBER_OS COMMAND CENTER ▶",
            bg=Colors.SURFACE_HIGH,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 11, "bold")
        ).pack(side=tk.LEFT, padx=16, pady=12)
        
        controls = tk.Frame(top_bar, bg=Colors.SURFACE_HIGH)
        controls.pack(side=tk.RIGHT, padx=8)
        
        # START MONITOR button
        StyledButton(
            controls,
            text="▶ START MONITOR",
            command=self.start_monitor_mode,
            variant="primary"
        ).pack(side=tk.RIGHT, padx=4, pady=8)
        
        # STOP MONITOR button
        StyledButton(
            controls,
            text="⏻ STOP MONITOR",
            command=self.shutdown_monitor,
            variant="danger"
        ).pack(side=tk.RIGHT, padx=4, pady=8)
        
        StyledButton(
            controls,
            text="↻ REFRESH",
            command=self.refresh_current_page,
            variant="default"
        ).pack(side=tk.RIGHT, padx=4, pady=8)
    
    def create_tab_navigation(self):
        tab_frame = tk.Frame(self, bg=Colors.SURFACE)
        tab_frame.pack(fill=tk.X, padx=8, pady=(0, 0))
        
        self.tab_buttons = {}
        tabs = [
            ("scan", "📡 NETWORK SCAN"),
            ("crack", "🔓 CRACK WPA"),
            ("settings", "⚙ SETTINGS"),
            ("logs", "📋 SYSTEM LOGS"),
        ]
        
        for tab_id, tab_text in tabs:
            btn = tk.Button(
                tab_frame,
                text=tab_text,
                command=lambda t=tab_id: self.show_page(t),
                bg=Colors.SURFACE,
                fg=Colors.ON_SURFACE_VARIANT,
                font=("JetBrains Mono", 9, "bold"),
                relief=tk.FLAT,
                padx=20,
                pady=10,
                cursor="hand2",
                bd=0,
                activebackground=Colors.PRIMARY_DARK,
                activeforeground="#000000"
            )
            btn.pack(side=tk.LEFT)
            self.tab_buttons[tab_id] = btn
    
    def show_page(self, page_name: str):
        for tab_id, btn in self.tab_buttons.items():
            if tab_id == page_name:
                btn.config(bg=Colors.PRIMARY_DARK, fg="#000000")
            else:
                btn.config(bg=Colors.SURFACE, fg=Colors.ON_SURFACE_VARIANT)
        
        if page_name in self.pages:
            for page in self.pages.values():
                page.pack_forget()
            self.pages[page_name].pack(fill=tk.BOTH, expand=True)
            
            if page_name == "crack":
                self.update_crack_target()
    
    def create_scan_page(self):
        """Create network scanning page with clickable network cards"""
        page = tk.Frame(self.content_frame, bg=Colors.BACKGROUND)
        self.pages["scan"] = page
        
        left_panel = tk.Frame(page, bg=Colors.SURFACE, width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))
        left_panel.pack_propagate(False)
        
        tk.Label(
            left_panel,
            text="◇ SCAN CONTROLS",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 10, "bold")
        ).pack(anchor="w", padx=12, pady=12)
        
        tk.Label(
            left_panel,
            text="SCAN DURATION (seconds)",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 8)
        ).pack(anchor="w", padx=12, pady=(8, 4))
        
        self.scan_time_var = tk.IntVar(value=20)
        scan_time_scale = tk.Scale(
            left_panel,
            from_=5,
            to=60,
            orient=tk.HORIZONTAL,
            variable=self.scan_time_var,
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            troughcolor=Colors.SURFACE_HIGH,
            highlightthickness=0,
            length=200
        )
        scan_time_scale.pack(fill=tk.X, padx=12, pady=(0, 8))
        
        self.scan_button = StyledButton(
            left_panel,
            text="▶ START SCAN",
            command=self.start_scan,
            variant="primary"
        )
        self.scan_button.pack(fill=tk.X, padx=12, pady=8)
        
        ttk.Separator(left_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=8)
        
        tk.Label(
            left_panel,
            text="◇ DISCOVERED NETWORKS",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 10, "bold")
        ).pack(anchor="w", padx=12, pady=8)
        
        self.network_count_label = tk.Label(
            left_panel,
            text="0 networks found",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 8)
        )
        self.network_count_label.pack(anchor="w", padx=12, pady=(0, 8))
        
        self.instruction_label = tk.Label(
            left_panel,
            text="👆 Click on a network to select it for attack",
            bg=Colors.SURFACE,
            fg=Colors.ACCENT,
            font=("JetBrains Mono", 7)
        )
        self.instruction_label.pack(anchor="w", padx=12, pady=(0, 4))
        
        list_container = tk.Frame(left_panel, bg=Colors.SURFACE)
        list_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        
        network_canvas = tk.Canvas(list_container, bg=Colors.SURFACE, highlightthickness=0)
        scrollbar = tk.Scrollbar(list_container, orient=tk.VERTICAL, command=network_canvas.yview)
        self.network_frame = tk.Frame(network_canvas, bg=Colors.SURFACE)
        
        self.network_frame.bind("<Configure>",
            lambda e: network_canvas.configure(scrollregion=network_canvas.bbox("all")))
        
        self.network_window = network_canvas.create_window((0, 0), window=self.network_frame, anchor="nw")
        
        def _configure_canvas(event):
            network_canvas.itemconfig(self.network_window, width=event.width)
        network_canvas.bind("<Configure>", _configure_canvas)
        
        network_canvas.configure(yscrollcommand=scrollbar.set)
        network_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        right_panel = tk.Frame(page, bg=Colors.BACKGROUND)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4, 0))
        
        self.selected_network_frame = tk.Frame(right_panel, bg=Colors.SURFACE)
        self.selected_network_frame.pack(fill=tk.X, pady=(0, 4))
        
        tk.Label(
            self.selected_network_frame,
            text="◇ SELECTED TARGET",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 10, "bold")
        ).pack(anchor="w", padx=12, pady=(12, 8))
        
        self.selected_network_info = tk.Label(
            self.selected_network_frame,
            text="No network selected\n\n👆 Click on a network from the list\nto select it for attack",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 9),
            justify=tk.LEFT
        )
        self.selected_network_info.pack(anchor="w", padx=12, pady=(0, 8))
        
        button_frame = tk.Frame(self.selected_network_frame, bg=Colors.SURFACE)
        button_frame.pack(fill=tk.X, padx=12, pady=(0, 12))
        
        self.use_for_crack_button = StyledButton(
            button_frame,
            text="🎯 ATTACK THIS NETWORK",
            command=self.use_network_for_cracking,
            variant="success"
        )
        self.use_for_crack_button.pack(side=tk.LEFT, padx=(0, 8))
        self.use_for_crack_button.config(state=tk.DISABLED)
        
        self.clear_selection_button = StyledButton(
            button_frame,
            text="CLEAR SELECTION",
            command=self.clear_network_selection,
            variant="default"
        )
        self.clear_selection_button.pack(side=tk.LEFT)
        self.clear_selection_button.config(state=tk.DISABLED)
        
        self.scan_terminal = TerminalPanel(right_panel, title="SCAN_OUTPUT", height=15)
        self.scan_terminal.pack(fill=tk.BOTH, expand=True)
        
        self.scan_terminal.add_line("Network scan page ready", "info")
        self.scan_terminal.add_line("1. Press START SCAN to discover networks", "info")
        self.scan_terminal.add_line("2. Click on a network to select it", "info")
        self.scan_terminal.add_line("3. Press ATTACK THIS NETWORK to begin", "info")
        
        self.selected_network = None
        self.network_cards = []
    
    def on_network_select(self, card: NetworkCard):
        """Handle network selection"""
        for c in self.network_cards:
            if c != card:
                c.set_selected(False)
        
        card.set_selected(True)
        self.selected_network = card.network
        
        net = card.network
        info_text = f"SSID: {net.get('ssid', 'Unknown')}\n"
        info_text += f"BSSID: {net.get('bssid', 'Unknown')}\n"
        info_text += f"Channel: {net.get('channel', 'Unknown')}\n"
        info_text += f"Security: {net.get('security', 'WPA/WPA2')}"
        
        self.selected_network_info.config(text=info_text, fg=Colors.PRIMARY)
        self.use_for_crack_button.config(state=tk.NORMAL)
        self.clear_selection_button.config(state=tk.NORMAL)
        
        self.scan_terminal.add_line(
            f"Selected: {net.get('ssid')} (CH:{net.get('channel')})",
            "success"
        )
        self.status_bar.set_status(f"● TARGET: {net.get('ssid', 'Unknown')}", Colors.ACCENT)
    
    def clear_network_selection(self):
        """Clear current network selection"""
        for card in self.network_cards:
            card.set_selected(False)
        self.selected_network = None
        self.selected_network_info.config(
            text="No network selected\n\n👆 Click on a network from the list\nto select it for attack",
            fg=Colors.ON_SURFACE_VARIANT
        )
        self.use_for_crack_button.config(state=tk.DISABLED)
        self.clear_selection_button.config(state=tk.DISABLED)
        self.scan_terminal.add_line("Selection cleared", "info")
        self.status_bar.set_status("● SYSTEM READY", Colors.SUCCESS)
    
    def start_scan(self):
        """Start network scanning"""
        self.scan_button.config(state=tk.DISABLED, text="SCANNING...")
        self.scan_terminal.clear()
        self.scan_terminal.add_line("Starting network scan...", "primary")
        self.scan_terminal.add_line("A terminal window will open for scanning", "warning")
        
        self.clear_network_selection()
        for widget in self.network_frame.winfo_children():
            widget.destroy()
        self.network_cards = []
        self.network_count_label.config(text="Scanning...")
        
        self.status_bar.set_status("● SCANNING...", Colors.WARNING)
        
        scan_time = self.scan_time_var.get()
        
        def on_scan_complete(results):
            self.scan_button.config(state=tk.NORMAL, text="▶ START SCAN")
            
            if results.get("status") == "progress":
                self.scan_terminal.add_line(results.get("message"), "info")
            elif results.get("status") == "success":
                networks = results.get("networks", [])
                self.network_count_label.config(text=f"{len(networks)} networks found")
                self.scan_terminal.add_line(f"✓ Scan complete! Found {len(networks)} networks", "success")
                self.scan_terminal.add_line("Click on a network card to select it", "accent")
                
                if networks:
                    for net in networks:
                        card = NetworkCard(
                            self.network_frame,
                            net,
                            on_select=self.on_network_select
                        )
                        card.pack(fill=tk.X, padx=4, pady=2)
                        self.network_cards.append(card)
                        
                        self.scan_terminal.add_line(
                            f"  • {net['ssid']} | CH:{net['channel']} | {net['bssid']}",
                            "info"
                        )
                    self.status_bar.set_status(f"● {len(networks)} NETWORKS FOUND", Colors.SUCCESS)
                else:
                    self.scan_terminal.add_line("No networks found", "warning")
                    self.status_bar.set_status("● NO NETWORKS", Colors.WARNING)
            else:
                self.scan_terminal.add_line(f"✗ Error: {results.get('message')}", "error")
                self.status_bar.set_status("● SCAN FAILED", Colors.ERROR)
        
        BackendInterface.start_network_scan(on_scan_complete, scan_time=scan_time)
    
    def use_network_for_cracking(self):
        """Use selected network for cracking"""
        if self.selected_network:
            AppState().crack_target = self.selected_network
            net = self.selected_network
            self.scan_terminal.add_line(
                f"Target set: {net.get('ssid')} | Switching to Crack WPA tab...",
                "success"
            )
            self.show_page("crack")
    
    def create_crack_page(self):
        """Create WPA cracking page"""
        page = tk.Frame(self.content_frame, bg=Colors.BACKGROUND)
        self.pages["crack"] = page
        
        # ============================================================
        # LEFT PANEL CONTAINER
        # ============================================================
        left_panel_container = tk.Frame(page, bg=Colors.SURFACE, width=350)
        left_panel_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))
        left_panel_container.pack_propagate(False)
        
        # ============================================================
        # SCROLLABLE AREA - FIXED VERSION
        # ============================================================
        
        # Canvas for scrolling
        left_canvas = tk.Canvas(
            left_panel_container,
            bg=Colors.SURFACE,
            highlightthickness=0,
            relief=tk.FLAT
        )
        
        # Scrollbar (visible on right)
        left_scrollbar = tk.Scrollbar(
            left_panel_container,
            orient=tk.VERTICAL,
            command=left_canvas.yview,
            bg=Colors.SURFACE_HIGHER,
            troughcolor=Colors.SURFACE_HIGH,
            activebackground=Colors.PRIMARY,
            width=14,
            borderwidth=0,
            highlightthickness=0
        )
        
        # Inner frame to hold content
        left_panel = tk.Frame(left_canvas, bg=Colors.SURFACE)
        
        # Create window in canvas
        canvas_window = left_canvas.create_window((0, 0), window=left_panel, anchor="nw")
        
        # Configure canvas scrolling
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        # Update scroll region when inner frame changes
        def on_frame_configure(event=None):
            left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        
        left_panel.bind("<Configure>", on_frame_configure)
        
        # Make canvas window width match canvas width
        def on_canvas_configure(event):
            left_canvas.itemconfig(canvas_window, width=event.width)
        
        left_canvas.bind("<Configure>", on_canvas_configure)
        
        # Pack canvas and scrollbar
        left_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        left_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Mouse wheel scrolling - FIXED
        def on_mousewheel(event):
            left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        # Bind mousewheel when mouse enters canvas
        left_canvas.bind("<MouseWheel>", on_mousewheel)
        left_panel.bind("<MouseWheel>", on_mousewheel)
        
        # Linux scroll support
        left_canvas.bind("<Button-4>", lambda e: left_canvas.yview_scroll(-3, "units"))
        left_canvas.bind("<Button-5>", lambda e: left_canvas.yview_scroll(3, "units"))
        
        # ============================================================
        # TARGET NETWORK SECTION
        # ============================================================
        tk.Label(
            left_panel,
            text="◇ TARGET NETWORK",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9, "bold")
        ).pack(anchor="w", padx=10, pady=(8, 4))
        
        self.crack_target_frame = tk.Frame(left_panel, bg=Colors.SURFACE_HIGH, padx=6, pady=4)
        self.crack_target_frame.pack(fill=tk.X, padx=10, pady=(0, 3))
        
        self.crack_target_label = tk.Label(
            self.crack_target_frame,
            text="NO TARGET SELECTED\nGo to Network Scan tab to select a target",
            bg=Colors.SURFACE_HIGH,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 8),
            justify=tk.LEFT
        )
        self.crack_target_label.pack(anchor="w")
        
        # Button to switch to scan tab
        StyledButton(
            left_panel,
            text="← GO TO NETWORK SCAN",
            command=lambda: self.show_page("scan"),
            variant="default",
            padx=6,
            pady=3
        ).pack(fill=tk.X, padx=10, pady=(0, 4))
        
        ttk.Separator(left_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=3)
        
        # ============================================================
        # ATTACK CONFIGURATION
        # ============================================================
        tk.Label(
            left_panel,
            text="◇ ATTACK CONFIG",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9, "bold")
        ).pack(anchor="w", padx=10, pady=(6, 4))
        
        tk.Label(
            left_panel,
            text="DEAUTH PACKETS",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        ).pack(anchor="w", padx=10, pady=(2, 1))
        
        self.deauth_var = tk.IntVar(value=10)
        deauth_scale = tk.Scale(
            left_panel,
            from_=1,
            to=100,
            orient=tk.HORIZONTAL,
            variable=self.deauth_var,
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            troughcolor=Colors.SURFACE_HIGH,
            highlightthickness=0,
            length=280
        )
        deauth_scale.pack(fill=tk.X, padx=10, pady=(0, 4))
        
        # CAPTURE HANDSHAKE BUTTON
        self.capture_button = StyledButton(
            left_panel,
            text="📡 CAPTURE HANDSHAKE",
            command=self.capture_handshake,
            variant="primary",
            padx=8,
            pady=4
        )
        self.capture_button.pack(fill=tk.X, padx=10, pady=(3, 3))
        self.capture_button.config(state=tk.DISABLED)
        
        ttk.Separator(left_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=8, pady=3)
        
        # ============================================================
        # WORDLIST GENERATOR SECTION
        # ============================================================
        tk.Label(
            left_panel,
            text="◇ WORDLIST GEN",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9, "bold")
        ).pack(anchor="w", padx=10, pady=(6, 4))
        
        tk.Label(
            left_panel,
            text="BASE WORD",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        ).pack(anchor="w", padx=10, pady=(2, 1))
        
        self.base_word_var = tk.StringVar(value="admin")
        base_word_entry = tk.Entry(
            left_panel,
            textvariable=self.base_word_var,
            bg=Colors.TERM_BG,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9),
            insertbackground=Colors.PRIMARY,
            relief=tk.FLAT
        )
        base_word_entry.pack(fill=tk.X, padx=10, pady=(0, 3))
        
        tk.Label(
            left_panel,
            text="OPERATOR (e.g., @, #, $)",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        ).pack(anchor="w", padx=10, pady=(2, 1))
        
        self.operator_var = tk.StringVar()
        operator_entry = tk.Entry(
            left_panel,
            textvariable=self.operator_var,
            bg=Colors.TERM_BG,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9),
            insertbackground=Colors.PRIMARY,
            relief=tk.FLAT
        )
        operator_entry.pack(fill=tk.X, padx=10, pady=(0, 3))
        
        self.add_numbers_var = tk.BooleanVar(value=False)
        numbers_check = tk.Checkbutton(
            left_panel,
            text="Add numbers (0-9999)",
            variable=self.add_numbers_var,
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE,
            selectcolor=Colors.SURFACE_HIGH,
            activebackground=Colors.SURFACE,
            activeforeground=Colors.PRIMARY,
            font=("JetBrains Mono", 7)
        )
        numbers_check.pack(anchor="w", padx=10, pady=2)
        
        self.generate_wordlist_button = StyledButton(
            left_panel,
            text="🔧 GENERATE WORDLIST",
            command=self.generate_wordlist,
            variant="default",
            padx=8,
            pady=4
        )
        self.generate_wordlist_button.pack(fill=tk.X, padx=10, pady=(4, 2))
        
        ttk.Separator(left_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=4)
        
        # ============================================================
        # WORDLIST PATH
        # ============================================================
        tk.Label(
            left_panel,
            text="WORDLIST PATH",
            bg=Colors.SURFACE,
            fg=Colors.ON_SURFACE_VARIANT,
            font=("JetBrains Mono", 7)
        ).pack(anchor="w", padx=10, pady=(2, 1))
        
        wordlist_frame = tk.Frame(left_panel, bg=Colors.SURFACE)
        wordlist_frame.pack(fill=tk.X, padx=10, pady=(0, 4))
        
        self.wordlist_var = tk.StringVar(value="/usr/share/wordlists/cracker.txt")
        wordlist_entry = tk.Entry(
            wordlist_frame,
            textvariable=self.wordlist_var,
            bg=Colors.TERM_BG,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9),
            insertbackground=Colors.PRIMARY,
            relief=tk.FLAT
        )
        wordlist_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # ============================================================
        # CRACK PASSWORD BUTTON (sticky to bottom)
        # ============================================================
        tk.Label(
            left_panel,
            text="",
            bg=Colors.SURFACE
        ).pack(pady=10)  # Spacer
        
        self.crack_button = StyledButton(
            left_panel,
            text="🔓 CRACK PASSWORD",
            command=self.crack_password,
            variant="success",
            padx=8,
            pady=4
        )
        self.crack_button.pack(fill=tk.X, padx=10, pady=(6, 4))
        self.crack_button.config(state=tk.DISABLED)
        
        # CRACKED PASSWORD DISPLAY
        tk.Label(
            left_panel,
            text="◇ CRACKED PASSWORD",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 8, "bold")
        ).pack(anchor="w", padx=10, pady=(4, 2))
        
        self.password_display = tk.Entry(
            left_panel,
            bg=Colors.TERM_BG,
            fg=Colors.SUCCESS,
            font=("JetBrains Mono", 11, "bold"),
            justify=tk.CENTER,
            relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.password_display.pack(fill=tk.X, padx=10, pady=(0, 3))
        
        self.copy_button = StyledButton(
            left_panel,
            text="📋 COPY PASSWORD",
            command=self.copy_password,
            variant="default",
            padx=8,
            pady=3
        )
        self.copy_button.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.copy_button.config(state=tk.DISABLED)
        
        # ============================================================
        # RIGHT PANEL - TERMINAL
        # ============================================================
        right_panel = tk.Frame(page, bg=Colors.BACKGROUND)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4, 0))
        
        self.crack_terminal = TerminalPanel(right_panel, title="CRACK_OUTPUT", height=25)
        self.crack_terminal.pack(fill=tk.BOTH, expand=True)
        
        self.crack_terminal.add_line("WPA Cracking module ready", "info")
        self.crack_terminal.add_line("Steps:", "info")
        self.crack_terminal.add_line("  1. Select target from Network Scan tab", "info")
        self.crack_terminal.add_line("  2. Configure deauth, capture handshake", "info")
        self.crack_terminal.add_line("  3. Generate wordlist or use existing", "info")
        self.crack_terminal.add_line("  4. Click CRACK PASSWORD", "info")
    
    def update_crack_target(self):
        """Update crack page with selected target"""
        target = AppState().crack_target
        if target:
            info = f"SSID: {target.get('ssid', 'Unknown')}\n"
            info += f"BSSID: {target.get('bssid', 'Unknown')}\n"
            info += f"Channel: {target.get('channel', 'Unknown')}\n"
            info += f"Security: {target.get('security', 'WPA/WPA2')}"
            self.crack_target_label.config(text=info, fg=Colors.PRIMARY)
            self.capture_button.config(state=tk.NORMAL)
        else:
            self.crack_target_label.config(
                text="NO TARGET SELECTED\n\nGo to Network Scan tab\nto select a target network",
                fg=Colors.ON_SURFACE_VARIANT
            )
            self.capture_button.config(state=tk.DISABLED)
    
    def generate_wordlist(self):
        """Generate custom wordlist"""
        base_word = self.base_word_var.get().strip()
        operator = self.operator_var.get().strip() or None
        add_numbers = self.add_numbers_var.get()
        
        if not base_word:
            messagebox.showwarning("Input Required", "Please enter a base word")
            return
        
        cracker = AppState().get_cracker()
        if not cracker:
            messagebox.showerror("Error", "System not initialized")
            return
        
        self.generate_wordlist_button.config(state=tk.DISABLED, text="GENERATING...")
        self.crack_terminal.add_line(f"Generating wordlist for: {base_word}", "primary")
        
        # Run in thread to avoid UI freeze
        def generate_thread():
            try:
                wordlist_path = cracker.create_wordlist(
                    name=base_word,
                    opt=operator,
                    numbers=add_numbers
                )
                
                # Update UI from main thread
                self.after(0, lambda: self._on_wordlist_generated(wordlist_path))
            except Exception as e:
                self.after(0, lambda: self._on_wordlist_error(str(e)))
        
        threading.Thread(target=generate_thread, daemon=True).start()
    
    def _on_wordlist_generated(self, wordlist_path):
        """Called when wordlist generation completes"""
        self.generate_wordlist_button.config(state=tk.NORMAL, text="🔧 GENERATE WORDLIST")
        if wordlist_path:
            self.wordlist_var.set(wordlist_path)
            self.crack_terminal.add_line(f"Wordlist created: {wordlist_path}", "success")
            messagebox.showinfo("Wordlist Generated", 
                f"Wordlist saved to:\n{wordlist_path}")
    
    def _on_wordlist_error(self, error_msg):
        """Called when wordlist generation fails"""
        self.generate_wordlist_button.config(state=tk.NORMAL, text="🔧 GENERATE WORDLIST")
        self.crack_terminal.add_line(f"Wordlist generation failed: {error_msg}", "error")
    
    def capture_handshake(self):
        target = AppState().crack_target
        if not target:
            messagebox.showwarning("No Target", "Please select a target network first")
            return
        
        self.capture_button.config(state=tk.DISABLED, text="CAPTURING...")
        self.crack_terminal.clear()
        self.crack_terminal.add_line(f"Target: {target.get('ssid')} ({target.get('bssid')})", "primary")
        self.crack_terminal.add_line("Starting handshake capture...", "primary")
        self.status_bar.set_status("● CAPTURING HANDSHAKE...", Colors.WARNING)
        
        deauth_count = self.deauth_var.get()
        
        def on_capture_complete(results):
            self.capture_button.config(state=tk.NORMAL, text="📡 CAPTURE HANDSHAKE")
            
            if results.get("status") == "progress":
                self.crack_terminal.add_line(results.get("message"), "info")
            elif results.get("status") == "success":
                self.crack_terminal.add_line(results.get("message"), "success")
                self.crack_button.config(state=tk.NORMAL)
                self.status_bar.set_status("● HANDSHAKE CAPTURED", Colors.SUCCESS)
            else:
                self.crack_terminal.add_line(f"Error: {results.get('message')}", "error")
                self.status_bar.set_status("● CAPTURE FAILED", Colors.ERROR)
        
        BackendInterface.capture_handshake(target, deauth_count, on_capture_complete)
    
    def crack_password(self):
        """Crack captured handshake"""
        wordlist = self.wordlist_var.get().strip()
        if not wordlist:
            messagebox.showwarning("Wordlist Required", "Please specify a wordlist path")
            return
        
        if not os.path.exists(wordlist):
            common_wordlists = [
                '/usr/share/wordlists/rockyou.txt']
            found = False
            for wl in common_wordlists:
                if os.path.exists(wl):
                    self.wordlist_var.set(wl)
                    wordlist = wl
                    found = True
                    self.crack_terminal.add_line(f"Auto-detected wordlist: {wl}", "success")
                    break
            
            if not found:
                response = messagebox.askyesno(
                    "Wordlist Not Found",
                    f"Wordlist not found at: {wordlist}\n\n"
                    "Do you want to continue anyway?"
                )
                if not response:
                    return
        
        self.crack_button.config(state=tk.DISABLED, text="CRACKING...")
        self.crack_terminal.clear()
        self.crack_terminal.add_line("=" * 50, "info")
        self.crack_terminal.add_line("STARTING PASSWORD CRACKING", "primary")
        self.crack_terminal.add_line("=" * 50, "info")
        self.crack_terminal.add_line(f"Wordlist: {wordlist}", "info")
        
        self.status_bar.set_status("● CRACKING PASSWORD...", Colors.WARNING)
        
        self._crack_start_time = time.time()
        self._cracking = True
        self._animate_cracking()
        
        def on_crack_complete(results):
            self._cracking = False
            self.crack_button.config(state=tk.NORMAL, text="🔓 CRACK PASSWORD")
            
            if results.get("status") == "progress":
                msg = results.get("message", "")
                prog = results.get("progress", "0%")
                
                # Check if password was found in progress update
                if "KEY FOUND" in msg:
                    pwd = results.get("password", "")
                    self.crack_terminal.add_line(f"✓ {msg}", "success")
                    self.status_bar.set_status("● KEY FOUND!", Colors.SUCCESS)
                    
                    # Show password immediately
                    if pwd:
                        self.password_display.config(state=tk.NORMAL)
                        self.password_display.delete(0, tk.END)
                        self.password_display.insert(0, pwd)
                        self.password_display.config(state=tk.DISABLED)
                        self.copy_button.config(state=tk.NORMAL)
                        self.clipboard_clear()
                        self.clipboard_append(pwd)
                else:
                    self.crack_terminal.add_line(f"[{prog}] {msg}", "info")
                    self.status_bar.set_status(f"● CRACKING {prog}", Colors.WARNING)
            
            elif results.get("status") == "success":
                password = results.get("password", "")
                elapsed = time.time() - self._crack_start_time
                
                self.crack_terminal.add_line("=" * 50, "success")
                self.crack_terminal.add_line("✓ PASSWORD CRACKED SUCCESSFULLY!", "success")
                self.crack_terminal.add_line(f"Password: {password}", "success")
                self.crack_terminal.add_line(f"Time: {elapsed:.1f}s", "info")
                self.crack_terminal.add_line("=" * 50, "success")
                
                self.password_display.config(state=tk.NORMAL)
                self.password_display.delete(0, tk.END)
                self.password_display.insert(0, password)
                self.password_display.config(state=tk.DISABLED)
                self.copy_button.config(state=tk.NORMAL)
                self.status_bar.set_status("● PASSWORD CRACKED!", Colors.WARNING)
                
                self.clipboard_clear()
                self.clipboard_append(password)
                
                target = AppState().crack_target
                target_name = target.get('ssid', 'Unknown') if target else 'Unknown'
                messagebox.showinfo("Password Cracked!",
                    f"Network: {target_name}\nPassword: {password}")
            
            else:
                elapsed = time.time() - self._crack_start_time
                self.crack_terminal.add_line(f"✗ FAILED ({elapsed:.1f}s)", "error")
                self.crack_terminal.add_line(results.get("message", ""), "error")
                self.status_bar.set_status("● CRACKING FAILED", Colors.ERROR)
        BackendInterface.crack_password(on_crack_complete, wordlist)
    
    def _animate_cracking(self):
        """Animate cracking progress"""
        if not self._cracking:
            return
        
        elapsed = time.time() - self._crack_start_time
        dots = "." * (int(elapsed) % 4)
        self.status_bar.set_status(f"● CRACKING{dots}", Colors.WARNING)
        
        if self._cracking:
            self.after(500, self._animate_cracking)
    
    def copy_password(self):
        password = self.password_display.get()
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            self.crack_terminal.add_line("Password copied to clipboard", "success")
    
    def start_monitor_mode(self):
        """Start monitor mode"""
        self.status_bar.set_status("● STARTING MONITOR MODE...", Colors.WARNING)
        
        def on_start_complete(results):
            if results.get("status") == "success":
                self.status_bar.set_status("● MONITOR MODE ACTIVE", Colors.SUCCESS)
                self.status_bar.set_monitor_mode(True)
                AppState().monitor_mode_active = True
                messagebox.showinfo("Monitor Mode", results.get("message"))
            else:
                self.status_bar.set_status("● FAILED TO START MONITOR", Colors.ERROR)
                messagebox.showerror("Error", results.get("message"))
        
        BackendInterface.start_monitor_mode(on_start_complete)
    
    def create_settings_page(self):
        page = tk.Frame(self.content_frame, bg=Colors.BACKGROUND)
        self.pages["settings"] = page
        
        settings_frame = tk.Frame(page, bg=Colors.SURFACE)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(
            settings_frame,
            text="◇ SYSTEM SETTINGS",
            bg=Colors.SURFACE,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 12, "bold")
        ).pack(anchor="w", padx=16, pady=16)
        
        info_frame = tk.Frame(settings_frame, bg=Colors.SURFACE_HIGH, padx=12, pady=12)
        info_frame.pack(fill=tk.X, padx=16, pady=8)
        
        tk.Label(
            info_frame,
            text="SYSTEM INFORMATION",
            bg=Colors.SURFACE_HIGH,
            fg=Colors.PRIMARY,
            font=("JetBrains Mono", 9, "bold")
        ).pack(anchor="w")
        
        info_text = f"Monitor Mode: {'ACTIVE' if AppState().monitor_mode_active else 'INACTIVE'}\n"
        info_text += f"Interface: wlan0mon\n"
        info_text += f"Handshake Directory: {os.path.join(os.getcwd(), 'handshakes')}\n"
        info_text += f"Default Wordlist: /usr/share/wordlists/cracker.txt"
        
        tk.Label(
            info_frame,
            text=info_text,
            bg=Colors.SURFACE_HIGH,
            fg=Colors.ON_SURFACE,
            font=("JetBrains Mono", 8),
            justify=tk.LEFT
        ).pack(anchor="w", pady=(8, 0))
    
    def create_logs_page(self):
        page = tk.Frame(self.content_frame, bg=Colors.BACKGROUND)
        self.pages["logs"] = page
        
        self.log_terminal = TerminalPanel(page, title="SYSTEM_LOGS", height=25)
        self.log_terminal.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.log_terminal.add_line("System logs initialized", "info")
    
    def shutdown_monitor(self):
        if messagebox.askyesno("Shutdown Monitor",
            "Stop monitor mode and restore network services?"):
            self.status_bar.set_status("● SHUTTING DOWN...", Colors.WARNING)
            
            def on_shutdown(results):
                if results.get("status") == "success":
                    self.status_bar.set_status("● SERVICES RESTORED", Colors.SUCCESS)
                    self.status_bar.set_monitor_mode(False)
                    messagebox.showinfo("Shutdown", results.get("message"))
                else:
                    self.status_bar.set_status("● SHUTDOWN FAILED", Colors.ERROR)
            
            BackendInterface.shutdown_system(on_shutdown)
    
    def refresh_current_page(self):
        self.update_crack_target()
        self.status_bar.set_status("● REFRESHED", Colors.INFO)

# ============================================================================
# MAIN APPLICATION
# ============================================================================
class WiFiAuditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CYBER_OS | WiFi Auditor Suite v2.0")
        self.geometry("1400x800")
        self.config(bg=Colors.BACKGROUND)
        self.minsize(1200, 700)
        
        # ✅ CONNECT THE ON-CLOSE HANDLER
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.setup_styles()
        
        self.container = tk.Frame(self, bg=Colors.BACKGROUND)
        self.container.pack(fill=tk.BOTH, expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        
        # ✅ START WITH AIRCRACK CHECK INSTEAD OF SPLASH
        self.check_and_proceed()
    
        self.center_window()
    def check_and_proceed(self):
        """Quick check if aircrack-ng is installed, skip check screen if so"""
        def on_check_result(result):
            if result.get("installed"):
                print('Already installed → go directly to splash')
                self.show_splash()
            else:
                print('Not installed → show check/install screen')
                self.show_aircrack_check()
        
        BackendInterface.check_aircrack_installed(on_check_result)
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            'Cyber.Horizontal.TProgressbar',
            background=Colors.PRIMARY,
            troughcolor=Colors.SURFACE,
            bordercolor=Colors.BORDER,
            lightcolor=Colors.PRIMARY,
            darkcolor=Colors.PRIMARY_DARK
        )
        style.configure('TSeparator', background=Colors.BORDER)
    
    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    # ✅ NEW: Show aircrack check screen
    def show_aircrack_check(self):
        """Show aircrack-ng installation check screen"""
        if AircrackCheckScreen not in self.frames:
            frame = AircrackCheckScreen(
                self.container,
                on_aircrack_ready=self.show_splash
            )
            self.frames[AircrackCheckScreen] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        else:
            self.frames[AircrackCheckScreen].tkraise()
    
    def show_splash(self):
        """Show password entry splash screen"""
        if SplashScreen not in self.frames:
            frame = SplashScreen(self.container, on_continue=self.show_dashboard)
            self.frames[SplashScreen] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        else:
            self.frames[SplashScreen].tkraise()
    
    def show_dashboard(self):
        """Show main dashboard"""
        if DashboardScreen not in self.frames:
            frame = DashboardScreen(self.container)
            self.frames[DashboardScreen] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        else:
            self.frames[DashboardScreen].tkraise()
            self.frames[DashboardScreen].update_crack_target()
    
    # ✅ IMPROVED: On-close handler with proper monitor mode shutdown
    def on_closing(self):
        """Handle window close event"""
        if AppState().monitor_mode_active:
            # Ask user what to do
            response = messagebox.askyesnocancel(
                "Exit WiFi Auditor",
                "Monitor mode is still active!\n\n"
                "Closing the application will:\n"
                "  • Stop monitor mode on wlan0\n"
                "  • Restore network services\n"
                "  • Return interface to managed mode\n\n"
                "Do you want to continue?"
            )
            
            if response is None:  # Cancel
                return
            elif response is True:  # Yes - proceed with graceful shutdown
                self.status_bar = getattr(self, 'status_bar', None)
                if self.status_bar:
                    self.status_bar.set_status("● SHUTTING DOWN...", Colors.WARNING)
                
                try:
                    # Stop monitor mode
                    cracker = AppState().get_cracker()
                    if cracker:
                        cracker.stop_monitor_mode()
                        AppState().monitor_mode_active = False
                        
                        # Brief delay to let commands complete
                        import time
                        time.sleep(0.5)
                except Exception as e:
                    print(f"Error during shutdown: {e}")
                    messagebox.showerror(
                        "Shutdown Error",
                        f"Error stopping monitor mode:\n{str(e)}\n\n"
                        "You may need to manually restore your network interface.\n"
                        "Run: sudo airmon-ng stop wlan0mon"
                    )
        
        # Destroy window
        self.destroy()


def show_installation_help():
        """Show help for manual aircrack-ng installation"""
        help_text = """
    If automatic installation fails, install aircrack-ng manually:

    Ubuntu/Debian:
        sudo apt-get update
        sudo apt-get install -y aircrack-ng

    Fedora/RHEL:
        sudo dnf install -y aircrack-ng

    Arch:
        sudo pacman -S aircrack-ng

    macOS (Homebrew):
        brew install aircrack-ng

    After installation, restart the WiFi Auditor application.
        """
        messagebox.showinfo("Manual Installation", help_text)

def main():
    app = WiFiAuditorApp()
    app.mainloop()

if __name__ == "__main__":
    main()