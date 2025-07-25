import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from PIL import Image, ImageTk
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import math

HEADERS_TO_CHECK = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def scan_url(url, output_box, max_threads):
    def log(msg):
        output_box.insert(tk.END, msg + '\n')
        output_box.see(tk.END)

    # Helper to slice lists by thread % (cap at 100%)
    def slice_by_thread_percent(lst):
        count = len(lst)
        # Clamp max_threads between 1 and 100 for percentage calculation
        percent = max(1, min(max_threads, 100))
        num_to_use = math.ceil((percent / 100) * count)
        return lst[:num_to_use]

    try:
        with open("paths.txt", "r") as f:
            COMMON_PATHS = [line.strip() for line in f if line.strip()]
        COMMON_PATHS = slice_by_thread_percent(COMMON_PATHS)
        log(f"[*] Loaded {len(COMMON_PATHS)} paths from paths.txt (sliced by {max_threads}%)")
    except:
        log("[!] Could not load paths.txt... No path scanning will occur.")
        COMMON_PATHS = []

    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (VulnScanner)"})
        log("[✓] Site is reachable: " + url)
    except:
        log("[!] Site not reachable.")
        return

    log("[*] Checking security headers...")
    for header in HEADERS_TO_CHECK:
        if header not in r.headers:
            log(f"[!] Missing header: {header}")

    if COMMON_PATHS:
        log("[*] Checking common paths from file...")
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for path in COMMON_PATHS:
                full = urljoin(url, path)
                futures.append(executor.submit(check_path, full, path, log))
            for future in as_completed(futures):
                pass

    log("[*] Testing SQL Injection with payloads...")
    try:
        with open("sqli_payloads.txt", "r", encoding="utf-8") as f:
            sqli_payloads = [line.strip() for line in f if line.strip()]
        sqli_payloads = slice_by_thread_percent(sqli_payloads)
        log(f"[*] Loaded {len(sqli_payloads)} SQL payloads (sliced by {max_threads}%)")
    except:
        log("[!] Could not load sqli_payloads.txt")
        sqli_payloads = []

    sql_errors = ['sql syntax', 'mysql_fetch', 'ORA-', 'syntax error', 'unterminated', 'mysqli_', 'pg_query', 'you have an error', 'warning']

    def test_sqli(payload):
        test_url = url + payload
        try:
            res = requests.get(test_url, timeout=10)
            if res.status_code == 200 and any(err in res.text.lower() for err in sql_errors):
                return f"[!!!] SQLi Detected: {test_url}"
            return None
        except:
            return f"[!] Request failed for {test_url}"

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(test_sqli, p) for p in sqli_payloads]
        for future in as_completed(futures):
            result = future.result()
            if result:
                log(result)

    log("[*] Testing basic reflected XSS...")
    xss_payload = "<script>alert(1337)</script>"
    try:
        res = requests.get(url, params={"x": xss_payload}, timeout=10)
        if res.status_code == 200 and xss_payload in res.text:
            log(f"[!!!] Reflected XSS found at: {res.url}")
        else:
            log(f"[-] XSS test returned status code: {res.status_code}")
    except:
        log("[!] Error during XSS check")

    log("[*] Checking forms for XSS using payloads...")
    try:
        with open("xss_payloads.txt", "r", encoding="utf-8") as f:
            xss_payloads = [line.strip() for line in f if line.strip()]
        xss_payloads = slice_by_thread_percent(xss_payloads)
        log(f"[*] Loaded {len(xss_payloads)} XSS payloads (sliced by {max_threads}%)")
    except:
        log("[!] Could not load xss_payloads.txt")
        xss_payloads = []

    try:
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        def test_form_xss(form, payload):
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            submit_url = urljoin(url, action or "")
            data = {inp.get("name"): payload for inp in inputs if inp.get("name")}

            try:
                if method == "post":
                    res = requests.post(submit_url, data=data, timeout=10)
                else:
                    res = requests.get(submit_url, params=data, timeout=10)

                if payload in res.text:
                    return f"[!!!] Reflected XSS found at: {submit_url} using payload: {payload}"
            except:
                return None
            return None

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for form in forms:
                for payload in xss_payloads:
                    futures.append(executor.submit(test_form_xss, form, payload))
            for future in as_completed(futures):
                result = future.result()
                if result:
                    log(result)

    except Exception as e:
        log(f"[!] Error during form-based XSS check: {e}")

    log("[✓] Scan complete. Have a nice day.")

def check_path(full, path, log):
    try:
        res = requests.get(full, timeout=10)
        if res.status_code == 200:
            log(f"[!] Found possible sensitive path: {full}")
            if '.env' in path and 'APP_KEY=' in res.text:
                log(f"[!!!] .env leak confirmed: {full}")
            elif '.git' in path and 'Index of' in res.text:
                log(f"[!!!] .git directory is exposed: {full}")
            elif 'phpinfo' in path and 'phpinfo()' in res.text:
                log(f"[!!!] phpinfo exposed: {full}")
        else:
            log(f"[-] {full} returned status code: {res.status_code}")
    except:
        log(f"[!] Error requesting: {full}")

def start_scan(domain_entry, thread_entry, output_box):
    url = domain_entry.get().strip()
    if not url.startswith("http"):
        url = "http://" + url
    output_box.delete(1.0, tk.END)
    try:
        threads = int(thread_entry.get())
        if threads < 1 or threads > 100:
            messagebox.showerror("Error", "Threads must be between 1 and 100 for percent slicing.")
            return
    except:
        messagebox.showerror("Error", "Threads must be a number.")
        return
    threading.Thread(target=scan_url, args=(url, output_box, threads), daemon=True).start()

def main():
    root = tk.Tk()
    root.title("WEBDOXER | CREATE THEIR DOWNFALL")
    root.geometry("600x520")
    root.configure(bg="black")
    root.resizable(False, False)

    title_label = tk.Label(root, text="WEBDOXER", font=("Arial", 18, "bold"), fg="red", bg="black")
    title_label.pack(pady=(10, 5))

    try:
        img = Image.open("logo.png")
        img = img.resize((150, 150))
        logo_img = ImageTk.PhotoImage(img)
        logo_label = tk.Label(root, image=logo_img, bg="black")
        logo_label.image = logo_img
        logo_label.pack(pady=5)
    except:
        logo_label = tk.Label(root, text="[Logo Missing]", font=("Arial", 14), fg="white", bg="black")
        logo_label.pack(pady=10)

    input_frame = tk.Frame(root, bg="black")
    input_frame.pack(pady=5)

    tk.Label(input_frame, text="Target Domain:", fg="white", bg="black").grid(row=0, column=0, sticky="e", padx=5)
    domain_entry = tk.Entry(input_frame, width=40, bg="#222", fg="white", insertbackground='white')
    domain_entry.grid(row=0, column=1)

    tk.Label(input_frame, text="Threads (1-100):", fg="white", bg="black").grid(row=1, column=0, sticky="e", padx=5)
    thread_entry = tk.Entry(input_frame, width=40, bg="#222", fg="white", insertbackground='white')
    thread_entry.insert(0, "10")
    thread_entry.grid(row=1, column=1, sticky="w")

    start_btn = ttk.Button(root, text="Start Scan", command=lambda: start_scan(domain_entry, thread_entry, output_box))
    start_btn.pack(pady=10)

    output_box = scrolledtext.ScrolledText(root, width=70, height=15, bg="#111", fg="#0f0", insertbackground='white')
    output_box.pack(padx=10, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
