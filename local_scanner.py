import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(APP_DIR, "local_scanner_settings.json")
LOGO_FILE = os.path.join(APP_DIR, "local-scanner.jpeg")

DEFAULT_PORTS = "22,53,80,443,445,554,631,8080,8443"
MAX_HOSTS = 256
PORT_TIMEOUT = 0.25
FIELDS = (
    "ip", "hostname", "vendor", "device_guess",
    "ping", "ttl", "mac", "os_guess", "open_ports"
)

THEMES = {
    "blue": {
        "bg": "#10243a", "panel": "#17334f", "fg": "#f2f6fa",
        "button": "#235b83", "tree": "#ffffff"
    },
    "hacker": {
        "bg": "#080b08", "panel": "#151d16", "fg": "#72ff8b",
        "button": "#b51f2e", "tree": "#ffffff"
    },
    "light": {
        "bg": "#eeeeee", "panel": "#ffffff", "fg": "#17202a",
        "button": "#d8e3ec", "tree": "#ffffff"
    },
    "dark": {
        "bg": "#202124", "panel": "#303134", "fg": "#f1f3f4",
        "button": "#484a4d", "tree": "#ffffff"
    },
}



def load_settings():
    result = {"ports": DEFAULT_PORTS, "theme": "blue"}
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as file:
            result.update(json.load(file))
    except (OSError, ValueError):
        pass

    # Migrate the old theme name so existing settings still load.
    if result.get("theme") == "dark blue":
        result["theme"] = "blue"

    if result.get("theme") not in THEMES:
        result["theme"] = "blue"
    return result



settings = load_settings()
all_results = []
logo_image = None
colors = THEMES[settings["theme"]]
started = False


def save_settings():
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as file:
            json.dump(settings, file, indent=2)
    except OSError as error:
        messagebox.showerror("Settings error", str(error))


def run_command(command, timeout=2):
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, OSError):
        return None


def ping_info(ip):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "700", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    result = run_command(command)
    if not result or result.returncode != 0:
        return False, "", ""

    output = result.stdout + result.stderr
    time_match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, re.I)
    ttl_match = re.search(r"\bttl[=]\s*(\d+)", output, re.I)
    return (
        True,
        time_match.group(1) + " ms" if time_match else "yes",
        ttl_match.group(1) if ttl_match else ""
    )


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0].rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""


def discover_hostname(ip):
    name = reverse_dns(ip)
    if name:
        return name

    result = run_command(["avahi-resolve", "-a", str(ip)])
    if result and result.returncode == 0 and result.stdout.strip():
        name = result.stdout.strip().split()[-1].rstrip(".")
        return name[:-6] if name.lower().endswith(".local") else name

    result = run_command(["nmblookup", "-A", str(ip)])
    if result:
        for line in result.stdout.splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)\s+<00>\s+", line)
            if match and match.group(1).upper() != "WORKGROUP":
                return match.group(1)
    return ""


def get_mac(ip):
    if platform.system().lower() == "windows":
        command = ["arp", "-a", str(ip)]
    else:
        command = ["ip", "neigh", "show", str(ip)]

    result = run_command(command)
    if not result:
        return ""

    match = re.search(
        r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b",
        result.stdout
    )
    return match.group(0).replace("-", ":").upper() if match else ""


def load_vendor_database():
    paths = (
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
        "/usr/share/ieee-data/oui.csv",
    )
    vendors = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as file:
                for line in file:
                    match = re.match(
                        r"^\s*([0-9A-Fa-f-]{6,8})\s+"
                        r"\((?:hex|base 16)\)\s+(.+?)\s*$", line
                    )
                    if match:
                        prefix = re.sub(
                            r"[^0-9A-Fa-f]", "", match.group(1)
                        ).upper()
                        vendors[prefix] = match.group(2).strip()
            if vendors:
                break
        except OSError:
            continue
    return vendors


VENDORS = load_vendor_database()


def get_vendor(mac):
    if not mac:
        return ""
    normalized = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    for length in (9, 7, 6):
        if normalized[:length] in VENDORS:
            return VENDORS[normalized[:length]]
    return "Unknown" if VENDORS else "No OUI database"


def scan_ports(ip, ports):
    found = []
    for port in ports:
        try:
            with socket.create_connection(
                (str(ip), port), timeout=PORT_TIMEOUT
            ):
                found.append(port)
        except (OSError, TimeoutError):
            pass
    return found


def guess_os(ttl, ports):
    try:
        value = int(ttl)
    except (TypeError, ValueError):
        value = None

    if 445 in ports:
        return "Possible Windows"
    if value is not None:
        if value <= 64:
            return "Possible Linux/Unix/Apple"
        if value <= 128:
            return "Possible Windows"
        return "Possible network device"
    return "Unknown"


def guess_device(hostname, vendor, ports):
    name = (hostname or "").lower()
    maker = (vendor or "").lower()

    if any(word in name for word in ("iphone", "ipad", "android", "pixel", "phone")):
        return "Possible phone/tablet"
    if any(word in name for word in ("printer", "print")) or 631 in ports:
        return "Possible printer"
    if 554 in ports:
        return "Possible camera/media device"
    if any(word in name for word in ("macbook", "imac", "apple")) or "apple" in maker:
        return "Possible Apple device"
    if 445 in ports:
        return "Possible Windows/file sharing"
    if 22 in ports:
        return "Possible Linux/server/device"
    return "Unknown device"


def scan_one(ip, ports):
    responded, ping_time, ttl = ping_info(ip)
    open_ports = scan_ports(ip, ports)
    hostname = discover_hostname(ip)
    mac = get_mac(ip)
    vendor = get_vendor(mac)

    if not (responded or open_ports or hostname or mac):
        return None

    return {
        "ip": str(ip),
        "hostname": hostname,
        "vendor": vendor,
        "device_guess": guess_device(hostname, vendor, open_ports),
        "ping": ping_time if responded else "No reply",
        "ttl": ttl,
        "mac": mac,
        "os_guess": guess_os(ttl, open_ports),
        "open_ports": ", ".join(map(str, open_ports)),
    }


def read_ports(text):
    try:
        ports = sorted(set(
            int(part.strip()) for part in text.split(",") if part.strip()
        ))
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError
        return ports
    except ValueError:
        raise ValueError("Enter comma-separated TCP ports from 1 to 65535.")


def clear_page():
    for child in content.winfo_children():
        child.destroy()


def page_title(title):
    bar = tk.Frame(content, bg=colors["bg"])
    bar.pack(fill="x", pady=(0, 4))
    tk.Button(
        bar, text="← Menu", command=show_menu,
        bg=colors["button"], fg=colors["fg"]
    ).pack(side="left")
    tk.Label(
        bar, text=title, font=("Arial", 16, "bold"),
        bg=colors["bg"], fg=colors["fg"]
    ).pack(side="left", padx=12)


def show_menu():
    clear_page()
    panel = tk.Frame(content, bg=colors["panel"])
    panel.place(relx=0.5, rely=0.5, anchor="center")

    global logo_image
    logo_image = None
    if os.path.isfile(LOGO_FILE):
        try:
            from PIL import Image, ImageTk
            image = Image.open(LOGO_FILE)
            image.thumbnail((220, 120))
            logo_image = ImageTk.PhotoImage(image)
            tk.Label(panel, image=logo_image, bg=colors["panel"]).pack(
                pady=(8, 3)
            )
        except ImportError:
            tk.Label(
                panel, text="JPEG logo needs Pillow installed",
                bg=colors["panel"], fg=colors["fg"]
            ).pack(pady=5)
        except Exception:
            pass

    tk.Label(
        panel, text="Local Scanner", font=("Arial", 20, "bold"),
        bg=colors["panel"], fg=colors["fg"]
    ).pack(pady=(2, 12))

    for label, action in (
        ("Scan", show_scan),
        ("Compare exports", show_compare),
        ("Guide", show_guide),
        ("Settings", show_settings),
    ):
        tk.Button(
            panel, text=label, command=action, width=24,
            font=("Arial", 12), bg=colors["button"], fg=colors["fg"]
        ).pack(pady=4)
    tk.Label(
    content,
    text="© 2026 Rozod - Local Scanner · Version 1.1.3",
    bg=colors["bg"],
    fg=colors["fg"],
    font=("Arial", 8)
).pack(side="bottom", pady=(0, 4))

def install_tree_tooltips(tree):
    state = {"after_id": None, "window": None, "cell": None}

    def hide():
        if state["after_id"] is not None:
            tree.after_cancel(state["after_id"])
            state["after_id"] = None
        if state["window"] is not None:
            state["window"].destroy()
            state["window"] = None
        state["cell"] = None

    def show_tooltip(row, column, text, x_root, y_root):
        state["after_id"] = None
        if not tree.winfo_exists():
            return

        popup = tk.Toplevel(tree)
        popup.wm_overrideredirect(True)
        popup.wm_geometry(f"+{x_root + 14}+{y_root + 18}")

        label = tk.Label(
            popup,
            text=text,
            justify="left",
            wraplength=420,
            bg="#fffbd6",
            fg="#111111",
            relief="solid",
            borderwidth=1,
            padx=6,
            pady=4
        )
        label.pack()
        state["window"] = popup

    def on_motion(event):
        row = tree.identify_row(event.y)
        column = tree.identify_column(event.x)

        if not row or not column or column == "#0":
            hide()
            return

        text = tree.set(row, column)
        if not text:
            hide()
            return

        cell = (row, column)
        if cell == state["cell"]:
            return

        hide()
        state["cell"] = cell
        state["after_id"] = tree.after(
            450,
            lambda: show_tooltip(
                row, column, text, event.x_root, event.y_root
            )
        )

    tree.bind("<Motion>", on_motion)
    tree.bind("<Leave>", lambda event: hide())

def show_scan():
    clear_page()
    page_title("Scan")

    controls = tk.Frame(content, bg=colors["bg"])
    controls.pack(fill="x")

    tk.Label(
        controls, text="Network (CIDR)",
        bg=colors["bg"], fg=colors["fg"]
    ).grid(row=0, column=0, sticky="w")

    network_box = tk.Entry(controls, width=19)
    network_box.insert(0, "192.168.1.0/24")
    network_box.grid(row=1, column=0, padx=(0, 8), sticky="ew")

    tk.Label(
        controls, text="TCP ports",
        bg=colors["bg"], fg=colors["fg"]
    ).grid(row=0, column=1, sticky="w")

    ports_box = tk.Entry(controls)
    ports_box.insert(0, settings.get("ports", DEFAULT_PORTS))
    ports_box.grid(row=1, column=1, padx=(0, 8), sticky="ew")
    controls.columnconfigure(1, weight=1)

    scan_btn = tk.Button(
        controls, text="Start", bg=colors["button"], fg=colors["fg"]
    )
    scan_btn.grid(row=1, column=2, padx=(0, 5))

    export_btn = tk.Button(
        controls, text="Export CSV", bg=colors["button"], fg=colors["fg"]
    )
    export_btn.grid(row=1, column=3)

    status = tk.StringVar(value="Ready")
    tk.Label(
        content, textvariable=status,
        bg=colors["bg"], fg=colors["fg"]
    ).pack(anchor="w", pady=(3, 4))

    tablebox = tk.Frame(content, bg=colors["bg"])
    tablebox.pack(fill="both", expand=True)
    tablebox.rowconfigure(0, weight=1)
    tablebox.columnconfigure(0, weight=1)

    tree = ttk.Treeview(tablebox, columns=FIELDS, show="headings")
    labels = {
        "ip": "IP", "hostname": "Hostname", "vendor": "Company/vendor",
        "device_guess": "Device", "ping": "Ping", "ttl": "TTL",
        "mac": "MAC", "os_guess": "OS guess", "open_ports": "Open ports"
    }

    for field in FIELDS:
        tree.heading(field, text=labels[field])
        tree.column(field, width=120, minwidth=80, stretch=False)

    ybar = ttk.Scrollbar(tablebox, orient="vertical", command=tree.yview)
    xbar = ttk.Scrollbar(tablebox, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    ybar.grid(row=0, column=1, sticky="ns")
    xbar.grid(row=1, column=0, sticky="ew")
    install_tree_tooltips(tree)

    def export_csv():
        if not all_results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="local_scan.csv"
        )
        if path:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(all_results)
            status.set("Export saved.")

    def begin_scan():
        try:
            network = ipaddress.ip_network(
                network_box.get().strip(), strict=False
            )
            if not network.is_private:
                raise ValueError("Enter a private local network.")
            hosts = list(network.hosts())
            if len(hosts) > MAX_HOSTS:
                raise ValueError(
                    f"Use a network with at most {MAX_HOSTS} hosts."
                )
            ports = read_ports(ports_box.get())
        except ValueError as error:
            messagebox.showerror("Check scan settings", str(error))
            return

        for row in tree.get_children():
            tree.delete(row)
        all_results.clear()
        scan_btn.config(state="disabled")
        status.set(f"Checking {len(hosts)} local addresses…")

        def worker():
            found = []
            with ThreadPoolExecutor(max_workers=24) as pool:
                jobs = [pool.submit(scan_one, ip, ports) for ip in hosts]
                for count, job in enumerate(as_completed(jobs), start=1):
                    try:
                        item = job.result()
                        if item:
                            found.append(item)
                    except Exception:
                        pass
                    root.after(
                        0,
                        lambda n=count: status.set(
                            f"Checked {n}/{len(hosts)}…"
                        )
                    )

            def finish():
                found.sort(
                    key=lambda item: ipaddress.ip_address(item["ip"])
                )
                all_results.extend(found)
                for item in found:
                    tree.insert(
                        "", "end",
                        values=tuple(item[field] for field in FIELDS)
                    )
                status.set(f"Done — {len(found)} device(s) found")
                scan_btn.config(state="normal")

            root.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    scan_btn.config(command=begin_scan)
    export_btn.config(command=export_csv)


def show_compare():
    clear_page()
    page_title("Compare exports")

    paths = [tk.StringVar(), tk.StringVar()]
    status = tk.StringVar(value="Choose two CSV exports from this scanner.")

    for index, label in enumerate(("Older export", "Newer export")):
        row = tk.Frame(content, bg=colors["bg"])
        row.pack(fill="x", pady=8)

        tk.Label(
            row, text=label, width=13, anchor="w",
            bg=colors["bg"], fg=colors["fg"]
        ).pack(side="left")

        tk.Entry(row, textvariable=paths[index]).pack(
            side="left", fill="x", expand=True, padx=5
        )

        tk.Button(
            row, text="Browse",
            command=lambda i=index: paths[i].set(
                filedialog.askopenfilename(
                    filetypes=[("CSV files", "*.csv")]
                )
            ),
            bg=colors["button"], fg=colors["fg"]
        ).pack(side="left")

    output = tk.Text(content, height=12, wrap="word")
    output.pack(fill="both", expand=True, pady=6)

    def compare():
        try:
            datasets = []
            for path in (paths[0].get(), paths[1].get()):
                with open(path, newline="", encoding="utf-8-sig") as file:
                    rows = list(csv.DictReader(file))
                datasets.append({
                    row.get("ip", "").strip(): row
                    for row in rows if row.get("ip")
                })
        except (OSError, csv.Error) as error:
            messagebox.showerror("Could not read CSV", str(error))
            return

        old, new = datasets
        try:
            added = sorted(
                new.keys() - old.keys(), key=ipaddress.ip_address
            )
            missing = sorted(
                old.keys() - new.keys(), key=ipaddress.ip_address
            )
        except ValueError as error:
            messagebox.showerror("Invalid IP in CSV", str(error))
            return

        output.delete("1.0", "end")
        output.insert("end", f"New in newer export ({len(added)}):\n")
        output.insert("end", "\n".join(added) if added else "None")
        output.insert("end", f"\n\nMissing from newer export ({len(missing)}):\n")
        output.insert("end", "\n".join(missing) if missing else "None")
        status.set(f"Compared {len(old)} older and {len(new)} newer IPs.")

    tk.Button(
        content, text="Compare files", command=compare,
        bg=colors["button"], fg=colors["fg"]
    ).pack(anchor="w")

    tk.Label(
        content, textvariable=status,
        bg=colors["bg"], fg=colors["fg"]
    ).pack(anchor="w", pady=4)


def show_guide():
    clear_page()
    page_title("Guide")

    text = tk.Text(content, wrap="word", font=("TkFixedFont", 10))
    scroll = ttk.Scrollbar(content, command=text.yview)
    text.configure(yscrollcommand=scroll.set)
    text.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")

    guide = """ABOUT
Local Scanner checks a private network for devices that respond to ping,
selected TCP ports, or hostname/MAC lookups. Device and OS labels are clues,
not certain identifications.

HOW TO USE
1. Open Scan.
2. Enter your LAN range, for example 192.168.1.0/24.
3. Choose TCP ports or leave the defaults.
4. Press Start. Use the bottom scrollbar to see all columns.
5. Export CSV to save a scan. Compare exports to see IPs that appeared
   or disappeared between scans.

TCP PORT REFERENCE
Port   Stands for / common use
20     FTP data transfer
21     FTP control
22     SSH — secure remote login and file transfer
23     Telnet — unencrypted remote terminal
25     SMTP — sending email between mail servers
53     DNS — domain-name lookups
80     HTTP — unencrypted web traffic
110    POP3 — retrieving email
123    NTP — network time synchronization
143    IMAP — accessing email
443    HTTPS — encrypted web traffic
445    SMB — Windows file and printer sharing
554    RTSP — some camera/media streaming services
631    IPP — network printing
993    IMAPS — encrypted email access
8080   Alternate HTTP port; often used for web interfaces
8443   Alternate HTTPS port; often used for secure web interfaces

A device may be present but not show up if it blocks ping and the selected
ports, or if the router isolates wireless clients. Hostnames, MAC vendors,
and OS/device guesses may be unavailable or misleading. Only scan networks
you own or are authorized to check.

TROUBLESHOOTING
App will not open:
Run it from a terminal with: python3 local_scanner.py
The terminal may show the error that explains what is missing.

Some devices are missing:
A device may block ping or the selected ports. Wi-Fi client isolation
or a firewall can also prevent discovery.

Hostnames or vendor names are blank:
Reverse DNS, local name-resolution tools, or the OUI vendor database
may be unavailable on this computer.

The logo does not appear:
The JPEG logo is optional. Install Pillow if you want JPEG support.

CONTACT
Project and updates: [github.com/RozodOfficial/Local-Scanner]
Questions or bug reports: [github.com/RozodOfficial/Local-Scanner/issues]
"""

    text.insert("1.0", guide)
    text.config(state="disabled")


def show_settings():
    clear_page()
    page_title("Settings")

    tk.Label(
        content, text="Default TCP ports (comma-separated):",
        bg=colors["bg"], fg=colors["fg"]
    ).pack(anchor="w", pady=(8, 3))

    ports_box = tk.Entry(content)
    ports_box.insert(0, settings.get("ports", DEFAULT_PORTS))
    ports_box.pack(fill="x", pady=(0, 12))

    tk.Label(
        content, text="Theme:", bg=colors["bg"], fg=colors["fg"]
    ).pack(anchor="w")

    theme_var = tk.StringVar(value=settings.get("theme", "dark blue"))
    for theme_name in ("blue (default)", "black green red", "light", "dark"):
       tk.Radiobutton(
    content, text=theme_name.title(), variable=theme_var,
    value=theme_name,
    bg=colors["bg"], fg=colors["fg"],
    selectcolor=colors["panel"], activebackground=colors["bg"]
).pack(anchor="w")


    def save():
        try:
            read_ports(ports_box.get())
        except ValueError as error:
            messagebox.showerror("Invalid ports", str(error))
            return

        settings["ports"] = ports_box.get().strip()
        settings["theme"] = theme_var.get()
        save_settings()
        apply_theme(settings["theme"])
        show_settings()
        messagebox.showinfo("Saved", "Settings saved.")


    tk.Button(
        content, text="Save settings", command=save,
        bg=colors["button"], fg=colors["fg"]
    ).pack(anchor="w", pady=12)


def apply_theme(name):
    global colors
    colors = THEMES.get(name, THEMES["blue"])
    root.configure(bg=colors["bg"])
    content.configure(bg=colors["bg"])

    style = ttk.Style()
    style.configure(
        "Treeview", background=colors["tree"],
        fieldbackground=colors["tree"], foreground="#111111"
    )
    style.configure(
        "Treeview.Heading", background=colors["button"],
        foreground=colors["fg"]
    )



root = tk.Tk()
root.title("Local Scanner")
root.geometry("720x480")
root.minsize(600, 360)
root.resizable(True, True)

# Tkinter does not normally read JPEG files directly. Pillow enables JPEG
# loading for the window icon; the menu logo is loaded in show_menu().
try:
    if os.path.isfile(LOGO_FILE):
        from PIL import Image, ImageTk
        icon_image = ImageTk.PhotoImage(Image.open(LOGO_FILE))
        root.iconphoto(True, icon_image)
        root._icon_image = icon_image
except (ImportError, OSError, tk.TclError):
    pass

style = ttk.Style()
style.theme_use("clam")

content = tk.Frame(root, bg=colors["bg"])
content.pack(fill="both", expand=True, padx=8, pady=6)

apply_theme(settings["theme"])
started = True
show_menu()
root.mainloop()
