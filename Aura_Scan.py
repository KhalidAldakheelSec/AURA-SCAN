import os
import sys
import re
import threading
import customtkinter as ctk
from tkinter import filedialog, ttk, messagebox
from datetime import datetime

ctk.set_appearance_mode("dark")

# ==============================================================================
#  PATTERNS — name -> (regex, severity)
# ==============================================================================
PATTERNS = {
    "AWS Access Key":               (r"AKIA[0-9A-Z]{16}",                                                                           "High"),
    "AWS Secret Key":               (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",                                    "High"),
    "Google API Key":               (r"AIza[0-9A-Za-z-_]{35}",                                                                     "High"),
    "OpenAI API Key":               (r"sk-[a-zA-Z0-9]{48}",                                                                        "High"),
    "GitHub Token":                 (r"ghp_[0-9a-zA-Z]{36}",                                                                       "High"),
    "Stripe Secret Key":            (r"sk_live_[0-9a-zA-Z]{24,}",                                                                  "High"),
    "Hardcoded Password":           (r"(?i)(password|passwd|pwd|pass)\s*=\s*['\"][^'\"]{4,64}['\"]",                                "High"),
    "Database URL Connection":      (r"(postgres|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9.-]+:\d+\/[a-zA-Z0-9_\-]+", "High"),
    "Telegram Bot Token":           (r"\d{8,10}:[0-9a-zA-Z_-]{35}",                                                               "High"),
    "Private Key Block":            (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",                                           "High"),
    "JWT Token":                    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",                           "Medium"),
    "Suspicious Lookalike Domain":  (r"https?://(?:www\.)?(?:go0gle|g00gle|amazeon|paypa1|micros0ft|fac3book|binanc3)[a-z0-9.-]+\.[a-z]{2,}", "Medium"),
    "Alarming Phishing Language":   (r"\b(verify your account|urgent action|update password immediately|free bitcoin|click here to claim)\b", "Medium"),
    "Hardcoded Secret Variable":    (r"(?i)(secret|token|api_key|apikey|auth_key)\s*=\s*['\"][^'\"]{6,}['\"]",                    "Medium"),
    "IP-Based URL (Harmful)":       (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?",                        "Low"),
    "Email Address Detected":       (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",                                          "Low"),
    "Internal IP Address":          (r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "Low"),
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

# ==============================================================================
#  HELPER — resource path (for PyInstaller .exe)
# ==============================================================================
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ==============================================================================
#  CORE — scan a single file
# ==============================================================================
def scan_file(file_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for name, (pattern, severity) in PATTERNS.items():
                    flags = re.IGNORECASE if name in ("Alarming Phishing Language", "Hardcoded Password",
                                                       "Hardcoded Secret Variable", "AWS Secret Key") else 0
                    matches = re.findall(pattern, line, flags)
                    for match in matches:
                        if isinstance(match, tuple):
                            content_sample = match[1].strip() if len(match) > 1 else match[0].strip()
                        else:
                            content_sample = match.strip()
                        if len(content_sample) > 45:
                            content_sample = content_sample[:22] + "..." + content_sample[-12:]
                        findings.append((
                            os.path.basename(file_path),
                            str(line_num),
                            name,
                            severity,
                            content_sample
                        ))
    except Exception:
        pass
    return findings

# ==============================================================================
#  GUI
# ==============================================================================
class AuraScanGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AURA SCAN - UNIVERSAL SECURITY SCANNER")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.resizable(True, True)
        self.configure(fg_color="#08090f")

        try:
            icon_path = resource_path("radar.ico")
            if os.path.exists(icon_path):
                self.iconbitmap(default=icon_path)
                self.after(200, lambda: self.iconbitmap(default=icon_path))
        except Exception:
            pass

        self._scan_thread = None
        self._all_findings = []   # used for sorting / filtering display

        self._build_ui()

    # ------------------------------------------------------------------
    #  UI BUILDER
    # ------------------------------------------------------------------
    def _build_ui(self):
        # ── Header ──────────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text="⚡ AURA SCAN AUTOMATION",
            font=ctk.CTkFont(family="Segoe UI", size=27, weight="bold"),
            text_color="#ff007f"
        ).pack(pady=(18, 2))

        ctk.CTkLabel(
            self,
            text="Advanced Cyber Security Scanner for Hidden Leaks & Phishing Threats",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#6e7681"
        ).pack(pady=(0, 12))

        # ── Control bar ─────────────────────────────────────────────────
        ctrl = ctk.CTkFrame(self, fg_color="#12131a", corner_radius=12,
                             border_width=1, border_color="#1f2335")
        ctrl.pack(pady=(0, 8), padx=25, fill="x")

        # Row 0 — path + ext + buttons
        self.path_entry = ctk.CTkEntry(
            ctrl, placeholder_text="Select a folder or file to scan...",
            width=340, height=38,
            fg_color="#1c1e27", border_color="#ff007f", text_color="#ffffff"
        )
        self.path_entry.grid(row=0, column=0, padx=10, pady=12, sticky="w")

        self.ext_entry = ctk.CTkEntry(
            ctrl, placeholder_text="Ext filter: .py,.js,.env",
            width=160, height=38,
            fg_color="#1c1e27", border_color="#3b4261", text_color="#00f0ff"
        )
        self.ext_entry.grid(row=0, column=1, padx=5, pady=12)

        btn_cfg = dict(font=ctk.CTkFont(weight="bold"), height=38,
                       fg_color="#25293e", hover_color="#3b4261", text_color="#00f0ff")

        ctk.CTkButton(ctrl, text="📁 Folder", width=90,
                      command=self.browse_folder, **btn_cfg).grid(row=0, column=2, padx=5, pady=12)
        ctk.CTkButton(ctrl, text="📄 File", width=80,
                      command=self.browse_file, **btn_cfg).grid(row=0, column=3, padx=5, pady=12)

        self.scan_btn = ctk.CTkButton(
            ctrl, text="🚀 START SCAN", font=ctk.CTkFont(weight="bold"),
            width=120, height=38, command=self.start_scan,
            fg_color="#ff007f", hover_color="#cc0065", text_color="white"
        )
        self.scan_btn.grid(row=0, column=4, padx=8, pady=12)

        self.export_btn = ctk.CTkButton(
            ctrl, text="💾 EXPORT", font=ctk.CTkFont(weight="bold"),
            width=100, height=38, command=self.export_report,
            fg_color="#00f0ff", hover_color="#00c0cc", text_color="black"
        )
        self.export_btn.grid(row=0, column=5, padx=8, pady=12)

        self.clear_btn = ctk.CTkButton(
            ctrl, text="🗑 CLEAR", font=ctk.CTkFont(weight="bold"),
            width=90, height=38, command=self.clear_results,
            fg_color="#25293e", hover_color="#3b4261", text_color="#ff007f"
        )
        self.clear_btn.grid(row=0, column=6, padx=8, pady=12)

        # Row 1 — severity filter checkboxes
        filter_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        filter_frame.grid(row=1, column=0, columnspan=7, padx=10, pady=(0, 8), sticky="w")

        ctk.CTkLabel(filter_frame, text="Filter:", text_color="#6e7681",
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 8))

        from tkinter import IntVar
        self._var_high   = IntVar(value=1)
        self._var_medium = IntVar(value=1)
        self._var_low    = IntVar(value=1)

        self.filter_high   = ctk.CTkCheckBox(filter_frame, text="🔴 High",   text_color="#ff0055",
                                              variable=self._var_high,   command=self._apply_filter,
                                              fg_color="#ff0055", hover_color="#cc0044")
        self.filter_medium = ctk.CTkCheckBox(filter_frame, text="🟡 Medium", text_color="#ffaa00",
                                              variable=self._var_medium, command=self._apply_filter,
                                              fg_color="#ffaa00", hover_color="#cc8800")
        self.filter_low    = ctk.CTkCheckBox(filter_frame, text="🟢 Low",    text_color="#00ff66",
                                              variable=self._var_low,    command=self._apply_filter,
                                              fg_color="#00ff66", hover_color="#00cc50")
        for cb in (self.filter_high, self.filter_medium, self.filter_low):
            cb.pack(side="left", padx=10)

        # ── Progress bar ────────────────────────────────────────────────
        self.progress = ctk.CTkProgressBar(self, height=8, progress_color="#00f0ff",
                                            fg_color="#1c1e27", corner_radius=4)
        self.progress.pack(fill="x", padx=25, pady=(0, 4))
        self.progress.set(0)

        # ── Stats bar ───────────────────────────────────────────────────
        stats_bar = ctk.CTkFrame(self, fg_color="transparent")
        stats_bar.pack(fill="x", padx=25)

        self.lbl_high   = ctk.CTkLabel(stats_bar, text="🔴 High: 0",   text_color="#ff0055", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_medium = ctk.CTkLabel(stats_bar, text="🟡 Medium: 0", text_color="#ffaa00", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_low    = ctk.CTkLabel(stats_bar, text="🟢 Low: 0",    text_color="#00ff66", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_total  = ctk.CTkLabel(stats_bar, text="Total: 0",     text_color="#6e7681", font=ctk.CTkFont(size=12))
        for lbl in (self.lbl_high, self.lbl_medium, self.lbl_low, self.lbl_total):
            lbl.pack(side="left", padx=14)

        # ── Table ───────────────────────────────────────────────────────
        table_frame = ctk.CTkFrame(self, fg_color="#12131a", corner_radius=12,
                                    border_width=1, border_color="#1f2335")
        table_frame.pack(pady=8, padx=25, fill="both", expand=True)

        ctk.CTkLabel(
            table_frame, text="📊 Live Threat Analysis Board",
            font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffffff"
        ).pack(pady=8)

        # ttk style
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                         background="#1c1e27", fieldbackground="#1c1e27",
                         foreground="#ffffff", rowheight=28, borderwidth=0,
                         font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                         background="#25293e", foreground="#ff007f",
                         font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Treeview",
                  background=[('selected', '#2a2d3e')],
                  foreground=[('selected', '#ffffff')])

        columns = ("File Name", "Line", "Threat Type", "Severity", "Detected Content")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")

        col_widths = {"File Name": 150, "Line": 55, "Threat Type": 210, "Severity": 85, "Detected Content": 380}
        for col in columns:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_column(c))
            self.tree.column(col, width=col_widths[col],
                             anchor="center" if col in ("Line", "Severity") else "w")

        self.tree.tag_configure("High",   foreground="#ff0055", background="#1c0010")
        self.tree.tag_configure("Medium", foreground="#ffaa00", background="#1c1500")
        self.tree.tag_configure("Low",    foreground="#00ff66", background="#001c0d")

        vsb = ttk.Scrollbar(table_frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 12))
        vsb.pack(side="right", fill="y", padx=(0, 12), pady=(0, 12))
        hsb.pack(side="bottom", fill="x", padx=12, pady=(0, 4))

        # ── Status bar ──────────────────────────────────────────────────
        self.status_label = ctk.CTkLabel(
            self, text="System: Ready. Select target to begin scanning.",
            font=ctk.CTkFont(size=12), text_color="#565f89"
        )
        self.status_label.pack(pady=(0, 10))

    # ------------------------------------------------------------------
    #  BROWSE
    # ------------------------------------------------------------------
    def browse_folder(self):
        path = filedialog.askdirectory(title="Select Folder to Scan")
        if path:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, path)
            self.status_label.configure(text=f"📁 Target Folder: {path}", text_color="#00f0ff")

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select File to Scan")
        if path:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, path)
            self.status_label.configure(text=f"📄 Target File: {os.path.basename(path)}", text_color="#00f0ff")

    # ------------------------------------------------------------------
    #  SCAN  (runs in a background thread so UI stays responsive)
    # ------------------------------------------------------------------
    def start_scan(self):
        path = self.path_entry.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid file or folder path first!")
            return

        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Info", "A scan is already running. Please wait.")
            return

        # clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._all_findings.clear()
        self._update_stats()

        self.scan_btn.configure(state="disabled", text="⏳ SCANNING...")
        self.progress.set(0)
        self.status_label.configure(text="⚡ Gathering files...", text_color="#ffaa00")
        self.update()

        self._scan_thread = threading.Thread(target=self._scan_worker, args=(path,), daemon=True)
        self._scan_thread.start()

    def _scan_worker(self, path):
        raw_exts = self.ext_entry.get().replace(" ", "").split(",") if self.ext_entry.get().strip() else []
        ext_filter = [e if e.startswith('.') else f'.{e}' for e in raw_exts if e]

        # collect files
        files_to_scan = []
        if os.path.isfile(path):
            files_to_scan.append(path)
        else:
            IGNORED = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', '.idea', 'dist', 'build'}
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in IGNORED]
                for file in files:
                    if not ext_filter or any(file.endswith(ext) for ext in ext_filter):
                        files_to_scan.append(os.path.join(root, file))

        total = len(files_to_scan)
        if total == 0:
            self.after(0, self._scan_done, 0, "No matching files found to scan.", "#565f89")
            return

        self.after(0, lambda: self.status_label.configure(
            text=f"⚡ Scanning {total} files...", text_color="#ffaa00"))

        for i, f_path in enumerate(files_to_scan):
            results = scan_file(f_path)
            if results:
                self.after(0, self._insert_rows, results)
            self.after(0, self.progress.set, (i + 1) / total)
            self.after(0, lambda fp=f_path: self.status_label.configure(
                text=f"Scanning: {os.path.basename(fp)}", text_color="#ffaa00"))

        total_found = len(self._all_findings)
        if total_found > 0:
            msg  = f"⚠ CRITICAL: {total_found} threats detected!"
            color = "#ff0055"
        else:
            msg  = "🟢 SECURE: Target is completely clean and safe!"
            color = "#00ff66"

        self.after(0, self._scan_done, total_found, msg, color)

    def _insert_rows(self, rows):
        for row in rows:
            self._all_findings.append(row)
        self._apply_filter()
        self._update_stats()

    def _scan_done(self, count, msg, color):
        self.progress.set(1)
        self.status_label.configure(text=msg, text_color=color)
        self.scan_btn.configure(state="normal", text="🚀 START SCAN")
        if count > 0:
            messagebox.showwarning("Scan Complete", f"Found {count} security threats/leaks!")
        else:
            messagebox.showinfo("Scan Complete", "Excellent! No threats detected.")

    # ------------------------------------------------------------------
    #  FILTER
    # ------------------------------------------------------------------
    def _apply_filter(self):
        active = set()
        if self._var_high.get():   active.add("High")
        if self._var_medium.get(): active.add("Medium")
        if self._var_low.get():    active.add("Low")

        for item in self.tree.get_children():
            self.tree.delete(item)

        for row in self._all_findings:
            severity = row[3]
            if severity in active:
                self.tree.insert("", "end", values=row, tags=(severity,))

    # ------------------------------------------------------------------
    #  SORT
    # ------------------------------------------------------------------
    _sort_reverse = {}

    def _sort_column(self, col):
        rev = self._sort_reverse.get(col, False)
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children()]
        if col == "Severity":
            data.sort(key=lambda x: SEVERITY_ORDER.get(x[0], 9), reverse=rev)
        elif col == "Line":
            data.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=rev)
        else:
            data.sort(key=lambda x: x[0].lower(), reverse=rev)
        for index, (_, k) in enumerate(data):
            self.tree.move(k, '', index)
        self._sort_reverse[col] = not rev

    # ------------------------------------------------------------------
    #  STATS
    # ------------------------------------------------------------------
    def _update_stats(self):
        counts = {"High": 0, "Medium": 0, "Low": 0}
        for row in self._all_findings:
            counts[row[3]] = counts.get(row[3], 0) + 1
        total = sum(counts.values())
        self.lbl_high.configure(text=f"🔴 High: {counts['High']}")
        self.lbl_medium.configure(text=f"🟡 Medium: {counts['Medium']}")
        self.lbl_low.configure(text=f"🟢 Low: {counts['Low']}")
        self.lbl_total.configure(text=f"Total: {total}")

    # ------------------------------------------------------------------
    #  CLEAR
    # ------------------------------------------------------------------
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._all_findings.clear()
        self._update_stats()
        self.progress.set(0)
        self.status_label.configure(text="System: Ready. Select target to begin scanning.", text_color="#565f89")

    # ------------------------------------------------------------------
    #  EXPORT
    # ------------------------------------------------------------------
    def export_report(self):
        if not self._all_findings:
            messagebox.showerror("Error", "No results to export! Run a scan first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"AURA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            filetypes=[("Text Report", "*.txt"), ("CSV File", "*.csv")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                if file_path.endswith(".csv"):
                    f.write("File Name,Line,Threat Type,Severity,Detected Content\n")
                    for row in self._all_findings:
                        f.write(f'{row[0]},{row[1]},"{row[2]}",{row[3]},"{row[4]}"\n')
                else:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write("=" * 60 + "\n")
                    f.write("         AURA SCAN — SECURITY THREAT REPORT\n")
                    f.write(f"         Generated: {now}\n")
                    f.write("=" * 60 + "\n\n")

                    counts = {"High": 0, "Medium": 0, "Low": 0}
                    for row in self._all_findings:
                        counts[row[3]] = counts.get(row[3], 0) + 1
                    f.write(f"  Total Threats : {len(self._all_findings)}\n")
                    f.write(f"  High          : {counts['High']}\n")
                    f.write(f"  Medium        : {counts['Medium']}\n")
                    f.write(f"  Low           : {counts['Low']}\n")
                    f.write("\n" + "=" * 60 + "\n\n")

                    for row in self._all_findings:
                        f.write(f"[{row[3].upper()}] {row[2]}\n")
                        f.write(f"  File    : {row[0]}  |  Line: {row[1]}\n")
                        f.write(f"  Content : {row[4]}\n")
                        f.write("-" * 60 + "\n")

            messagebox.showinfo("Success", f"Report saved:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save report:\n{e}")


# ==============================================================================
#  ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    app = AuraScanGUI()
    app.mainloop()
