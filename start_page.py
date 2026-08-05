# ui/start_page.py
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from profile_manager import list_profiles, load_profile, PROFILE_DIR

class StartPage(tk.Frame):
    """
    Landing page:
      • Select an existing profile and load it
      • Create a new profile
      • Manage profiles (refresh / delete / open folder)
    """
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#4a4a4a")
        self.controller = controller

        # --- Header ---
        title = tk.Label(self, text="Log Analysis Profiles", font=("Arial", 20, "bold"), fg="white", bg="#4a4a4a")
        subtitle = tk.Label(self, text="Choose a saved configuration or create a new one", font=("Arial", 11), fg="#C8CDD5", bg="#4a4a4a")
        title.pack(anchor="w")
        subtitle.pack(anchor="w", pady=(0, 16))

        # --- Card container ---
        card = tk.Frame(self, bg="#4a4a4a", bd=0, highlightthickness=0)
        card.pack(fill="x", padx=4, pady=4)

        # Left column: controls
        left = tk.Frame(card, bg="#4a4a4a")
        left.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)

        tk.Label(left, text="Select Profile", fg="white", bg="#4a4a4a").grid(row=0, column=0, sticky="w")
        self.profile_combo = ttk.Combobox(left, width=40, values=list_profiles(), state="readonly")
        self.profile_combo.grid(row=1, column=0, sticky="w", pady=(4, 8))
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_selected)

        btns = tk.Frame(left, bg="#4a4a4a")
        btns.grid(row=2, column=0, sticky="w", pady=(6, 0))

        ttk.Button(btns, text="Load Profile", command=self._load_clicked).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btns, text="Create New Profile", command=self._new_clicked).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(btns, text="Refresh", command=self._refresh_clicked).grid(row=0, column=2)

        mgmt = tk.Frame(left, bg="#4a4a4a")
        mgmt.grid(row=3, column=0, sticky="w", pady=(12, 0))
        ttk.Button(mgmt, text="Delete Profile", command=self._delete_clicked).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(mgmt, text="Open Profiles Folder", command=self._open_folder).grid(row=0, column=1)

        # Right column: profile preview
        right = tk.Frame(card, bg="#4a4a4a")
        right.grid(row=0, column=1, sticky="nsew", padx=16, pady=16)
        card.columnconfigure(0, weight=0)
        card.columnconfigure(1, weight=1)

        tk.Label(right, text="Profile Details", font=("Arial", 12, "bold"), fg="white", bg="#4a4a4a").pack(anchor="w")
        self.preview = tk.Text(right, height=14, bg="#4a4a4a", fg="#E6E8EA", insertbackground="#4a4a4a", bd=0)
        self.preview.configure(highlightthickness=0, padx=10, pady=10)
        self.preview.pack(fill="both", expand=True, pady=(6, 0))
        self.preview.config(state="disabled")

    # -----------------
    # Page lifecycle
    # -----------------
    def on_show(self):
        """Refresh profile list when page is shown."""
        self.reload_profiles(list_profiles())

    def reload_profiles(self, names):
        current = self.profile_combo.get()
        self.profile_combo["values"] = list(sorted(names))
        if current in names:
            self.profile_combo.set(current)
        else:
            self.profile_combo.set("")
        self._clear_preview()

    # -----------------
    # Actions
    # -----------------
    def _on_profile_selected(self, _evt=None):
        name = self.profile_combo.get()
        if not name:
            self._clear_preview()
            return
        try:
            data = load_profile(name)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile '{name}':\n{e}")
            return
        self._show_preview(name, data)

    def _load_clicked(self):
        name = self.profile_combo.get()
        if not name:
            messagebox.showerror("Error", "Please select a profile to load.")
            return
        self.controller.state["current_profile_name"] = name
        # Lazy import to avoid circular import at module load time
        RunAnalysisPage = self._run_page_class()
        page = self.controller.pages[RunAnalysisPage]
        page.load_profile(name)
        self.controller.show(RunAnalysisPage)

    def _new_clicked(self):
        self.controller.show(self._editor_page_class())

    def _refresh_clicked(self):
        self.reload_profiles(list_profiles())

    def _delete_clicked(self):
        name = self.profile_combo.get()
        if not name:
            messagebox.showerror("Error", "Select a profile to delete.")
            return
        if messagebox.askyesno("Confirm", f"Delete profile '{name}'? This cannot be undone."):
            try:
                os.remove(os.path.join(PROFILE_DIR, f"{name}.json"))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete profile:\n{e}")
            self.reload_profiles(list_profiles())

    def _open_folder(self):
        try:
            if sys.platform.startswith("win"):
                os.startfile(PROFILE_DIR)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess
                subprocess.run(["open", PROFILE_DIR], check=False)
            else:
                import subprocess
                subprocess.run(["xdg-open", PROFILE_DIR], check=False)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder:\n{e}")

    # -----------------
    # Helpers (lazy imports prevent circulars)
    # -----------------
    def _editor_page_class(self):
        from ui.profile_editor_page import ProfileEditorPage  # lazy import
        return ProfileEditorPage

    def _run_page_class(self):
        from ui.run_analysis_page import RunAnalysisPage  # lazy import
        return RunAnalysisPage

    def _clear_preview(self):
        self.preview.config(state="normal")
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", "No profile selected.")
        self.preview.config(state="disabled")

    def _show_preview(self, name, data):
        lines = [f"Name: {name}"]
        def add(k, label):
            v = data.get(k, "")
            if v:
                lines.append(f"{label}: {v}")
        add("ixl_file", "IXL File")
        add("cm_log_file", "CM Log File")
        add("pcap_file", "PCAP File")
        add("packetswitch_file", "Packetswitch File")
        add("ixl_excel_file", "IXL Excel File")
        add("output_suffix", "Output Suffix")
        add("target_address_dotted", "Target Address (dotted)")
        add("target_address_hex", "Target Address (hex)")

        text = "\n".join(lines)
        self.preview.config(state="normal")
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", text)
        self.preview.config(state="disabled")