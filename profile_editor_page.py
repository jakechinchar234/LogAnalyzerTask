# ui/profile_editor_page.py
"""
Create or edit a profile (file paths + output suffix + target address).
- Stores BOTH target_address_hex (for backend) and target_address_dotted (for UI).
- Does NOT store Start/End time.
- Uses LAZY imports to avoid circular/import-time errors.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from profile_manager import save_profile
from profile_manager import list_profiles

class ProfileEditorPage(tk.Frame):
    """Create or edit a profile (file paths + suffix + target address)."""
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#4a4a4a")
        main_container = tk.Frame(self, bg="#4a4a4a")
        main_container.pack(fill="both", expand=True)
        self.form_container = tk.Frame(main_container, bg="#4a4a4a")
        self.form_container.pack(side="left", fill="y", padx=(20, 10), pady=20)
        #right side
        self.profile_panel = tk.Frame(main_container, bg="#363636", width=260, height= 200)
        self.profile_panel.pack(side="right", fill="none", padx=(10, 20), pady=10)
        self.profile_panel.pack_propagate(False)
        self.controller = controller

        #Title & subtitle

        tk.Label(
            self.profile_panel,
            text="Profiles",
            bg="#363636",
            fg="white",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=12, pady=(5, 5))

        self.profile_listbox = tk.Listbox(
            self.profile_panel,
            bg="#4a4a4a",
            fg="white",
            selectbackground="#8A5CF6",
            borderwidth=0,
            highlightthickness=0
        )

        self.profile_listbox.pack(fill="both", expand=True, padx=10, pady=10)
        for p in list_profiles():
            self.profile_listbox.insert("end", p)
        self.profile_listbox.bind("<<ListboxSelect>>", self._on_profile_select)

        tk.Label(
            self.form_container, text="Create / Edit Profile",
            font=("Arial", 20, "bold"), fg="white", bg="#4a4a4a"
        ).pack(anchor="w")
        tk.Label(
            self.form_container,
            text="Profiles save file paths, output suffix and target address (time is chosen at run time).",
            fg="#C8CDD5", bg="#4a4a4a"
        ).pack(anchor="w", pady=(0, 12))

        # ---- Card surface ----
        card = tk.Frame(self.form_container, bg="#4a4a4a")
        card.pack(fill="x", padx=4, pady=4)

        # ---- Form grid ----
        form = tk.Frame(card, bg="#4a4a4a")
        form.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")

        # Keep references to entries
        self._entries = {}
        row = 0

        # -------- File pickers --------
        def add_file_field(label, key, filetypes):
            nonlocal row
            tk.Label(form, text=label, fg="white", bg="#4a4a4a").grid(row=row, column=0, sticky="w", pady=4)
            e = ttk.Entry(form, width=56)
            e.grid(row=row, column=1, sticky="w", pady=4)
            ttk.Button(form, text="Browse", command=lambda: self._browse_into(e, filetypes)).grid(row=row, column=2, padx=(8, 0))
            self._entries[key] = e
            row += 1

        add_file_field("IXL Text File",        "ixl_file",         [("Text", "*.txt"), ("All", "*.*")])
        add_file_field("CM Log Text File",     "cm_log_file",      [("Text", "*.txt"), ("All", "*.*")])
        add_file_field("Wireshark PCAP File",  "pcap_file",        [("PCAP", "*.pcap"), ("All", "*.*")])
        add_file_field("Packetswitch File",    "packetswitch_file",[("HTML", "*.html"), ("DOCX", "*.docx"), ("All", "*.*")])
        add_file_field("Office File", "office_file",[("Office Files", "*.txt *.html *.docx"),("Text", "*.txt"),("HTML", "*.html"),("Word", "*.docx"),("All", "*.*")])
        add_file_field("Component Excel File",       "ixl_excel_file",   [("Excel", "*.xlsx"), ("All", "*.*")])
        add_file_field("Location Excel File", "location_excel_file",[("Excel", "*.xlsx"), ("All", "*.*")])


        # not in use
        tk.Label(form, text="Output Suffix", fg="white", bg="#4a4a4a").grid(row=row, column=0, sticky="w", pady=4)
        e_suffix = ttk.Entry(form, width=32)
        e_suffix.grid(row=row, column=1, sticky="w", pady=4)
        self._entries["output_suffix"] = e_suffix
        row += 1

        tk.Label(form, text="Target Address (hex or dotted)", fg="white", bg="#4a4a4a").grid(row=row, column=0, sticky="w", pady=4)
        e_addr = ttk.Entry(form, width=32)
        e_addr.grid(row=row, column=1, sticky="w", pady=4)
        self._entries["target_address_input"] = e_addr
        row += 1

        tk.Label(form, text="Profile Name", fg="white", bg="#4a4a4a").grid(row=row, column=0, sticky="w", pady=(10, 4))
        self.name_entry = ttk.Entry(form, width=32)
        self.name_entry.grid(row=row, column=1, sticky="w", pady=(10, 4))
        row += 1

        actions = tk.Frame(card, bg="#4a4a4a")
        actions.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 16))
        ttk.Button(actions, text="Save Profile", command=self._save).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(actions, text="Back", command=lambda: controller.show(self._start_page_class())).grid(row=0, column=1)

    def load_blank(self):
        """Clear all fields to start a fresh profile."""
        self.name_entry.delete(0, tk.END)
        for e in self._entries.values():
            e.delete(0, tk.END)

    # ------------------------
    # Internal helpers
    # ------------------------
    def _browse_into(self, entry, filetypes):
        initial = os.path.dirname(entry.get()) if entry.get() else os.getcwd()
        path = filedialog.askopenfilename(title="Select file", filetypes=filetypes, initialdir=initial)
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def _start_page_class(self):
        from ui.start_page import StartPage   #lazy import
        return StartPage
    
    def _on_profile_select(self, event):
        selection = self.profile_listbox.curselection()
        if not selection:
            return

        name = self.profile_listbox.get(selection[0])
        self.load_profile_into_form(name)

    def _compute_hex_and_dotted(self, addr_text: str):
        """
        Return (hex_str, dotted_str) from user input that may be dotted or hex.
        - If dotted is given (X.XXX.XXX.XXX), convert to hex by removing dots and
          replacing '0' → 'a' (matching the original backend address rule).
        - If hex is given, derive dotted using backend helper.
        - Trim hex to first 10 nibbles (5 bytes).
        """
        #lazy import
        try:
            from analyzer_backend import to_dotted_atcs_format
        except Exception as e:
            messagebox.showerror("Error", f"Could not load address formatter:\n{e}")
            return "", ""

        s = (addr_text or "").strip()
        if not s:
            return "", ""

        raw = s.replace(":", "").replace("-", "").replace(".", "")
        if "." in s:
            hex_str = raw.replace("0", "a")
            dotted_str = s
        else:
            hex_str = raw
            dotted_str = to_dotted_atcs_format(s)

        hex_str = "".join([c for c in hex_str if c.lower() in "0123456789abcdef"])[:10]
        return (hex_str, dotted_str)
    
    def load_profile_into_form(self, name):
        from profile_manager import load_profile

        data = load_profile(name)

        self.name_entry.delete(0, tk.END)
        self.name_entry.insert(0, name)

        # fill all fields
        self._entries["ixl_file"].delete(0, tk.END)
        self._entries["ixl_file"].insert(0, data.get("ixl_file", ""))

        self._entries["cm_log_file"].delete(0, tk.END)
        self._entries["cm_log_file"].insert(0, data.get("cm_log_file", ""))

        self._entries["pcap_file"].delete(0, tk.END)
        self._entries["pcap_file"].insert(0, data.get("pcap_file", ""))

        self._entries["packetswitch_file"].delete(0, tk.END)
        self._entries["packetswitch_file"].insert(0, data.get("packetswitch_file", ""))

        self._entries["office_file"].delete(0, tk.END)
        self._entries["office_file"].insert(0, data.get("office_file", ""))

        self._entries["ixl_excel_file"].delete(0, tk.END)
        self._entries["ixl_excel_file"].insert(0, data.get("ixl_excel_file", ""))

        self._entries["location_excel_file"].delete(0, tk.END)
        self._entries["location_excel_file"].insert(0, data.get("location_excel_file", ""))

        self._entries["output_suffix"].delete(0, tk.END)
        self._entries["output_suffix"].insert(0, data.get("output_suffix", ""))

        self._entries["target_address_input"].delete(0, tk.END)
        self._entries["target_address_input"].insert(
            0, data.get("target_address_dotted", "") or data.get("target_address_hex", ""))
        
        for i in range(self.profile_listbox.size()):
            if self.profile_listbox.get(i) == name:
                self.profile_listbox.selection_clear(0, tk.END)
                self.profile_listbox.selection_set(i)
                self.profile_listbox.see(i)
                break
    
    def on_show(self):
        self.load_blank()
        self.profile_listbox.selection_clear(0, tk.END)

    def _save(self):
        name = self.name_entry.get().strip()
        if not name:
            messagebox.showerror("Error", "Enter a profile name.")
            return

        addr_input = self._entries["target_address_input"].get().strip()
        hex_addr, dotted_addr = self._compute_hex_and_dotted(addr_input)

        data = {
            "ixl_file":          self._entries["ixl_file"].get().strip(),
            "cm_log_file":       self._entries["cm_log_file"].get().strip(),
            "pcap_file":         self._entries["pcap_file"].get().strip(),
            "packetswitch_file": self._entries["packetswitch_file"].get().strip(),
            "office_file": self._entries["office_file"].get().strip(),
            "ixl_excel_file":    self._entries["ixl_excel_file"].get().strip(),
            "location_excel_file": self._entries["location_excel_file"].get().strip(),
            "output_suffix":     self._entries["output_suffix"].get().strip(),
            "target_address_hex":    hex_addr,
            "target_address_dotted": dotted_addr,
        }

        try:
            save_profile(name, data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile:\n{e}")
            return
        self.profile_listbox.delete(0, tk.END)

        for p in list_profiles():
            self.profile_listbox.insert("end", p)

        messagebox.showinfo("Saved", f"Profile '{name}' saved.")
        # Ask StartPage to refresh the list and go back
        self.controller.refresh_start_page_profiles()
        self.controller.show(self._start_page_class())
