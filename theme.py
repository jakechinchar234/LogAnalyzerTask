# ui/theme.py
"""
Applies a modern dark theme to Tkinter/ttk widgets.
IGNORE PALETTE FOR NOW _ TESTING DIFFERENT COLOURS AND LAYOUTS.
------------------------------------------------------------
Palette
-------
Background (app):     #1E1F22
Surface / Card:       #2B2D31
Surface (sunken):     #232428
Accent (hover):       #3A3D42
Text (primary):       #FFFFFF
Text (muted):         #C8CDD5
------------------------------------------------------------
"""
from tkinter import ttk


def apply_dark_theme(root):
    """
    Apply a clean, professional dark theme to the whole application.
    Call this once in your root App.__init__ before laying out widgets.
    """
    # App background
    root.configure(bg="#4a4a4a")

    style = ttk.Style(root)
    # 'clam' is theme base
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # -------------------------
    # Base styles
    # -------------------------
    style.configure(".", background="#4a4a4a", foreground="#FFFFFF", fieldbackground="#4a4a4a", borderwidth=0, relief="flat")

    # Frames
    style.configure("TFrame", background="#4a4a4a")
    style.configure("Card.TFrame", background="#4a4a4a")

    # Labels
    style.configure("TLabel", background="#4a4a4a", foreground="#FFFFFF")

    # Buttons
    style.configure(
        "TButton",
        background="#4a4a4a",
        foreground="#FFFFFF",
        padding=6,
        relief="flat",
    )
    style.map(
        "TButton",
        background=[("active", "#4a4a4a"), ("pressed", "#4a4a4a")],
        relief=[("pressed", "flat"), ("!pressed", "flat")],
    )

    # Entries
    style.configure(
        "TEntry",
        fieldbackground="#4a4a4a",
        foreground="#FFFFFF",
        insertcolor="#FFFFFF",
        padding=4,
        relief="flat",
    )

    # Combobox
    style.configure(
        "TCombobox",
        fieldbackground="#4a4a4a",
        foreground="#FFFFFF",
        arrowcolor="#FFFFFF",
        padding=2,
        relief="flat",
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", "#4a4a4a"), ("!disabled", "#4a4a4a")],
        foreground=[("readonly", "#FFFFFF")],
        background=[("active", "#4a4a4a")],
    )

    # Notebook (tabs) — in case you use it later
    style.configure(
        "TNotebook",
        background="#4a4a4a",
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background="#4a4a4a",
        foreground="#FFFFFF",
        padding=(10, 6),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", "#4a4a4a"), ("active", "#4a4a4a")],
        foreground=[("selected", "#FFFFFF")],
    )

    # Progressbar
    style.configure(
        "TProgressbar",
        background="#4a4a4a",
        troughcolor="#232428",
        bordercolor="#232428",
        lightcolor="#3A3D42",
        darkcolor="#3A3D42",
    )

    # Treeview
    style.configure(
        "Treeview",
        background="#4a4a4a",
        fieldbackground="#4a4a4a",
        foreground="#FFFFFF",
        rowheight=24,
        borderwidth=0,
    )
    style.configure(
        "Treeview.Heading",
        background="#4a4a4a",
        foreground="#FFFFFF",
        borderwidth=0,
        relief="flat",
    )
    style.map(
        "Treeview",
        background=[("selected", "#4a4a4a")],
        foreground=[("selected", "#FFFFFF")],
    )

    # Scrollbar
    style.configure(
        "Vertical.TScrollbar",
        background="#2B2D31",
        troughcolor="#232428",
        bordercolor="#232428",
        arrowcolor="#FFFFFF",
    )
    style.configure(
        "Horizontal.TScrollbar",
        background="#2B2D31",
        troughcolor="#232428",
        bordercolor="#232428",
        arrowcolor="#FFFFFF",
    )
    
    style.configure("Sidebar.TFrame", background="#363636")

    style.configure(
        "Sidebar.TButton",
        background="#363636",
        foreground="white",
        anchor="center",
        padding=10
    )

    style.map(
        "Sidebar.TButton",
        background=[("active", "#363636")]
    )
    return style