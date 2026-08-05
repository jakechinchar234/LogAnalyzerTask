import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk


class Sidebar(ttk.Frame):
    def __init__(self, parent, controller, pages):
        super().__init__(parent, style="Sidebar.TFrame")

        self.controller = controller
        self.animating = False
        self.state = "collapsed"  # or "expanded"

        # ========================
        # SIZE SETTINGS
        # ========================
        self.expanded_width = 200
        self.collapsed_width = 60
        self.current_width = self.collapsed_width
        self.target_width = self.collapsed_width

        # place instead of grid/pack (overlay)
        self.place(x=0, y=0, width=self.collapsed_width, relheight=1)

        # ========================
        # LOAD ICONS
        # ========================
        self.icons = {
            "Profiles": self.load_icon("icons/home.png"),
            "Run Analysis": self.load_icon("icons/play.png"),
            "Edit Profile": self.load_icon("icons/edit-icon.png"),
        }

        self._buttons = {}

        # ========================
        # CREATE BUTTONS
        # ========================
        for name, PageClass in pages:
            btn = ttk.Button(
                self,
                text="",
                image=self.icons.get(name),
                compound="left",
                command=lambda p=PageClass: self._on_nav(p),
                style="Sidebar.TButton"
            )

            btn.pack(fill="x", padx=6, pady=12)

            self._buttons[PageClass] = (btn, name)

        # ========================
        # HOVER EVENTS
        # ========================
        self.bind("<Enter>", self._expand)

    # ========================
    # ICON LOADER
    # ========================
    def load_icon(self, path):
        img = Image.open(path).resize((24, 24))
        return ImageTk.PhotoImage(img)

    # ========================
    # NAVIGATION
    # ========================
    def _on_nav(self, PageClass):
        if hasattr(self.controller, "show_frame"):
            self.controller.show_frame(PageClass.__name__)
        else:
            self.controller.show(PageClass)

        self.highlight(PageClass)

    def highlight(self, active):
        for PageClass, (btn, _) in self._buttons.items():
            if PageClass == active:
                btn.configure(style="SidebarSelected.TButton")
            else:
                btn.configure(style="Sidebar.TButton")

    # ========================
    # EXPAND / COLLAPSE
    # ========================
    def _expand(self, event=None):
        if self.state == "expanded" or self.animating:
            return

        self.state = "expanded"

        for btn, name in self._buttons.values():
            btn.configure(text="  " + name)

        self.animate(self.expanded_width)

        # start tracking mouse continuously
        self.after(50, self._track_mouse)

    def _check_mouse_exit(self):
        x, y = self.winfo_pointerxy()
        widget = self.winfo_containing(x, y)

        #key fix: ensure mouse is REALLY outside sidebar
        if widget is None:
            self._collapse()
            return

        if not self._is_child_of_sidebar(widget):
            self._collapse()

    def _track_mouse(self):
        if self.state != "expanded":
            return

        x, y = self.winfo_pointerxy()

        left = self.winfo_rootx()
        right = left + self.current_width

        top = self.winfo_rooty()
        bottom = top + self.winfo_height()

        # PURE GEOMETRY CHECK (no widget detection)
        inside = (left <= x <= right) and (top <= y <= bottom)

        if not inside:
            self._collapse()
            return

        self.after(50, self._track_mouse)

    def _is_child_of_sidebar(self, widget):
        while widget is not None:
            if widget == self:
                return True
            widget = widget.master
        return False

    def _collapse(self):
        if self.state == "collapsed":
            return

        self.state = "collapsed"

        for btn, _ in self._buttons.values():
            btn.configure(text="")

        self.animate(self.collapsed_width)

    # ========================
    # SMOOTH ANIMATION
    # ========================
    def animate(self, target_width):
        # always store latest goal
        self.target_width = target_width

        if self.animating:
            return

        self.animating = True

        def step():
            diff = self.target_width - self.current_width

            if abs(diff) < 2:
                self.current_width = self.target_width
            else:
                self.current_width += diff * 0.3

            self.current_width = int(self.current_width)

            self.place_configure(width=self.current_width)

            #keep going until we reach CURRENT target
            if self.current_width != self.target_width:
                self.after(10, step)
            else:
                self.animating = False

        step()