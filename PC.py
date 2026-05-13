import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import numpy as np
import json
import os

# ── Glyph Sets ────────────────────────────────────────────────────────────────
GLYPH_SETS = {
    "Classic":   ['·', '+', '×', '#', '@'],
    "Blocks":    [' ', '░', '▒', '▓', '█'],
    "Braille":   ['⠀', '⠂', '⠖', '⠿', '⣿'],
    "Arrows":    ['↗', '→', '↘', '↓', '↙'],
    "Faces":     ['○', '◔', '◑', '◕', '●'],
    "Runes":     ['ᚠ', 'ᚢ', 'ᚦ', 'ᚨ', 'ᚱ'],
    "Math":      ['∅', '∝', '∞', '∑', '∏'],
    "Currency":  ['¢', '£', '€', '¥', '₿'],
    "Greek":     ['α', 'β', 'γ', 'δ', 'Ω'],
    "Dice":      ['⚀', '⚁', '⚂', '⚃', '⚄'],
    "Stars":     ['✦', '✧', '✩', '✪', '★'],
    "Binary":    ['░', '▄', '▀', '▌', '█'],
}

# ── Reshape Presets ────────────────────────────────────────────────────────────
RESHAPE_CYCLE = [
    (10, 12), (12, 10), (6, 20), (20, 6),
    (5, 24),  (8, 15),  (4, 30), (15, 8),
    (3, 40),  (2, 60),  (1, 120),
]


class StorageOS:
    def __init__(self, root):
        self.root = root
        self.root.title("StorageOS v0.2 — Desktop Interface")
        self.root.geometry("1280x820")
        self.root.configure(bg="#080b0e")
        self.root.minsize(1050, 720)

        # Core storage
        self.storage_buffer = np.random.rand(10, 12).astype(np.float32)
        self.custom_glyphs  = np.full((10, 12), '', dtype='U1')

        # Memory slots (5 named slots)
        self.memory_slots = {str(i): None for i in range(5)}

        # Glyph set selector
        self.glyph_set_name = tk.StringVar(value="Classic")

        # Reshape index
        self._reshape_idx = 0

        # Terminal memory (legacy labeler save/load)
        self.terminal_memory        = None
        self.terminal_glyphs_memory = None

        self.setup_ui()
        self.render_labeller()

    # ── UI ────────────────────────────────────────────────────────────────────

    def setup_ui(self):
        # ── LEFT PANEL ────────────────────────────────────────────────────────
        self.left_panel = tk.Frame(self.root, bg="#0e1317", width=780)
        self.left_panel.pack(side="left", fill="both", expand=True)
        self.left_panel.pack_propagate(False)

        # Header
        header = tk.Frame(self.left_panel, bg="#0e1317", padx=30, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="§ 3 — STORAGE FORMATS", bg="#0e1317", fg="#5a7080",
                 font=("Consolas", 10, "bold")).pack(anchor="w")
        tk.Label(header, text="Array ASCII Labeller", bg="#0e1317", fg="#00e87a",
                 font=("Consolas", 18, "bold")).pack(anchor="w")

        # ── Controls row 1: matrix ops ────────────────────────────────────────
        ctrl1 = tk.Frame(self.left_panel, bg="#141a20", relief="ridge", bd=1)
        ctrl1.pack(fill="x", padx=30, pady=(0, 4))
        tk.Label(ctrl1, text="MATRIX OPS", bg="#141a20", fg="#f5a623",
                 font=("Consolas", 10, "bold")).pack(anchor="w", padx=15, pady=(8, 4))
        bf1 = tk.Frame(ctrl1, bg="#141a20")
        bf1.pack(fill="x", padx=15, pady=(0, 8))
        for label, color, cmd in [
            ("GEMM",      "#00e87a", self.gemm_demo),
            ("Transpose", "#4d9fff", self.transpose_matrix),
            ("Reshape ↻", "#f5a623", self.reshape_matrix),
            ("Normalize", "#ff4d6a", self.normalize_matrix),
            ("Randomize", "#c86dff", self.randomize_matrix),
            ("Zeros",     "#5a7080", self.zero_matrix),
            ("Gradient",  "#ffb347", self.gradient_matrix),
        ]:
            tk.Button(bf1, text=label, bg="#0e1317", fg=color,
                      font=("Consolas", 9), relief="flat", padx=6,
                      command=cmd).pack(side="left", padx=2)

        # ── Controls row 2: glyphs + file ops ─────────────────────────────────
        ctrl2 = tk.Frame(self.left_panel, bg="#141a20", relief="ridge", bd=1)
        ctrl2.pack(fill="x", padx=30, pady=(0, 4))
        top2 = tk.Frame(ctrl2, bg="#141a20")
        top2.pack(fill="x", padx=15, pady=(8, 4))

        tk.Label(top2, text="GLYPH SET:", bg="#141a20", fg="#5a7080",
                 font=("Consolas", 9)).pack(side="left")
        gs_menu = tk.OptionMenu(top2, self.glyph_set_name,
                                *GLYPH_SETS.keys(), command=self._glyph_set_changed)
        gs_menu.config(bg="#0e1317", fg="#00e87a", font=("Consolas", 9),
                       activebackground="#141a20", activeforeground="#00e87a",
                       highlightthickness=0, relief="flat")
        gs_menu["menu"].config(bg="#0e1317", fg="#00e87a", font=("Consolas", 9))
        gs_menu.pack(side="left", padx=(4, 20))

        self.custom_mode = tk.BooleanVar(value=True)
        tk.Checkbutton(top2, text="Custom Glyphs", variable=self.custom_mode,
                       bg="#141a20", fg="#00e87a", selectcolor="#0e1317",
                       font=("Consolas", 9),
                       command=self.toggle_custom_mode).pack(side="left", padx=8)

        bf2 = tk.Frame(ctrl2, bg="#141a20")
        bf2.pack(fill="x", padx=15, pady=(0, 8))
        tk.Label(bf2, text="FILE:", bg="#141a20", fg="#5a7080",
                 font=("Consolas", 9)).pack(side="left")
        for label, color, cmd in [
            ("Save JSON",  "#4d9fff", self.file_save_json),
            ("Load JSON",  "#4d9fff", self.file_load_json),
            ("Save CSV",   "#f5a623", self.file_save_csv),
            ("Load CSV",   "#f5a623", self.file_load_csv),
            ("Save NPZ",   "#c86dff", self.file_save_npz),
            ("Load NPZ",   "#c86dff", self.file_load_npz),
        ]:
            tk.Button(bf2, text=label, bg="#0e1317", fg=color,
                      font=("Consolas", 9), relief="flat", padx=6,
                      command=cmd).pack(side="left", padx=2)

        # ── Controls row 3: memory slots ──────────────────────────────────────
        ctrl3 = tk.Frame(self.left_panel, bg="#141a20", relief="ridge", bd=1)
        ctrl3.pack(fill="x", padx=30, pady=(0, 8))
        top3 = tk.Frame(ctrl3, bg="#141a20")
        top3.pack(fill="x", padx=15, pady=(8, 8))
        tk.Label(top3, text="SLOTS:", bg="#141a20", fg="#5a7080",
                 font=("Consolas", 9)).pack(side="left")
        for i in range(5):
            slot = str(i)
            f = tk.Frame(top3, bg="#141a20")
            f.pack(side="left", padx=6)
            tk.Label(f, text=f"[{i}]", bg="#141a20", fg="#5a7080",
                     font=("Consolas", 9)).pack(side="left")
            tk.Button(f, text="W", bg="#0e1317", fg="#00e87a",
                      font=("Consolas", 8), relief="flat", padx=3,
                      command=lambda s=slot: self.slot_write(s)).pack(side="left")
            tk.Button(f, text="R", bg="#0e1317", fg="#ff4d6a",
                      font=("Consolas", 8), relief="flat", padx=3,
                      command=lambda s=slot: self.slot_read(s)).pack(side="left")

        # Scrollable grid
        canvas_frame = tk.Frame(self.left_panel, bg="#080b0e")
        canvas_frame.pack(fill="both", expand=True, padx=30, pady=(0, 10))

        self.canvas = tk.Canvas(canvas_frame, bg="#080b0e", highlightthickness=0)
        scrollbar_y = tk.Scrollbar(canvas_frame, orient="vertical",
                                   command=self.canvas.yview)
        scrollbar_x = tk.Scrollbar(canvas_frame, orient="horizontal",
                                   command=self.canvas.xview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#080b0e")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar_y.set,
                              xscrollcommand=scrollbar_x.set)
        scrollbar_x.pack(side="bottom", fill="x")
        scrollbar_y.pack(side="right",  fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Status bar
        self.status_var = tk.StringVar()
        tk.Label(self.left_panel, textvariable=self.status_var,
                 bg="#080b0e", fg="#5a7080",
                 font=("Consolas", 9)).pack(fill="x", padx=30, pady=(0, 6))

        # ── RIGHT PANEL: TERMINAL ─────────────────────────────────────────────
        self.right_panel = tk.Frame(self.root, bg="#080b0e", width=440)
        self.right_panel.pack(side="right", fill="y", padx=(0, 20), pady=20)
        self.right_panel.pack_propagate(False)

        tk.Label(self.right_panel, text="CONSOLE SUBSYSTEM",
                 bg="#080b0e", fg="#00e87a",
                 font=("Consolas", 10, "bold")).pack(anchor="w", pady=(0, 5))

        self.term_output = scrolledtext.ScrolledText(
            self.right_panel, height=32, bg="#000", fg="#a8d4a0",
            font=("Consolas", 10), borderwidth=0, state="normal")
        self.term_output.pack(fill="both", expand=True, pady=(0, 10))

        self.term_input = tk.Entry(
            self.right_panel, bg="#141a20", fg="#e8f4ff",
            insertbackground="#00e87a", font=("Consolas", 11), relief="flat")
        self.term_input.pack(fill="x")
        self.term_input.bind("<Return>", self.handle_terminal)
        self.term_input.focus()

        self.write_terminal(
            "StorageOS v0.2 | Glyphs ✓  File I/O ✓  Slots ✓\n"
            "Type 'help' for commands.\n\n$ ")
        self.update_status()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

    def safe_color(self, val):
        alpha = int(np.clip(60 + val * 195, 0, 255))
        g = int(np.clip(alpha * 0.48, 0, 255))
        return f"#{0:02x}{alpha:02x}{g:02x}"

    def current_glyphs(self):
        return GLYPH_SETS[self.glyph_set_name.get()]

    def get_display_glyph(self, r, c):
        if self.custom_mode.get() and self.custom_glyphs[r, c] != '':
            return self.custom_glyphs[r, c]
        val  = float(np.clip(self.storage_buffer[r, c], 0.0, 1.0))
        gs   = self.current_glyphs()
        return gs[int(val * (len(gs) - 1))]

    def _glyph_set_changed(self, *_):
        self.render_labeller()
        self.write_terminal(f"\n✓ Glyph set → {self.glyph_set_name.get()}\n")

    # ── Render ────────────────────────────────────────────────────────────────

    def render_labeller(self):
        for w in self.scrollable_frame.winfo_children():
            w.destroy()

        rows, cols = self.storage_buffer.shape

        for r in range(rows):
            row_frame = tk.Frame(self.scrollable_frame, bg="#080b0e")
            row_frame.pack(fill="x", pady=1)

            for c in range(cols):
                val   = float(np.clip(self.storage_buffer[r, c], 0.0, 1.0))
                glyph = self.get_display_glyph(r, c)

                cell = tk.Entry(row_frame, width=3, justify="center",
                                font=("Consolas", 15, "bold"),
                                bg="#000", fg=self.safe_color(val),
                                relief="flat", bd=1,
                                highlightthickness=1, highlightcolor="#00e87a")
                cell.insert(0, glyph)
                cell.pack(side="left", padx=1)
                cell.r = r
                cell.c = c
                cell.bind("<KeyRelease>", self.on_cell_edit)
                cell.bind("<FocusOut>",   self.on_cell_edit)

        self.update_status()
        self.root.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_cell_edit(self, event):
        widget = event.widget
        text   = widget.get().strip()
        r, c   = widget.r, widget.c

        if (len(text) == 1 and text.isprintable()
                and text not in ['\n', '\t', '\r']):
            self.custom_glyphs[r, c] = text
            widget.config(fg=self.safe_color(self.storage_buffer[r, c]))
        else:
            widget.delete(0, "end")
            widget.insert(0, self.get_display_glyph(r, c))
            widget.config(fg=self.safe_color(self.storage_buffer[r, c]))

        if not hasattr(self, '_refresh_id'):
            self._refresh_id = self.root.after(200, self._refresh_cb)

    def _refresh_cb(self):
        delattr(self, '_refresh_id')
        self.render_labeller()

    def refresh_labeller(self):
        self.render_labeller()

    def toggle_custom_mode(self):
        if not self.custom_mode.get():
            self.custom_glyphs.fill('')
            self.write_terminal("\n✓ Custom glyphs CLEARED — auto mode\n")
        else:
            self.write_terminal("\n✓ Custom glyphs ENABLED — type any char\n")
        self.render_labeller()

    def update_status(self):
        rows, cols   = self.storage_buffer.shape
        custom_count = np.sum(self.custom_glyphs != '')
        mode         = "CUSTOM" if self.custom_mode.get() else "AUTO"
        s            = self.storage_buffer
        gs           = self.glyph_set_name.get()
        self.status_var.set(
            f"{rows}×{cols}  {mode}  glyphs:{custom_count}  set:{gs}  "
            f"min:{s.min():.2f}  max:{s.max():.2f}  mean:{s.mean():.2f}")

    # ── Matrix Operations ─────────────────────────────────────────────────────

    def gemm_demo(self):
        rows, cols = 4, 4
        A = np.random.rand(rows, rows)
        B = np.random.rand(rows, cols)
        C = np.dot(A, B)
        self.storage_buffer[:rows, :cols] = C
        self.custom_glyphs[:rows, :cols]  = ''
        self.render_labeller()
        self.write_terminal(f"\nGEMM: C=A·B (4×4 blocked)\n"
                            f"GFLOPS: ~{2*rows**3/1e9:.1f}\n")

    def transpose_matrix(self):
        old_shape            = self.storage_buffer.shape
        self.storage_buffer  = self.storage_buffer.T
        self.custom_glyphs   = self.custom_glyphs.T
        # Update reshape index to match current shape
        if self.storage_buffer.shape in RESHAPE_CYCLE:
            self._reshape_idx = RESHAPE_CYCLE.index(self.storage_buffer.shape)
        self.render_labeller()
        self.write_terminal(f"\nTRANSPOSE: {old_shape} → {self.storage_buffer.shape}\n")

    def reshape_matrix(self):
        current     = self.storage_buffer.shape
        total       = self.storage_buffer.size
        # Find current index in cycle (or nearest by total elements)
        try:
            self._reshape_idx = RESHAPE_CYCLE.index(current)
        except ValueError:
            self._reshape_idx = 0
        self._reshape_idx = (self._reshape_idx + 1) % len(RESHAPE_CYCLE)
        # Only use shapes whose total matches
        attempts = 0
        while (RESHAPE_CYCLE[self._reshape_idx][0] *
               RESHAPE_CYCLE[self._reshape_idx][1] != total):
            self._reshape_idx = (self._reshape_idx + 1) % len(RESHAPE_CYCLE)
            attempts += 1
            if attempts > len(RESHAPE_CYCLE):
                self.write_terminal(f"\n⚠ No alternate reshape for {total} elements\n")
                return
        new_shape            = RESHAPE_CYCLE[self._reshape_idx]
        self.storage_buffer  = self.storage_buffer.flatten().reshape(new_shape)
        self.custom_glyphs   = self.custom_glyphs.flatten().reshape(new_shape)
        self.render_labeller()
        self.write_terminal(f"\nRESHAPE: {current} → {new_shape} ({total} elements)\n")

    def normalize_matrix(self):
        old_min, old_max = self.storage_buffer.min(), self.storage_buffer.max()
        if old_max > old_min + 1e-8:
            self.storage_buffer = ((self.storage_buffer - old_min) /
                                   (old_max - old_min)).astype(np.float32)
        self.render_labeller()
        self.write_terminal(f"\nNORMALIZE: [{old_min:.3f},{old_max:.3f}] → [0,1]\n")

    def randomize_matrix(self):
        self.storage_buffer = np.random.rand(*self.storage_buffer.shape).astype(np.float32)
        self.render_labeller()
        self.write_terminal("\nRANDOMIZE: new random values\n")

    def zero_matrix(self):
        self.storage_buffer.fill(0.0)
        self.render_labeller()
        self.write_terminal("\nZEROS: buffer cleared\n")

    def gradient_matrix(self):
        rows, cols = self.storage_buffer.shape
        row_vals   = np.linspace(0, 1, rows)
        col_vals   = np.linspace(0, 1, cols)
        rr, cc     = np.meshgrid(row_vals, col_vals, indexing='ij')
        self.storage_buffer = ((rr + cc) / 2).astype(np.float32)
        self.render_labeller()
        self.write_terminal("\nGRADIENT: diagonal ramp applied\n")

    # ── Memory Slots ──────────────────────────────────────────────────────────

    def slot_write(self, slot):
        self.memory_slots[slot] = {
            "buffer": self.storage_buffer.copy(),
            "glyphs": self.custom_glyphs.copy(),
            "glyph_set": self.glyph_set_name.get(),
        }
        self.write_terminal(f"\n✓ Slot [{slot}] written  "
                            f"{self.storage_buffer.shape}\n")

    def slot_read(self, slot):
        data = self.memory_slots[slot]
        if data is None:
            self.write_terminal(f"\n❌ Slot [{slot}] empty\n")
            return
        self.storage_buffer = data["buffer"].copy()
        self.custom_glyphs  = data["glyphs"].copy()
        self.glyph_set_name.set(data.get("glyph_set", "Classic"))
        self.render_labeller()
        self.write_terminal(f"\n✓ Slot [{slot}] loaded  "
                            f"{self.storage_buffer.shape}\n")

    # ── File I/O ──────────────────────────────────────────────────────────────

    def _ask_save(self, ext, filetypes):
        return filedialog.asksaveasfilename(
            defaultextension=ext, filetypes=filetypes,
            initialdir=os.path.expanduser("~"),
            title="Save StorageOS array")

    def _ask_load(self, filetypes):
        return filedialog.askopenfilename(
            filetypes=filetypes,
            initialdir=os.path.expanduser("~"),
            title="Load StorageOS array")

    def file_save_json(self):
        path = self._ask_save(".json", [("JSON files", "*.json")])
        if not path:
            return
        data = {
            "shape":     list(self.storage_buffer.shape),
            "glyph_set": self.glyph_set_name.get(),
            "values":    self.storage_buffer.tolist(),
            "custom_glyphs": self.custom_glyphs.tolist(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.write_terminal(f"\n✓ Saved JSON → {os.path.basename(path)}\n")

    def file_load_json(self):
        path = self._ask_load([("JSON files", "*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.storage_buffer = np.array(data["values"], dtype=np.float32)
            glyphs_list         = data.get("custom_glyphs", [])
            if glyphs_list:
                self.custom_glyphs = np.array(glyphs_list, dtype='U1')
            else:
                self.custom_glyphs = np.full(self.storage_buffer.shape, '', dtype='U1')
            gs = data.get("glyph_set", "Classic")
            if gs in GLYPH_SETS:
                self.glyph_set_name.set(gs)
            self.render_labeller()
            self.write_terminal(f"\n✓ Loaded JSON ← {os.path.basename(path)}  "
                                f"{self.storage_buffer.shape}\n")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            self.write_terminal(f"\n❌ JSON load error: {e}\n")

    def file_save_csv(self):
        path = self._ask_save(".csv", [("CSV files", "*.csv")])
        if not path:
            return
        np.savetxt(path, self.storage_buffer, delimiter=",", fmt="%.6f",
                   header=f"shape={self.storage_buffer.shape}")
        self.write_terminal(f"\n✓ Saved CSV → {os.path.basename(path)}\n")

    def file_load_csv(self):
        path = self._ask_load([("CSV files", "*.csv")])
        if not path:
            return
        try:
            data = np.loadtxt(path, delimiter=",", comments="#").astype(np.float32)
            if data.ndim == 1:
                data = data.reshape(1, -1)
            self.storage_buffer = data
            self.custom_glyphs  = np.full(data.shape, '', dtype='U1')
            self.render_labeller()
            self.write_terminal(f"\n✓ Loaded CSV ← {os.path.basename(path)}  "
                                f"{self.storage_buffer.shape}\n")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            self.write_terminal(f"\n❌ CSV load error: {e}\n")

    def file_save_npz(self):
        path = self._ask_save(".npz", [("NumPy archive", "*.npz")])
        if not path:
            return
        np.savez(path,
                 buffer=self.storage_buffer,
                 glyphs=self.custom_glyphs,
                 glyph_set=np.array([self.glyph_set_name.get()]))
        self.write_terminal(f"\n✓ Saved NPZ → {os.path.basename(path)}\n")

    def file_load_npz(self):
        path = self._ask_load([("NumPy archive", "*.npz")])
        if not path:
            return
        try:
            npz = np.load(path, allow_pickle=False)
            self.storage_buffer = npz["buffer"].astype(np.float32)
            self.custom_glyphs  = npz["glyphs"]
            if "glyph_set" in npz:
                gs = str(npz["glyph_set"][0])
                if gs in GLYPH_SETS:
                    self.glyph_set_name.set(gs)
            self.render_labeller()
            self.write_terminal(f"\n✓ Loaded NPZ ← {os.path.basename(path)}  "
                                f"{self.storage_buffer.shape}\n")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            self.write_terminal(f"\n❌ NPZ load error: {e}\n")

    # ── Terminal ──────────────────────────────────────────────────────────────

    def write_terminal(self, text):
        self.term_output.config(state="normal")
        self.term_output.insert("end", text)
        self.term_output.config(state="disabled")
        self.term_output.see("end")

    def handle_terminal(self, event):
        cmd_str = self.term_input.get().strip()
        if not cmd_str:
            return
        self.term_input.delete(0, "end")
        self.write_terminal(f"{cmd_str}\n")

        parts  = cmd_str.split()
        cmd    = parts[0].lower() if parts else ""
        response = ""

        METHODS = {
            "gemm":      self.gemm_demo,
            "transpose": self.transpose_matrix,
            "reshape":   self.reshape_matrix,
            "normalize": self.normalize_matrix,
            "randomize": self.randomize_matrix,
            "zeros":     self.zero_matrix,
            "gradient":  self.gradient_matrix,
        }

        if cmd in METHODS:
            try:
                METHODS[cmd]()
            except Exception as e:
                response = f"Error: {e}"

        elif cmd == "help":
            response = (
                "COMMANDS:\n"
                "  gemm          — 4×4 matrix multiply demo\n"
                "  transpose     — In-place transpose\n"
                "  reshape       — Cycle through reshape presets\n"
                "  normalize     — Min-max [0,1]\n"
                "  randomize     — New random values\n"
                "  zeros         — Fill with 0\n"
                "  gradient      — Diagonal ramp\n"
                "  add <0-1>     — Circular append\n"
                "  fill <0-1>    — Fill buffer with value\n"
                "  glyphs        — List glyph sets\n"
                "  glyphs <name> — Set glyph set\n"
                "  slot w <0-4>  — Write slot\n"
                "  slot r <0-4>  — Read slot\n"
                "  save json     — Save as JSON (file dialog)\n"
                "  save csv      — Save as CSV\n"
                "  save npz      — Save as NPZ\n"
                "  load json     — Load JSON\n"
                "  load csv      — Load CSV\n"
                "  load npz      — Load NPZ\n"
                "  dump          — Print raw arrays\n"
                "  stats         — Statistics\n"
                "  shapes        — List reshape presets\n"
                "  clear         — Clear terminal\n"
                "  exit          — Quit"
            )

        elif cmd == "glyphs":
            if len(parts) == 1:
                names = "  ".join(GLYPH_SETS.keys())
                response = f"Available sets:\n  {names}"
            else:
                name = parts[1].capitalize()
                if name in GLYPH_SETS:
                    self.glyph_set_name.set(name)
                    self.render_labeller()
                    response = f"✓ Glyph set → {name}"
                else:
                    response = f"Unknown set '{parts[1]}'. Try: {', '.join(GLYPH_SETS)}"

        elif cmd == "slot" and len(parts) >= 3:
            sub  = parts[1].lower()
            slot = parts[2]
            if slot not in [str(i) for i in range(5)]:
                response = "❌ Slot must be 0-4"
            elif sub == "w":
                self.slot_write(slot)
                return
            elif sub == "r":
                self.slot_read(slot)
                return
            else:
                response = "Usage: slot w <0-4> | slot r <0-4>"

        elif cmd == "save" and len(parts) > 1:
            {"json": self.file_save_json,
             "csv":  self.file_save_csv,
             "npz":  self.file_save_npz}.get(parts[1].lower(),
                lambda: self.write_terminal("❌ save json|csv|npz\n"))()
            return

        elif cmd == "load" and len(parts) > 1:
            {"json": self.file_load_json,
             "csv":  self.file_load_csv,
             "npz":  self.file_load_npz}.get(parts[1].lower(),
                lambda: self.write_terminal("❌ load json|csv|npz\n"))()
            return

        elif cmd == "add" and len(parts) > 1:
            try:
                v    = np.clip(float(parts[1]), 0, 1)
                flat = self.storage_buffer.flatten()
                flat = np.roll(flat, -1)
                flat[-1] = v
                self.storage_buffer = flat.reshape(self.storage_buffer.shape)
                self.render_labeller()
                response = f"✓ Added {v:.3f}"
            except Exception:
                response = "Error: add <0-1>"

        elif cmd == "fill" and len(parts) > 1:
            try:
                v = np.clip(float(parts[1]), 0, 1)
                self.storage_buffer.fill(v)
                self.render_labeller()
                response = f"✓ Filled {v:.3f}"
            except Exception:
                response = "Error: fill <0-1>"

        elif cmd == "dump":
            response = (f"VALUES:\n{np.array2string(self.storage_buffer, precision=3)}\n"
                        f"GLYPHS:\n{np.array2string(self.custom_glyphs, max_line_width=100)}")

        elif cmd == "stats":
            s  = self.storage_buffer
            cc = np.sum(self.custom_glyphs != '')
            response = (f"SHAPE:{s.shape}  CUSTOM:{cc}  SET:{self.glyph_set_name.get()}\n"
                        f"MIN:{s.min():.3f}  MAX:{s.max():.3f}  "
                        f"MEAN:{s.mean():.3f}  STD:{s.std():.3f}")

        elif cmd == "shapes":
            total = self.storage_buffer.size
            valids = [f"{r}×{c}" for r, c in RESHAPE_CYCLE if r * c == total]
            response = (f"Presets for {total} elements:\n  " +
                        "  ".join(valids) if valids else
                        f"No presets for {total} elements")

        elif cmd == "clear":
            self.term_output.config(state="normal")
            self.term_output.delete("1.0", "end")
            self.term_output.config(state="disabled")
            self.write_terminal("Cleared.\n\n$ ")
            return

        elif cmd == "exit":
            self.root.quit()
            return

        else:
            response = f"Unknown '{cmd}'. Type 'help'."

        if response:
            self.write_terminal(f"{response}\n\n$ ")


if __name__ == "__main__":
    root = tk.Tk()
    app  = StorageOS(root)
    root.mainloop()
