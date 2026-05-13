import tkinter as tk
from tkinter import scrolledtext
import numpy as np

class StorageOS:
    def __init__(self, root):
        self.root = root
        self.root.title("StorageOS v0.1 — Desktop Interface")
        self.root.geometry("1200x800")
        self.root.configure(bg="#080b0e")
        self.root.minsize(1000, 700)

        # Core Storage: values [0,1] + custom glyphs per cell
        self.storage_buffer = np.random.rand(10, 12).astype(np.float32)
        self.custom_glyphs = np.full((10, 12), '', dtype='U1')  # Custom char per cell
        
        # Terminal memory
        self.terminal_memory = None
        self.terminal_glyphs_memory = None
        
        self.setup_ui()
        self.render_labeller()

    def setup_ui(self):
        # LEFT PANEL: ASCII LABELLER + CONTROLS
        self.left_panel = tk.Frame(self.root, bg="#0e1317", width=750)
        self.left_panel.pack(side="left", fill="both", expand=True)
        self.left_panel.pack_propagate(False)

        # Header
        header = tk.Frame(self.left_panel, bg="#0e1317", padx=30, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="§ 3 — STORAGE FORMATS", bg="#0e1317", fg="#5a7080", 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        tk.Label(header, text="Array ASCII Labeller", bg="#0e1317", fg="#00e87a", 
                font=("Consolas", 18, "bold")).pack(anchor="w")

        # Controls
        ctrl_frame = tk.Frame(self.left_panel, bg="#141a20", relief="ridge", bd=1)
        ctrl_frame.pack(fill="x", padx=30, pady=(10,15))
        
        tk.Label(ctrl_frame, text="MATRIX OPS", bg="#141a20", fg="#f5a623", 
                font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10,5))
        
        btn_frame = tk.Frame(ctrl_frame, bg="#141a20")
        btn_frame.pack(fill="x", padx=15, pady=(0,10))
        
        tk.Button(btn_frame, text="GEMM Test", bg="#0e1317", fg="#00e87a", font=("Consolas", 10),
                 command=self.gemm_demo).pack(side="left", padx=(0,5))
        tk.Button(btn_frame, text="Transpose", bg="#0e1317", fg="#4d9fff", font=("Consolas", 10),
                 command=self.transpose_matrix).pack(side="left", padx=(0,5))
        tk.Button(btn_frame, text="Reshape", bg="#0e1317", fg="#f5a623", font=("Consolas", 10),
                 command=self.reshape_matrix).pack(side="left", padx=(0,5))
        tk.Button(btn_frame, text="Normalize", bg="#0e1317", fg="#ff4d6a", font=("Consolas", 10),
                 command=self.normalize_matrix).pack(side="left", padx=(10,0))

        # Custom glyph toggle
        self.custom_mode = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl_frame, text="Custom Glyphs", variable=self.custom_mode, 
                      bg="#141a20", fg="#00e87a", selectcolor="#0e1317", font=("Consolas", 10),
                      command=self.toggle_custom_mode).pack(anchor="e", padx=15)

        # Scrollable grid
        canvas_frame = tk.Frame(self.left_panel, bg="#080b0e")
        canvas_frame.pack(fill="both", expand=True, padx=30, pady=(0,20))
        
        self.canvas = tk.Canvas(canvas_frame, bg="#080b0e", highlightthickness=0)
        scrollbar = tk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#080b0e")

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Status bar
        self.status_var = tk.StringVar()
        tk.Label(self.left_panel, textvariable=self.status_var, bg="#080b0e", fg="#5a7080", 
                font=("Consolas", 10)).pack(fill="x", padx=30)

        # RIGHT PANEL: TERMINAL
        self.right_panel = tk.Frame(self.root, bg="#080b0e", width=400)
        self.right_panel.pack(side="right", fill="y", padx=(0,20), pady=20)
        self.right_panel.pack_propagate(False)

        tk.Label(self.right_panel, text="CONSOLE SUBSYSTEM", bg="#080b0e", fg="#00e87a", 
                font=("Consolas", 10, "bold")).pack(anchor="w", pady=(0,5))
        
        self.term_output = scrolledtext.ScrolledText(self.right_panel, height=32, bg="#000", fg="#a8d4a0", 
                                                   font=("Consolas", 10), borderwidth=0, state="normal")
        self.term_output.pack(fill="both", expand=True, pady=(0,10))

        self.term_input = tk.Entry(self.right_panel, bg="#141a20", fg="#e8f4ff", 
                                 insertbackground="#00e87a", font=("Consolas", 11), relief="flat")
        self.term_input.pack(fill="x")
        self.term_input.bind("<Return>", self.handle_terminal)
        self.term_input.focus()

        self.write_terminal("StorageOS v0.1 | Custom glyphs ✓\nType 'help' for commands.\n\n$ ")
        self.update_status()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        return "break"

    def safe_color(self, val):
        """Safe hex color generation."""
        alpha = int(np.clip(128 + val * 127, 0, 255))
        g = int(np.clip(alpha * 0.5, 0, 255))
        return f"#{0:02x}{alpha:02x}{g:02x}"

    def get_display_glyph(self, r, c):
        """Display glyph: custom OR computed from value."""
        if self.custom_glyphs[r, c] != '':
            return self.custom_glyphs[r, c]
        val = float(np.clip(self.storage_buffer[r, c], 0.0, 1.0))
        glyphs = ['·', '+', '×', '#', '@']
        return glyphs[int(val * (len(glyphs) - 1))]

    def render_labeller(self):
        """Render full editable grid."""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        rows, cols = self.storage_buffer.shape
        cell_width = 4
        
        for r in range(rows):
            row_frame = tk.Frame(self.scrollable_frame, bg="#080b0e")
            row_frame.pack(fill="x", pady=1)
            
            for c in range(cols):
                val = float(np.clip(self.storage_buffer[r, c], 0.0, 1.0))
                glyph = self.get_display_glyph(r, c)
                
                cell = tk.Entry(row_frame, width=cell_width, justify="center", 
                               font=("Consolas", 16, "bold"), bg="#000", fg=self.safe_color(val), 
                               relief="flat", bd=1, highlightthickness=1, highlightcolor="#00e87a")
                cell.insert(0, glyph)
                cell.pack(side="left", padx=1)
                
                # Store coordinates on widget
                cell.r = r
                cell.c = c
                cell.bind("<KeyRelease>", self.on_cell_edit)
                cell.bind("<FocusOut>", self.on_cell_edit)

        self.update_status()
        self.root.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_cell_edit(self, event):
        """Handle cell editing - accepts ANY printable char."""
        widget = event.widget
        text = widget.get().strip()
        r, c = widget.r, widget.c
        
        if len(text) == 1 and text.isprintable() and text not in ['\n', '\t', '\r']:
            self.custom_glyphs[r, c] = text
            widget.config(fg=self.safe_color(self.storage_buffer[r, c]))
        else:
            # Revert invalid input
            widget.delete(0, "end")
            widget.insert(0, self.get_display_glyph(r, c))
            widget.config(fg=self.safe_color(self.storage_buffer[r, c]))
        
        # Debounced refresh
        if not hasattr(self, '_refresh_id'):
            self._refresh_id = self.root.after(150, self.refresh_labeller)

    def refresh_labeller(self):
        """Safe refresh callback."""
        delattr(self, '_refresh_id')
        self.render_labeller()

    def toggle_custom_mode(self):
        """Enable/disable custom glyphs."""
        if not self.custom_mode.get():
            self.custom_glyphs.fill('')
            self.write_terminal("\n✓ Custom glyphs CLEARED - auto mode\n")
        else:
            self.write_terminal("\n✓ Custom glyphs ENABLED - type any char\n")
        self.render_labeller()

    def update_status(self):
        """Update status bar."""
        rows, cols = self.storage_buffer.shape
        custom_count = np.sum(self.custom_glyphs != '')
        mode = "CUSTOM" if self.custom_mode.get() else "AUTO"
        stats = self.storage_buffer
        self.status_var.set(f"{rows}×{cols} | {mode} | glyphs:{custom_count} | "
                          f"min:{stats.min():.2f} max:{stats.max():.2f} mean:{stats.mean():.2f}")

    # === MATRIX OPERATIONS (Preserve Custom Glyphs) ===
    def gemm_demo(self):
        """4×4 GEMM demo."""
        rows, cols = 4, 4
        A = np.random.rand(rows, rows)
        B = np.random.rand(rows, cols)
        C = np.dot(A, B)
        
        # Write to top-left, clear custom glyphs there
        self.storage_buffer[:rows, :cols] = C
        self.custom_glyphs[:rows, :cols] = ''
        self.render_labeller()
        self.write_terminal(f"\nGEMM: C=A·B (4×4 blocked)\nGFLOPS: ~{2*rows**3/1e9:.1f}\n")

    def transpose_matrix(self):
        """Transpose preserves glyphs."""
        old_shape = self.storage_buffer.shape
        self.storage_buffer = self.storage_buffer.T
        self.custom_glyphs = self.custom_glyphs.T
        self.render_labeller()
        self.write_terminal(f"\nTRANSPOSE: {old_shape} → {self.storage_buffer.shape}\n")

    def reshape_matrix(self):
        """Reshape cycle preserving glyphs."""
        current = self.storage_buffer.shape
        total = self.storage_buffer.size
        
        if current == (10, 12):
            new_shape = (12, 10)
        elif current == (12, 10):
            new_shape = (6, 20)
        elif current == (6, 20):
            new_shape = (10, 12)
        else:
            new_shape = (10, 12)
            
        # Flatten preserves order
        self.storage_buffer = self.storage_buffer.flatten().reshape(new_shape)
        self.custom_glyphs = self.custom_glyphs.flatten().reshape(new_shape)
        self.render_labeller()
        self.write_terminal(f"\nRESHAPE: {current} → {new_shape} ({total} elements)\n")

    def normalize_matrix(self):
        """Min-max normalize."""
        old_min, old_max = self.storage_buffer.min(), self.storage_buffer.max()
        if old_max > old_min + 1e-8:
            self.storage_buffer = (self.storage_buffer - old_min) / (old_max - old_min)
        self.render_labeller()
        self.write_terminal(f"\nNORMALIZE: [{old_min:.3f},{old_max:.3f}] → [0,1]\n")

    def write_terminal(self, text):
        self.term_output.config(state="normal")
        self.term_output.insert("end", text)
        self.term_output.config(state="disabled")
        self.term_output.see("end")

    def handle_terminal(self, event):
        cmd_str = self.term_input.get().strip()
        if not cmd_str: return
        
        self.term_input.delete(0, "end")
        self.write_terminal(f"{cmd_str}\n")
        
        parts = cmd_str.lower().split()
        cmd = parts[0] if parts else ""
        response = ""

        # Command dispatch
        methods = {
            "gemm": self.gemm_demo,
            "transpose": self.transpose_matrix,
            "reshape": self.reshape_matrix,
            "normalize": self.normalize_matrix
        }
        
        if cmd in methods:
            try:
                methods[cmd]()
                return
            except Exception as e:
                response = f"Error: {str(e)}"
                
        elif cmd == "help":
            response = """COMMANDS:
  gemm          — 4×4 matrix multiply demo
  transpose     — In-place transpose (glyphs preserved)  
  reshape       — 10×12 ↔ 12×10 ↔ 6×20 cycle
  normalize     — Min-max [0,1]
  add <0-1>     — Circular append
  fill <0-1>    — Fill buffer
  dump          — Raw arrays
  stats         — Statistics
  labeler save  — Save values+glyphs
  labeler load  — Restore values+glyphs  
  clear         — Clear terminal
  exit          — Quit"""
            
        elif cmd == "add" and len(parts) > 1:
            try:
                v = np.clip(float(parts[1]), 0, 1)
                flat = self.storage_buffer.flatten()
                flat = np.roll(flat, -1)
                flat[-1] = v
                self.storage_buffer = flat.reshape(self.storage_buffer.shape)
                self.render_labeller()
                response = f"✓ Added {v:.3f}"
            except:
                response = "Error: 'add 0.8'"
                
        elif cmd == "fill" and len(parts) > 1:
            try:
                v = np.clip(float(parts[1]), 0, 1)
                self.storage_buffer.fill(v)
                self.render_labeller()
                response = f"✓ Filled {v:.3f}"
            except:
                response = "Error: 'fill 0.5'"
                
        elif cmd == "dump":
            response = (f"VALUES:\n{np.array2string(self.storage_buffer, precision=3)}\n"
                       f"CUSTOM GLYPHS:\n{np.array2string(self.custom_glyphs, max_line_width=80)}")
            
        elif cmd == "stats":
            s = self.storage_buffer
            custom_count = np.sum(self.custom_glyphs != '')
            response = (f"SHAPE: {s.shape} | CUSTOM: {custom_count}\n"
                       f"MIN:{s.min():.3f} MAX:{s.max():.3f} MEAN:{s.mean():.3f} STD:{s.std():.3f}")
            
        elif cmd == "labeler" and len(parts) > 1:
            subcmd = parts[1]
            if subcmd == "save":
                self.terminal_memory = self.storage_buffer.copy()
                self.terminal_glyphs_memory = self.custom_glyphs.copy()
                custom_count = np.sum(self.custom_glyphs != '')
                response = f"✓ Saved {self.storage_buffer.shape} + {custom_count} custom glyphs"
            elif subcmd == "load":
                if self.terminal_memory is not None and self.terminal_glyphs_memory is not None:
                    self.storage_buffer = self.terminal_memory.copy()
                    self.custom_glyphs = self.terminal_glyphs_memory.copy()
                    self.render_labeller()
                    response = f"✓ Loaded {self.storage_buffer.shape} w/ custom glyphs"
                else:
                    response = "❌ No saved state"
                    
        elif cmd == "clear":
            self.term_output.delete("1.0", "end")
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
    app = StorageOS(root)
    root.mainloop()
