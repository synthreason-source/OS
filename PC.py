import tkinter as tk
from tkinter import scrolledtext, messagebox
import numpy as np

class StorageOS:
    def __init__(self, root):
        self.root = root
        self.root.title("StorageOS v0.1 — Desktop Interface")
        self.root.geometry("1200x800")
        self.root.configure(bg="#080b0e")
        self.root.minsize(1000, 700)

        # Core Storage: 10x12 Array 
        self.storage_buffer = np.random.rand(10, 12)
        self.glyphs = ['·', '+', '×', '#', '@']  # 'signal' schema
        
        # Terminal memory for labeler state
        self.terminal_memory = None
        
        self.setup_ui()
        self.render_labeller()

    def setup_ui(self):
        # --- LEFT PANEL: ASCII LABELLER + MATRIX CONTROLS ---
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

        # Matrix Controls
        ctrl_frame = tk.Frame(self.left_panel, bg="#141a20", relief="ridge", bd=1)
        ctrl_frame.pack(fill="x", padx=30, pady=(10,15))
        
        tk.Label(ctrl_frame, text="MATRIX OPS", bg="#141a20", fg="#f5a623", 
                font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10,5))
        
        btn_frame = tk.Frame(ctrl_frame, bg="#141a20")
        btn_frame.pack(fill="x", padx=15, pady=(0,10))
        
        tk.Button(btn_frame, text="GEMM Test", bg="#0e1317", fg="#00e87a", font=("Consolas", 10),
                 command=self.gemm_demo).pack(side="left", padx=(0,10))
        tk.Button(btn_frame, text="Transpose", bg="#0e1317", fg="#4d9fff", font=("Consolas", 10),
                 command=self.transpose_matrix).pack(side="left", padx=(0,10))
        tk.Button(btn_frame, text="Reshape", bg="#0e1317", fg="#f5a623", font=("Consolas", 10),
                 command=self.reshape_matrix).pack(side="left", padx=(0,10))
        tk.Button(btn_frame, text="Normalize", bg="#0e1317", fg="#ff4d6a", font=("Consolas", 10),
                 command=self.normalize_matrix).pack(side="left")

        # Scrollable grid canvas
        canvas_frame = tk.Frame(self.left_panel, bg="#080b0e")
        canvas_frame.pack(fill="both", expand=True, padx=30, pady=(0,20))
        
        self.canvas = tk.Canvas(canvas_frame, bg="#080b0e", highlightthickness=0)
        scrollbar = tk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#080b0e")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Mousewheel binding
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Status bar
        self.status_var = tk.StringVar(value=f"10×12 | min:{self.storage_buffer.min():.2f} max:{self.storage_buffer.max():.2f}")
        status = tk.Label(self.left_panel, textvariable=self.status_var, bg="#080b0e", fg="#5a7080", 
                         font=("Consolas", 10))
        status.pack(fill="x", padx=30)

        # --- RIGHT PANEL: TERMINAL ---
        self.right_panel = tk.Frame(self.root, bg="#080b0e", width=400)
        self.right_panel.pack(side="right", fill="y", padx=(0,20), pady=20)
        self.right_panel.pack_propagate(False)

        tk.Label(self.right_panel, text="CONSOLE SUBSYSTEM", bg="#080b0e", fg="#00e87a", 
                font=("Consolas", 10, "bold")).pack(anchor="w", pady=(0,5))
        
        self.term_output = scrolledtext.ScrolledText(
            self.right_panel, height=32, bg="#000", fg="#a8d4a0", 
            font=("Consolas", 10), borderwidth=0, state="normal"
        )
        self.term_output.pack(fill="both", expand=True, pady=(0,10))

        self.term_input = tk.Entry(
            self.right_panel, bg="#141a20", fg="#e8f4ff", 
            insertbackground="#00e87a", font=("Consolas", 11), relief="flat"
        )
        self.term_input.pack(fill="x")
        self.term_input.bind("<Return>", self.handle_terminal)
        self.term_input.focus()

        self.write_terminal("StorageOS v0.1 Online\nType 'help' for matrix commands.\n\n$ ")

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        return "break"

    def render_labeller(self):
        """Renders editable ASCII grid from numpy buffer."""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        rows, cols = self.storage_buffer.shape
        cell_width = 4
        
        for r in range(rows):
            row_frame = tk.Frame(self.scrollable_frame, bg="#080b0e")
            row_frame.pack(fill="x", pady=1)
            
            for c in range(cols):
                val = self.storage_buffer[r, c]
                g_idx = int(np.clip(val * (len(self.glyphs) - 1), 0, len(self.glyphs) - 1))
                glyph = self.glyphs[g_idx]
                
                cell = tk.Entry(
                    row_frame, width=cell_width, justify="center", 
                    font=("Consolas", 16, "bold"), bg="#000", fg=self.get_color(val), 
                    relief="flat", bd=1, highlightthickness=1, highlightcolor="#00e87a"
                )
                cell.insert(0, glyph)
                cell.pack(side="left", padx=1)
                
                cell.bind("<KeyRelease>", lambda e, row=r, col=c, w=cell: self.sync_cell(row, col, w))
                cell.bind("<FocusOut>", lambda e, row=r, col=c, w=cell: self.sync_cell(row, col, w))

        self.status_var.set(f"{rows}×{cols} | min:{self.storage_buffer.min():.2f} max:{self.storage_buffer.max():.2f} mean:{self.storage_buffer.mean():.2f}")
        self.scrollable_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def get_color(self, val):
        alpha = int(128 + val * 127)
        return f"#{0:02x}{alpha:02x}{int(alpha * 0.5):02x}"

    def sync_cell(self, r, c, widget):
        text = widget.get().strip()
        if text and text in self.glyphs:
            val = self.glyphs.index(text) / (len(self.glyphs) - 1)
            self.storage_buffer[r, c] = val
            widget.config(fg=self.get_color(val))
            self.render_labeller()  # Refresh status

    # === MATRIX OPERATIONS ===
    def gemm_demo(self):
        """C=A·B GEMM demo (simplified 4×4 blocked)."""
        rows, cols = 4, 4
        A = np.random.rand(rows, rows)
        B = np.random.rand(rows, cols)
        C = np.dot(A, B)
        
        self.storage_buffer[:rows, :cols] = C
        self.render_labeller()
        self.write_terminal(f"\nGEMM Demo: C=A·B (4×4 blocked)\nA.shape={A.shape} → C={C.shape}\nGFLOPS: ~{2*rows**3/1e9:.1f}\n")

    def transpose_matrix(self):
        """In-place transpose."""
        self.storage_buffer = self.storage_buffer.T
        self.render_labeller()
        self.write_terminal(f"\nTRANSPOSE: {self.storage_buffer.shape} → {self.storage_buffer.T.shape}\n")

    def reshape_matrix(self):
        """Dynamic reshape 10×12 ↔ 12×10 ↔ 6×20."""
        current = self.storage_buffer.shape
        if current == (10, 12):
            new_shape = (12, 10)
        elif current == (12, 10):
            new_shape = (6, 20)
        else:
            new_shape = (10, 12)
            
        total = self.storage_buffer.size
        self.storage_buffer = self.storage_buffer.flatten().reshape(new_shape)
        self.render_labeller()
        self.write_terminal(f"\nRESHAPE: {current} → {new_shape} ({total} elements)\n")

    def normalize_matrix(self):
        """Min-max normalization to [0,1]."""
        old_min, old_max = self.storage_buffer.min(), self.storage_buffer.max()
        self.storage_buffer = (self.storage_buffer - old_min) / (old_max - old_min + 1e-8)
        self.render_labeller()
        self.write_terminal(f"\nNORMALIZE: [{old_min:.3f},{old_max:.3f}] → [0.0,1.0]\n")

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

        # Existing commands...
        if cmd == "help":
            response = """MATRIX COMMANDS:
  gemm          — 4×4 GEMM demo (C=A·B)
  transpose     — In-place transpose  
  reshape       — Cycle 10×12 ↔ 12×10 ↔ 6×20
  normalize     — Min-max to [0,1]
  add <0-1>     — Append value
  fill <0-1>    — Fill buffer
  dump          — Raw array
  stats         — Statistics
  labeler save  — Save to terminal mem
  labeler load  — Load from terminal mem
  clear         — Clear output
  exit          — Quit"""
            
        elif cmd in ["gemm", "transpose", "reshape", "normalize"]:
            getattr(self, cmd + "_matrix")() if cmd != "gemm" else self.gemm_demo()
            return
            
        elif cmd == "add" and len(parts) > 1:
            try:
                v = float(parts[1])
                if 0 <= v <= 1:
                    flat = self.storage_buffer.flatten()
                    flat = np.roll(flat, -1)
                    flat[-1] = v
                    self.storage_buffer = flat.reshape(self.storage_buffer.shape)
                    self.render_labeller()
                    response = f"✓ Added {v:.3f}"
                else:
                    response = "Error: 0.0-1.0"
            except:
                response = "Error: 'add 0.8'"
                
        elif cmd == "fill" and len(parts) > 1:
            try:
                v = float(parts[1])
                self.storage_buffer.fill(np.clip(v, 0, 1))
                self.render_labeller()
                response = f"✓ Filled {v:.3f}"
            except:
                response = "Error: 'fill 0.5'"
                
        elif cmd == "dump":
            response = f"STORAGE:\n{self.storage_buffer}\n"
            
        elif cmd == "stats":
            response = f"SHAPE: {self.storage_buffer.shape}\nMIN:{self.storage_buffer.min():.3f} MAX:{self.storage_buffer.max():.3f} MEAN:{self.storage_buffer.mean():.3f}"
            
        elif cmd == "labeler" and len(parts) > 1:
            subcmd = parts[1]
            if subcmd == "save":
                self.terminal_memory = self.storage_buffer.copy()
                response = f"✓ Saved {self.storage_buffer.shape}"
            elif subcmd == "load":
                if self.terminal_memory is not None:
                    self.storage_buffer = self.terminal_memory.copy()
                    self.render_labeller()
                    response = f"✓ Loaded {self.storage_buffer.shape}"
                else:
                    response = "No saved state"
                    
        elif cmd == "clear":
            self.term_output.delete("1.0", "end")
            self.write_terminal("Cleared.\n\n$ ")
            return
        elif cmd == "exit":
            self.root.quit()
            return
        else:
            response = f"Unknown: '{cmd}'. 'help'"

        self.write_terminal(f"{response}\n\n$ ")

if __name__ == "__main__":
    root = tk.Tk()
    app = StorageOS(root)
    root.mainloop()
