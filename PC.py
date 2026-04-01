"""
TiO2 Memristor Lattice PC — Tkinter Visual Simulation
Phosphor-green CRT aesthetic. Industrial/retro-futuristic.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import random, struct, time, math, threading
from collections import deque

# ══════════════════════════════════════════════
#  PALETTE  — phosphor green CRT
# ══════════════════════════════════════════════
BG       = "#0a0f0a"
BG2      = "#0d140d"
PANEL    = "#111811"
BORDER   = "#1a2e1a"
GREEN    = "#00ff41"
GREEN2   = "#00cc33"
GREEN3   = "#009922"
DIM      = "#003311"
AMBER    = "#ffb300"
RED      = "#ff3333"
CYAN     = "#00ffcc"
WHITE    = "#e0ffe0"
FONT_MONO = ("Courier", 9)
FONT_MONO_SM = ("Courier", 8)
FONT_BIG  = ("Courier", 11, "bold")
FONT_TITLE= ("Courier", 13, "bold")

# ══════════════════════════════════════════════
#  HARDWARE MODELS
# ══════════════════════════════════════════════

class TiO2Memristor:
    R_ON=100; R_OFF=16000; MU_V=1e-14; D=10e-9
    def __init__(self, w=0.0): self.w=max(0.0,min(1.0,w))
    @property
    def resistance(self): return self.w*self.R_ON+(1-self.w)*self.R_OFF
    def write_bit(self, b): self.w=1.0 if b else 0.0
    def read_bit(self): return 1 if self.w>0.5 else 0

class MemristorLattice:
    def __init__(self, rows=512, cols=8):
        self.rows=rows; self.cols=cols
        self.grid=[[TiO2Memristor() for _ in range(cols)] for _ in range(rows)]
        self.last_addr=-1; self.last_op=""
    def write_byte(self, addr, val):
        if not(0<=addr<self.rows): return
        val&=0xFF
        for b in range(8): self.grid[addr][b].write_bit((val>>(7-b))&1)
        self.last_addr=addr; self.last_op="W"
    def read_byte(self, addr):
        if not(0<=addr<self.rows): return 0
        r=0
        for b in range(8): r=(r<<1)|self.grid[addr][b].read_bit()
        self.last_addr=addr; self.last_op="R"
        return r
    def dump(self, start, length):
        return [self.read_byte(a) for a in range(start, min(start+length,self.rows))]
    def cell_w(self, row, col): return self.grid[row][col].w

class CyclicSwitch:
    def __init__(self, size): self.size=size; self.ptr=0; self.cycles=0
    def select(self, a): self.ptr=a%self.size; self.cycles+=1; return self.ptr
    def tick(self): self.ptr=(self.ptr+1)%self.size; self.cycles+=1

class I2CBus:
    ADDR=0x50
    def __init__(self, lattice):
        self.lat=lattice; self.txn=0; self.tx_bytes=0; self.log=deque(maxlen=200)
        self.state="IDLE"  # IDLE / START / ADDR / DATA / STOP
    def _log(self, msg): self.log.appendleft(msg)
    def write(self, addr, data):
        self.state="START"
        self._log(f"START → W addr=0x{addr:04X} data={data.hex()}")
        for i,b in enumerate(data):
            self.lat.write_byte(addr+i,b); self.tx_bytes+=1
        self.txn+=1; self.state="STOP"
        self._log(f"STOP  ✓ txn#{self.txn}")
        self.state="IDLE"
    def read(self, addr, n):
        self.state="START"
        self._log(f"START → R addr=0x{addr:04X} n={n}")
        data=bytes(self.lat.read_byte(addr+i) for i in range(n))
        self.txn+=1; self.state="STOP"
        self._log(f"STOP  ✓ → {data.hex()} txn#{self.txn}")
        self.state="IDLE"
        return data

class Transceiver:
    BAUD=9600
    def __init__(self): self.tx=0; self.rx=0; self.frames=deque(maxlen=100)
    def transmit(self, data):
        for b in data:
            bits=[0]+[(b>>i)&1 for i in range(8)]+[1]
            self.frames.appendleft(f"TX 0x{b:02X} [{''.join(map(str,bits))}]")
            self.tx+=1
    def receive(self, data):
        for b in data:
            self.frames.appendleft(f"RX 0x{b:02X} [{chr(b) if 32<=b<127 else '.'}]")
            self.rx+=1

class SecurityModule:
    def __init__(self, bus):
        self.bus=bus; self.locked=True; self.attempts=0; self.MAX=3
        self._pin_hash=0; self._salt=0
    def _hash(self, pin, salt):
        h=salt
        for c in pin: h=((h<<5)+h)^ord(c)
        return h&0xFFFFFFFF
    def set_pin(self, pin):
        self._salt=random.randint(0,0xFFFFFFFF)
        self._pin_hash=self._hash(pin,self._salt)
        self.bus.write(0x1F4, struct.pack(">I",self._salt))
        self.bus.write(0x1F0, struct.pack(">I",self._pin_hash))
        self.locked=False; return True
    def unlock(self, pin):
        if self.attempts>=self.MAX: return False,"LOCKOUT"
        if self._hash(pin,self._salt)==self._pin_hash:
            self.locked=False; self.attempts=0; return True,"OK"
        self.attempts+=1; return False,f"FAIL {self.attempts}/{self.MAX}"
    def lock(self): self.locked=True

# ══════════════════════════════════════════════
#  MAIN GUI
# ══════════════════════════════════════════════

class MemristorPC(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TiO₂ Memristor Lattice PC  ·  MemOS v0.1")
        self.configure(bg=BG)
        self.resizable(True, True)

        # Hardware
        self.lat  = MemristorLattice(512, 8)
        self.rsw  = CyclicSwitch(512)
        self.csw  = CyclicSwitch(8)
        self.bus  = I2CBus(self.lat)
        self.trx  = Transceiver()
        self.sec  = SecurityModule(self.bus)
        self.kb_buf = deque(maxlen=32)
        self.kb_ptr = 0x1E0
        self.booted = False
        self.sim_running = False
        self.sim_speed = 50   # ms per tick
        self._blink = True

        self._build_ui()
        self._start_blink()
        self.after(200, self._boot)

    # ─── UI BUILD ────────────────────────────

    def _build_ui(self):
        # ── Title bar
        bar = tk.Frame(self, bg=BG, pady=4)
        bar.pack(fill="x", padx=6, pady=(6,0))
        tk.Label(bar, text="▓▓  TiO₂ MEMRISTOR LATTICE PC  ▓▓",
                 font=FONT_TITLE, fg=GREEN, bg=BG).pack(side="left")
        self._status_lbl = tk.Label(bar, text="● BOOTING", font=FONT_MONO,
                                    fg=AMBER, bg=BG)
        self._status_lbl.pack(side="right", padx=8)

        # ── Main columns
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=6, pady=4)
        main.columnconfigure(0, weight=2)
        main.columnconfigure(1, weight=3)
        main.columnconfigure(2, weight=2)
        main.rowconfigure(0, weight=1)

        left  = tk.Frame(main, bg=BG); left.grid(row=0,column=0,sticky="nsew",padx=(0,3))
        mid   = tk.Frame(main, bg=BG); mid.grid(row=0,column=1,sticky="nsew",padx=3)
        right = tk.Frame(main, bg=BG); right.grid(row=0,column=2,sticky="nsew",padx=(3,0))

        self._build_left(left)
        self._build_mid(mid)
        self._build_right(right)

        # ── Bottom status strip
        self._build_bottom()

    def _panel(self, parent, title, height=None):
        f = tk.Frame(parent, bg=PANEL, bd=0, highlightthickness=1,
                     highlightbackground=BORDER)
        f.pack(fill="both", expand=(height is None), pady=2,
               ipady=2, ipadx=2)
        tk.Label(f, text=f"┤ {title} ├", font=FONT_MONO, fg=GREEN3,
                 bg=PANEL, anchor="w").pack(fill="x", padx=4, pady=(2,0))
        tk.Frame(f, bg=BORDER, height=1).pack(fill="x")
        return f

    # ── LEFT column ──────────────────────────

    def _build_left(self, p):
        # Lattice visualiser
        lp = self._panel(p, "MEMRISTOR LATTICE  512×8")
        self._lattice_canvas = tk.Canvas(lp, bg=BG2, width=220, height=220,
                                         highlightthickness=0)
        self._lattice_canvas.pack(fill="both", expand=True, padx=4, pady=4)

        # Cyclic switches
        sp = self._panel(p, "CYCLIC SWITCHES")
        sf = tk.Frame(sp, bg=PANEL)
        sf.pack(fill="x", padx=4, pady=2)
        self._row_sw_lbl = tk.Label(sf, text="ROW: 000", font=FONT_MONO,
                                    fg=CYAN, bg=PANEL, width=14, anchor="w")
        self._row_sw_lbl.pack(side="left")
        self._col_sw_lbl = tk.Label(sf, text="COL: 0", font=FONT_MONO,
                                    fg=CYAN, bg=PANEL, width=10, anchor="w")
        self._col_sw_lbl.pack(side="left")

        # Switch ring visualiser
        self._sw_canvas = tk.Canvas(sp, bg=BG2, width=220, height=60,
                                    highlightthickness=0)
        self._sw_canvas.pack(fill="x", padx=4, pady=2)

        # Cell info
        cp = self._panel(p, "SELECTED CELL")
        self._cell_info = tk.Label(cp, text="addr=—  bit=—  w=—  R=—Ω",
                                   font=FONT_MONO_SM, fg=GREEN2, bg=PANEL,
                                   anchor="w", justify="left", wraplength=220)
        self._cell_info.pack(fill="x", padx=4, pady=2)

    # ── MIDDLE column ────────────────────────

    def _build_mid(self, p):
        # Hex dump
        hp = self._panel(p, "HEX DUMP")
        hf = tk.Frame(hp, bg=PANEL); hf.pack(fill="x", padx=4, pady=2)
        tk.Label(hf, text="Addr:", font=FONT_MONO, fg=GREEN3, bg=PANEL).pack(side="left")
        self._hex_addr = tk.Entry(hf, width=6, bg=BG2, fg=GREEN, insertbackground=GREEN,
                                  font=FONT_MONO, relief="flat", bd=1)
        self._hex_addr.insert(0,"0x00"); self._hex_addr.pack(side="left", padx=2)
        tk.Button(hf, text="DUMP", command=self._do_hex_dump,
                  **self._btn_style()).pack(side="left", padx=2)
        tk.Button(hf, text="ASCII", command=self._dump_ascii,
                  **self._btn_style()).pack(side="left", padx=2)
        tk.Button(hf, text="FULL", command=self._dump_full,
                  **self._btn_style()).pack(side="left", padx=2)

        self._hex_text = tk.Text(hp, bg=BG2, fg=GREEN2, font=FONT_MONO_SM,
                                 width=52, height=14, relief="flat",
                                 insertbackground=GREEN, state="disabled",
                                 selectbackground=DIM, selectforeground=GREEN)
        self._hex_text.pack(fill="both", expand=True, padx=4, pady=2)

        # Write to memory
        wp = self._panel(p, "WRITE BYTE  (I²C)")
        wf = tk.Frame(wp, bg=PANEL); wf.pack(fill="x", padx=4, pady=2)
        tk.Label(wf, text="Addr:", font=FONT_MONO, fg=GREEN3, bg=PANEL).pack(side="left")
        self._wr_addr = tk.Entry(wf, width=6, bg=BG2, fg=GREEN,
                                 insertbackground=GREEN, font=FONT_MONO, relief="flat")
        self._wr_addr.insert(0,"0x100"); self._wr_addr.pack(side="left", padx=2)
        tk.Label(wf, text="Val:", font=FONT_MONO, fg=GREEN3, bg=PANEL).pack(side="left")
        self._wr_val = tk.Entry(wf, width=5, bg=BG2, fg=GREEN,
                                insertbackground=GREEN, font=FONT_MONO, relief="flat")
        self._wr_val.insert(0,"0x41"); self._wr_val.pack(side="left", padx=2)
        tk.Button(wf, text="WRITE", command=self._do_write,
                  **self._btn_style(fg=AMBER)).pack(side="left", padx=2)

        # Keyboard input
        kp = self._panel(p, "KEYBOARD INPUT")
        kf = tk.Frame(kp, bg=PANEL); kf.pack(fill="x", padx=4, pady=2)
        self._kb_entry = tk.Entry(kf, width=22, bg=BG2, fg=GREEN,
                                  insertbackground=GREEN, font=FONT_MONO, relief="flat")
        self._kb_entry.pack(side="left", padx=2)
        self._kb_entry.bind("<Return>", lambda e: self._do_keyboard())
        tk.Button(kf, text="SEND", command=self._do_keyboard,
                  **self._btn_style()).pack(side="left", padx=2)
        self._kb_buf_lbl = tk.Label(kp, text="Buffer: —", font=FONT_MONO_SM,
                                    fg=GREEN2, bg=PANEL, anchor="w")
        self._kb_buf_lbl.pack(fill="x", padx=4)

        # Transceiver
        tp = self._panel(p, "TRANSCEIVER  UART 9600 8N1")
        tf = tk.Frame(tp, bg=PANEL); tf.pack(fill="x", padx=4, pady=2)
        self._trx_entry = tk.Entry(tf, width=16, bg=BG2, fg=GREEN,
                                   insertbackground=GREEN, font=FONT_MONO, relief="flat")
        self._trx_entry.insert(0,"HELLO"); self._trx_entry.pack(side="left", padx=2)
        tk.Button(tf, text="TX", command=self._do_transmit,
                  **self._btn_style(fg=CYAN)).pack(side="left", padx=2)
        tk.Button(tf, text="RX PING", command=self._do_receive,
                  **self._btn_style(fg=CYAN)).pack(side="left", padx=2)

        self._trx_text = tk.Text(tp, bg=BG2, fg=CYAN, font=FONT_MONO_SM,
                                 width=52, height=5, relief="flat",
                                 insertbackground=GREEN, state="disabled")
        self._trx_text.pack(fill="both", expand=True, padx=4, pady=2)

    # ── RIGHT column ─────────────────────────

    def _build_right(self, p):
        # I2C log
        ip = self._panel(p, "I²C BUS LOG")
        self._i2c_text = tk.Text(ip, bg=BG2, fg=GREEN2, font=FONT_MONO_SM,
                                 width=34, height=10, relief="flat",
                                 insertbackground=GREEN, state="disabled")
        self._i2c_text.pack(fill="both", expand=True, padx=4, pady=2)

        # Security
        sp = self._panel(p, "SECURITY MODULE")
        sf = tk.Frame(sp, bg=PANEL); sf.pack(fill="x", padx=4, pady=2)
        self._sec_pin = tk.Entry(sf, width=8, bg=BG2, fg=AMBER,
                                 show="*", insertbackground=AMBER,
                                 font=FONT_MONO, relief="flat")
        self._sec_pin.insert(0,"1234"); self._sec_pin.pack(side="left", padx=2)
        tk.Button(sf, text="UNLOCK", command=self._do_unlock,
                  **self._btn_style(fg=GREEN)).pack(side="left", padx=2)
        tk.Button(sf, text="LOCK", command=self._do_lock,
                  **self._btn_style(fg=RED)).pack(side="left", padx=2)
        tk.Button(sf, text="SET PIN", command=self._do_setpin,
                  **self._btn_style(fg=AMBER)).pack(side="left", padx=2)
        self._sec_lbl = tk.Label(sp, text="● LOCKED", font=FONT_BIG,
                                 fg=RED, bg=PANEL)
        self._sec_lbl.pack(pady=2)
        self._sec_hash = tk.Label(sp, text="hash=00000000  salt=00000000",
                                  font=FONT_MONO_SM, fg=DIM, bg=PANEL)
        self._sec_hash.pack()

        # Stats
        xp = self._panel(p, "LATTICE STATS")
        self._stats_text = tk.Text(xp, bg=BG2, fg=GREEN2, font=FONT_MONO_SM,
                                   width=34, height=7, relief="flat",
                                   state="disabled")
        self._stats_text.pack(fill="both", expand=True, padx=4, pady=2)

        # Simulation control
        cp = self._panel(p, "SIMULATION CONTROL")
        cf = tk.Frame(cp, bg=PANEL); cf.pack(fill="x", padx=4, pady=2)
        self._sim_btn = tk.Button(cf, text="▶ START SIM",
                                  command=self._toggle_sim,
                                  **self._btn_style(fg=GREEN, width=12))
        self._sim_btn.pack(side="left", padx=2)
        tk.Button(cf, text="RESET", command=self._do_reset,
                  **self._btn_style(fg=RED, width=6)).pack(side="left", padx=2)
        sf2 = tk.Frame(cp, bg=PANEL); sf2.pack(fill="x", padx=4, pady=2)
        tk.Label(sf2, text="Speed:", font=FONT_MONO, fg=GREEN3, bg=PANEL).pack(side="left")
        self._speed_var = tk.IntVar(value=50)
        sc = tk.Scale(sf2, from_=10, to=500, orient="horizontal",
                      variable=self._speed_var, bg=PANEL, fg=GREEN,
                      troughcolor=BG2, highlightthickness=0,
                      activebackground=GREEN2, length=100,
                      command=lambda v: setattr(self,'sim_speed',int(v)))
        sc.pack(side="left")

    # ── BOTTOM strip ─────────────────────────

    def _build_bottom(self):
        bot = tk.Frame(self, bg=PANEL, bd=0, highlightthickness=1,
                       highlightbackground=BORDER)
        bot.pack(fill="x", padx=6, pady=(0,6), ipady=3)
        self._log_text = tk.Text(bot, bg=PANEL, fg=GREEN3, font=FONT_MONO_SM,
                                 height=4, relief="flat", state="disabled",
                                 wrap="word")
        sb = tk.Scrollbar(bot, command=self._log_text.yview,
                          bg=PANEL, troughcolor=BG2)
        self._log_text.configure(yscrollcommand=sb.set)
        self._log_text.pack(side="left", fill="both", expand=True, padx=4)
        sb.pack(side="right", fill="y")

    def _btn_style(self, fg=GREEN2, width=None):
        s = dict(bg=BG2, fg=fg, activebackground=DIM, activeforeground=fg,
                 relief="flat", bd=0, font=FONT_MONO, cursor="hand2",
                 padx=4, pady=1, highlightthickness=1,
                 highlightbackground=BORDER)
        if width: s["width"]=width
        return s

    # ─── DRAW ROUTINES ───────────────────────

    def _draw_lattice(self):
        c = self._lattice_canvas
        c.delete("all")
        W = c.winfo_width() or 220
        H = c.winfo_height() or 220
        # Show a 32×8 window centred on last_addr
        rows_vis = 32
        start = max(0, min(self.lat.last_addr - rows_vis//2,
                           self.lat.rows - rows_vis))
        cell_w = (W - 40) / 8
        cell_h = (H - 20) / rows_vis
        # Column headers
        for col in range(8):
            x = 36 + col * cell_w + cell_w/2
            c.create_text(x, 8, text=str(col), font=("Courier",7),
                          fill=GREEN3, anchor="center")
        # Rows
        for ri in range(rows_vis):
            addr = start + ri
            y = 18 + ri * cell_h
            c.create_text(34, y+cell_h/2, text=f"{addr:03X}",
                          font=("Courier",6), fill=GREEN3, anchor="e")
            for col in range(8):
                x = 36 + col * cell_w
                w = self.lat.cell_w(addr, col)
                # colour: bright green = set, dark = clear
                intensity = int(w * 255)
                r = 0; g = intensity; b = int(intensity * 0.25)
                col_hex = f"#{r:02x}{g:02x}{b:02x}"
                pad = 1
                c.create_rectangle(x+pad, y+pad,
                                   x+cell_w-pad, y+cell_h-pad,
                                   fill=col_hex, outline="")
                # highlight last touched
                if addr == self.lat.last_addr:
                    c.create_rectangle(x+pad, y+pad,
                                       x+cell_w-pad, y+cell_h-pad,
                                       fill="", outline=AMBER, width=1)
        # Viewport label
        c.create_text(W/2, H-4, text=f"rows {start}–{start+rows_vis-1}  (last op: {self.lat.last_op or '—'} @ 0x{self.lat.last_addr:04X})",
                      font=("Courier",7), fill=GREEN3)

    def _draw_switches(self):
        c = self._sw_canvas
        c.delete("all")
        W = c.winfo_width() or 220
        # Row switch ring (top half)
        cx, cy, r = 50, 25, 18
        for i in range(16):
            angle = math.radians(i * 360/16 - 90)
            x = cx + r * math.cos(angle)
            y = cy + r * math.sin(angle)
            sel = (i == self.rsw.ptr % 16)
            c.create_oval(x-3,y-3,x+3,y+3,
                          fill=GREEN if sel else DIM, outline="")
        c.create_text(cx, cy, text=f"{self.rsw.ptr:03}", font=("Courier",7),
                      fill=CYAN)
        c.create_text(cx, 56, text="ROW SW", font=("Courier",6), fill=GREEN3)
        # Col switch ring
        cx2 = 130
        for i in range(8):
            angle = math.radians(i * 45 - 90)
            x = cx2 + r * math.cos(angle)
            y = 25 + r * math.sin(angle)
            sel = (i == self.csw.ptr)
            c.create_oval(x-3,y-3,x+3,y+3,
                          fill=GREEN if sel else DIM, outline="")
        c.create_text(cx2, 25, text=str(self.csw.ptr), font=("Courier",7),
                      fill=CYAN)
        c.create_text(cx2, 56, text="COL SW", font=("Courier",6), fill=GREEN3)
        # I2C state indicator
        states = {"IDLE": DIM, "START": AMBER, "STOP": GREEN3}
        col = states.get(self.bus.state, WHITE)
        c.create_text(190, 25, text=self.bus.state, font=("Courier",7),
                      fill=col)
        c.create_text(190, 40, text="I²C", font=("Courier",6), fill=GREEN3)

    def _refresh_stats(self):
        ones = sum(self.lat.grid[r][b].read_bit()
                   for r in range(self.lat.rows)
                   for b in range(self.lat.cols))
        total = self.lat.rows * self.lat.cols
        util = ones / total * 100
        bar_w = 16
        filled = int(util/100*bar_w)
        bar = "█"*filled + "░"*(bar_w-filled)
        text = (
            f"Cells : {total}  ({self.lat.rows}×{self.lat.cols})\n"
            f"SET   : {ones}\n"
            f"CLEAR : {total-ones}\n"
            f"UTIL  : {bar} {util:.1f}%\n"
            f"I²C TXN: {self.bus.txn}\n"
            f"TX bytes: {self.trx.tx}   RX: {self.trx.rx}\n"
            f"R-SW cycles: {self.rsw.cycles}\n"
        )
        self._set_text(self._stats_text, text)

    def _refresh_i2c_log(self):
        text = "\n".join(list(self.bus.log)[:40])
        self._set_text(self._i2c_text, text)

    def _refresh_trx(self):
        text = "\n".join(list(self.trx.frames)[:20])
        self._set_text(self._trx_text, text)

    def _set_text(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0","end")
        widget.insert("1.0", text)
        widget.config(state="disabled")

    def _log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self._log_text.config(state="normal")
        self._log_text.insert("end", f"[{ts}] {msg}\n")
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    def _update_all(self):
        self._draw_lattice()
        self._draw_switches()
        self._refresh_stats()
        self._refresh_i2c_log()
        self._refresh_trx()
        self._row_sw_lbl.config(text=f"ROW: {self.rsw.ptr:03d}")
        self._col_sw_lbl.config(text=f"COL: {self.csw.ptr}")
        # cell info for last address
        if self.lat.last_addr >= 0:
            a = self.lat.last_addr
            b_idx = self.csw.ptr
            cell = self.lat.grid[a][b_idx]
            self._cell_info.config(
                text=f"addr=0x{a:04X}  bit={b_idx}  w={cell.w:.4f}  R={cell.resistance:.0f}Ω"
            )

    # ─── BOOT ────────────────────────────────

    def _boot(self):
        self._log("BOOT: Loading ASCII table into memristor lattice…")
        for code in range(32, 127):
            self.bus.write(code, bytes([code]))
        self._log(f"BOOT: {127-32} codes written → 0x20–0x7E")
        self.sec.set_pin("1234")
        self._log("BOOT: Security module init. Default PIN=1234")
        self._update_sec_label()
        self.booted = True
        self._set_status("● READY", GREEN)
        self._log("BOOT: Complete. MemOS v0.1 ready.")
        self._do_hex_dump()
        self._update_all()

    # ─── CONTROLS ────────────────────────────

    def _do_hex_dump(self):
        raw = self._hex_addr.get().strip()
        try:
            addr = int(raw, 16) if raw.startswith("0x") else int(raw)
        except: addr = 0
        addr = max(0, min(addr, 480))
        data = self.lat.dump(addr, 64)
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            asc_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
            lines.append(f"{addr+i:04X}  {hex_part:<47}  |{asc_part}|")
        self._set_text(self._hex_text, "\n".join(lines))
        self.lat.last_addr = addr
        self._update_all()

    def _dump_ascii(self):
        self._hex_addr.delete(0,"end"); self._hex_addr.insert(0,"0x20")
        self._do_hex_dump()

    def _dump_full(self):
        data = self.lat.dump(0, 512)
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            asc_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
            lines.append(f"{i:04X}  {hex_part:<47}  |{asc_part}|")
        self._set_text(self._hex_text, "\n".join(lines))
        self._update_all()

    def _do_write(self):
        try:
            addr = int(self._wr_addr.get().strip(), 16)
            val  = int(self._wr_val.get().strip(), 16)
        except:
            self._log("WRITE: parse error — use hex e.g. 0x100, 0x41")
            return
        self.bus.write(addr, bytes([val & 0xFF]))
        self.rsw.select(addr); self.csw.select(0)
        self._log(f"WRITE: 0x{val:02X} → addr 0x{addr:04X}  ('{chr(val) if 32<=val<127 else '.'}') via I²C")
        self._do_hex_dump()
        self._update_all()

    def _do_keyboard(self):
        text = self._kb_entry.get()
        if not text: return
        for ch in text:
            code = ord(ch) & 0xFF
            self.bus.write(self.kb_ptr, bytes([code]))
            self.kb_buf.append(ch)
            self.kb_ptr += 1
            if self.kb_ptr >= 0x200: self.kb_ptr = 0x1E0
        buf_str = "".join(self.kb_buf)
        self._kb_buf_lbl.config(text=f"Buffer: {buf_str[-28:]}")
        self._log(f"KB: typed \"{text}\"  ({len(text)} chars → 0x1E0 region)")
        self._kb_entry.delete(0,"end")
        self._update_all()

    def _do_transmit(self):
        text = self._trx_entry.get() or "PING"
        self.trx.transmit(text.encode())
        self._log(f"TRX TX: \"{text}\" ({len(text)} bytes, 9600 baud 8N1)")
        self._refresh_trx()
        self._update_all()

    def _do_receive(self):
        msg = f"ACK{random.randint(0,99):02d}"
        self.trx.receive(msg.encode())
        self._log(f"TRX RX: received \"{msg}\"")
        self._refresh_trx()

    def _do_unlock(self):
        pin = self._sec_pin.get()
        ok, msg = self.sec.unlock(pin)
        self._log(f"SEC UNLOCK: PIN={'*'*len(pin)} → {msg}")
        self._update_sec_label()

    def _do_lock(self):
        self.sec.lock()
        self._log("SEC: locked")
        self._update_sec_label()

    def _do_setpin(self):
        pin = self._sec_pin.get()
        if len(pin) < 1:
            self._log("SEC: PIN too short"); return
        self.sec.set_pin(pin)
        self._log(f"SEC: PIN set (hash=0x{self.sec._pin_hash:08X})")
        self._update_sec_label()

    def _update_sec_label(self):
        if self.sec.locked:
            self._sec_lbl.config(text="● LOCKED", fg=RED)
        else:
            self._sec_lbl.config(text="● UNLOCKED", fg=GREEN)
        self._sec_hash.config(
            text=f"hash={self.sec._pin_hash:08X}  salt={self.sec._salt:08X}")

    def _do_reset(self):
        self.lat = MemristorLattice(512,8)
        self.bus = I2CBus(self.lat)
        self.sec = SecurityModule(self.bus)
        self.trx = Transceiver()
        self.rsw = CyclicSwitch(512); self.csw = CyclicSwitch(8)
        self.kb_buf.clear(); self.kb_ptr=0x1E0
        self._log("RESET: hardware cleared. Re-booting…")
        self._set_status("● BOOTING", AMBER)
        self.after(300, self._boot)

    # ─── SIMULATION LOOP ─────────────────────

    def _toggle_sim(self):
        self.sim_running = not self.sim_running
        if self.sim_running:
            self._sim_btn.config(text="■ STOP SIM")
            self._log("SIM: started — random I²C r/w activity")
            self._sim_tick()
        else:
            self._sim_btn.config(text="▶ START SIM")
            self._log("SIM: stopped")

    def _sim_tick(self):
        if not self.sim_running: return
        # Random activity: write random byte, tick switches
        addr = random.randint(0x100, 0x1CF)
        val  = random.randint(0, 255)
        self.bus.write(addr, bytes([val]))
        self.rsw.select(addr); self.csw.tick()
        self._update_all()
        self.after(self.sim_speed, self._sim_tick)

    # ─── BLINK ───────────────────────────────

    def _start_blink(self):
        self._blink = not self._blink
        # blink the status dot
        if hasattr(self, '_status_lbl'):
            cur = self._status_lbl.cget("fg")
            if self._blink and cur == GREEN:
                self._status_lbl.config(fg=GREEN3)
            elif not self._blink and cur == GREEN3:
                self._status_lbl.config(fg=GREEN)
        self.after(600, self._start_blink)

    def _set_status(self, text, color):
        self._status_lbl.config(text=text, fg=color)


# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    app = MemristorPC()
    app.geometry("1200x820")
    app.mainloop()