/* driver.h — self-contained test/diagnostic routines for each
 * hardware-facing service the guest ABI in drivers.h exposes.
 *
 * This is the "driver kit" itself: one small self-test per driver
 * (console, keyboard, mouse, disk, graphics), each returning a
 * pass/fail result plus a one-line human-readable message. A GUI
 * front-end (see driverkit.c) just lists these, wires each one to a
 * button, and displays drv_status_t.message — none of the actual ABI
 * plumbing (ports, mailboxes, framebuffer) needs to leak into the UI
 * code at all.
 *
 * Style notes (matching the rest of this guest ABI):
 *   - No libc, no malloc — drv_status_t.message is a fixed-size
 *     buffer, filled in place with the same tiny string helpers
 *     editf.c uses (append_str/append_int-style), just local to this
 *     header under a drv__ prefix so they can't collide with a
 *     caller's own copies of the same idea.
 *   - Every function here is `static inline`, same convention as
 *     comp.h and drivers.h: #include this from any number of guest
 *     programs' translation units without ODR/link problems, since
 *     there's normally only ever one .c file per guest ELF anyway.
 *   - Nothing here calls gfx_present() or drives its own frame loop —
 *     these are building blocks a caller's own GUI loop invokes on
 *     demand (usually on a button click) or every frame (the
 *     keyboard/mouse pollers, and the graphics pattern drawer), so
 *     the caller stays in full control of pacing and screen layout.
 */
#pragma once
#include "drivers.h"

#define DRV_MSG_MAX 64

/* result: -1 = never run yet, 0 = pass, 1 = fail */
typedef struct {
    const char *name;
    int         last_result;
    char        message[DRV_MSG_MAX];
} drv_status_t;

/* ── tiny string helpers (no libc available here either) ─────────── */
static inline int drv__strlen(const char *s) { int n = 0; while (s[n]) n++; return n; }

static inline void drv__strcpy(char *dst, const char *src, int cap)
{
    int i = 0;
    while (src[i] && i < cap - 1) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static inline int drv__append_str(char *dst, int pos, int cap, const char *s)
{
    while (*s && pos < cap - 1) dst[pos++] = *s++;
    dst[pos] = 0;
    return pos;
}

static inline int drv__append_int(char *dst, int pos, int cap, int v)
{
    if (pos >= cap - 1) { dst[pos] = 0; return pos; }
    if (v == 0) { dst[pos++] = '0'; dst[pos] = 0; return pos; }
    unsigned int u = (v < 0) ? (unsigned int)(-v) : (unsigned int)v;
    if (v < 0 && pos < cap - 1) dst[pos++] = '-';
    char tmp[12]; int n = 0;
    while (u && n < 12) { tmp[n++] = (char)('0' + (u % 10)); u /= 10; }
    while (n && pos < cap - 1) dst[pos++] = tmp[--n];
    dst[pos] = 0;
    return pos;
}

/* Bounded compare -- used by drv_disk_test() below to verify the
 * read-back payload without assuming either buffer is NUL-terminated
 * (the read buffer isn't; kfread() only returns a byte count). */
static inline int drv__streq_n(const char *a, const char *b, int n)
{
    for (int i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static inline void drv_status_init(drv_status_t *st, const char *name)
{
    st->name        = name;
    st->last_result = -1;
    drv__strcpy(st->message, "Not run yet.", DRV_MSG_MAX);
}

/* ── console driver (port 0xE9, kputs/kputc) ──────────────────────
 * Just proves the write side of the console ABI works. Note: while
 * this program is presenting a gfx frame (see drv_graphics_test
 * below / comp.h's ui_frame_end()), the kernel shows the graphics
 * canvas in place of scrolling text, so this line won't be visible
 * on screen until the program calls gfx_exit() or ends — the test
 * still genuinely exercises the port-0xE9 path either way. */
static inline void drv_console_test(drv_status_t *st)
{
    kputs("[driverkit] console self-test: hello from port 0xE9\n");
    st->last_result = 0;
    drv__strcpy(st->message, "Wrote a line via kputs() (port 0xE9).", DRV_MSG_MAX);
}

/* ── keyboard driver ────────────────────────────────────────────────
 * Non-blocking: call this once per frame (like key_poll() itself) so
 * it never stalls the caller's GUI loop the way getch() would. Only
 * updates the status message when a key actually arrives, so the
 * caller can just always call it and let last_result/message hold
 * the most recent keystroke seen. */
static inline void drv_keyboard_poll(drv_status_t *st, int *out_key)
{
    int k = key_poll();
    *out_key = k;
    if (k == 0) return;

    st->last_result = 0;
    int p = 0;
    p = drv__append_str(st->message, p, DRV_MSG_MAX, "Last key: ");
    if (k == KEY_UP)          p = drv__append_str(st->message, p, DRV_MSG_MAX, "UP");
    else if (k == KEY_DOWN)   p = drv__append_str(st->message, p, DRV_MSG_MAX, "DOWN");
    else if (k == KEY_LEFT)   p = drv__append_str(st->message, p, DRV_MSG_MAX, "LEFT");
    else if (k == KEY_RIGHT)  p = drv__append_str(st->message, p, DRV_MSG_MAX, "RIGHT");
    else if (k == KEY_DELETE) p = drv__append_str(st->message, p, DRV_MSG_MAX, "DELETE");
    else if (k == KEY_HOME)   p = drv__append_str(st->message, p, DRV_MSG_MAX, "HOME");
    else if (k == KEY_END)    p = drv__append_str(st->message, p, DRV_MSG_MAX, "END");
    else if (k >= 32 && k < 127) {
        char one[2] = { (char)k, 0 };
        p = drv__append_str(st->message, p, DRV_MSG_MAX, "'");
        p = drv__append_str(st->message, p, DRV_MSG_MAX, one);
        p = drv__append_str(st->message, p, DRV_MSG_MAX, "'");
    } else {
        p = drv__append_str(st->message, p, DRV_MSG_MAX, "code ");
        p = drv__append_int(st->message, p, DRV_MSG_MAX, k);
    }
}

/* ── mouse driver ───────────────────────────────────────────────────
 * Also meant to be called once per frame. Reports position + button
 * state whenever the cursor is over this program's canvas; otherwise
 * reports that plainly rather than showing stale coordinates. */
static inline void drv_mouse_poll(drv_status_t *st, mouse_state_t *ms)
{
    mouse_poll(ms);

    if (!ms->in_window) {
        st->last_result = -1;
        drv__strcpy(st->message, "Cursor outside window (or window unfocused).", DRV_MSG_MAX);
        return;
    }

    st->last_result = 0;
    int p = 0;
    p = drv__append_str(st->message, p, DRV_MSG_MAX, "(");
    p = drv__append_int(st->message, p, DRV_MSG_MAX, ms->x);
    p = drv__append_str(st->message, p, DRV_MSG_MAX, ",");
    p = drv__append_int(st->message, p, DRV_MSG_MAX, ms->y);
    p = drv__append_str(st->message, p, DRV_MSG_MAX, ")");
    if (ms->left_down)  p = drv__append_str(st->message, p, DRV_MSG_MAX, " L");
    if (ms->right_down) p = drv__append_str(st->message, p, DRV_MSG_MAX, " R");
}

/* ── disk driver ────────────────────────────────────────────────────
 * Full round-trip self-test: write a known payload to a scratch file,
 * stat it, read it back, verify the bytes match, then clean up after
 * itself. Exercises all four disk_mailbox_t commands in one call.
 * Safe to run repeatedly — always overwrites/removes its own file and
 * never touches anything else on disk.img. */
static inline void drv_disk_test(drv_status_t *st)
{
    static const char  *TESTFILE = "drvkit.tmp";
    static const char  *PAYLOAD  = "driver-kit disk self-test payload 0123456789";
    char buf[80];

    int wr = kfwrite(TESTFILE, PAYLOAD, (unsigned int)drv__strlen(PAYLOAD));
    if (wr != DISK_OK) {
        st->last_result = 1;
        drv__strcpy(st->message, "FAIL: write error.", DRV_MSG_MAX);
        return;
    }

    unsigned int size = 0;
    int stat_rc = kfstat(TESTFILE, &size);
    if (stat_rc != DISK_OK) {
        st->last_result = 1;
        drv__strcpy(st->message, "FAIL: stat error after write.", DRV_MSG_MAX);
        return;
    }
    if (size != (unsigned int)drv__strlen(PAYLOAD)) {
        st->last_result = 1;
        int p = 0;
        p = drv__append_str(st->message, p, DRV_MSG_MAX, "FAIL: size mismatch (");
        p = drv__append_int(st->message, p, DRV_MSG_MAX, (int)size);
        p = drv__append_str(st->message, p, DRV_MSG_MAX, ").");
        return;
    }

    int rd = kfread(TESTFILE, buf, (unsigned int)sizeof(buf));
    if (rd < 0 || (unsigned int)rd != size || !drv__streq_n(buf, PAYLOAD, rd)) {
        st->last_result = 1;
        drv__strcpy(st->message, "FAIL: read-back didn't match.", DRV_MSG_MAX);
        kfremove(TESTFILE);
        return;
    }

    kfremove(TESTFILE);
    st->last_result = 0;
    int p = 0;
    p = drv__append_str(st->message, p, DRV_MSG_MAX, "PASS: wrote/read/verified ");
    p = drv__append_int(st->message, p, DRV_MSG_MAX, (int)size);
    p = drv__append_str(st->message, p, DRV_MSG_MAX, " bytes.");
}

/* ── graphics driver ────────────────────────────────────────────────
 * Unlike the other tests, this isn't a one-shot call: it draws a
 * small test pattern into a caller-supplied rectangle of the CURRENT
 * frame every time it's called, so a GUI front-end can just call it
 * from its own per-frame draw loop (guarded by a "graphics test
 * enabled" flag the caller owns) instead of it trying to own
 * gfx_clear()/gfx_present() itself -- those stay the caller's
 * responsibility, same as any other widget in comp.h.
 *
 * LEAN BY DESIGN: an earlier version blended a diagonal brightness
 * gradient into the bars, which meant computing a shade with three
 * multiplies and three divides (one per color channel) for every
 * single pixel. Under software-interpreted CPU emulation (this
 * runs as a guest ELF via bochs_glue.cpp, not native code) integer
 * division is by a wide margin the most expensive thing a guest can
 * do, and this test redraws every pixel of its rect every single
 * frame while enabled -- so that gradient made the single most
 * expensive part of this whole driver kit something purely
 * decorative. Three flat-color vertical bars below still prove the
 * same thing (every pixel in the rect is still addressed and written
 * individually via gfx_set_pixel) at a fraction of the per-pixel
 * cost: no division, no multiplication, no even per-pixel branching
 * -- each of the three inner loops below writes one constant color
 * in a straight run. */
static inline void drv_graphics_test(drv_status_t *st, int x, int y, int w, int h)
{
    if (w <= 0 || h <= 0) { st->last_result = 1; drv__strcpy(st->message, "FAIL: empty rect.", DRV_MSG_MAX); return; }

    int bar_w  = w / 3;
    int bar2_w = 2 * bar_w;
    for (int j = 0; j < h; j++) {
        int py = y + j;
        int i = 0;
        for (; i < bar_w;  i++) gfx_set_pixel(x + i, py, 0xFF3B30); /* red   */
        for (; i < bar2_w; i++) gfx_set_pixel(x + i, py, 0x34C759); /* green */
        for (; i < w;      i++) gfx_set_pixel(x + i, py, 0x0A84FF); /* blue  */
    }

    st->last_result = 0;
    int p = 0;
    p = drv__append_str(st->message, p, DRV_MSG_MAX, "Presenting ");
    p = drv__append_int(st->message, p, DRV_MSG_MAX, w);
    p = drv__append_str(st->message, p, DRV_MSG_MAX, "x");
    p = drv__append_int(st->message, p, DRV_MSG_MAX, h);
    p = drv__append_str(st->message, p, DRV_MSG_MAX, " test pattern.");
}
