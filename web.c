/* web.c -- a basic web renderer ("browser") for the self-hosted TCC.
 *
 * Build (from the host):
 *     make cc SRC=web.c
 * Or from inside the OS shell (needs comp.h, drivers.h, font.h on disk):
 *     cc web.c
 *     web
 *
 * What it does
 * ------------
 * Loads an HTML file from the FAT32 disk (kfread), lays it out with a
 * small flow-layout engine, and draws it into the 320x200 gfx canvas
 * using comp.h's widgets for the toolbar (Back / Home / URL box / Go)
 * and the scrollbar.  Clicking a link opens the target file.
 *
 * Supported markup (anything else is ignored, its text still shows):
 *   h1..h6  p  br  hr  div  center  blockquote  pre  code/tt/kbd/samp
 *   b/strong  i/em/cite  u/ins  a href  ul/ol/li  dl/dt/dd
 *   table/tr/td/th (flattened to "a | b" rows)  img (shown as [alt])
 *   title  <!-- comments -->  <script>/<style> (skipped)
 *   entities: &amp; &lt; &gt; &quot; &nbsp; &#NN; ... (ASCII subset)
 * Non-.htm/.html files (.txt .c .h ...) open as plain monospace text.
 *
 * Network: guest programs have no socket ABI (the kernel's NIC/DNS code
 * in 07b_network.h is not exposed through drivers.h and there is no
 * TCP), so http:// links show an explanatory page instead of fetching.
 *
 * Keys (when the URL box is not focused)
 *   Up/Down scroll   Space / b  page down / up   Home/End  top / bottom
 *   Backspace  back   h  home page   g  focus URL box   q  quit
 *
 * Style: no libc, no malloc -- every buffer is a fixed static array,
 * like editf.c.  Layout runs once per page load; drawing happens only
 * when something changed (scroll, hover, navigation), so an idle page
 * costs just the toolbar redraw per frame.
 */
#include "comp.h"

/* ── limits & geometry ───────────────────────────────────────────── */
#define PAGE_MAX   48000        /* largest file we can open (bytes)   */
#define POOL_MAX   48000        /* decoded text storage (< 65536: off is u16) */
#define ITEM_MAX   3000         /* laid-out words/rules/bullets       */
#define LINK_MAX   96
#define NAME_LEN   64           /* == disk_mailbox_t.name[64] (local files)   */
#define URL_LEN    160          /* http:// URLs, link targets, history        */
#define HIST_MAX   8

#define VIEW_Y     19
#define VIEW_W     306
#define VIEW_H     168
#define STATUS_Y   188
#define MARGIN     5
#define TEXT_W     (VIEW_W - 2 * MARGIN)

#define PG_BG      0xF4F2EA
#define PG_TEXT    0x1E1E24
#define PG_LINK    0x1D4ED8
#define PG_LINKHOT 0xD9480F
#define PG_H1      0x14306E
#define PG_H2      0x1F4E8C
#define PG_H3      0x35607F
#define PG_CODE    0x8A3A00
#define PG_QUOTE   0x4A4A56
#define PG_DIM     0x80808A
#define PG_RULE    0x9A9AA2

#define IT_TEXT    0
#define IT_HR      1
#define IT_BULLET  2
#define F_BOLD     1
#define F_ITAL     2
#define F_UL       4

typedef struct {
    short          x;        /* from left margin                       */
    short          link;     /* index into s_links, or -1              */
    int            y;        /* document y of the line's top           */
    unsigned short off;      /* text offset in s_pool                  */
    unsigned char  len, scale, kind, flags;
    unsigned int   color;
} wb_item_t;

/* ── storage ─────────────────────────────────────────────────────── */
static char       s_page[PAGE_MAX + 1];
static char       s_pool[POOL_MAX];
static wb_item_t  s_items[ITEM_MAX];
static char       s_links[LINK_MAX][URL_LEN];
static char       s_title[40];
static char       s_cur[URL_LEN];              /* page now on screen (file name or URL) */
static char       s_hist[HIST_MAX][URL_LEN];
static char       s_status[48];
static int        s_hist_n, s_pool_n, s_item_n, s_link_n;
static int        s_doc_h, s_bytes, s_truncated;
static int        s_dirty = 1, s_hover = -1;
static int        s_last_mx = -1, s_last_my = -1, s_last_scroll = -1, s_last_in = 0;

static ui_scrollbar_t s_bar;
static ui_textbox_t   s_url;

/* ── tiny string helpers (w_ prefix: can't clash with other headers) ─ */
static int w_len(const char* s) { int n = 0; while (s[n]) n++; return n; }
static int w_lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
static int w_is_ws(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
static int w_is_alpha(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static int w_eq(const char* a, const char* b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

static int w_starts_ci(const char* s, const char* p)
{
    while (*p) { if (w_lower((unsigned char)*s) != w_lower((unsigned char)*p)) return 0; s++; p++; }
    return 1;
}

/* copy at most max-1 chars, always NUL-terminate, return length */
static int w_cpy(char* d, const char* s, int max)
{
    int i = 0;
    while (s[i] && i < max - 1) { d[i] = s[i]; i++; }
    d[i] = 0;
    return i;
}

static int w_cat(char* d, const char* s, int max)
{
    int n = w_len(d);
    return n + w_cpy(d + n, s, max - n);
}

static int w_itoa(int v, char* out)
{
    char t[12]; int n = 0, k = 0;
    if (v < 0) { out[k++] = '-'; v = -v; }
    if (v == 0) t[n++] = '0';
    while (v && n < 11) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n) out[k++] = t[--n];
    out[k] = 0;
    return k;
}

static int w_has_dot(const char* s) { while (*s) if (*s++ == '.') return 1; return 0; }

static int w_ends_ci(const char* s, const char* suf)
{
    int a = w_len(s), b = w_len(suf);
    if (b > a) return 0;
    return w_starts_ci(s + a - b, suf);
}

/* ── layout state ────────────────────────────────────────────────── */
static int L_cx, L_cy, L_lineh, L_indent, L_line_first, L_gap, L_pending;
static int L_bold, L_ital, L_ul, L_code, L_pre, L_pre_first, L_center, L_quote, L_dim;
static int L_scale, L_link, L_title, L_skip, L_dd, L_cell, L_ldepth;
static unsigned int L_hcol;
static char L_ltype[6];
static int  L_lcount[6];
static int  L_lamt[6];            /* indent added by each open list */
static char W[64];                 /* word / pre-run accumulator */
static int  wn;

static void lay_reset(void)
{
    s_item_n = 0; s_pool_n = 0; s_link_n = 0; s_truncated = 0; s_title[0] = 0;
    L_cx = 0; L_cy = 4; L_lineh = 0; L_indent = 0; L_line_first = 0;
    L_gap = 0; L_pending = 0;
    L_bold = 0; L_ital = 0; L_ul = 0; L_code = 0; L_pre = 0; L_pre_first = 0;
    L_center = 0; L_quote = 0; L_dim = 0;
    L_scale = 1; L_link = -1; L_title = 0; L_skip = 0; L_dd = 0; L_cell = 0;
    L_ldepth = 0; L_hcol = 0; wn = 0;
}

static unsigned int cur_color(void)
{
    if (L_link >= 0) return PG_LINK;
    if (L_dim)       return PG_DIM;
    if (L_hcol)      return L_hcol;
    if (L_code)      return PG_CODE;
    if (L_quote)     return PG_QUOTE;
    return PG_TEXT;
}

static int cur_flags(void)
{
    return (L_bold ? F_BOLD : 0) | (L_ital ? F_ITAL : 0) | ((L_ul || L_link >= 0) ? F_UL : 0);
}

/* vertical gap requested by a block boundary applies when the next
 * item starts a fresh line (never at the very top of the page). */
static void lay_gap_apply(void)
{
    if (L_line_first == s_item_n && L_gap) {
        if (s_item_n > 0) L_cy += L_gap;
        L_gap = 0;
    }
}

static int add_item(int x, int kind, const char* txt, int len)
{
    wb_item_t* it;
    int i, h;
    if (s_item_n >= ITEM_MAX || s_pool_n + len > POOL_MAX) { s_truncated = 1; return 0; }
    lay_gap_apply();
    it = &s_items[s_item_n++];
    it->x = (short)x; it->y = L_cy; it->kind = (unsigned char)kind;
    it->scale = (unsigned char)L_scale; it->flags = (unsigned char)cur_flags();
    it->color = cur_color(); it->link = (short)L_link;
    it->off = (unsigned short)s_pool_n; it->len = (unsigned char)len;
    for (i = 0; i < len; i++) s_pool[s_pool_n++] = txt[i];
    h = 8 * L_scale + 2;
    if (h > L_lineh) L_lineh = h;
    return 1;
}

/* end the current line (centering it first if asked) */
static void lay_flush(void)
{
    int i;
    if (L_line_first < s_item_n) {
        if (L_center) {
            int start = s_items[L_line_first].x;
            int sh = (TEXT_W - (L_cx - start)) / 2 - start;
            if (sh > 0) for (i = L_line_first; i < s_item_n; i++) s_items[i].x = (short)(s_items[i].x + sh);
        }
        L_cy += L_lineh;
    }
    L_cx = L_indent; L_lineh = 0; L_line_first = s_item_n; L_pending = 0;
}

static void lay_br(void)
{
    if (L_line_first < s_item_n) lay_flush();
    else { lay_gap_apply(); L_cy += 8 * L_scale + 2; L_cx = L_indent; L_pending = 0; }
}

static void lay_block(int gap)
{
    lay_flush();
    if (gap > L_gap) L_gap = gap;
}

static void set_indent(int delta)
{
    lay_flush();
    L_indent += delta;
    if (L_indent < 0) L_indent = 0;
    L_cx = L_indent;
}

/* place one word with wrapping; words longer than a line are split */
static void lay_word(const char* w, int n)
{
    int cw = 8 * L_scale;
    while (n > 0) {
        int sp = (L_pending && L_cx > L_indent) ? cw : 0;
        int fit = n;
        if (L_cx > L_indent && sp + n * cw > TEXT_W - L_cx) { lay_flush(); continue; }
        if (L_cx + sp + n * cw > TEXT_W) {
            fit = (TEXT_W - L_cx - sp) / cw;
            if (fit < 1) fit = 1;
        }
        add_item(L_cx + sp, IT_TEXT, w, fit);
        L_cx += sp + fit * cw;
        L_pending = 0;
        w += fit; n -= fit;
        if (n > 0) lay_flush();
    }
}

static void lay_run(const char* s, int n)          /* <pre>: no wrapping logic */
{
    if (n <= 0) return;
    add_item(L_cx, IT_TEXT, s, n);
    L_cx += n * 8 * L_scale;
}

static void word_flush(void)  { if (wn) { lay_word(W, wn); wn = 0; } }
static void pre_flush(void)   { if (wn) { lay_run(W, wn);  wn = 0; } }
static void flush_text(void)  { if (L_pre) pre_flush(); else word_flush(); }

/* one decoded character of body text */
static void text_char(int c)
{
    if (c & 0x80) { if ((c & 0xFF) >= 0xC0) c = '?'; else return; }   /* UTF-8 -> '?' */

    if (L_title) {
        int l = w_len(s_title);
        if (w_is_ws(c)) {
            if (l > 0 && s_title[l - 1] != ' ' && l < 38) { s_title[l] = ' '; s_title[l + 1] = 0; }
        } else if (l < 38 && c >= 32 && c < 127) { s_title[l] = (char)c; s_title[l + 1] = 0; }
        return;
    }
    if (L_pre) {
        if (c == '\r') return;
        if (L_pre_first) { L_pre_first = 0; if (c == '\n') return; }   /* HTML drops the 1st newline */
        if (c == '\n') { pre_flush(); lay_br(); return; }
        if (c == '\t') { int k; for (k = 0; k < 4; k++) text_char(' '); return; }
        if (c < 32 || c > 126) c = '?';
        W[wn++] = (char)c;
        if (wn >= (TEXT_W - L_cx) / 8 || wn >= 60) { pre_flush(); lay_flush(); }
        return;
    }
    if (w_is_ws(c)) { word_flush(); L_pending = 1; return; }
    if (c < 32 || c > 126) c = '?';
    if (wn >= 60) word_flush();
    W[wn++] = (char)c;
}

/* ── entities ────────────────────────────────────────────────────── */
static const char* ent_names[] = { "amp", "lt", "gt", "quot", "apos", "nbsp", "copy", "reg",
    "mdash", "ndash", "hellip", "bull", "laquo", "raquo", "middot", "rarr", "larr", "trade", 0 };
static const char* ent_strs[] = { "&", "<", ">", "\"", "'", " ", "(c)", "(R)",
    "--", "-", "...", "*", "<<", ">>", ".", "->", "<-", "(TM)" };

/* s points at '&'.  Returns the replacement text (possibly several
 * characters), or 0 if this isn't an entity.  *adv = chars consumed. */
static const char* decode_entity(const char* s, int n, int* adv, char* one)
{
    char nm[10]; int k = 0, i = 1;
    while (i < n && i < 10 && s[i] != ';' && !w_is_ws(s[i])) { nm[k++] = s[i]; i++; }
    if (i >= n || s[i] != ';' || k == 0) return 0;
    nm[k] = 0;
    *adv = i + 1;
    if (nm[0] == '#') {
        int v = 0, j = 1;
        if (nm[1] == 'x' || nm[1] == 'X') {
            for (j = 2; nm[j]; j++) {
                int d = w_lower(nm[j]);
                if (d >= '0' && d <= '9') v = v * 16 + d - '0';
                else if (d >= 'a' && d <= 'f') v = v * 16 + d - 'a' + 10;
                else return 0;
            }
        } else {
            for (; nm[j]; j++) { if (nm[j] < '0' || nm[j] > '9') return 0; v = v * 10 + nm[j] - '0'; }
        }
        one[1] = 0;
        if (v >= 32 && v < 127) one[0] = (char)v;
        else if (v == 160) one[0] = ' ';
        else if (v == 8211 || v == 8212) one[0] = '-';
        else if (v == 8216 || v == 8217) one[0] = '\'';
        else if (v == 8220 || v == 8221) one[0] = '"';
        else if (v == 8226) one[0] = '*';
        else one[0] = '?';
        return one;
    }
    for (i = 0; ent_names[i]; i++) if (w_eq(nm, ent_names[i])) return ent_strs[i];
    return 0;
}

/* ── tag attributes ──────────────────────────────────────────────── */
/* a points just past the tag name, n is the remaining length */
static int get_attr(const char* a, int n, const char* want, char* out, int max)
{
    int i = 0;
    while (i < n) {
        char nm[16]; int k = 0, vs = 0, ve = 0;
        while (i < n && (w_is_ws(a[i]) || a[i] == '/')) i++;
        while (i < n && !w_is_ws(a[i]) && a[i] != '=' && a[i] != '/') { if (k < 15) nm[k++] = (char)w_lower(a[i]); i++; }
        nm[k] = 0;
        while (i < n && w_is_ws(a[i])) i++;
        if (i < n && a[i] == '=') {
            i++;
            while (i < n && w_is_ws(a[i])) i++;
            if (i < n && (a[i] == '"' || a[i] == '\'')) {
                char q = a[i++]; vs = i;
                while (i < n && a[i] != q) i++;
                ve = i; if (i < n) i++;
            } else {
                vs = i;
                while (i < n && !w_is_ws(a[i])) i++;
                ve = i;
            }
        }
        if (k > 0 && w_eq(nm, want)) {
            int len = ve - vs, j;
            if (len > max - 1) len = max - 1;
            for (j = 0; j < len; j++) out[j] = a[vs + j];
            out[len] = 0;
            return 1;
        }
    }
    return 0;
}

/* ── list marker ─────────────────────────────────────────────────── */
static void lay_bullet(int idx)
{
    int x = L_indent - 10;
    if (x < 0) x = 0;
    if (idx >= 0 && L_ltype[idx] == 'o') {
        char nb[12]; int n = w_itoa(L_lcount[idx], nb);
        nb[n++] = '.'; nb[n] = 0;
        x = L_indent - 8 * n - 3;
        if (x < 0) x = 0;
        add_item(x, IT_TEXT, nb, n);
    } else {
        add_item(x + 1, IT_BULLET, "", 0);
    }
}

/* ── tag handling ────────────────────────────────────────────────── */
static void do_tag(const char* t, int n)
{
    char nm[12], buf[URL_LEN];
    int k = 0, i = 0, closing = 0, open;
    const char* a;
    int an;

    if (i < n && t[i] == '/') { closing = 1; i++; }
    while (i < n && !w_is_ws(t[i]) && t[i] != '/' && t[i] != '>') { if (k < 11) nm[k++] = (char)w_lower(t[i]); i++; }
    nm[k] = 0;
    a = t + i; an = n - i;
    open = !closing;

    flush_text();                       /* pending word keeps its old style */

    if (nm[0] == 'h' && nm[1] >= '1' && nm[1] <= '6' && !nm[2]) {
        if (open) {
            int lv = nm[1] - '0';
            lay_block(lv == 1 ? 8 : 6);
            L_scale = (lv == 1) ? 2 : 1;
            L_bold++;
            L_hcol = (lv == 1) ? PG_H1 : (lv == 2 ? PG_H2 : PG_H3);
        } else {
            lay_flush();
            L_scale = 1; if (L_bold > 0) L_bold--; L_hcol = 0;
            lay_block(5);
        }
    }
    else if (w_eq(nm, "p"))          lay_block(6);
    else if (w_eq(nm, "div") || w_eq(nm, "section") || w_eq(nm, "article") || w_eq(nm, "header") ||
             w_eq(nm, "footer") || w_eq(nm, "nav") || w_eq(nm, "main") || w_eq(nm, "form") ||
             w_eq(nm, "address") || w_eq(nm, "figure") || w_eq(nm, "tbody") || w_eq(nm, "thead"))
        lay_block(0);
    else if (w_eq(nm, "br"))         { if (open) lay_br(); }
    else if (w_eq(nm, "hr"))         { if (open) { lay_block(3); add_item(0, IT_HR, "", 0); lay_block(4); } }
    else if (w_eq(nm, "b") || w_eq(nm, "strong")) { if (open) L_bold++; else if (L_bold > 0) L_bold--; }
    else if (w_eq(nm, "i") || w_eq(nm, "em") || w_eq(nm, "cite") || w_eq(nm, "var") || w_eq(nm, "dfn"))
        { if (open) L_ital++; else if (L_ital > 0) L_ital--; }
    else if (w_eq(nm, "u") || w_eq(nm, "ins"))
        { if (open) L_ul++; else if (L_ul > 0) L_ul--; }
    else if (w_eq(nm, "code") || w_eq(nm, "tt") || w_eq(nm, "kbd") || w_eq(nm, "samp"))
        { if (open) L_code++; else if (L_code > 0) L_code--; }
    else if (w_eq(nm, "a")) {
        if (open) {
            if (get_attr(a, an, "href", buf, URL_LEN) && s_link_n < LINK_MAX) {
                w_cpy(s_links[s_link_n], buf, URL_LEN);
                L_link = s_link_n++;
            }
        } else L_link = -1;
    }
    else if (w_eq(nm, "ul") || w_eq(nm, "ol")) {
        if (open) {
            lay_block(L_ldepth ? 0 : 4);
            if (L_ldepth < 6) {
                L_ltype[L_ldepth] = (nm[0] == 'o') ? 'o' : 'u';
                L_lcount[L_ldepth] = 0;
                L_lamt[L_ldepth] = (nm[0] == 'o') ? 26 : 14;
            }
            set_indent((L_ldepth < 6) ? L_lamt[L_ldepth] : 14);
            L_ldepth++;
        } else if (L_ldepth > 0) {
            L_ldepth--;
            set_indent(-((L_ldepth < 6) ? L_lamt[L_ldepth] : 14));
            lay_block(L_ldepth ? 0 : 4);
        }
    }
    else if (w_eq(nm, "li")) {
        if (open) {
            int idx = L_ldepth - 1;
            if (idx > 5) idx = 5;
            lay_flush();
            if (idx >= 0) L_lcount[idx]++;
            lay_bullet(idx);
        } else lay_flush();
    }
    else if (w_eq(nm, "pre")) {
        if (open) { lay_block(4); L_pre++; L_code++; L_pre_first = 1; }
        else { if (L_pre > 0) L_pre--; if (L_code > 0) L_code--; lay_block(4); }
    }
    else if (w_eq(nm, "blockquote")) {
        if (open) { lay_block(5); set_indent(16); L_quote++; }
        else { set_indent(-16); if (L_quote > 0) L_quote--; lay_block(5); }
    }
    else if (w_eq(nm, "center"))     { lay_block(0); if (open) L_center++; else if (L_center > 0) L_center--; }
    else if (w_eq(nm, "title"))      L_title = open;
    else if (w_eq(nm, "img")) {
        if (open) {
            const char* p;
            if (!get_attr(a, an, "alt", buf, 40) || !buf[0]) w_cpy(buf, "img", 40);
            L_dim++;
            L_pending = 1;
            text_char('['); for (p = buf; *p; p++) text_char((unsigned char)*p); text_char(']');
            word_flush();
            L_pending = 1;
            L_dim--;
        }
    }
    else if (w_eq(nm, "table"))      lay_block(4);
    else if (w_eq(nm, "tr"))         { lay_block(0); L_cell = 0; }
    else if (w_eq(nm, "td") || w_eq(nm, "th")) {
        if (open) {
            if (L_cell > 0) { L_dim++; L_pending = 1; lay_word("|", 1); L_dim--; }
            L_pending = 1; L_cell++;
            if (nm[1] == 'h') L_bold++;
        } else if (nm[1] == 'h' && L_bold > 0) L_bold--;
    }
    else if (w_eq(nm, "dl"))         { if (L_dd) { set_indent(-16); L_dd = 0; } lay_block(open ? 4 : 4); }
    else if (w_eq(nm, "dt")) {
        if (L_dd) { set_indent(-16); L_dd = 0; }
        if (open) { lay_block(2); L_bold++; } else if (L_bold > 0) L_bold--;
    }
    else if (w_eq(nm, "dd")) {
        if (open) { if (L_dd) set_indent(-16); lay_block(0); set_indent(16); L_dd = 1; }
        else if (L_dd) { set_indent(-16); L_dd = 0; }
    }
    else if (w_eq(nm, "script")) { if (open) L_skip = 1; }
    else if (w_eq(nm, "style"))  { if (open) L_skip = 2; }
    /* anything else (html, head, body, span, meta, link, font ...): ignored */
}

/* find "</name" (case-insensitive) at or after i; return index just past its '>' */
static int skip_to_close(const char* s, int n, int i, const char* name)
{
    int nl = w_len(name);
    while (i + 2 + nl < n) {
        if (s[i] == '<' && s[i + 1] == '/' && w_starts_ci(s + i + 2, name)) {
            while (i < n && s[i] != '>') i++;
            return i + 1;
        }
        i++;
    }
    return n;
}

static void parse_html(const char* s, int n)
{
    int i = 0;
    while (i < n) {
        int c = (unsigned char)s[i];
        if (c == '<') {
            int d = (i + 1 < n) ? (unsigned char)s[i + 1] : 0;
            if (d == '!' && i + 3 < n && s[i + 2] == '-' && s[i + 3] == '-') {      /* comment */
                i += 4;
                while (i + 2 < n && !(s[i] == '-' && s[i + 1] == '-' && s[i + 2] == '>')) i++;
                i += 3;
                continue;
            }
            if (w_is_alpha(d) || d == '/' || d == '!' || d == '?') {
                int j = i + 1; char q = 0;
                while (j < n) {
                    if (q) { if (s[j] == q) q = 0; }
                    else if (s[j] == '"' || s[j] == '\'') q = s[j];
                    else if (s[j] == '>') break;
                    j++;
                }
                if (d != '!' && d != '?') do_tag(s + i + 1, j - (i + 1));
                i = j + 1;
                if (L_skip) {
                    i = skip_to_close(s, n, i, (L_skip == 2) ? "style" : "script");
                    L_skip = 0;
                }
                continue;
            }
        } else if (c == '&') {
            int adv = 0;
            char one[2];
            const char* e = decode_entity(s + i, n - i, &adv, one);
            if (e) { while (*e) text_char((unsigned char)*e++); i += adv; continue; }
        }
        text_char(c);
        i++;
    }
}

static void parse_plain(const char* s, int n)       /* .txt/.c/.h ... : monospace, no markup */
{
    int i;
    L_pre = 1; L_code = 1; L_pre_first = 0;
    for (i = 0; i < n; i++) text_char((unsigned char)s[i]);
}

/* ── rendering ───────────────────────────────────────────────────── */
static void draw_glyph(int x, int y, int ch, unsigned int col, int sc, int ital, int bold)
{
    const unsigned char* g;
    int row, cb, r, dx;
    if (ch < 0 || ch >= 128) return;
    g = &font[ch * 8];
    for (row = 0; row < 8; row++) {
        unsigned char bits = g[row];
        int off;
        if (!bits) continue;
        off = ital ? (((7 - row) * sc) >> 2) : 0;
        for (r = 0; r < sc; r++) {
            int yy = y + row * sc + r;
            if (yy < VIEW_Y || yy >= VIEW_Y + VIEW_H) continue;
            for (cb = 0; cb < 8; cb++) {
                if (bits & (0x80 >> cb)) {
                    int px = x + off + cb * sc;
                    for (dx = 0; dx < sc + (bold ? 1 : 0); dx++)
                        if (px + dx >= 0 && px + dx < VIEW_W) gfx_set_pixel(px + dx, yy, col);
                }
            }
        }
    }
}

static void draw_hline(int x0, int x1, int y, unsigned int col)
{
    int x;
    if (y < VIEW_Y || y >= VIEW_Y + VIEW_H) return;
    for (x = x0; x < x1; x++) if (x >= 0 && x < VIEW_W) gfx_set_pixel(x, y, col);
}

static void draw_view(void)
{
    int i, j, scroll = s_bar.value;
    ui_fill_rect(0, VIEW_Y, VIEW_W, VIEW_H, PG_BG);
    for (i = 0; i < s_item_n; i++) {
        wb_item_t* it = &s_items[i];
        int sc = it->scale, sy = VIEW_Y + it->y - scroll, x = MARGIN + it->x;
        int h = 8 * sc + 2;
        unsigned int col = it->color;
        if (sy + h <= VIEW_Y || sy >= VIEW_Y + VIEW_H) continue;

        if (it->kind == IT_HR) {
            draw_hline(MARGIN, MARGIN + TEXT_W, sy + 4, PG_RULE);
            draw_hline(MARGIN, MARGIN + TEXT_W, sy + 5, 0xFFFFFF);
        } else if (it->kind == IT_BULLET) {
            for (j = 0; j < 4; j++) draw_hline(x, x + 4, sy + 2 + j, PG_TEXT);
        } else {
            int hot = (it->link >= 0 && it->link == s_hover);
            if (hot) col = PG_LINKHOT;
            for (j = 0; j < it->len; j++)
                draw_glyph(x + j * 8 * sc, sy, (unsigned char)s_pool[it->off + j], col, sc,
                           it->flags & F_ITAL, it->flags & F_BOLD);
            if ((it->flags & F_UL) || hot) draw_hline(x, x + it->len * 8 * sc, sy + 8 * sc, col);
        }
    }
    if (s_truncated) ui_draw_text(MARGIN, VIEW_Y + VIEW_H - 10, "[page truncated]", PG_DIM);
}

static void draw_status(void)
{
    char b[44];
    ui_fill_rect(0, STATUS_Y, 320, 12, UI_COLOR_PANEL);
    ui_fill_rect(0, STATUS_Y, 320, 1, UI_COLOR_BORDER);
    if (s_hover >= 0) { w_cpy(b, "-> ", 44); w_cat(b, s_links[s_hover], 40); }
    else w_cpy(b, s_status, 44);
    ui_draw_text(2, STATUS_Y + 2, b, s_hover >= 0 ? UI_COLOR_ACCENT : UI_COLOR_TEXT_DIM);
}

static int hit_link(int mx, int my)
{
    int i, scroll = s_bar.value;
    for (i = 0; i < s_item_n; i++) {
        wb_item_t* it = &s_items[i];
        int sy, w;
        if (it->link < 0 || it->kind != IT_TEXT) continue;
        sy = VIEW_Y + it->y - scroll;
        w = it->len * 8 * it->scale;
        if (ui_point_in_rect(mx, my, MARGIN + it->x, sy, w, 8 * it->scale + 2)) return it->link;
    }
    return -1;
}

static void set_status(const char* name)
{
    char nb[12];
    w_cpy(s_status, s_title[0] ? s_title : name, 30);
    w_cat(s_status, "  ", 48);
    w_itoa(s_bytes, nb);
    w_cat(s_status, nb, 48);
    w_cat(s_status, "b", 48);
}

static void render(const char* src, int n, int plain, const char* name)
{
    int max;
    lay_reset();
    if (plain) parse_plain(src, n); else parse_html(src, n);
    flush_text();
    lay_flush();
    s_doc_h = L_cy + 6;
    max = s_doc_h - VIEW_H;
    if (max < 0) max = 0;
    ui_scrollbar_init(&s_bar, VIEW_W + 2, VIEW_Y, 12, VIEW_H, 0, max, 0);
    s_bytes = n;
    s_hover = -1; s_last_scroll = -1;
    set_status(name);
    s_dirty = 1;
}

/* ── built-in pages ───────────────────────────────────────────────── */
static const char HOME_FALLBACK[] =
    "<title>web</title><h1>web</h1><p>No <b>home.htm</b> was found on the disk.</p>"
    "<p>Type a file name or a web address in the box above and press Go, e.g. "
    "<b>example.com</b>, <a href=\"editf.c\">editf.c</a> or <a href=\"web.c\">web.c</a>.</p>";

static void show_html(const char* html, const char* name)
{
    int n = w_cpy(s_page, html, PAGE_MAX);
    render(s_page, n, 0, name);
}

static void hist_push(const char* name)
{
    int i;
    if (s_hist_n == HIST_MAX) {
        for (i = 1; i < HIST_MAX; i++) w_cpy(s_hist[i - 1], s_hist[i], URL_LEN);
        s_hist_n--;
    }
    w_cpy(s_hist[s_hist_n++], name, URL_LEN);
}

static void set_url_box(const char* s)
{
    s_url.len = w_cpy(s_url.buf, s, UI_TEXTBOX_MAX);   /* the box holds 63 chars; the page keeps the full URL */
}

/* "Error" page: head line, explanation, and the offending name/URL
 * (sanitised so it can't inject markup). */
static void show_error(const char* head, const char* body, const char* arg)
{
    char msg[700], a[URL_LEN];
    int i;
    w_cpy(a, arg, URL_LEN);
    for (i = 0; a[i]; i++) if (a[i] == '<' || a[i] == '>' || a[i] == '&' || a[i] == '"') a[i] = '_';
    w_cpy(msg, "<title>", sizeof msg);
    w_cat(msg, head, sizeof msg);
    w_cat(msg, "</title><h2>", sizeof msg);
    w_cat(msg, head, sizeof msg);
    w_cat(msg, "</h2><p>", sizeof msg);
    w_cat(msg, body, sizeof msg);
    w_cat(msg, "</p><p><b>", sizeof msg);
    w_cat(msg, a, sizeof msg);
    w_cat(msg, "</b></p><p><a href=\"home.htm\">Back to the home page</a></p>", sizeof msg);
    s_cur[0] = 0;
    set_url_box(a);
    show_html(msg, head);
}

/* ── URL helpers ──────────────────────────────────────────────────── */
static int is_http(const char* u)  { return w_starts_ci(u, "http://"); }
static int is_https(const char* u) { return w_starts_ci(u, "https://"); }

/* any "scheme:" we should not treat as a relative path */
static int has_scheme(const char* u)
{
    int i;
    if (w_starts_ci(u, "mailto:") || w_starts_ci(u, "javascript:") || w_starts_ci(u, "tel:") ||
        w_starts_ci(u, "data:")) return 1;
    for (i = 0; i < 10 && w_is_alpha(u[i]); i++) { }
    return i > 0 && u[i] == ':' && u[i + 1] == '/' && u[i + 2] == '/';
}

static void strip_frag(char* u) { while (*u) { if (*u == '#') { *u = 0; return; } u++; } }

/* typed "example.com/x" (no scheme): a host if its first segment has a dot
 * and doesn't end in a known file extension -- "web.c" stays a local file. */
static int looks_like_host(const char* u)
{
    char seg[URL_LEN]; int i = 0;
    while (u[i] && u[i] != '/' && i < URL_LEN - 1) { seg[i] = u[i]; i++; }
    seg[i] = 0;
    if (!w_has_dot(seg)) return 0;
    if (w_ends_ci(seg, ".htm") || w_ends_ci(seg, ".html") || w_ends_ci(seg, ".txt") ||
        w_ends_ci(seg, ".c") || w_ends_ci(seg, ".h") || w_ends_ci(seg, ".md")) return 0;
    return 1;
}

/* http://host[:port]/path  ->  host, port, path ("/" at least).  0 = ok. */
static int parse_url(const char* url, char* host, unsigned* port, char* path)
{
    int i = 7, k = 0, colon = -1, j;
    char hp[80];
    if (!is_http(url)) return -1;
    while (url[i] && url[i] != '/' && url[i] != '?' && url[i] != '#') {
        if (k >= 79) return -1;
        if (url[i] == ':') colon = k;
        hp[k++] = url[i++];
    }
    hp[k] = 0;
    *port = 80;
    if (colon >= 0) {
        unsigned v = 0;
        for (j = colon + 1; hp[j]; j++) { if (hp[j] < '0' || hp[j] > '9') return -1; v = v * 10 + (unsigned)(hp[j] - '0'); if (v > 65535) return -1; }
        if (v == 0) return -1;
        *port = v;
        hp[colon] = 0;
    }
    if (!hp[0] || w_len(hp) > 63) return -1;
    w_cpy(host, hp, 64);
    j = 0;
    if (url[i] == '?') path[j++] = '/';
    while (url[i] && url[i] != '#') {
        if (j >= 191) return -1;
        path[j++] = url[i++];
    }
    if (j == 0) path[j++] = '/';
    path[j] = 0;
    return 0;
}

/* resolve `ref` (an href) against absolute http(s) URL `base` */
static void resolve_url(const char* base, const char* ref, char* out)
{
    char b[URL_LEN];
    int ae, q, last, j, secure;
    if (is_http(ref) || is_https(ref)) { w_cpy(out, ref, URL_LEN); strip_frag(out); return; }
    w_cpy(b, base, URL_LEN);
    strip_frag(b);
    secure = is_https(b);
    ae = secure ? 8 : 7;
    while (b[ae] && b[ae] != '/' && b[ae] != '?') ae++;
    if (ref[0] == '/' && ref[1] == '/') {
        w_cpy(out, secure ? "https:" : "http:", URL_LEN); w_cat(out, ref, URL_LEN);
        strip_frag(out); return;
    }
    if (ref[0] == '/') {
        b[ae] = 0; w_cpy(out, b, URL_LEN); w_cat(out, ref, URL_LEN);
        strip_frag(out); return;
    }
    q = ae; while (b[q] && b[q] != '?') q++;
    if (ref[0] == '?') { b[q] = 0; w_cpy(out, b, URL_LEN); w_cat(out, ref, URL_LEN); strip_frag(out); return; }
    last = ae;
    for (j = ae; j < q; j++) if (b[j] == '/') last = j;
    b[last] = 0;                                   /* directory part, no trailing slash */
    for (;;) {
        if (ref[0] == '.' && ref[1] == '/') ref += 2;
        else if (ref[0] == '.' && ref[1] == '.' && ref[2] == '/') {
            int p = -1;
            ref += 3;
            for (j = ae; b[j]; j++) if (b[j] == '/') p = j;
            if (p >= 0) b[p] = 0;
        } else break;
    }
    w_cpy(out, b, URL_LEN); w_cat(out, "/", URL_LEN); w_cat(out, ref, URL_LEN);
    strip_frag(out);
}

/* ── HTTP response handling ───────────────────────────────────────── */
/* value of header `name` (case-insensitive) in h[0..hlen), or 0 */
static int hdr_get(const char* h, int hlen, const char* name, char* out, int max)
{
    int i = 0, nl = w_len(name);
    while (i < hlen) {
        int ls = i, le = i;
        while (le < hlen && h[le] != '\n') le++;
        if (le - ls > nl && h[ls + nl] == ':' && w_starts_ci(h + ls, name)) {
            int v = ls + nl + 1, k = 0;
            while (v < le && (h[v] == ' ' || h[v] == '\t')) v++;
            while (v < le && h[v] != '\r' && k < max - 1) out[k++] = h[v++];
            out[k] = 0;
            return 1;
        }
        i = le + 1;
    }
    return 0;
}

/* decode "Transfer-Encoding: chunked" in place; returns new length */
static int dechunk(char* b, int n)
{
    int r = 0, w = 0;
    while (r < n) {
        int sz = 0, digits = 0, i;
        while (r < n && digits < 7) {
            int c = w_lower((unsigned char)b[r]);
            if (c >= '0' && c <= '9') sz = sz * 16 + c - '0';
            else if (c >= 'a' && c <= 'f') sz = sz * 16 + c - 'a' + 10;
            else break;
            r++; digits++;
        }
        while (r < n && b[r] != '\n') r++;          /* chunk extensions, CR */
        if (r < n) r++;
        if (!digits || sz == 0) break;
        if (sz > n - r) sz = n - r;
        for (i = 0; i < sz; i++) b[w++] = b[r++];
        if (r < n && b[r] == '\r') r++;
        if (r < n && b[r] == '\n') r++;
    }
    return w;
}

static void show_loading(const char* host)
{
    /* the fetch blocks the whole desktop, so say so first */
    w_cpy(s_status, "Loading ", 48);
    w_cat(s_status, host, 48);
    w_cat(s_status, "...", 48);
    s_hover = -1;
    draw_status();
    ui_frame_end();
}

/* "http://host" -> "http://host/" */
static void canon_url(char* u)
{
    int i = is_https(u) ? 8 : 7;
    while (u[i] && u[i] != '/' && u[i] != '?') i++;
    if (u[i] == '/') return;
    if (u[i] == '?') { int n = w_len(u); if (n + 1 < URL_LEN) { int k; for (k = n + 1; k > i; k--) u[k] = u[k - 1]; u[i] = '/'; } }
    else if (i + 1 < URL_LEN) { u[i] = '/'; u[i + 1] = 0; }
}

/* fetch an http:// URL (following redirects) and show it */
static void nav_net(const char* url_in, int push)
{
    char url[URL_LEN], host[64], path[192], loc[URL_LEN], ctype[48], tmp[URL_LEN];
    unsigned port, got, flags;
    int hop, rc;

    w_cpy(url, url_in, URL_LEN);
    strip_frag(url);
    canon_url(url);
    if (push && s_cur[0] && !w_eq(s_cur, url)) hist_push(s_cur);

    for (hop = 0; hop < 6; hop++) {
        int code = 0, hend = -1, hl, blen, i, plain, trunc, chunked;
        if (is_https(url)) {
            show_error("https is not supported",
                       "Encrypted connections need TLS, which this OS does not have. Plain http:// "
                       "sites work. Many sites redirect http to https and will not load.", url);
            return;
        }
        if (parse_url(url, host, &port, path) != 0) { show_error("Bad address", "Could not understand this URL:", url); return; }

        show_loading(host);
        rc = knet_http_get(host, port, path, s_page, PAGE_MAX, &got, &flags);
        if (rc != KNET_OK) {
            const char* why =
                rc == KNET_ERR_NONIC   ? "No network card or IP address. Start QEMU with -nic user,model=e1000" :
                rc == KNET_ERR_DNS     ? "Could not look up this host name (DNS failed)." :
                rc == KNET_ERR_CONNECT ? "Could not connect (refused or timed out)." :
                rc == KNET_ERR_NODATA  ? "Connected, but the server sent nothing." :
                rc == KNET_ERR_UNREACHABLE ? "This kernel build has no network ABI. Rebuild the kernel and main.iso from the updated sources." :
                                         "Network request failed.";
            show_error("Cannot load page", why, url);
            return;
        }
        s_page[got] = 0;
        trunc = (flags & KNET_F_TRUNC) != 0;

        /* split headers / body */
        for (i = 0; i + 1 < (int)got; i++) {
            if (s_page[i] == '\n' && s_page[i + 1] == '\n') { hend = i + 2; break; }
            if (i + 3 < (int)got && s_page[i] == '\r' && s_page[i + 1] == '\n' && s_page[i + 2] == '\r' && s_page[i + 3] == '\n') { hend = i + 4; break; }
        }
        if (hend < 0 || !w_starts_ci(s_page, "HTTP/")) {
            /* show what did arrive: byte count + first bytes (control chars as '.') */
            char pv[96]; int n = 0, m = (int)got < 40 ? (int)got : 40;
            n += w_itoa((int)got, pv + n);
            pv[n++] = 'b'; pv[n++] = ':'; pv[n++] = ' ';
            for (i = 0; i < m; i++) { unsigned char ch = (unsigned char)s_page[i]; pv[n++] = (ch >= 32 && ch < 127) ? (char)ch : '.'; }
            pv[n] = 0;
            show_error("Not an HTTP response", "The server did not answer with HTTP. Received:", pv);
            return;
        }
        hl = hend;
        for (i = 0; s_page[i] && s_page[i] != ' '; i++) { }
        while (s_page[i] == ' ') i++;
        while (s_page[i] >= '0' && s_page[i] <= '9') code = code * 10 + (s_page[i++] - '0');

        if ((code == 301 || code == 302 || code == 303 || code == 307 || code == 308) &&
            hdr_get(s_page, hl, "location", loc, URL_LEN)) {
            resolve_url(url, loc, tmp);
            w_cpy(url, tmp, URL_LEN);
            canon_url(url);
            continue;
        }

        /* read what we need from the headers BEFORE the body overwrites them */
        ctype[0] = 0;
        hdr_get(s_page, hl, "content-type", ctype, sizeof ctype);
        chunked = hdr_get(s_page, hl, "transfer-encoding", tmp, URL_LEN) && w_starts_ci(tmp, "chunked");

        blen = (int)got - hend;
        for (i = 0; i < blen; i++) s_page[i] = s_page[hend + i];
        s_page[blen] = 0;
        if (chunked) { blen = dechunk(s_page, blen); s_page[blen] = 0; }

        if (blen == 0) {
            w_cpy(tmp, "The server returned status ", URL_LEN);
            { char nb[12]; w_itoa(code, nb); w_cat(tmp, nb, URL_LEN); }
            w_cat(tmp, " with no content.", URL_LEN);
            show_error("Empty response", tmp, url);
            return;
        }

        /* choose a renderer from Content-Type (sniff if missing) */
        if (ctype[0]) {
            if (w_starts_ci(ctype, "text/html") || w_starts_ci(ctype, "application/xhtml")) plain = 0;
            else if (w_starts_ci(ctype, "text/")) plain = 1;
            else {
                w_cpy(tmp, "This browser can only show HTML and text, not: ", URL_LEN);
                w_cat(tmp, ctype, URL_LEN);
                show_error("Unsupported content", tmp, url);
                return;
            }
        } else {
            i = 0; while (i < blen && w_is_ws((unsigned char)s_page[i])) i++;
            plain = !(i < blen && s_page[i] == '<');
        }

        w_cpy(s_cur, url, URL_LEN);
        set_url_box(url);
        render(s_page, blen, plain, url + 7);
        if (trunc) s_truncated = 1;
        return;
    }
    show_error("Too many redirects", "Giving up after 6 redirects:", url);
}

/* ── local files ──────────────────────────────────────────────────── */
static void normalize(const char* u, char* out)
{
    int k = 0;
    while (w_is_ws(*u)) u++;
    if (w_starts_ci(u, "file://")) u += 7; else if (w_starts_ci(u, "file:")) u += 5;
    while (*u == '/' || (*u == '.' && u[1] == '/')) u += (*u == '/') ? 1 : 2;
    while (*u && *u != '#' && *u != '?' && k < NAME_LEN - 1 && !w_is_ws(*u)) out[k++] = *u++;
    out[k] = 0;
}

static void nav_file(const char* u, int push)
{
    char name[NAME_LEN], alt[NAME_LEN + 8];
    int rc;

    normalize(u, name);
    if (!name[0]) w_cpy(name, "home.htm", NAME_LEN);
    if (push && s_cur[0] && !w_eq(s_cur, name)) hist_push(s_cur);

    rc = kfread(name, s_page, PAGE_MAX);
    if (rc == DISK_ERR_NOTFOUND && !w_has_dot(name) && w_len(name) < NAME_LEN - 6) {
        w_cpy(alt, name, sizeof alt); w_cat(alt, ".htm", sizeof alt);
        rc = kfread(alt, s_page, PAGE_MAX);
        if (rc >= 0) w_cpy(name, alt, NAME_LEN);
        else if (rc == DISK_ERR_NOTFOUND) {
            w_cpy(alt, name, sizeof alt); w_cat(alt, ".html", sizeof alt);
            rc = kfread(alt, s_page, PAGE_MAX);
            if (rc >= 0) w_cpy(name, alt, NAME_LEN);
        }
    }
    if (rc < 0) {
        if (rc == DISK_ERR_NOTFOUND && w_starts_ci(name, "home.htm")) {
            s_cur[0] = 0; set_url_box(name);
            show_html(HOME_FALLBACK, "home");
            return;
        }
        show_error(rc == DISK_ERR_NOTFOUND ? "File not found" : rc == DISK_ERR_TOOBIG ? "File too big" : "Disk error",
                   rc == DISK_ERR_NOTFOUND ? "No such file on the disk:" :
                   rc == DISK_ERR_TOOBIG   ? "Files over 48000 bytes cannot be opened:" : "Could not read:", name);
        return;
    }
    s_page[rc] = 0;
    w_cpy(s_cur, name, URL_LEN);
    set_url_box(name);
    render(s_page, rc, !(w_ends_ci(name, ".htm") || w_ends_ci(name, ".html")), name);
}

/* ── navigation entry point ───────────────────────────────────────── */
/* rel = 1 when `url_in` came from a link on the current page (so relative
 * hrefs resolve against it); 0 for typed addresses and built-in targets. */
static void nav_to(const char* url_in, int push, int rel)
{
    char u[URL_LEN], r[URL_LEN];

    w_cpy(u, url_in, URL_LEN);                  /* url_in may point into s_links / s_url */
    while (w_is_ws((unsigned char)u[0])) w_cpy(u, u + 1, URL_LEN);
    if (u[0] == '#') { s_bar.value = 0; s_dirty = 1; return; }
    if (w_starts_ci(u, "mailto:") || w_starts_ci(u, "javascript:") || w_starts_ci(u, "tel:") ||
        w_starts_ci(u, "data:")) return;                                  /* nothing to open */

    if (!has_scheme(u)) {
        if (rel && is_http(s_cur)) { resolve_url(s_cur, u, r); w_cpy(u, r, URL_LEN); }
        else if (!rel && looks_like_host(u)) { w_cpy(r, "http://", URL_LEN); w_cat(r, u, URL_LEN); w_cpy(u, r, URL_LEN); }
    }
    if (is_http(u) || is_https(u)) { nav_net(u, push); return; }
    if (has_scheme(u)) { show_error("Unsupported address", "Only http:// addresses and disk files can be opened:", u); return; }
    nav_file(u, push);
}

static void nav_back(void)
{
    char t[URL_LEN];
    if (s_hist_n <= 0) return;
    w_cpy(t, s_hist[--s_hist_n], URL_LEN);
    nav_to(t, 0, 0);
}

/* ── main loop ───────────────────────────────────────────────────── */
static ui_button_t b_back = {   2, 1, 36, 16, "Back" };
static ui_button_t b_home = {  40, 1, 36, 16, "Home" };
static ui_button_t b_go   = { 286, 1, 32, 16, "Go"   };

static void clamp_scroll(void)
{
    if (s_bar.value < s_bar.min) s_bar.value = s_bar.min;
    if (s_bar.value > s_bar.max) s_bar.value = s_bar.max;
}

void _start(void)
{
    kputs("web: starting (opens .htm/.html/.txt/.c files from the disk)\n");

    ui_textbox_init(&s_url, 78, 1, 206, 16);
    ui_scrollbar_init(&s_bar, VIEW_W + 2, VIEW_Y, 12, VIEW_H, 0, 0, 0);
    s_cur[0] = 0; s_hist_n = 0;
#ifdef WEB_START_URL
    nav_to(WEB_START_URL, 0, 0);        /* test builds: cc -DWEB_START_URL='"http://10.0.2.2:8000/"' */
#else
    nav_to("home.htm", 0, 0);
#endif

    for (;;) {
        ui_frame_t f;
        int go = 0, back = 0, home = 0, quit = 0, was_focus, in_view, clicked_link = -1;
        int old_scroll;

        mouse_poll(&f.mouse);
        f.key = key_poll();
        old_scroll = s_bar.value;

        /* keyboard: URL box owns it while focused, otherwise it scrolls/navigates */
        if (s_url.focused) {
            if (f.key == '\n' || f.key == '\r') go = 1;
        } else if (f.key) {
            int consumed = 1;
            switch (f.key) {
            case KEY_UP:    s_bar.value -= 10; break;
            case KEY_DOWN:  s_bar.value += 10; break;
            case KEY_HOME:  s_bar.value = s_bar.min; break;
            case KEY_END:   s_bar.value = s_bar.max; break;
            case ' ':       s_bar.value += VIEW_H - 20; break;
            case 'b':       s_bar.value -= VIEW_H - 20; break;
            case '\b':
            case 127:       back = 1; break;
            case 'h':       home = 1; break;
            case 'g':       s_url.focused = 1; s_url.buf[0] = 0; s_url.len = 0; break;
            case 'q':       quit = 1; break;
            default:        consumed = 0; break;
            }
            if (consumed) f.key = 0;
        }
        clamp_scroll();

        /* toolbar (redrawn every frame; it also gives hot/pressed feedback) */
        ui_fill_rect(0, 0, 320, VIEW_Y - 1, UI_COLOR_PANEL);
        ui_fill_rect(0, VIEW_Y - 1, 320, 1, UI_COLOR_BORDER);
        was_focus = s_url.focused;
        ui_textbox_update(&f, &s_url);
        if (!was_focus && s_url.focused) { s_url.buf[0] = 0; s_url.len = 0; }   /* click = select all */
        ui_textbox_draw(&s_url);
        if (ui_button(&f, &b_back)) back = 1;
        if (ui_button(&f, &b_home)) home = 1;
        if (ui_button(&f, &b_go))   go = 1;
        if (was_focus && !s_url.focused && !go) set_url_box(s_cur);              /* abandoned edit */

        ui_scrollbar_update(&f, &s_bar);
        ui_scrollbar_draw(&s_bar);
        if (s_bar.value != old_scroll) s_dirty = 1;

        /* hover / click on links (hit-test only when something moved) */
        in_view = f.mouse.in_window && f.mouse.x < VIEW_W && f.mouse.y >= VIEW_Y && f.mouse.y < VIEW_Y + VIEW_H;
        if (in_view != s_last_in || (in_view && (f.mouse.x != s_last_mx || f.mouse.y != s_last_my)) ||
            s_bar.value != s_last_scroll) {
            int hv = in_view ? hit_link(f.mouse.x, f.mouse.y) : -1;
            if (hv != s_hover) { s_hover = hv; s_dirty = 1; }
            s_last_in = in_view; s_last_mx = f.mouse.x; s_last_my = f.mouse.y; s_last_scroll = s_bar.value;
        }
        if (in_view && f.mouse.left_clicked && s_hover >= 0) clicked_link = s_hover;

        /* actions */
        if (quit) break;
        if (go)                    nav_to(s_url.buf, 1, 0);
        else if (home)             nav_to("home.htm", 1, 0);
        else if (back)             nav_back();
        else if (clicked_link >= 0) nav_to(s_links[clicked_link], 1, 1);

        if (s_dirty) { draw_view(); draw_status(); s_dirty = 0; }
        ui_frame_end();
    }

    gfx_exit();
    kputs("web: bye\n");
    kexit(0);
    for (;;) { }
}
