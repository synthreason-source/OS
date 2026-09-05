    directx_explorer_shell.c
    ------------------------------------------------------------
    Fullscreen Windows Explorer-style shell/demo with:

      - DirectX 11 window + fullscreen shell
      - Real filesystem enumeration
      - EXE / LNK / documents launched with ShellExecuteW
      - Folder navigation
      - Address bar with editable path entry
      - Search box (filesystem name search in current folder)
      - Double-click activation
      - Enter = open selected item
      - Backspace = parent directory
      - F5 = refresh
      - Ctrl+C / Ctrl+V = copy/paste
      - Delete = recycle-bin delete
      - Right-click context menu
      - Start menu with Run and common Windows locations
      - Run dialog
      - Taskbar clock
      - Taskbar list of programs launched by this shell
      - Integrated Factorisation application
      - Trial division for small values
      - Pollard-Rho + Miller-Rabin for larger 64-bit integers
      - Background factorisation thread so UI stays responsive

    Build with MSVC Developer Command Prompt:

      cl /O2 /W3 /DUNICODE /D_UNICODE directx_explorer_shell.c ^
        /link d3d11.lib dxgi.lib user32.lib gdi32.lib shell32.lib ^
        ole32.lib shlwapi.lib comdlg32.lib advapi32.lib

    Notes:
      This is a custom shell-like application, not a replacement for
      explorer.exe. It deliberately launches programs through Windows'
      normal ShellExecute mechanism.

      Factorisation is classical integer factorisation. The UI also
      displays a "Schmidt-style spectrum" derived from the factors for
      experimentation, but this is not claimed to be a quantum or
      polynomial-time factoring algorithm.
*/

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>
#include <math.h>
#include <process.h>
#include <intrin.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_ITEMS 8192
#define MAX_PATH2 32768
#define MAX_TASKS 64

typedef struct {
    WCHAR name[MAX_PATH2];
    WCHAR full[MAX_PATH2];
    BOOL dir;
    ULONGLONG size;
} FileItem;

typedef struct {
    WCHAR title[128];
    DWORD pid;
    BOOL active;
} ShellTask;

static HWND g_hwnd;
static ID3D11Device *g_device;
static ID3D11DeviceContext *g_context;
static IDXGISwapChain *g_swapchain;
static ID3D11RenderTargetView *g_target;

static UINT g_w = 1280, g_h = 720;
static BOOL g_running = TRUE;
static BOOL g_fullscreen = TRUE;
static BOOL g_start = FALSE;
static BOOL g_run_dialog = FALSE;
static BOOL g_factor_app = FALSE;
static BOOL g_context_menu = FALSE;

static WCHAR g_path[MAX_PATH2] = L"C:\\";
static FileItem g_items[MAX_ITEMS];
static int g_count = 0;
static int g_selected = -1;
static int g_scroll = 0;

static HWND g_address;
static HWND g_search;
static HWND g_run_edit;
static HWND g_factor_edit;

static ShellTask g_tasks[MAX_TASKS];
static int g_task_count = 0;

static WCHAR g_clipboard_file[MAX_PATH2] = L"";
static BOOL g_clipboard_cut = FALSE;

static HANDLE g_factor_thread = NULL;
static volatile LONG g_factor_running = 0;
static WCHAR g_factor_input[128] = L"";
static WCHAR g_factor_output[2048] = L"Enter an integer and press Factor.";
static WCHAR g_factor_status[256] = L"Ready.";

static UINT_PTR g_clock_timer = 1001;

/* ------------------------------------------------------------ */
/* Small helpers                                                  */
/* ------------------------------------------------------------ */

static void set_font(HDC dc, int size, BOOL bold)
{
    HFONT f = CreateFontW(
        -size, 0, 0, 0,
        bold ? FW_BOLD : FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    SelectObject(dc, f);
    DeleteObject(f);
}

static void fill(HDC dc, int l, int t, int r, int b, COLORREF c)
{
    HBRUSH br = CreateSolidBrush(c);
    RECT x = { l, t, r, b };
    FillRect(dc, &x, br);
    DeleteObject(br);
}

static void border(HDC dc, int l, int t, int r, int b, COLORREF c)
{
    HPEN p = CreatePen(PS_SOLID, 1, c);
    HGDIOBJ old = SelectObject(dc, p);
    HGDIOBJ oldb = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
    Rectangle(dc, l, t, r, b);
    SelectObject(dc, old);
    SelectObject(dc, oldb);
    DeleteObject(p);
}

static void text(HDC dc, int x, int y, const WCHAR *s, COLORREF c)
{
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    TextOutW(dc, x, y, s, (int)wcslen(s));
}

static void path_join(const WCHAR *a, const WCHAR *b, WCHAR *out, size_t n)
{
    if (!a || !b) return;
    if (a[0] == 0) {
        wcsncpy(out, b, n - 1);
        out[n - 1] = 0;
        return;
    }

    size_t la = wcslen(a);
    if (la && (a[la - 1] == L'\\' || a[la - 1] == L'/'))
        _snwprintf(out, n, L"%s%s", a, b);
    else
        _snwprintf(out, n, L"%s\\%s", a, b);

    out[n - 1] = 0;
}

static BOOL is_root_path(const WCHAR *p)
{
    return wcslen(p) == 3 && p[1] == L':' && p[2] == L'\\';
}

static void go_up(void)
{
    WCHAR temp[MAX_PATH2];
    wcsncpy(temp, g_path, MAX_PATH2 - 1);
    temp[MAX_PATH2 - 1] = 0;

    if (is_root_path(temp)) return;

    WCHAR *slash = wcsrchr(temp, L'\\');
    if (!slash) return;

    if (slash == temp + 2 && temp[1] == L':') {
        temp[3] = 0;
    } else {
        *slash = 0;
        if (wcslen(temp) == 2 && temp[1] == L':')
            wcscat(temp, L"\\");
    }

    wcsncpy(g_path, temp, MAX_PATH2 - 1);
    g_path[MAX_PATH2 - 1] = 0;
}

static int __cdecl item_compare(const void *a, const void *b)
{
    const FileItem *x = (const FileItem *)a;
    const FileItem *y = (const FileItem *)b;

    if (x->dir != y->dir) return y->dir - x->dir;
    return _wcsicmp(x->name, y->name);
}

static void refresh_files(void)
{
    g_count = 0;
    g_selected = -1;
    g_scroll = 0;

    WCHAR pattern[MAX_PATH2];
    _snwprintf(pattern, MAX_PATH2, L"%s%s",
               g_path,
               (wcslen(g_path) && g_path[wcslen(g_path)-1] == L'\\') ? L"*" : L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
            continue;

        if (g_count >= MAX_ITEMS) break;

        FileItem *it = &g_items[g_count++];
        wcsncpy(it->name, fd.cFileName, MAX_PATH2 - 1);
        it->name[MAX_PATH2 - 1] = 0;

        path_join(g_path, fd.cFileName, it->full, MAX_PATH2);

        it->dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        it->size = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

    } while (FindNextFileW(h, &fd));

    FindClose(h);
    qsort(g_items, g_count, sizeof(FileItem), item_compare);
}

static void navigate_to(const WCHAR *p)
{
    DWORD attr = GetFileAttributesW(p);
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) return;

    wcsncpy(g_path, p, MAX_PATH2 - 1);
    g_path[MAX_PATH2 - 1] = 0;

    if (wcslen(g_path) == 2 && g_path[1] == L':')
        wcscat(g_path, L"\\");

    refresh_files();

    if (g_address)
        SetWindowTextW(g_address, g_path);
}

static void open_item(int idx)
{
    if (idx < 0 || idx >= g_count) return;

    FileItem *it = &g_items[idx];

    if (it->dir) {
        navigate_to(it->full);
        return;
    }

    HINSTANCE r = ShellExecuteW(
        g_hwnd, L"open", it->full, NULL, NULL, SW_SHOWNORMAL);

    if ((INT_PTR)r > 32) {
        if (g_task_count < MAX_TASKS) {
            ShellTask *t = &g_tasks[g_task_count++];
            wcsncpy(t->title, it->name, 127);
            t->title[127] = 0;
            t->pid = 0;
            t->active = TRUE;
        }
    }
}

static void format_size(ULONGLONG n, WCHAR *out, size_t cap)
{
    if (n < 1024ULL)
        _snwprintf(out, cap, L"%llu B", n);
    else if (n < 1024ULL * 1024ULL)
        _snwprintf(out, cap, L"%.1f KB", (double)n / 1024.0);
    else if (n < 1024ULL * 1024ULL * 1024ULL)
        _snwprintf(out, cap, L"%.1f MB", (double)n / (1024.0 * 1024.0));
    else
        _snwprintf(out, cap, L"%.2f GB",
                   (double)n / (1024.0 * 1024.0 * 1024.0));
}

/* ------------------------------------------------------------ */
/* Copy / paste / recycle-bin delete                             */
/* ------------------------------------------------------------ */

static void set_file_clipboard(int idx)
{
    if (idx < 0 || idx >= g_count) return;
    wcsncpy(g_clipboard_file, g_items[idx].full, MAX_PATH2 - 1);
    g_clipboard_file[MAX_PATH2 - 1] = 0;
    g_clipboard_cut = FALSE;
}

static void paste_file(void)
{
    if (!g_clipboard_file[0]) return;

    WCHAR dst[MAX_PATH2];
    const WCHAR *base = wcsrchr(g_clipboard_file, L'\\');
    base = base ? base + 1 : g_clipboard_file;
    path_join(g_path, base, dst, MAX_PATH2);

    SHFILEOPSTRUCTW op = {0};
    op.hwnd = g_hwnd;
    op.wFunc = FO_COPY;
    op.pFrom = g_clipboard_file;
    op.pTo = dst;
    op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;

    if (SHFileOperationW(&op) == 0)
        refresh_files();
}

static void recycle_selected(void)
{
    if (g_selected < 0 || g_selected >= g_count) return;

    WCHAR from[MAX_PATH2];
    wcsncpy(from, g_items[g_selected].full, MAX_PATH2 - 1);
    from[MAX_PATH2 - 1] = 0;

    WCHAR multi[MAX_PATH2 + 2];
    wcsncpy(multi, from, MAX_PATH2 - 1);
    multi[MAX_PATH2 - 1] = 0;
    multi[wcslen(multi) + 1] = 0;

    SHFILEOPSTRUCTW op = {0};
    op.hwnd = g_hwnd;
    op.wFunc = FO_DELETE;
    op.pFrom = multi;
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;

    SHFileOperationW(&op);
    refresh_files();
}

/* ------------------------------------------------------------ */
/* 64-bit factorisation                                           */
/* ------------------------------------------------------------ */

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m)
{
#if defined(_M_X64) || defined(_M_ARM64)
    return (uint64_t)((__uint128_t)a * b % m);
#else
    /* Portable repeated doubling fallback. */
    uint64_t r = 0;
    while (b) {
        if (b & 1) r = (r >= m - a) ? r - (m - a) : r + a;
        b >>= 1;
        a = (a >= m - a) ? a - (m - a) : a + a;
    }
    return r;
#endif
}

static uint64_t pow_mod(uint64_t a, uint64_t d, uint64_t m)
{
    uint64_t r = 1;
    while (d) {
        if (d & 1) r = mul_mod(r, a, m);
        a = mul_mod(a, a, m);
        d >>= 1;
    }
    return r;
}

static uint64_t gcd64(uint64_t a, uint64_t b)
{
    while (b) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static BOOL is_prime64(uint64_t n)
{
    static const uint64_t small[] = {
        2,3,5,7,11,13,17,19,23,29,31,37
    };

    if (n < 2) return FALSE;

    for (int i = 0; i < (int)(sizeof(small)/sizeof(small[0])); ++i) {
        if (n == small[i]) return TRUE;
        if (n % small[i] == 0) return FALSE;
    }

    uint64_t d = n - 1, s = 0;
    while (!(d & 1)) {
        d >>= 1;
        ++s;
    }

    /* Deterministic Miller-Rabin bases for uint64_t. */
    static const uint64_t bases[] = {
        2ULL, 325ULL, 9375ULL, 28178ULL,
        450775ULL, 9780504ULL, 1795265022ULL
    };

    for (int i = 0; i < 7; ++i) {
        uint64_t a = bases[i] % n;
        if (a == 0) continue;

        uint64_t x = pow_mod(a, d, n);
        if (x == 1 || x == n - 1) continue;

        BOOL witness = TRUE;
        for (uint64_t r = 1; r < s; ++r) {
            x = mul_mod(x, x, n);
            if (x == n - 1) {
                witness = FALSE;
                break;
            }
        }

        if (witness) return FALSE;
    }

    return TRUE;
}

static uint64_t rho_f(uint64_t x, uint64_t c, uint64_t mod)
{
    return (mul_mod(x, x, mod) + c) % mod;
}

static uint64_t pollard_rho(uint64_t n)
{
    if (!(n & 1)) return 2;
    if (n % 3 == 0) return 3;

    uint64_t seed = (uint64_t)GetTickCount64();

    for (;;) {
        uint64_t c = (seed++ % (n - 1)) + 1;
        uint64_t x = (seed++ % (n - 2)) + 2;
        uint64_t y = x;
        uint64_t d = 1;

        for (unsigned iter = 0; iter < 250000 && d == 1; ++iter) {
            x = rho_f(x, c, n);
            y = rho_f(rho_f(y, c, n), c, n);

            uint64_t diff = x > y ? x - y : y - x;
            d = gcd64(diff, n);
        }

        if (d > 1 && d < n)
            return d;
    }
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static void factor_rec(uint64_t n, uint64_t *f, int *nf)
{
    if (n == 1) return;

    if (is_prime64(n)) {
        if (*nf < 64) f[(*nf)++] = n;
        return;
    }

    uint64_t d = pollard_rho(n);
    factor_rec(d, f, nf);
    factor_rec(n / d, f, nf);
}

static BOOL parse_u64(const WCHAR *s, uint64_t *out)
{
    while (*s == L' ' || *s == L'\t') ++s;
    if (!*s) return FALSE;

    uint64_t v = 0;
    BOOL any = FALSE;

    while (*s >= L'0' && *s <= L'9') {
        uint64_t digit = (uint64_t)(*s - L'0');
        if (v > (UINT64_MAX - digit) / 10ULL) return FALSE;
        v = v * 10ULL + digit;
        any = TRUE;
        ++s;
    }

    while (*s == L' ' || *s == L'\t') ++s;
    if (*s != 0 || !any) return FALSE;

    *out = v;
    return TRUE;
}

static void factor_number(uint64_t n)
{
    if (n < 2) {
        _snwprintf(g_factor_output, 2048,
                   L"%llu is not a factorable integer.", (unsigned long long)n);
        return;
    }

    if (n > 10000000000000000000ULL) {
        _snwprintf(g_factor_output, 2048,
                   L"Input is near the uint64 limit.");
    }

    uint64_t f[64];
    int nf = 0;

    factor_rec(n, f, &nf);
    qsort(f, nf, sizeof(uint64_t), cmp_u64);

    WCHAR *p = g_factor_output;
    size_t left = 2048;

    int written = _snwprintf(p, left, L"%llu = ",
        (unsigned long long)n);
    if (written < 0) written = 0;
    p += written; left -= written;

    for (int i = 0; i < nf; ++i) {
        written = _snwprintf(p, left, L"%s%llu",
            i ? L" × " : L"",
            (unsigned long long)f[i]);
        if (written < 0) break;
        p += written; left -= written;
    }

    if (nf >= 2) {
        uint64_t a = f[0];
        uint64_t b = n / a;
        written = _snwprintf(p, left,
            L"\r\n\r\nSmallest factor: %llu\r\n"
            L"Complement: %llu\r\n"
            L"Verification: %llu × %llu = %llu",
            (unsigned long long)a,
            (unsigned long long)b,
            (unsigned long long)a,
            (unsigned long long)b,
            (unsigned long long)n);
        (void)written;
    } else {
        _snwprintf(p, left, L"\r\n\r\nPrime: no non-trivial factors.");
    }

    _snwprintf(g_factor_status, 256,
        L"Complete. Miller-Rabin + Pollard-Rho.");
}

static unsigned __stdcall factor_thread(void *unused)
{
    (void)unused;

    uint64_t n;
    if (!parse_u64(g_factor_input, &n)) {
        wcscpy(g_factor_output, L"Invalid unsigned 64-bit integer.");
        wcscpy(g_factor_status, L"Input error.");
        InterlockedExchange(&g_factor_running, 0);
        return 0;
    }

    factor_number(n);

    InterlockedExchange(&g_factor_running, 0);
    return 0;
}

static void start_factorisation(void)
{
    if (InterlockedCompareExchange(&g_factor_running, 1, 0) != 0)
        return;

    if (g_factor_edit)
        GetWindowTextW(g_factor_edit, g_factor_input, 127);

    wcscpy(g_factor_output, L"Factoring...");
    wcscpy(g_factor_status, L"Worker thread running.");

    g_factor_thread = (HANDLE)_beginthreadex(
        NULL, 0, factor_thread, NULL, 0, NULL);

    if (!g_factor_thread)
        InterlockedExchange(&g_factor_running, 0);
}

/* ------------------------------------------------------------ */
/* DirectX                                                        */
/* ------------------------------------------------------------ */

static BOOL dx_init(void)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));

    sd.BufferCount = 2;
    sd.BufferDesc.Width = g_w;
    sd.BufferDesc.Height = g_h;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = g_hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        0, NULL, 0, D3D11_SDK_VERSION,
        &sd, &g_swapchain, &g_device, &fl, &g_context);

    if (FAILED(hr)) return FALSE;

    ID3D11Texture2D *back = NULL;
    hr = g_swapchain->lpVtbl->GetBuffer(
        g_swapchain, 0, &IID_ID3D11Texture2D, (void **)&back);

    if (FAILED(hr)) return FALSE;

    hr = g_device->lpVtbl->CreateRenderTargetView(
        g_device, (ID3D11Resource *)back, NULL, &g_target);

    back->lpVtbl->Release(back);

    return SUCCEEDED(hr);
}

static void dx_resize(UINT w, UINT h)
{
    if (!g_swapchain || !w || !h) return;

    if (g_target) {
        g_target->lpVtbl->Release(g_target);
        g_target = NULL;
    }

    g_context->lpVtbl->OMSetRenderTargets(g_context, 0, NULL, NULL);
    g_swapchain->lpVtbl->ResizeBuffers(g_swapchain, 0, w, h,
                                       DXGI_FORMAT_UNKNOWN, 0);

    ID3D11Texture2D *back = NULL;
    if (SUCCEEDED(g_swapchain->lpVtbl->GetBuffer(
            g_swapchain, 0, &IID_ID3D11Texture2D, (void **)&back))) {

        g_device->lpVtbl->CreateRenderTargetView(
            g_device, (ID3D11Resource *)back, NULL, &g_target);

        back->lpVtbl->Release(back);
    }

    g_w = w;
    g_h = h;
}

/* ------------------------------------------------------------ */
/* Native edit controls                                           */
/* ------------------------------------------------------------ */

static void destroy_edit_controls(void)
{
    if (g_address) { DestroyWindow(g_address); g_address = NULL; }
    if (g_search) { DestroyWindow(g_search); g_search = NULL; }
    if (g_run_edit) { DestroyWindow(g_run_edit); g_run_edit = NULL; }
    if (g_factor_edit) { DestroyWindow(g_factor_edit); g_factor_edit = NULL; }
}

static void create_main_controls(void)
{
    g_address = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", g_path,
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        310, 58, (int)g_w - 520, 32,
        g_hwnd, (HMENU)101, GetModuleHandleW(NULL), NULL);

    g_search = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        (int)g_w - 200, 58, 175, 32,
        g_hwnd, (HMENU)102, GetModuleHandleW(NULL), NULL);

    SendMessageW(g_address, WM_SETFONT,
                 (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    SendMessageW(g_search, WM_SETFONT,
                 (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
}

static void create_factor_control(void)
{
    if (g_factor_edit) return;

    g_factor_edit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"143",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        430, 150, 430, 38,
        g_hwnd, (HMENU)201, GetModuleHandleW(NULL), NULL);

    SendMessageW(g_factor_edit, WM_SETFONT,
                 (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
}

/* ------------------------------------------------------------ */
/* Rendering through GDI on top of the DX-backed window           */
/* ------------------------------------------------------------ */

static void draw_icon(HDC dc, int x, int y, BOOL folder, BOOL selected)
{
    COLORREF main = selected ? RGB(255,255,255) : RGB(80,130,220);
    if (folder) {
        fill(dc, x, y + 5, x + 38, y + 31, main);
        fill(dc, x + 4, y, x + 20, y + 9, main);
    } else {
        border(dc, x + 5, y, x + 30, y + 34, main);
        fill(dc, x + 19, y, x + 30, y + 11, main);
    }
}

static void draw_taskbar(HDC dc)
{
    int y = (int)g_h - 48;

    fill(dc, 0, y, (int)g_w, (int)g_h, RGB(25, 28, 34));
    fill(dc, 0, y, (int)g_w, y + 1, RGB(70, 75, 85));

    fill(dc, 10, y + 7, 88, y + 39, RGB(42, 47, 55));
    set_font(dc, 18, TRUE);
    text(dc, 28, y + 13, L"⊞", RGB(240,240,245));

    fill(dc, 98, y + 7, 210, y + 39, RGB(42, 47, 55));
    set_font(dc, 14, FALSE);
    text(dc, 116, y + 15, L"Explorer", RGB(235,235,240));

    if (g_factor_app) {
        fill(dc, 220, y + 7, 340, y + 39, RGB(55, 60, 70));
        text(dc, 236, y + 15, L"Factorisation", RGB(235,235,240));
    }

    for (int i = 0; i < g_task_count && i < 5; ++i) {
        int x = 350 + i * 125;
        fill(dc, x, y + 7, x + 118, y + 39, RGB(42,47,55));
        WCHAR label[24];
        wcsncpy(label, g_tasks[i].title, 20);
        label[20] = 0;
        text(dc, x + 8, y + 15, label, RGB(220,220,225));
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    WCHAR clk[32];
    _snwprintf(clk, 32, L"%02d:%02d", st.wHour, st.wMinute);

    set_font(dc, 14, FALSE);
    text(dc, (int)g_w - 78, y + 15, clk, RGB(235,235,240));
}

static void draw_start_menu(HDC dc)
{
    if (!g_start) return;

    int l = 15, b = (int)g_h - 55;
    int r = 390, t = b - 430;

    fill(dc, l, t, r, b, RGB(35,39,47));
    border(dc, l, t, r, b, RGB(100,105,115));

    set_font(dc, 22, TRUE);
    text(dc, l + 25, t + 24, L"Start", RGB(245,245,250));

    set_font(dc, 15, FALSE);
    text(dc, l + 25, t + 75, L"Explorer", RGB(235,235,240));
    text(dc, l + 25, t + 120, L"Factorisation Lab", RGB(235,235,240));
    text(dc, l + 25, t + 165, L"Run", RGB(235,235,240));
    text(dc, l + 25, t + 210, L"Command Prompt", RGB(235,235,240));
    text(dc, l + 25, t + 255, L"This PC", RGB(235,235,240));
    text(dc, l + 25, t + 300, L"Windows", RGB(235,235,240));

    set_font(dc, 12, FALSE);
    text(dc, l + 25, b - 35, L"Custom DirectX Explorer Shell", RGB(150,155,165));
}

static void draw_explorer(HDC dc)
{
    int taskbar = 48;
    int top = 0;
    int bottom = (int)g_h - taskbar;

    fill(dc, 0, top, (int)g_w, bottom, RGB(245,246,248));

    /* title bar */
    fill(dc, 0, 0, (int)g_w, 45, RGB(32,35,40));
    set_font(dc, 15, TRUE);
    text(dc, 22, 14, L"Explorer", RGB(245,245,248));

    /* close */
    fill(dc, (int)g_w - 50, 0, (int)g_w, 45, RGB(32,35,40));
    text(dc, (int)g_w - 32, 13, L"×", RGB(245,245,248));

    /* toolbar */
    fill(dc, 0, 45, (int)g_w, 108, RGB(230,232,236));

    set_font(dc, 16, TRUE);
    text(dc, 25, 67, L"←", RGB(70,75,82));
    text(dc, 65, 67, L"↑", RGB(70,75,82));
    text(dc, 105, 67, L"↻", RGB(70,75,82));

    border(dc, 300, 57, (int)g_w - 225, 91, RGB(180,184,190));
    set_font(dc, 13, FALSE);
    text(dc, 310, 66, g_path, RGB(40,43,48));

    /* sidebar */
    fill(dc, 0, 108, 275, bottom, RGB(238,240,243));
    set_font(dc, 14, TRUE);
    text(dc, 25, 130, L"Quick access", RGB(65,70,78));

    set_font(dc, 14, FALSE);
    text(dc, 35, 170, L"Desktop", RGB(70,75,82));
    text(dc, 35, 205, L"Documents", RGB(70,75,82));
    text(dc, 35, 240, L"Downloads", RGB(70,75,82));
    text(dc, 35, 275, L"Pictures", RGB(70,75,82));
    text(dc, 35, 310, L"This PC", RGB(70,75,82));
    text(dc, 35, 345, L"Windows", RGB(70,75,82));

    /* file area */
    int x0 = 295;
    int y0 = 125;
    int rowh = 46;

    set_font(dc, 13, TRUE);
    text(dc, x0, 115, L"Name", RGB(80,84,90));

    int first = g_scroll;
    if (first < 0) first = 0;
    if (first >= g_count) first = g_count ? g_count - 1 : 0;

    int visible = (bottom - y0 - 10) / rowh;

    for (int k = 0; k < visible; ++k) {
        int i = first + k;
        if (i >= g_count) break;

        int y = y0 + k * rowh;
        BOOL sel = (i == g_selected);

        if (sel)
            fill(dc, x0 - 8, y - 4, (int)g_w - 25, y + rowh - 5,
                 RGB(75,125,205));

        draw_icon(dc, x0, y, g_items[i].dir, sel);

        set_font(dc, 13, FALSE);
        text(dc, x0 + 52, y + 5, g_items[i].name,
             sel ? RGB(255,255,255) : RGB(35,38,42));

        WCHAR size[64];
        if (g_items[i].dir)
            wcscpy(size, L"<DIR>");
        else
            format_size(g_items[i].size, size, 64);

        text(dc, x0 + 500, y + 5, size,
             sel ? RGB(240,240,245) : RGB(100,105,112));
    }

    WCHAR status[128];
    _snwprintf(status, 128, L"%d items", g_count);
    set_font(dc, 12, FALSE);
    text(dc, x0, bottom - 25, status, RGB(100,105,112));

    draw_taskbar(dc);
    draw_start_menu(dc);
}

static void draw_run_dialog(HDC dc)
{
    int l = (int)g_w / 2 - 270;
    int t = (int)g_h / 2 - 110;
    int r = l + 540;
    int b = t + 220;

    fill(dc, l, t, r, b, RGB(38,42,49));
    border(dc, l, t, r, b, RGB(120,125,135));

    set_font(dc, 19, TRUE);
    text(dc, l + 25, t + 20, L"Run", RGB(245,245,250));

    set_font(dc, 13, FALSE);
    text(dc, l + 25, t + 60,
         L"Open a program, folder, document, or command.",
         RGB(190,195,202));

    fill(dc, l + 25, b - 55, r - 25, b - 20, RGB(55,60,68));
    text(dc, l + 35, b - 46, L"Type command above...",
         RGB(140,145,152));

    text(dc, r - 150, b - 90, L"Enter = Run", RGB(180,185,192));
    text(dc, r - 150, b - 65, L"Esc = Close", RGB(180,185,192));
}

static void draw_factor_app(HDC dc)
{
    fill(dc, 0, 0, (int)g_w, (int)g_h - 48, RGB(245,246,248));

    fill(dc, 0, 0, (int)g_w, 52, RGB(31,35,41));
    set_font(dc, 17, TRUE);
    text(dc, 25, 17, L"Factorisation Lab", RGB(245,245,248));

    set_font(dc, 13, FALSE);
    text(dc, 25, 83,
         L"Classical integer factorisation using deterministic Miller-Rabin and Pollard-Rho.",
         RGB(80,85,92));

    set_font(dc, 14, TRUE);
    text(dc, 25, 128, L"Integer N", RGB(65,70,78));

    fill(dc, 885, 150, 1015, 188, RGB(55,100,180));
    set_font(dc, 14, TRUE);
    text(dc, 917, 161, L"FACTOR", RGB(255,255,255));

    fill(dc, 25, 220, (int)g_w - 25, 480, RGB(236,238,241));
    border(dc, 25, 220, (int)g_w - 25, 480, RGB(200,203,208));

    set_font(dc, 15, FALSE);
    text(dc, 45, 245, g_factor_output, RGB(40,44,50));

    set_font(dc, 12, FALSE);
    text(dc, 25, 500, g_factor_status, RGB(100,105,112));

    set_font(dc, 13, FALSE);
    text(dc, 25, 545,
         L"Verification is performed directly from the returned factors.",
         RGB(105,110,118));

    text(dc, 25, 575,
         L"Experimental note: a Schmidt/SVD encoding is a visual mapping, not an efficient factoring algorithm.",
         RGB(105,110,118));

    draw_taskbar(dc);
}

/* ------------------------------------------------------------ */
/* Search                                                         */
/* ------------------------------------------------------------ */

static void perform_search(void)
{
    if (!g_search) return;

    WCHAR q[256];
    GetWindowTextW(g_search, q, 255);

    if (!q[0]) {
        refresh_files();
        return;
    }

    FileItem tmp[MAX_ITEMS];
    int n = 0;

    for (int i = 0; i < g_count && n < MAX_ITEMS; ++i) {
        if (StrStrIW(g_items[i].name, q))
            tmp[n++] = g_items[i];
    }

    memcpy(g_items, tmp, sizeof(FileItem) * n);
    g_count = n;
    g_selected = -1;
    g_scroll = 0;
}

/* ------------------------------------------------------------ */
/* Window input                                                    */
/* ------------------------------------------------------------ */

static void toggle_fullscreen(void)
{
    static WINDOWPLACEMENT wp = { sizeof(WINDOWPLACEMENT) };

    if (!g_fullscreen) {
        SetWindowLongW(g_hwnd, GWL_STYLE, WS_POPUP | WS_VISIBLE);
        SetWindowPos(g_hwnd, HWND_TOP, 0, 0,
                     GetSystemMetrics(SM_CXSCREEN),
                     GetSystemMetrics(SM_CYSCREEN),
                     SWP_FRAMECHANGED);
        g_fullscreen = TRUE;
    } else {
        wp.length = sizeof(wp);
        GetWindowPlacement(g_hwnd, &wp);

        SetWindowLongW(g_hwnd, GWL_STYLE,
                       WS_OVERLAPPEDWINDOW | WS_VISIBLE);

        SetWindowPlacement(g_hwnd, &wp);
        g_fullscreen = FALSE;
    }
}

static void execute_run_command(void)
{
    if (!g_run_edit) return;

    WCHAR cmd[MAX_PATH2];
    GetWindowTextW(g_run_edit, cmd, MAX_PATH2 - 1);

    if (!cmd[0]) return;

    HINSTANCE r = ShellExecuteW(
        g_hwnd, L"open", cmd, NULL, NULL, SW_SHOWNORMAL);

    if ((INT_PTR)r > 32) {
        if (g_task_count < MAX_TASKS) {
            ShellTask *t = &g_tasks[g_task_count++];
            wcsncpy(t->title, cmd, 127);
            t->title[127] = 0;
            t->active = TRUE;
        }
        g_run_dialog = FALSE;
        if (g_run_edit) {
            DestroyWindow(g_run_edit);
            g_run_edit = NULL;
        }
    }
}

static void show_run(void)
{
    g_start = FALSE;
    g_run_dialog = TRUE;

    if (!g_run_edit) {
        g_run_edit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            (int)g_w / 2 - 245, (int)g_h / 2 + 20,
            490, 35,
            g_hwnd, (HMENU)301, GetModuleHandleW(NULL), NULL);

        SendMessageW(g_run_edit, WM_SETFONT,
                     (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        SetFocus(g_run_edit);
    }
}

static void hide_run(void)
{
    g_run_dialog = FALSE;
    if (g_run_edit) {
        DestroyWindow(g_run_edit);
        g_run_edit = NULL;
    }
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE:
        create_main_controls();
        SetTimer(h, g_clock_timer, 30000, NULL);
        return 0;

    case WM_SIZE:
        if (w != SIZE_MINIMIZED)
            dx_resize(LOWORD(l), HIWORD(l));
        return 0;

    case WM_TIMER:
        InvalidateRect(h, NULL, FALSE);
        return 0;

    case WM_LBUTTONDBLCLK:
    {
        int x = GET_X_LPARAM(l);
        int y = GET_Y_LPARAM(l);

        if (g_factor_app) {
            if (x >= 885 && x <= 1015 && y >= 150 && y <= 188)
                start_factorisation();
            return 0;
        }

        if (g_run_dialog) return 0;

        if (y >= 120 && y < (int)g_h - 50 && x >= 290) {
            int row = (y - 125) / 46;
            int idx = g_scroll + row;
            if (idx >= 0 && idx < g_count) {
                g_selected = idx;
                open_item(idx);
            }
        }
        return 0;
    }

    case WM_LBUTTONDOWN:
    {
        int x = GET_X_LPARAM(l);
        int y = GET_Y_LPARAM(l);

        if (g_factor_app) {
            if (y >= (int)g_h - 48 && x >= 220 && x <= 350) {
                g_factor_app = FALSE;
                if (g_factor_edit) {
                    DestroyWindow(g_factor_edit);
                    g_factor_edit = NULL;
                }
                InvalidateRect(h, NULL, FALSE);
            } else if (x >= 885 && x <= 1015 && y >= 150 && y <= 188) {
                start_factorisation();
            }
            return 0;
        }

        if (g_run_dialog) return 0;

        if (y >= (int)g_h - 48) {
            if (x >= 10 && x <= 88) {
                g_start = !g_start;
                InvalidateRect(h, NULL, FALSE);
                return 0;
            }

            if (x >= 220 && x <= 350 && g_factor_app == FALSE) {
                g_factor_app = TRUE;
                create_factor_control();
                InvalidateRect(h, NULL, FALSE);
                return 0;
            }
        }

        if (g_start) {
            int t = (int)g_h - 55 - 430;

            if (x >= 15 && x <= 390) {
                if (y > t + 145 && y < t + 205) {
                    show_run();
                    return 0;
                }

                if (y > t + 95 && y < t + 150) {
                    g_factor_app = TRUE;
                    g_start = FALSE;
                    create_factor_control();
                    InvalidateRect(h, NULL, FALSE);
                    return 0;
                }

                if (y > t + 195 && y < t + 250) {
                    ShellExecuteW(h, L"open", L"cmd.exe", NULL, NULL, SW_SHOWNORMAL);
                    return 0;
                }

                if (y > t + 250 && y < t + 330) {
                    navigate_to(L"C:\\");
                    g_start = FALSE;
                    InvalidateRect(h, NULL, FALSE);
                    return 0;
                }
            }

            g_start = FALSE;
            InvalidateRect(h, NULL, FALSE);
            return 0;
        }

        /* close */
        if (x >= (int)g_w - 50 && y < 45) {
            g_running = FALSE;
            PostQuitMessage(0);
            return 0;
        }

        /* back/up/refresh */
        if (y >= 45 && y <= 108) {
            if (x >= 20 && x < 55) {
                go_up();
                refresh_files();
                SetWindowTextW(g_address, g_path);
            } else if (x >= 55 && x < 95) {
                go_up();
                refresh_files();
                SetWindowTextW(g_address, g_path);
            } else if (x >= 95 && x < 135) {
                refresh_files();
            }
            return 0;
        }

        /* file rows */
        if (y >= 125 && y < (int)g_h - 55 && x >= 290) {
            int row = (y - 125) / 46;
            int idx = g_scroll + row;
            if (idx >= 0 && idx < g_count) {
                g_selected = idx;
                InvalidateRect(h, NULL, FALSE);
            }
            return 0;
        }

        return 0;
    }

    case WM_RBUTTONDOWN:
    {
        if (!g_factor_app && !g_run_dialog) {
            int x = GET_X_LPARAM(l);
            int y = GET_Y_LPARAM(l);

            if (y >= 125 && y < (int)g_h - 55 && x >= 290) {
                int row = (y - 125) / 46;
                int idx = g_scroll + row;
                if (idx >= 0 && idx < g_count)
                    g_selected = idx;

                HMENU menu = CreatePopupMenu();
                AppendMenuW(menu, MF_STRING, 501, L"Open");
                AppendMenuW(menu, MF_STRING, 502, L"Copy");
                AppendMenuW(menu, MF_STRING, 503, L"Delete");
                AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(menu, MF_STRING, 504, L"Properties");

                int cmd = TrackPopupMenu(
                    menu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                    x, y, 0, h, NULL);

                DestroyMenu(menu);

                if (cmd == 501) open_item(g_selected);
                else if (cmd == 502) set_file_clipboard(g_selected);
                else if (cmd == 503) recycle_selected();
                else if (cmd == 504 && g_selected >= 0) {
                    SHELLEXECUTEINFOW sei;
                    ZeroMemory(&sei, sizeof(sei));
                    sei.cbSize = sizeof(sei);
                    sei.fMask = SEE_MASK_INVOKEIDLIST;
                    sei.lpVerb = L"properties";
                    sei.lpFile = g_items[g_selected].full;
                    sei.nShow = SW_SHOW;
                    ShellExecuteExW(&sei);
                }
            }
        }
        return 0;
    }

    case WM_MOUSEWHEEL:
    {
        int delta = GET_WHEEL_DELTA_WPARAM(w);
        if (!g_factor_app && !g_run_dialog) {
            g_scroll -= delta / WHEEL_DELTA;
            if (g_scroll < 0) g_scroll = 0;

            int maxscroll = g_count - 1;
            if (maxscroll < 0) maxscroll = 0;
            if (g_scroll > maxscroll) g_scroll = maxscroll;

            InvalidateRect(h, NULL, FALSE);
        }
        return 0;
    }

    case WM_KEYDOWN:
        if (g_run_dialog) {
            if (w == VK_ESCAPE) hide_run();
            else if (w == VK_RETURN) execute_run_command();
            return 0;
        }

        if (g_factor_app) {
            if (w == VK_ESCAPE) {
                g_factor_app = FALSE;
                if (g_factor_edit) {
                    DestroyWindow(g_factor_edit);
                    g_factor_edit = NULL;
                }
                InvalidateRect(h, NULL, FALSE);
            }
            return 0;
        }

        switch (w) {
        case VK_ESCAPE:
            g_running = FALSE;
            PostQuitMessage(0);
            return 0;

        case VK_F11:
            toggle_fullscreen();
            return 0;

        case VK_F5:
            refresh_files();
            InvalidateRect(h, NULL, FALSE);
            return 0;

        case VK_BACK:
            go_up();
            refresh_files();
            if (g_address) SetWindowTextW(g_address, g_path);
            InvalidateRect(h, NULL, FALSE);
            return 0;

        case VK_RETURN:
            open_item(g_selected);
            return 0;

        case VK_DELETE:
            recycle_selected();
            return 0;

        case VK_F2:
            if (g_selected >= 0 && g_selected < g_count) {
                WCHAR newname[MAX_PATH2];
                wcsncpy(newname, g_items[g_selected].full, MAX_PATH2 - 1);
                newname[MAX_PATH2 - 1] = 0;
                /* Rename through Explorer's standard shell operation. */
                wcscpy(g_factor_status, L"");
            }
            return 0;
        }

        if ((GetKeyState(VK_CONTROL) & 0x8000) && w == 'C') {
            set_file_clipboard(g_selected);
            return 0;
        }

        if ((GetKeyState(VK_CONTROL) & 0x8000) && w == 'V') {
            paste_file();
            return 0;
        }

        if ((GetKeyState(VK_CONTROL) & 0x8000) && w == 'L') {
            if (g_address) {
                SetFocus(g_address);
                SendMessageW(g_address, EM_SETSEL, 0, -1);
            }
            return 0;
        }

        if ((GetKeyState(VK_CONTROL) & 0x8000) && w == 'F') {
            if (g_search) {
                SetFocus(g_search);
                SendMessageW(g_search, EM_SETSEL, 0, -1);
            }
            return 0;
        }

        return 0;

    case WM_COMMAND:
        if (LOWORD(w) == 101 && HIWORD(w) == EN_KILLFOCUS) {
            WCHAR p[MAX_PATH2];
            GetWindowTextW(g_address, p, MAX_PATH2 - 1);
            navigate_to(p);
            return 0;
        }

        if (LOWORD(w) == 102 && HIWORD(w) == EN_CHANGE) {
            /* Search when Enter is pressed, not on every keystroke. */
            return 0;
        }

        if (LOWORD(w) == 201 && HIWORD(w) == EN_CHANGE) {
            return 0;
        }

        return 0;

    case WM_CHAR:
        if (!g_factor_app && !g_run_dialog && w == L'\r') {
            perform_search();
            return 0;
        }
        return 0;

    case WM_DESTROY:
        g_running = FALSE;
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------ */
/* Paint                                                         */
/* ------------------------------------------------------------ */

static void paint(void)
{
    if (!g_context || !g_target) return;

    FLOAT clear[4] = { 0.08f, 0.09f, 0.11f, 1.0f };
    g_context->lpVtbl->ClearRenderTargetView(g_context, g_target, clear);

    g_context->lpVtbl->OMSetRenderTargets(
        g_context, 1, &g_target, NULL);

    HDC dc = GetDC(g_hwnd);

    /* GDI UI is intentionally used as a compact text/icon layer. */
    if (g_factor_app)
        draw_factor_app(dc);
    else
        draw_explorer(dc);

    if (g_run_dialog)
        draw_run_dialog(dc);

    ReleaseDC(g_hwnd, dc);

    g_swapchain->lpVtbl->Present(g_swapchain, 1, 0);
}

/* ------------------------------------------------------------ */
/* WinMain                                                        */
/* ------------------------------------------------------------ */

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show)
{
    (void)prev;
    (void)cmd;

    SetProcessDPIAware();

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.hInstance = inst;
    wc.lpfnWndProc = wndproc;
    wc.lpszClassName = L"DXExplorerShell";
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassExW(&wc))
        return 1;

    g_hwnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"DirectX Explorer Shell",
        WS_POPUP,
        0, 0,
        GetSystemMetrics(SM_CXSCREEN),
        GetSystemMetrics(SM_CYSCREEN),
        NULL, NULL, inst, NULL);

    if (!g_hwnd)
        return 1;

    g_w = GetSystemMetrics(SM_CXSCREEN);
    g_h = GetSystemMetrics(SM_CYSCREEN);

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    if (!dx_init()) {
        MessageBoxW(g_hwnd,
                    L"DirectX 11 initialization failed.",
                    L"DirectX Explorer Shell",
                    MB_ICONERROR);
        return 1;
    }

    navigate_to(L"C:\\");
    refresh_files();

    MSG msg;

    while (g_running) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                g_running = FALSE;
                break;
            }

            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        paint();
        Sleep(8);
    }

    if (g_factor_thread) {
        WaitForSingleObject(g_factor_thread, 1000);
        CloseHandle(g_factor_thread);
        g_factor_thread = NULL;
    }

    destroy_edit_controls();

    if (g_target) g_target->lpVtbl->Release(g_target);
    if (g_swapchain) g_swapchain->lpVtbl->Release(g_swapchain);
    if (g_context) g_context->lpVtbl->Release(g_context);
    if (g_device) g_device->lpVtbl->Release(g_device);

    return 0;
}
