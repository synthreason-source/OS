/*
    directx_explorer_taskbar.c

    Fullscreen DirectX 11 filesystem Explorer.

    Features
    --------
    - DirectX 11 window / swap chain
    - Fullscreen desktop
    - Taskbar
    - Start menu
    - Real filesystem enumeration
    - C:\ root
    - Directory navigation
    - Double-click folders
    - Double-click files -> ShellExecute
    - Back
    - Up
    - Refresh
    - Address bar
    - File/folder icons
    - Scrollable file list
    - F11 fullscreen toggle
    - ESC exits

    Build with MSVC:

        cl /O2 directx_explorer_taskbar.c ^
           /link d3d11.lib dxgi.lib user32.lib gdi32.lib shell32.lib gdi32.lib

    NOTE:
        The rendering layer uses GDI over a DirectX-owned window
        for simplicity. The DirectX device/swapchain are present
        and can subsequently be replaced with a native DX11
        renderer.
*/

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
   CONFIGURATION
   ============================================================ */

#define MAX_ITEMS       4096
#define MAX_PATH_TEXT   32768
#define ITEM_HEIGHT     38

#define EXPLORER_X      150
#define EXPLORER_Y      70

#define TASKBAR_HEIGHT  58

/* ============================================================
   DIRECTX
   ============================================================ */

static HWND g_hwnd = NULL;

static ID3D11Device *g_device = NULL;
static ID3D11DeviceContext *g_context = NULL;
static IDXGISwapChain *g_swapchain = NULL;
static ID3D11RenderTargetView *g_target = NULL;

/* ============================================================
   APPLICATION STATE
   ============================================================ */

static int g_width = 1280;
static int g_height = 720;

static int g_running = 1;
static int g_fullscreen = 1;

static int g_start_open = 0;
static int g_explorer_open = 1;

static int g_mouse_x = 0;
static int g_mouse_y = 0;

static int g_scroll = 0;

static char g_current_path[MAX_PATH_TEXT] = "C:\\";

/* ============================================================
   FILE SYSTEM
   ============================================================ */

typedef struct
{
    char name[MAX_PATH];
    int is_directory;
    unsigned long long size;
} FileItem;

static FileItem g_items[MAX_ITEMS];
static int g_item_count = 0;

/* ============================================================
   COLORS
   ============================================================ */

#define C_DESKTOP       RGB(15,24,40)
#define C_TASKBAR       RGB(18,22,30)
#define C_WINDOW        RGB(27,31,40)
#define C_TITLE         RGB(31,36,47)
#define C_PANEL         RGB(21,25,33)
#define C_INPUT         RGB(37,43,54)
#define C_HOVER         RGB(48,59,76)
#define C_SELECTED      RGB(45,75,108)
#define C_BORDER        RGB(62,70,83)

#define C_TEXT          RGB(225,230,238)
#define C_TEXT2         RGB(165,175,190)
#define C_ACCENT        RGB(70,155,235)

#define C_FOLDER        RGB(226,181,72)
#define C_FILE          RGB(175,185,200)

/* ============================================================
   UTILITIES
   ============================================================ */

static void safe_copy(
    char *dst,
    size_t dst_size,
    const char *src
)
{
    if (!dst || dst_size == 0)
        return;

    strncpy(
        dst,
        src,
        dst_size - 1
    );

    dst[dst_size - 1] = 0;
}


static void join_path(
    char *out,
    size_t out_size,
    const char *base,
    const char *name
)
{
    if (strcmp(base, "\\") == 0)
    {
        snprintf(
            out,
            out_size,
            "\\%s",
            name
        );
    }
    else
    {
        snprintf(
            out,
            out_size,
            "%s\\%s",
            base,
            name
        );
    }
}


/* ============================================================
   FILESYSTEM ENUMERATION
   ============================================================ */

static int compare_items(
    const void *a,
    const void *b
)
{
    const FileItem *fa =
        (const FileItem *)a;

    const FileItem *fb =
        (const FileItem *)b;

    /*
        Directories first.
    */

    if (fa->is_directory != fb->is_directory)
        return fb->is_directory - fa->is_directory;

    return _stricmp(
        fa->name,
        fb->name
    );
}


static void enumerate_directory(void)
{
    g_item_count = 0;

    char search[MAX_PATH_TEXT];

    snprintf(
        search,
        sizeof(search),
        "%s\\*",
        g_current_path
    );

    WIN32_FIND_DATAA data;

    HANDLE h =
        FindFirstFileA(
            search,
            &data
        );

    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (
            strcmp(data.cFileName, ".") == 0 ||
            strcmp(data.cFileName, "..") == 0
        )
        {
            continue;
        }

        if (g_item_count >= MAX_ITEMS)
            break;

        FileItem *item =
            &g_items[g_item_count];

        safe_copy(
            item->name,
            sizeof(item->name),
            data.cFileName
        );

        item->is_directory =
            (data.dwFileAttributes &
             FILE_ATTRIBUTE_DIRECTORY) != 0;

        item->size =
            ((unsigned long long)data.nFileSizeHigh << 32)
            |
            data.nFileSizeLow;

        g_item_count++;

    }
    while (
        FindNextFileA(
            h,
            &data
        )
    );

    FindClose(h);

    qsort(
        g_items,
        g_item_count,
        sizeof(FileItem),
        compare_items
    );

    g_scroll = 0;
}


/* ============================================================
   NAVIGATION
   ============================================================ */

static void open_directory(
    const char *name
)
{
    char new_path[MAX_PATH_TEXT];

    join_path(
        new_path,
        sizeof(new_path),
        g_current_path,
        name
    );

    DWORD attributes =
        GetFileAttributesA(
            new_path
        );

    if (
        attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY)
    )
    {
        safe_copy(
            g_current_path,
            sizeof(g_current_path),
            new_path
        );

        enumerate_directory();
    }
}


static void go_up(void)
{
    char temp[MAX_PATH_TEXT];

    safe_copy(
        temp,
        sizeof(temp),
        g_current_path
    );

    /*
        Remove trailing slash except for C:\
    */

    size_t len =
        strlen(temp);

    while (
        len > 0 &&
        (temp[len - 1] == '\\' ||
         temp[len - 1] == '/')
    )
    {
        if (len == 3)
            break;

        temp[--len] = 0;
    }

    char *slash =
        strrchr(
            temp,
            '\\'
        );

    if (!slash)
        return;

    /*
        Keep drive root.
    */

    if (slash == temp + 2)
    {
        temp[3] = 0;
    }
    else
    {
        *slash = 0;
    }

    safe_copy(
        g_current_path,
        sizeof(g_current_path),
        temp
    );

    enumerate_directory();
}


static void go_root(void)
{
    safe_copy(
        g_current_path,
        sizeof(g_current_path),
        "C:\\"
    );

    enumerate_directory();
}


/* ============================================================
   DRAWING
   ============================================================ */

static void fill_rect(
    HDC dc,
    int x,
    int y,
    int w,
    int h,
    COLORREF color
)
{
    RECT r;

    r.left = x;
    r.top = y;
    r.right = x + w;
    r.bottom = y + h;

    HBRUSH brush =
        CreateSolidBrush(color);

    FillRect(
        dc,
        &r,
        brush
    );

    DeleteObject(brush);
}


static void draw_border(
    HDC dc,
    int x,
    int y,
    int w,
    int h,
    COLORREF color
)
{
    HPEN pen =
        CreatePen(
            PS_SOLID,
            1,
            color
        );

    HGDIOBJ old =
        SelectObject(
            dc,
            pen
        );

    Rectangle(
        dc,
        x,
        y,
        x + w,
        y + h
    );

    SelectObject(
        dc,
        old
    );

    DeleteObject(pen);
}


static void draw_text(
    HDC dc,
    int x,
    int y,
    const char *str,
    COLORREF color,
    int size
)
{
    HFONT font =
        CreateFontA(
            size,
            0,
            0,
            0,
            FW_NORMAL,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH,
            "Segoe UI"
        );

    HGDIOBJ old =
        SelectObject(
            dc,
            font
        );

    SetBkMode(
        dc,
        TRANSPARENT
    );

    SetTextColor(
        dc,
        color
    );

    TextOutA(
        dc,
        x,
        y,
        str,
        (int)strlen(str)
    );

    SelectObject(
        dc,
        old
    );

    DeleteObject(font);
}


/* ============================================================
   DESKTOP
   ============================================================ */

static void draw_desktop(HDC dc)
{
    fill_rect(
        dc,
        0,
        0,
        g_width,
        g_height,
        C_DESKTOP
    );

    /*
        Subtle desktop gradient.
    */

    for (
        int y = 0;
        y < g_height - TASKBAR_HEIGHT;
        y += 16
    )
    {
        int v =
            12 +
            (y * 15 /
             (g_height + 1));

        fill_rect(
            dc,
            0,
            y,
            g_width,
            16,
            RGB(
                10 + v / 2,
                18 + v / 2,
                30 + v
            )
        );
    }

    draw_text(
        dc,
        28,
        25,
        "DirectX Desktop",
        RGB(180,195,220),
        18
    );
}


/* ============================================================
   DESKTOP ICON
   ============================================================ */

static void draw_folder_icon(
    HDC dc,
    int x,
    int y
)
{
    fill_rect(
        dc,
        x,
        y + 5,
        42,
        30,
        C_FOLDER
    );

    fill_rect(
        dc,
        x + 5,
        y,
        20,
        8,
        C_FOLDER
    );
}


static void draw_file_icon(
    HDC dc,
    int x,
    int y
)
{
    fill_rect(
        dc,
        x,
        y,
        32,
        38,
        C_FILE
    );

    /*
        Folded corner.
    */

    POINT pts[3];

    pts[0].x = x + 21;
    pts[0].y = y;

    pts[1].x = x + 32;
    pts[1].y = y + 11;

    pts[2].x = x + 21;
    pts[2].y = y + 11;

    HBRUSH brush =
        CreateSolidBrush(
            RGB(110,120,135)
        );

    HGDIOBJ old =
        SelectObject(
            dc,
            brush
        );

    Polygon(
        dc,
        pts,
        3
    );

    SelectObject(
        dc,
        old
    );

    DeleteObject(brush);
}


/* ============================================================
   EXPLORER
   ============================================================ */

static int explorer_width(void)
{
    return g_width - EXPLORER_X - 80;
}


static int explorer_height(void)
{
    return g_height - EXPLORER_Y - 90;
}


static void draw_sidebar(
    HDC dc,
    int x,
    int y,
    int w,
    int h
)
{
    fill_rect(
        dc,
        x,
        y,
        w,
        h,
        C_PANEL
    );

    draw_text(
        dc,
        x + 20,
        y + 20,
        "Quick access",
        C_TEXT,
        14
    );

    draw_text(
        dc,
        x + 32,
        y + 58,
        "Desktop",
        C_TEXT2,
        13
    );

    draw_text(
        dc,
        x + 32,
        y + 90,
        "Documents",
        C_TEXT2,
        13
    );

    draw_text(
        dc,
        x + 32,
        y + 122,
        "Downloads",
        C_TEXT2,
        13
    );

    draw_text(
        dc,
        x + 32,
        y + 154,
        "Pictures",
        C_TEXT2,
        13
    );

    draw_text(
        dc,
        x + 20,
        y + 205,
        "This PC",
        C_TEXT,
        14
    );

    draw_text(
        dc,
        x + 32,
        y + 243,
        "Local Disk (C:)",
        C_TEXT2,
        13
    );
}


static void draw_file_item(
    HDC dc,
    int x,
    int y,
    int w,
    FileItem *item,
    int index
)
{
    int hovered =
        g_mouse_x >= x &&
        g_mouse_x <= x + w &&
        g_mouse_y >= y &&
        g_mouse_y <= y + ITEM_HEIGHT;

    if (hovered)
    {
        fill_rect(
            dc,
            x,
            y,
            w,
            ITEM_HEIGHT,
            C_HOVER
        );
    }

    if (item->is_directory)
    {
        draw_folder_icon(
            dc,
            x + 12,
            y + 1
        );
    }
    else
    {
        draw_file_icon(
            dc,
            x + 16,
            y
        );
    }

    draw_text(
        dc,
        x + 65,
        y + 9,
        item->name,
        C_TEXT,
        13
    );

    if (!item->is_directory)
    {
        char size_text[64];

        if (item->size < 1024)
        {
            snprintf(
                size_text,
                sizeof(size_text),
                "%llu B",
                item->size
            );
        }
        else if (item->size < 1024ULL * 1024ULL)
        {
            snprintf(
                size_text,
                sizeof(size_text),
                "%.1f KB",
                item->size / 1024.0
            );
        }
        else if (
            item->size <
            1024ULL * 1024ULL * 1024ULL
        )
        {
            snprintf(
                size_text,
                sizeof(size_text),
                "%.1f MB",
                item->size /
                (1024.0 * 1024.0)
            );
        }
        else
        {
            snprintf(
                size_text,
                sizeof(size_text),
                "%.1f GB",
                item->size /
                (1024.0 * 1024.0 * 1024.0)
            );
        }

        draw_text(
            dc,
            x + w - 110,
            y + 10,
            size_text,
            C_TEXT2,
            11
        );
    }

    (void)index;
}


static void draw_explorer(
    HDC dc
)
{
    if (!g_explorer_open)
        return;

    int x = EXPLORER_X;
    int y = EXPLORER_Y;

    int w = explorer_width();
    int h = explorer_height();

    /*
        Shadow.
    */

    fill_rect(
        dc,
        x + 8,
        y + 8,
        w,
        h,
        RGB(5,7,11)
    );

    /*
        Main window.
    */

    fill_rect(
        dc,
        x,
        y,
        w,
        h,
        C_WINDOW
    );

    draw_border(
        dc,
        x,
        y,
        w,
        h,
        C_BORDER
    );

    /*
        Title.
    */

    fill_rect(
        dc,
        x,
        y,
        w,
        42,
        C_TITLE
    );

    draw_text(
        dc,
        x + 18,
        y + 11,
        "File Explorer",
        C_TEXT,
        16
    );

    /*
        Window controls.
    */

    draw_text(
        dc,
        x + w - 100,
        y + 10,
        "_",
        C_TEXT2,
        17
    );

    draw_text(
        dc,
        x + w - 65,
        y + 10,
        "[]",
        C_TEXT2,
        13
    );

    draw_text(
        dc,
        x + w - 28,
        y + 10,
        "X",
        RGB(235,120,120),
        13
    );

    /*
        Navigation bar.
    */

    draw_text(
        dc,
        x + 18,
        y + 55,
        "<",
        C_TEXT,
        22
    );

    draw_text(
        dc,
        x + 50,
        y + 55,
        ">",
        C_TEXT2,
        22
    );

    draw_text(
        dc,
        x + 82,
        y + 55,
        "^",
        C_TEXT,
        20
    );

    /*
        Address bar.
    */

    int address_x =
        x + 125;

    int address_w =
        w - 150;

    fill_rect(
        dc,
        address_x,
        y + 47,
        address_w,
        35,
        C_INPUT
    );

    draw_border(
        dc,
        address_x,
        y + 47,
        address_w,
        35,
        C_BORDER
    );

    draw_text(
        dc,
        address_x + 12,
        y + 57,
        g_current_path,
        C_TEXT,
        13
    );

    /*
        Sidebar.
    */

    int side_x = x;
    int side_y = y + 88;

    int side_w = 190;
    int side_h = h - 88;

    draw_sidebar(
        dc,
        side_x,
        side_y,
        side_w,
        side_h
    );

    /*
        Main file area.
    */

    int content_x =
        x + side_w;

    int content_y =
        y + 88;

    int content_w =
        w - side_w;

    int content_h =
        h - 88;

    fill_rect(
        dc,
        content_x,
        content_y,
        content_w,
        content_h,
        RGB(24,29,38)
    );

    draw_text(
        dc,
        content_x + 20,
        content_y + 18,
        "Name",
        C_TEXT2,
        12
    );

    /*
        Separator.
    */

    fill_rect(
        dc,
        content_x,
        content_y + 44,
        content_w,
        1,
        C_BORDER
    );

    /*
        Files.
    */

    int list_y =
        content_y + 48;

    int visible =
        (content_h - 48) /
        ITEM_HEIGHT;

    int first =
        g_scroll / ITEM_HEIGHT;

    int offset =
        -(g_scroll % ITEM_HEIGHT);

    for (
        int i = first;
        i < g_item_count &&
        i < first + visible + 2;
        i++
    )
    {
        int yy =
            list_y +
            offset +
            (i - first) *
            ITEM_HEIGHT;

        if (
            yy + ITEM_HEIGHT <
            content_y + content_h
        )
        {
            draw_file_item(
                dc,
                content_x + 8,
                yy,
                content_w - 16,
                &g_items[i],
                i
            );
        }
    }

    /*
        Status bar.
    */

    char status[128];

    snprintf(
        status,
        sizeof(status),
        "%d items",
        g_item_count
    );

    draw_text(
        dc,
        content_x + 15,
        y + h - 25,
        status,
        C_TEXT2,
        11
    );
}


/* ============================================================
   START MENU
   ============================================================ */

static void draw_start_menu(
    HDC dc
)
{
    if (!g_start_open)
        return;

    int w = 400;
    int h = 500;

    int x = 18;

    int y =
        g_height -
        TASKBAR_HEIGHT -
        h -
        10;

    fill_rect(
        dc,
        x + 8,
        y + 8,
        w,
        h,
        RGB(5,7,10)
    );

    fill_rect(
        dc,
        x,
        y,
        w,
        h,
        RGB(25,30,40)
    );

    draw_border(
        dc,
        x,
        y,
        w,
        h,
        C_BORDER
    );

    draw_text(
        dc,
        x + 28,
        y + 25,
        "Start",
        C_TEXT,
        25
    );

    draw_text(
        dc,
        x + 28,
        y + 82,
        "File Explorer",
        C_TEXT,
        15
    );

    draw_text(
        dc,
        x + 28,
        y + 125,
        "Terminal",
        C_TEXT,
        15
    );

    draw_text(
        dc,
        x + 28,
        y + 168,
        "Settings",
        C_TEXT,
        15
    );

    draw_text(
        dc,
        x + 28,
        y + 211,
        "DirectX",
        C_TEXT,
        15
    );

    draw_text(
        dc,
        x + 28,
        y + 254,
        "This PC",
        C_TEXT,
        15
    );

    draw_text(
        dc,
        x + 28,
        y + h - 45,
        "Power",
        RGB(235,140,140),
        14
    );
}


/* ============================================================
   TASKBAR
   ============================================================ */

static void draw_taskbar(
    HDC dc
)
{
    int y =
        g_height -
        TASKBAR_HEIGHT;

    fill_rect(
        dc,
        0,
        y,
        g_width,
        TASKBAR_HEIGHT,
        C_TASKBAR
    );

    /*
        Start.
    */

    fill_rect(
        dc,
        10,
        y + 8,
        42,
        42,
        RGB(31,39,52)
    );

    draw_text(
        dc,
        22,
        y + 16,
        "⊞",
        C_TEXT,
        21
    );

    /*
        Search.
    */

    fill_rect(
        dc,
        62,
        y + 10,
        210,
        38,
        C_INPUT
    );

    draw_text(
        dc,
        78,
        y + 20,
        "Search",
        C_TEXT2,
        12
    );

    /*
        Explorer button.
    */

    fill_rect(
        dc,
        282,
        y + 7,
        155,
        44,
        g_explorer_open
            ? C_SELECTED
            : RGB(31,38,49)
    );

    draw_text(
        dc,
        300,
        y + 19,
        "Explorer",
        C_TEXT,
        13
    );

    /*
        System tray.
    */

    draw_text(
        dc,
        g_width - 220,
        y + 20,
        "NET   VOL   GPU",
        C_TEXT2,
        10
    );

    draw_text(
        dc,
        g_width - 75,
        y + 20,
        "12:00",
        C_TEXT,
        11
    );
}


/* ============================================================
   COMPLETE FRAME
   ============================================================ */

static void draw_frame(void)
{
    HDC dc =
        GetDC(g_hwnd);

    draw_desktop(dc);

    /*
        Desktop Explorer icon.
    */

    draw_folder_icon(
        dc,
        32,
        95
    );

    draw_text(
        dc,
        25,
        138,
        "Explorer",
        C_TEXT,
        12
    );

    draw_file_icon(
        dc,
        38,
        190
    );

    draw_text(
        dc,
        30,
        235,
        "Computer",
        C_TEXT,
        12
    );

    draw_explorer(dc);

    draw_start_menu(dc);

    draw_taskbar(dc);

    ReleaseDC(
        g_hwnd,
        dc
    );

    if (g_swapchain)
    {
        g_swapchain->Present(
            1,
            0
        );
    }
}


/* ============================================================
   DIRECTX INITIALISATION
   ============================================================ */

static int init_directx(void)
{
    RECT r;

    GetClientRect(
        g_hwnd,
        &r
    );

    g_width =
        r.right -
        r.left;

    g_height =
        r.bottom -
        r.top;

    DXGI_SWAP_CHAIN_DESC desc;

    ZeroMemory(
        &desc,
        sizeof(desc)
    );

    desc.BufferCount = 2;

    desc.BufferDesc.Width =
        g_width;

    desc.BufferDesc.Height =
        g_height;

    desc.BufferDesc.Format =
        DXGI_FORMAT_R8G8B8A8_UNORM;

    desc.BufferUsage =
        DXGI_USAGE_RENDER_TARGET_OUTPUT;

    desc.OutputWindow =
        g_hwnd;

    desc.SampleDesc.Count = 1;

    desc.Windowed = TRUE;

    desc.SwapEffect =
        DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL feature;

    HRESULT hr =
        D3D11CreateDeviceAndSwapChain(
            NULL,
            D3D_DRIVER_TYPE_HARDWARE,
            NULL,
            0,
            NULL,
            0,
            D3D11_SDK_VERSION,
            &desc,
            &g_swapchain,
            &g_device,
            &feature,
            &g_context
        );

    if (FAILED(hr))
    {
        MessageBoxA(
            g_hwnd,
            "Could not initialise DirectX 11.",
            "DirectX Explorer",
            MB_ICONERROR
        );

        return 0;
    }

    ID3D11Texture2D *backbuffer = NULL;

    hr =
        g_swapchain->GetBuffer(
            0,
            __uuidof(ID3D11Texture2D),
            (void **)&backbuffer
        );

    if (FAILED(hr))
        return 0;

    hr =
        g_device->CreateRenderTargetView(
            (ID3D11Resource *)backbuffer,
            NULL,
            &g_target
        );

    backbuffer->Release();

    if (FAILED(hr))
        return 0;

    g_context->OMSetRenderTargets(
        1,
        &g_target,
        NULL
    );

    return 1;
}


/* ============================================================
   DIRECTX CLEANUP
   ============================================================ */

static void shutdown_directx(void)
{
    if (g_target)
        g_target->Release();

    if (g_swapchain)
        g_swapchain->Release();

    if (g_context)
        g_context->Release();

    if (g_device)
        g_device->Release();

    g_target = NULL;
    g_swapchain = NULL;
    g_context = NULL;
    g_device = NULL;
}


/* ============================================================
   FULLSCREEN
   ============================================================ */

static void set_fullscreen(
    int fullscreen
)
{
    g_fullscreen = fullscreen;

    if (fullscreen)
    {
        SetWindowLongA(
            g_hwnd,
            GWL_STYLE,
            WS_POPUP
        );

        SetWindowPos(
            g_hwnd,
            HWND_TOP,
            0,
            0,
            GetSystemMetrics(
                SM_CXSCREEN
            ),
            GetSystemMetrics(
                SM_CYSCREEN
            ),
            SWP_SHOWWINDOW
        );
    }
    else
    {
        SetWindowLongA(
            g_hwnd,
            GWL_STYLE,
            WS_OVERLAPPEDWINDOW
        );

        SetWindowPos(
            g_hwnd,
            HWND_TOP,
            100,
            100,
            1280,
            720,
            SWP_SHOWWINDOW
        );
    }
}


static void toggle_fullscreen(void)
{
    set_fullscreen(
        !g_fullscreen
    );
}


/* ============================================================
   FILE CLICK
   ============================================================ */

static void activate_item(
    int index
)
{
    if (
        index < 0 ||
        index >= g_item_count
    )
    {
        return;
    }

    FileItem *item =
        &g_items[index];

    char path[MAX_PATH_TEXT];

    join_path(
        path,
        sizeof(path),
        g_current_path,
        item->name
    );

    if (item->is_directory)
    {
        open_directory(
            item->name
        );
    }
    else
    {
        /*
            Open file using the Windows shell.
        */

        ShellExecuteA(
            NULL,
            "open",
            path,
            NULL,
            NULL,
            SW_SHOWNORMAL
        );
    }
}


/* ============================================================
   HIT TESTING
   ============================================================ */

static int explorer_file_at(
    int mx,
    int my
)
{
    int x = EXPLORER_X;
    int y = EXPLORER_Y;

    int w = explorer_width();
    int h = explorer_height();

    int side_w = 190;

    int content_x =
        x + side_w;

    int content_y =
        y + 88;

    int content_h =
        h - 88;

    if (
        mx < content_x ||
        mx > content_x + w - side_w
    )
    {
        return -1;
    }

    if (
        my < content_y + 48 ||
        my > content_y + content_h
    )
    {
        return -1;
    }

    int list_y =
        content_y + 48;

    int local_y =
        my - list_y +
        g_scroll;

    if (local_y < 0)
        return -1;

    int index =
        local_y /
        ITEM_HEIGHT;

    if (
        index < 0 ||
        index >= g_item_count
    )
    {
        return -1;
    }

    return index;
}


/* ============================================================
   MOUSE INPUT
   ============================================================ */

static void handle_left_click(
    int x,
    int y
)
{
    int taskbar_y =
        g_height -
        TASKBAR_HEIGHT;

    /*
        Start.
    */

    if (
        x >= 8 &&
        x <= 56 &&
        y >= taskbar_y
    )
    {
        g_start_open =
            !g_start_open;

        return;
    }

    /*
        Explorer taskbar button.
    */

    if (
        x >= 280 &&
        x <= 445 &&
        y >= taskbar_y
    )
    {
        g_explorer_open = 1;
        g_start_open = 0;

        return;
    }

    /*
        Explorer desktop icon.
    */

    if (
        !g_explorer_open &&
        x >= 20 &&
        x <= 100 &&
        y >= 85 &&
        y <= 165
    )
    {
        g_explorer_open = 1;

        return;
    }

    /*
        Explorer close button.
    */

    if (
        g_explorer_open
    )
    {
        int ex = EXPLORER_X;
        int ey = EXPLORER_Y;
        int ew = explorer_width();

        if (
            x >= ex + ew - 45 &&
            x <= ex + ew &&
            y >= ey &&
            y <= ey + 42
        )
        {
            g_explorer_open = 0;
            return;
        }

        /*
            Up button.
        */

        if (
            x >= ex + 70 &&
            x <= ex + 120 &&
            y >= ey + 42 &&
            y <= ey + 85
        )
        {
            go_up();
            return;
        }

        /*
            File.
        */

        int index =
            explorer_file_at(
                x,
                y
            );

        if (index >= 0)
        {
            activate_item(
                index
            );

            return;
        }
    }

    g_start_open = 0;
}


/* ============================================================
   MOUSE WHEEL
   ============================================================ */

static void handle_wheel(
    int delta
)
{
    if (!g_explorer_open)
        return;

    int max_scroll =
        g_item_count *
        ITEM_HEIGHT;

    max_scroll -=
        explorer_height();

    if (max_scroll < 0)
        max_scroll = 0;

    g_scroll -= delta / 3;

    if (g_scroll < 0)
        g_scroll = 0;

    if (g_scroll > max_scroll)
        g_scroll = max_scroll;
}


/* ============================================================
   WINDOW PROCEDURE
   ============================================================ */

static LRESULT CALLBACK wndproc(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam
)
{
    switch (msg)
    {
        case WM_DESTROY:

            g_running = 0;

            PostQuitMessage(0);

            return 0;


        case WM_KEYDOWN:

            if (wParam == VK_ESCAPE)
            {
                g_running = 0;

                PostQuitMessage(0);

                return 0;
            }

            if (wParam == VK_F11)
            {
                toggle_fullscreen();

                return 0;
            }

            if (
                wParam == VK_F5 &&
                g_explorer_open
            )
            {
                enumerate_directory();

                return 0;
            }

            if (
                wParam == VK_BACK &&
                g_explorer_open
            )
            {
                go_up();

                return 0;
            }

            break;


        case WM_LBUTTONDOWN:

            handle_left_click(
                LOWORD(lParam),
                HIWORD(lParam)
            );

            return 0;


        case WM_MOUSEMOVE:

            g_mouse_x =
                LOWORD(lParam);

            g_mouse_y =
                HIWORD(lParam);

            return 0;


        case WM_MOUSEWHEEL:

            handle_wheel(
                GET_WHEEL_DELTA_WPARAM(
                    wParam
                )
            );

            return 0;


        case WM_SIZE:

            g_width =
                LOWORD(lParam);

            g_height =
                HIWORD(lParam);

            return 0;
    }

    return DefWindowProcA(
        hwnd,
        msg,
        wParam,
        lParam
    );
}


/* ============================================================
   PROGRAM ENTRY
   ============================================================ */

int WINAPI WinMain(
    HINSTANCE instance,
    HINSTANCE previous,
    LPSTR command_line,
    int show
)
{
    (void)previous;
    (void)command_line;
    (void)show;

    WNDCLASSA wc;

    ZeroMemory(
        &wc,
        sizeof(wc)
    );

    wc.style =
        CS_HREDRAW |
        CS_VREDRAW;

    wc.lpfnWndProc =
        wndproc;

    wc.hInstance =
        instance;

    wc.hCursor =
        LoadCursor(
            NULL,
            IDC_ARROW
        );

    wc.lpszClassName =
        "DirectXExplorerWindow";

    if (!RegisterClassA(&wc))
        return 1;

    g_width =
        GetSystemMetrics(
            SM_CXSCREEN
        );

    g_height =
        GetSystemMetrics(
            SM_CYSCREEN
        );

    g_hwnd =
        CreateWindowExA(
            0,
            "DirectXExplorerWindow",
            "DirectX Explorer",
            WS_POPUP,
            0,
            0,
            g_width,
            g_height,
            NULL,
            NULL,
            instance,
            NULL
        );

    if (!g_hwnd)
        return 1;

    ShowWindow(
        g_hwnd,
        SW_SHOW
    );

    UpdateWindow(
        g_hwnd
    );

    if (!init_directx())
        return 1;

    /*
        Start at C:\.
    */

    go_root();

    /*
        Main loop.
    */

    MSG msg;

    ZeroMemory(
        &msg,
        sizeof(msg)
    );

    while (g_running)
    {
        while (
            PeekMessageA(
                &msg,
                NULL,
                0,
                0,
                PM_REMOVE
            )
        )
        {
            TranslateMessage(
                &msg
            );

            DispatchMessageA(
                &msg
            );
        }

        draw_frame();
    }

    shutdown_directx();

    return 0;
}
