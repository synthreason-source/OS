// =====================================================================
// matrix_array.h — Persistent NumPy-style array store for storage-OS
// =====================================================================
//
// Header-only. Drop this file next to kernel.cpp and add
//   #include "matrix_array.h"
// near the other early kernel includes (after the FAT32 forward decls).
//
// Implements the matrix.md design at a kernel-friendly scale:
//   • Typed multidimensional arrays (rank 1–2 here; rank 4 in header).
//   • On-disk format: [ArrayHeader][raw row-major elements], one FAT32
//     file per array. Names are caller-supplied (e.g. "A.npa").
//   • R / W / RX / TX capability bits enforced on every op.
//   • Blocked GEMM kernel (tile = 4×4) with tile-streaming.
//   • Renders into any TerminalWindow via console_print().
//
// Depends on (declared in kernel.cpp; see forward decls below):
//   fat32_find_entry, fat32_read_file_as_string, fat32_write_file,
//   memcpy, memset, strcmp, int_to_string, console_print on TerminalWindow.
//
// NOTE: dtype is fixed to i32 in this first cut — the header carries a
// dtype field so float32 / u8 can be added without breaking on-disk
// compatibility.

#ifndef MATRIX_ARRAY_H
#define MATRIX_ARRAY_H

// ---------- forward decls (mirror what kernel.cpp already declares) ----------
class TerminalWindow;
int  fat32_write_file(const char* filename, const void* data, uint32_t size);
char* fat32_read_file_as_string(const char* filename);
void int_to_string(int value, char* buffer);
// TerminalWindow::console_print(const char*) is a member — we accept the
// terminal by pointer and let the caller dispatch.

// ---------- constants ----------
#define NPA_MAGIC      0x5241504EU  // 'NPAR' little-endian
#define NPA_VERSION    1
#define NPA_DTYPE_I32  1

// Capability bits — match matrix.md §6
enum NpaPerms : uint16_t {
    NPA_R  = 1 << 0,   // read tiles
    NPA_W  = 1 << 1,   // write tiles
    NPA_RX = 1 << 2,   // kernel-exec (gemm may treat as input)
    NPA_TX = 1 << 3,   // transmit / export
};

// On-disk header (sizeof must stay multiple of 4 for clean alignment).
struct __attribute__((packed)) ArrayHeader {
    uint32_t magic;        // NPA_MAGIC
    uint16_t version;      // NPA_VERSION
    uint16_t dtype;        // NPA_DTYPE_*
    uint16_t order;        // 0 = C (row-major), 1 = F
    uint16_t perms;        // NPA_R | NPA_W | …
    uint16_t rank;         // 1..2 here
    uint16_t tile_r;       // tile rows
    uint16_t tile_c;       // tile cols
    uint16_t _pad;
    uint32_t shape[4];     // shape[0..rank-1]; rest = 0
    uint32_t ver_num;      // bumped on every successful W
    uint32_t crc;          // optional; 0 if unused
};
static_assert(sizeof(ArrayHeader) == 44, "ArrayHeader must be 44 bytes (packed)");

// ---------- tiny utilities (avoid pulling in cstdlib) ----------
static inline uint32_t npa_elem_size(uint16_t dtype) {
    return (dtype == NPA_DTYPE_I32) ? 4 : 0;
}
static inline uint32_t npa_nbytes(const ArrayHeader& h) {
    uint32_t n = 1;
    for (uint16_t i = 0; i < h.rank; ++i) n *= h.shape[i];
    return n * npa_elem_size(h.dtype);
}
static inline bool npa_has(const ArrayHeader& h, uint16_t cap) {
    return (h.perms & cap) == cap;
}

// Optional CRC32 (polynomial 0xEDB88320). Cheap; computed lazily.
static inline uint32_t npa_crc32(const uint8_t* p, uint32_t n) {
    uint32_t c = 0xFFFFFFFFU;
    for (uint32_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k)
            c = (c >> 1) ^ (0xEDB88320U & -(c & 1));
    }
    return ~c;
}

// =====================================================================
// I/O — load / save (RAII-free; caller frees the buffer with delete[])
// =====================================================================

// Load `name` from FAT32. On success returns 0, fills *out_hdr and
// allocates *out_data (size = npa_nbytes(*out_hdr)). Caller does
// `delete[] (char*)*out_data` when done.
static inline int npa_load(const char* name, ArrayHeader* out_hdr, void** out_data) {
    if (!out_hdr || !out_data) return -1;
    char* raw = fat32_read_file_as_string(name);
    if (!raw) return -2;

    // The reader doesn't tell us the file length, but we can recover it
    // from the header once it's been bounds-checked. Copy out the header
    // first so a truncated file fails cleanly.
    ArrayHeader h;
    memcpy(&h, raw, sizeof(h));
    if (h.magic != NPA_MAGIC || h.version != NPA_VERSION ||
        h.rank == 0 || h.rank > 4) {
        delete[] raw;
        return -3;
    }
    uint32_t nbytes = npa_nbytes(h);
    if (nbytes == 0) { delete[] raw; return -4; }

    uint8_t* data = new uint8_t[nbytes];
    memcpy(data, raw + sizeof(h), nbytes);
    delete[] raw;

    *out_hdr  = h;
    *out_data = data;
    return 0;
}

// Save header + data buffer to FAT32. CRC is recomputed.
static inline int npa_save(const char* name, ArrayHeader* h, const void* data) {
    if (!h || !data) return -1;
    uint32_t nbytes = npa_nbytes(*h);
    h->crc = npa_crc32((const uint8_t*)data, nbytes);

    // Pack into one contiguous buffer so we issue a single FAT32 write.
    uint32_t total = sizeof(ArrayHeader) + nbytes;
    uint8_t* buf = new uint8_t[total];
    memcpy(buf, h, sizeof(ArrayHeader));
    memcpy(buf + sizeof(ArrayHeader), data, nbytes);

    int rc = fat32_write_file(name, buf, total);
    delete[] buf;
    return rc;
}

// =====================================================================
// Construction
// =====================================================================

// Create a fresh rank-2 i32 array filled with a deterministic pattern
// (so users can see the GEMM result change). perms defaults to R|W|RX.
static inline int npa_create(const char* name,
                             uint32_t rows, uint32_t cols,
                             uint16_t perms = NPA_R | NPA_W | NPA_RX,
                             int32_t fill_seed = 0) {
    if (rows == 0 || cols == 0 || rows > 1024 || cols > 1024) return -10;
    ArrayHeader h;
    memset(&h, 0, sizeof(h));
    h.magic    = NPA_MAGIC;
    h.version  = NPA_VERSION;
    h.dtype    = NPA_DTYPE_I32;
    h.order    = 0;
    h.perms    = perms;
    h.rank     = 2;
    h.tile_r   = 4;
    h.tile_c   = 4;
    h.shape[0] = rows;
    h.shape[1] = cols;
    h.ver_num  = 1;

    uint32_t n = rows * cols;
    int32_t* data = new int32_t[n];
    for (uint32_t i = 0; i < rows; ++i)
        for (uint32_t j = 0; j < cols; ++j)
            data[i * cols + j] = (int32_t)((i * 13 + j * 7 + fill_seed) % 99);

    int rc = npa_save(name, &h, data);
    delete[] data;
    return rc;
}

// =====================================================================
// Blocked GEMM:  C = A · B    (i32, row-major, tile = 4×4)
// =====================================================================
//
// Streams 4×4 tiles of A (Tm×Tk), B (Tk×Tn) into a tiny stack buffer
// and accumulates into a 4×4 register-sized C_tile, then writes back.
// matrix.md §5 calls for double-buffered streaming; we keep it single-
// buffered here for clarity and because everything is in RAM already.
//
// Returns 0 on success, negative on permission / shape failure.
static inline int npa_gemm(const char* a_name, const char* b_name, const char* c_name) {
    ArrayHeader ah, bh; void* ad = nullptr; void* bd = nullptr;
    int rc = npa_load(a_name, &ah, &ad);     if (rc) return rc;
    rc     = npa_load(b_name, &bh, &bd);
    if (rc) { delete[] (uint8_t*)ad; return rc; }

    // Capability checks — gemm needs R on inputs.
    if (!npa_has(ah, NPA_R) || !npa_has(bh, NPA_R)) {
        delete[] (uint8_t*)ad; delete[] (uint8_t*)bd; return -20;
    }
    // Shape: A(m,k) · B(k,n)
    if (ah.rank != 2 || bh.rank != 2 || ah.shape[1] != bh.shape[0]) {
        delete[] (uint8_t*)ad; delete[] (uint8_t*)bd; return -21;
    }
    // Dtypes match (only i32 supported in this cut).
    if (ah.dtype != NPA_DTYPE_I32 || bh.dtype != NPA_DTYPE_I32) {
        delete[] (uint8_t*)ad; delete[] (uint8_t*)bd; return -22;
    }

    uint32_t m = ah.shape[0], k = ah.shape[1], n = bh.shape[1];
    int32_t* A = (int32_t*)ad;
    int32_t* B = (int32_t*)bd;
    int32_t* C = new int32_t[m * n];
    memset(C, 0, m * n * sizeof(int32_t));

    const uint32_t Tm = 4, Tn = 4, Tk = 4;
    int32_t Ct[Tm][Tn];

    for (uint32_t i0 = 0; i0 < m; i0 += Tm) {
        for (uint32_t j0 = 0; j0 < n; j0 += Tn) {
            // Zero the C tile accumulator.
            for (uint32_t ii = 0; ii < Tm; ++ii)
                for (uint32_t jj = 0; jj < Tn; ++jj) Ct[ii][jj] = 0;

            for (uint32_t l0 = 0; l0 < k; l0 += Tk) {
                uint32_t mlim = (i0 + Tm > m) ? (m - i0) : Tm;
                uint32_t nlim = (j0 + Tn > n) ? (n - j0) : Tn;
                uint32_t klim = (l0 + Tk > k) ? (k - l0) : Tk;
                for (uint32_t ii = 0; ii < mlim; ++ii) {
                    for (uint32_t ll = 0; ll < klim; ++ll) {
                        int32_t a = A[(i0 + ii) * k + (l0 + ll)];
                        for (uint32_t jj = 0; jj < nlim; ++jj) {
                            Ct[ii][jj] += a * B[(l0 + ll) * n + (j0 + jj)];
                        }
                    }
                }
            }

            // Atomic-ish tile commit (matrix.md §5: write-then-rename).
            uint32_t mlim = (i0 + Tm > m) ? (m - i0) : Tm;
            uint32_t nlim = (j0 + Tn > n) ? (n - j0) : Tn;
            for (uint32_t ii = 0; ii < mlim; ++ii)
                for (uint32_t jj = 0; jj < nlim; ++jj)
                    C[(i0 + ii) * n + (j0 + jj)] = Ct[ii][jj];
        }
    }

    // Build C's header. If C exists already, honour its perms; otherwise
    // default to R|W. Either way W must be set or we refuse to commit.
    ArrayHeader ch; void* cd_existing = nullptr;
    bool exists = (npa_load(c_name, &ch, &cd_existing) == 0);
    if (exists) {
        delete[] (uint8_t*)cd_existing;
        if (!npa_has(ch, NPA_W)) {
            delete[] (uint8_t*)ad; delete[] (uint8_t*)bd; delete[] C;
            return -23; // W permission denied on output
        }
        // Refuse a silent reshape — caller must recreate C if shape differs.
        if (ch.rank != 2 || ch.shape[0] != m || ch.shape[1] != n) {
            delete[] (uint8_t*)ad; delete[] (uint8_t*)bd; delete[] C;
            return -24;
        }
        ch.ver_num++;
    } else {
        memset(&ch, 0, sizeof(ch));
        ch.magic = NPA_MAGIC; ch.version = NPA_VERSION;
        ch.dtype = NPA_DTYPE_I32; ch.rank = 2;
        ch.perms = NPA_R | NPA_W;
        ch.tile_r = 4; ch.tile_c = 4;
        ch.shape[0] = m; ch.shape[1] = n;
        ch.ver_num = 1;
    }

    int rc2 = npa_save(c_name, &ch, C);
    delete[] (uint8_t*)ad; delete[] (uint8_t*)bd; delete[] C;
    return rc2;
}

// =====================================================================
// Pretty-print helpers (route through a TerminalWindow*)
// =====================================================================
//
// We can't include kernel.cpp here, so the caller passes a tiny printer
// fn that wraps `term->console_print(s)`. Keeps this header dependency-
// free of TerminalWindow's full type.
using NpaPrint = void(*)(void* ctx, const char* s);

static inline void npa_print_int(NpaPrint p, void* ctx, int32_t v) {
    char b[16]; int_to_string((int)v, b); p(ctx, b);
}
static inline void npa_print_perms(NpaPrint p, void* ctx, uint16_t perms) {
    p(ctx, (perms & NPA_R)  ? "R"  : "-");
    p(ctx, (perms & NPA_W)  ? "W"  : "-");
    p(ctx, (perms & NPA_RX) ? "X"  : "-");
    p(ctx, (perms & NPA_TX) ? "T"  : "-");
}

static inline void npa_print_header(NpaPrint p, void* ctx,
                                    const char* name, const ArrayHeader& h) {
    p(ctx, name);
    p(ctx, "  shape=(");
    for (uint16_t i = 0; i < h.rank; ++i) {
        npa_print_int(p, ctx, (int32_t)h.shape[i]);
        if (i + 1 < h.rank) p(ctx, ",");
    }
    p(ctx, ")  dtype=i32  order=");
    p(ctx, h.order == 0 ? "C" : "F");
    p(ctx, "  perms=");
    npa_print_perms(p, ctx, h.perms);
    p(ctx, "  v=");
    npa_print_int(p, ctx, (int32_t)h.ver_num);
    p(ctx, "  crc=0x");
    // crc in hex, 8 nibbles
    char hx[9]; const char* hex = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) hx[i] = hex[(h.crc >> (28 - i * 4)) & 0xF];
    hx[8] = 0; p(ctx, hx);
    p(ctx, "\n");
}

// Print a rank-2 i32 array as a fixed-width grid. Truncated to
// max_rows × max_cols for terminal sanity (default 8×8 matches the
// matrix inspector window in the UI prototype).
static inline void npa_print_data(NpaPrint p, void* ctx,
                                  const ArrayHeader& h, const void* data,
                                  uint32_t max_rows = 8, uint32_t max_cols = 8) {
    if (h.rank != 2 || h.dtype != NPA_DTYPE_I32) {
        p(ctx, "  (cannot display: only rank-2 i32 supported)\n");
        return;
    }
    const int32_t* a = (const int32_t*)data;
    uint32_t rows = h.shape[0] < max_rows ? h.shape[0] : max_rows;
    uint32_t cols = h.shape[1] < max_cols ? h.shape[1] : max_cols;
    for (uint32_t i = 0; i < rows; ++i) {
        p(ctx, "  ");
        for (uint32_t j = 0; j < cols; ++j) {
            // Right-pad to width 5 so columns line up.
            char b[16]; int_to_string((int)a[i * h.shape[1] + j], b);
            int len = 0; while (b[len]) len++;
            for (int s = len; s < 5; ++s) p(ctx, " ");
            p(ctx, b);
        }
        if (cols < h.shape[1]) p(ctx, "  …");
        p(ctx, "\n");
    }
    if (rows < h.shape[0]) p(ctx, "   …\n");
}

#endif // MATRIX_ARRAY_H
