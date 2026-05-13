Storage-only OS with NumPy-style Arrays, Matrix Multiplier, and Programmable ASCII Windowing

Abstract
We propose a minimal "storage-only OS" whose primary services are persistent, addressable storage of multidimensional arrays plus lightweight on-storage computation primitives (notably an optimized matrix multiplier). The OS exposes a compact NumPy-like API for array creation, slicing, and operations; an access-control model with Read/Write/Read-Execute/Transmit (R/W/RX/TX) semantics; and a character-mode UI subsystem that maps ASCII translation, display, keyboard input, and programmable windows with custom dot-cursor patterns. This design targets constrained devices where storage is the dominant persistent resource but local CPU is modest, and where users want array-first workflows tightly coupled to durable storage. (Background on NumPy arrays and matrix multiplication referenced.)[^2][^4]

1. Goals and constraints

- Goals: persistent array-first semantics; efficient large-matrix multiply near-storage; simple authorization model (R/W/RX/TX); ASCII-based display/keyboard for minimal UI with programmable windows and custom dot cursors; small trusted kernel providing safe primitives.
- Constraints: storage-centric (persistent storage as primary state), limited volatile memory, simple CPU (no heavy OS process model), deterministic operation for reproducibility. Related concerns for efficient matrix multiplication and memory trade-offs are well-studied.[^5][^1]

2. High-level architecture

- Components:
    - Storage layer: object store of typed multidimensional arrays (ndarray equivalents) with metadata (shape, dtype, layout, CRC/versions).
    - Execution primitives: storage-resident compute kernels (matrix multiply, elementwise ops) callable in-place or via streaming.
    - Access-control: per-object R/W/RX/TX flags; RX marks data executable by storage kernels; TX allows transmitting object snapshots to external nodes or networks.
    - ASCII UI service: window manager for text windows, ASCII translator, keyboard input queue, and cursor renderer supporting custom dot patterns.
    - RPC/API layer: a small syscall-like interface for clients to declare operations on objects; optional user-level client libraries implement NumPy-like conveniences.
- Rationale: pushing bulk operations like matrix multiply into storage reduces host memory pressure and I/O by operating in-place and streaming blocks. Prior work emphasizes memory-aware blocking for efficient matrix multiply.[^6][^1]

3. Storage formats and array representation

- Typed object store: each array object stores header (UUID, shape tuple, dtype, layout flag 'C' or 'F', block size), block-index for chunked arrays, and optional compressed block pointers. This mirrors NumPy’s ndarray metadata model and supports both row-major and column-major orders.[^3][^2]
- Chunking and sparse-friendly layouts: arrays are divided into fixed-size tiles (e.g., 128–4096 elements per tile) to allow streaming of tiles for compute kernels and to exploit redundancy (run-length, sparse blocks, quadtrees) when present. For highly redundant matrices consider quadtrees or run-length per tile to reduce stored footprint.[^7]
- Versioning and copy-on-write: in-place transforms create new versions or diffs depending on RX flag (RX allows changing executable kernels; W requires explicit write consent). TX-enabled objects carry signed manifests for safe transmission.

4. Array API and semantics (NumPy-style)

- Creation: storage.create_array(shape, dtype, order='C', fill=0) returns persistent object handle; mirrors numpy.array semantics for dtype and order.[^2]
- Views \& slicing: lightweight metadata views map into tiles; slicing produces either read-only or copy-on-write views depending on flags and contiguity; non-contiguous views use virtual indexing to avoid copying when possible.
- Broadcasting, ufuncs, and reductions: storage provides a set of built-in ufuncs executed by kernel primitives; broadcasting follows NumPy rules (align trailing dimensions and permit size-1 expansion). Implementations must explicitly check tile alignment and use streaming to avoid full materialization.[^2]
- Interoperability: a client library can present an in-memory ndarray façade that lazily pulls tiles on access and pushes modified tiles back; useful for interactive workflows.

5. Matrix multiplication execution model

- Objective: provide a storage-side matrix multiply primitive (GEMM-like) that multiplies A and B into C using block/tiling, minimizing host memory and I/O. Industry practice for GEMM (blocking, cache-tiling) applies; oneMKL/dgemm approaches and CPU-optimized techniques inform blocking strategy.[^8][^1]
- Algorithm:
    - Accept matrix objects A(m,k), B(k,n), optional alpha/beta scaling, and output object C(m,n) or target tiles.
    - Choose tile size Tm x Tn such that a single worker thread can hold tiles A_tile (Tm x Tk) and B_tile (Tk x Tn) in local memory; stream across k dimension reading A and B tiles from storage sequentially.
    - If storage supports computational scheduling, assign worker(s) to handle disjoint (i,j) tile ranges; use double-buffering to overlap read/write and compute.
    - If A/B sparse or compressed, decompress on-the-fly per tile, skipping zero tiles (quadtree or sparse map helps). Techniques for large-memory multiplications via swapping to disk apply.[^7][^5]
- Consistency: if C existed previously and RX/W flags permit overwrite, operate in-place using atomic tile commits or write-to-temp and atomic rename to avoid partial writes under failure.

6. R/W/RX/TX model (access control \& modes)

- Definitions:
    - R: read-only access to object tiles (no metadata or data changes).
    - W: can write data (create new versions or modify tiles).
    - RX: allows registering or executing storage-resident kernels that can treat object contents as executable inputs (enables matrix multiply library to run with privileged access).
    - TX: permits exporting object snapshots (signed) to external consumers (network or removable media).
- Enforcement: capability tokens attach to handles; the kernel checks tokens for each syscall. RX privileges are **restricted** and require code signing for kernels to reduce risk. TX requires either owner consent or an explicit ACL. This capability model keeps the OS minimal while preventing accidental or malicious modification.

7. ASCII translation, display, keyboard I/O

- ASCII translator: a service that maps byte sequences from arrays (or tiled regions) into display glyphs using code-page tables; supports translation for control codes, line-wrapping, and glyph transforms (e.g., box-drawing). A keyboard input queue maps scancodes to ASCII bytes and enqueues them into per-window buffers. External virtual keyboards or mapping tables (for extended characters) are supported. (Interactive ASCII keyboard mappings are common references.)[^9][^10]
- Windowing model:
    - Windows are rectangular text surfaces backed by arrays (2D arrays of char/dx attributes). Each window maps to a region of a backing storage array or to a transient buffer.
    - Programmable windows accept small scripts or handler callbacks (storage-resident kernels with RX permission) that implement custom rendering (e.g., scrolling, clipping, local cursor handling).
    - Cursor rendering: support dot cursors represented by small bit-patterns or glyphs that overlay window content. The system supports custom dot cursor patterns per window, supplied as small arrays (e.g., 3x3 or 5x5 masks) which the window compositor blends over text cells. Dot cursor plugins in web/UI contexts provide design examples for small custom cursors.[^11][^12]
- Input model: synchronous or event-driven; keyboard events post ASCII bytes to focused window, optionally generating control messages (window resize, cursor move).

8. Programmable dot cursor patterns and windows

- Cursor patterns: represent cursors as small bitmap arrays with transparency and optional color attributes; store patterns as small array objects so they can be versioned and shared. Applications can upload cursor arrays (RX required) and assign them to windows. Dot cursor implementations in UI toolkits show how small glyphs can replace default cursors.[^12][^11]
- Window semantics: windows keep per-cell attributes (foreground, background, blink flags) and maintain local cursor coordinates; compositing is done using a simple z-order and blending rules. Cursor overlay uses bitmasking to replace or highlight underlying ASCII cell glyphs.

9. Performance considerations and trade-offs

- Tile size tuning: choose tile size to balance read IO, computation granularity, and local memory constraints; tile sizes depend on storage throughput and CPU cache sizes. CPU-optimized GEMM literature guides blocking factors.[^1][^8]
- Compression vs compute: compressing tiles saves storage and IO but adds CPU decompression cost; use lightweight codecs or skip compression for hot tiles. Redundant data benefits from quadtree or run-length encodings to reduce footprint.[^7]
- Parallelism: use multiple worker threads or devices to process independent (i,j) tile ranges; coordinate commits to avoid write contention.
- Failure and atomicity: use per-tile checksums and write-ahead logs or atomic rename semantics for robustness.

10. Security and safety

- Kernel minimality: only a small set of signed kernels (matrix multiply, basic ufuncs, ASCII transliterator) are permitted to run with RX; others run in constrained sandboxed environments.
- Access tokens and auditing: every R/W/RX/TX operation is logged with object ID, user token, and timestamp to support auditing and rollback.
- Sanitization: disallow direct execution of arbitrary uploaded code unless signed and validated.

11. Example reference design (implementation notes)

- Hardware assumptions: SSD-backed object store with moderate throughput (hundreds of MB/s), CPU with SIMD support for local tile compute, small DRAM per worker (tens of MB).
- Software: storage kernel in Rust or C for safety and low-level control; user-space client library in Python exposing numpy-like API that translates array calls into short RPCs to the storage OS; matrix multiply implemented as an RX-signed kernel using blocked GEMM with vectorized inner loops. For interactive ASCII UI, a minimal compositor runs in kernel space with a small ring buffer for keyboard events and window state persisted as arrays. Reference NumPy docs and GEMM references inform API semantics and blocking strategies.[^8][^2]
- Example usage flow:

1. client: storage.create_array((4096,4096), dtype=float64)
2. client: upload A,B tiles (or create by mapping)
3. client: storage.call_kernel('gemm', handles=(A,B,C), args={alpha:1.0})
4. kernel: streams tiles, computes C tiles, writes with atomic commit
5. client: open window bound to C's tile region; assign custom 3x3 dot cursor array; keyboard sends control keys to window for navigation.

12. Related work and references

- NumPy ndarray semantics (array object, dtype, order) provide the API model.[^3][^2]
- Efficient matrix multiplication and blocking/GEMM techniques inform tile/block choices and streaming strategies.[^4][^1][^8]
- Storage-efficient matrix representations (quadtrees, run-length, and sparse storage) guide compression and skipping of zero tiles.[^5][^7]
- ASCII keyboard mapping and virtual keyboard concepts for input handling.[^10][^9]
- Small dot-cursor plugins and cursor replacement approaches illustrate minimal cursor glyph usage for UIs.[^11][^12]

Appendix: Minimal API sketch (pseudo-signatures)

- storage.create_array(shape, dtype, order='C', tile=(tm,tn)=None) -> handle.
- storage.open(handle, mode=('r'|'w'|'rx'|'tx')) -> token.
- storage.read_tile(handle, tile_index) -> raw bytes.
- storage.write_tile(handle, tile_index, data, token).
- storage.call_kernel(name, handles, args..., token) -> job_id.
- ui.create_window(handle_or_shape, pos, size) -> window_id.
- ui.set_cursor(window_id, cursor_handle).
- ui.read_keys(window_id) -> bytes/events.

Concluding note (concise)
This design ties persistent array storage, storage-resident compute (especially blocked matrix multiplication), a capability-based R/W/RX/TX model, and a minimal ASCII windowing/keyboard/cursor system into a lightweight storage-first OS suitable for data-centric workflows on constrained hosts. Implementation choices (tile size, compression, RX-signed kernel set) determine performance and security trade-offs; existing literature on NumPy semantics and GEMM informs API and performance tuning.[^1][^8][^2]


[^1]: https://tech-blog.sonos.com/posts/the-anatomy-of-efficient-matrix-multipliers/

[^2]: https://numpy.org/doc/stable/reference/generated/numpy.array.html

[^3]: https://numpy.org/doc/_downloads/numpy-user-1.13.0.pdf

[^4]: https://en.wikipedia.org/wiki/Matrix_multiplication_algorithm

[^5]: https://www.mathworks.com/matlabcentral/answers/275046-how-to-reduce-memory-for-matrix-multiplication

[^6]: https://www.infoworld.com/article/2336120/what-is-numpy-faster-array-and-matrix-math-in-python.html

[^7]: https://stackoverflow.com/questions/3098907/how-to-efficiently-store-a-matrix-with-highly-redundant-values

[^8]: https://www.intel.com/content/www/us/en/docs/onemkl/tutorial-c/2023-2/multiplying-matrices-using-dgemm.html

[^9]: https://getascii.com/keyboard-map

[^10]: https://support.google.com/translate/answer/6142469?hl=en\&co=GENIE.Platform%3DDesktop

[^11]: https://www.ghostplugins.com/free-plugins/dot-cursor

[^12]: https://www.etsy.com/au/listing/1778495532/custom-dot-cursor-squarespace-71-plugin

[^13]: https://cs61.seas.harvard.edu/site/2019/Section6/

[^14]: https://www.geeksforgeeks.org/python/basics-of-numpy-arrays/

[^15]: https://siboehm.com/articles/22/Fast-MMM-on-CPU

