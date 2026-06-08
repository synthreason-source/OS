# =============================================================================
# Makefile.tcc — TCC download, build, and embed rules.
#
# Include this from your main Makefile:
#   include Makefile.tcc
#
# Then add $(TCC_OBJ) to your kernel link line, and call
# extract_libtcc_to_filesystem() once during kernel startup.
#
# HOW IT MIRRORS THE BUSYBOX / HELLO PATTERN
# ────────────────────────────────────────────
# busybox / hello are downloaded or built at compile time, then embedded
# into the kernel ELF as a raw binary section using:
#
#   objcopy --add-section .rodata.hello=hello \
#           --set-section-flags .rodata.hello=alloc,load,readonly,data \
#           kernel.o
#
# The linker then emits hello_start / hello_end symbols that kernel.cpp
# reads at runtime to copy the binary to FAT32.
#
# We do exactly the same for libtcc.so:
#   libtcc_start / libtcc_end are the linker symbols.
#   extract_libtcc_to_filesystem() copies them to FAT32 as "libtcc.so".
#   tcc_module_init() reads "libtcc.so" from FAT32 and loads the ELF.
# =============================================================================

# ── Knobs ─────────────────────────────────────────────────────────────────
TCC        ?= 1
TCC_VERSION ?= 0.9.27
TCC_URL     ?= https://download.savannah.gnu.org/releases/tinycc/tcc-$(TCC_VERSION).tar.bz2
TCC_SRCDIR  ?= tcc-$(TCC_VERSION)
TCC_ARCHIVE ?= tcc-$(TCC_VERSION).tar.bz2

# Cross-compiler prefix for building i386 TCC on an x86_64 host.
# Set to empty if your host is already i386 or if TCC's configure handles it.
TCC_CC      ?= gcc
TCC_CROSS   ?= -m32

# ── File targets ──────────────────────────────────────────────────────────
LIBTCC_SO   := libtcc.so
TCC_OBJ_EMBED := libtcc_embed.o   # object file that holds the embedded .so

ifeq ($(TCC),1)
TCC_GLUE_OBJ := tcc_glue.o
TCCFLAGS     := -DTCC_GLUE
# libtcc_embed.o must come BEFORE tcc_glue.o in the link so the linker
# symbols libtcc_start / libtcc_end are already defined when tcc_glue.o
# references them.
TCC_LINK_OBJS := $(TCC_OBJ_EMBED) $(TCC_GLUE_OBJ)
else
TCC_GLUE_OBJ := tcc_stub.o
TCCFLAGS     :=
TCC_LINK_OBJS := $(TCC_GLUE_OBJ)
endif

# ── Download TCC source ───────────────────────────────────────────────────
$(TCC_ARCHIVE):
	@echo "[TCC] Downloading TCC $(TCC_VERSION)..."
	wget -q -O $@ $(TCC_URL) || \
	curl -fsSL -o $@ $(TCC_URL)
	@echo "[TCC] Download complete: $@"

# ── Extract TCC source ────────────────────────────────────────────────────
$(TCC_SRCDIR)/configure: $(TCC_ARCHIVE)
	@echo "[TCC] Extracting..."
	tar xf $(TCC_ARCHIVE)
	touch $@   # prevent re-extract on repeated make

# ── Build libtcc.so (i386, self-contained) ────────────────────────────────
#
# Configuration flags:
#   --cpu=i386          target i386 code generation inside TCC
#   --enable-static     embed libtcc's own C runtime; no external deps
#   --disable-nls       no locale/gettext dependencies
#   CC="gcc -m32"       build the host tools as 32-bit if cross-needed
#
# The resulting libtcc.so is a position-independent i386 ELF shared object
# that exports only the documented libtcc C API and has no undefined
# references (except __libc_start_main which is never called from the .so).
#
$(LIBTCC_SO): $(TCC_SRCDIR)/configure
	@echo "[TCC] Configuring TCC $(TCC_VERSION) for i386..."
	cd $(TCC_SRCDIR) && \
	  CC="$(TCC_CC) $(TCC_CROSS)" \
	  ./configure \
	    --prefix=/tmp/tcc-kernel-build \
	    --cpu=i386 \
	    --enable-static \
	    --disable-nls \
	    2>&1 | tail -5
	@echo "[TCC] Building libtcc.so..."
	$(MAKE) -C $(TCC_SRCDIR) libtcc.so \
	  CC="$(TCC_CC) $(TCC_CROSS)" \
	  CFLAGS="$(TCC_CROSS) -O2 -fPIC" \
	  2>&1 | tail -10
	@# Verify the build produced an ELF.
	@if file $(TCC_SRCDIR)/libtcc.so | grep -q ELF; then \
	    echo "[TCC] libtcc.so built OK"; \
	else \
	    echo "[TCC] ERROR: libtcc.so build failed or not ELF"; exit 1; \
	fi
	@# Strip debug info to keep size manageable (< 1 MiB typical).
	strip --strip-unneeded $(TCC_SRCDIR)/libtcc.so
	cp $(TCC_SRCDIR)/libtcc.so $(LIBTCC_SO)
	@echo "[TCC] libtcc.so -> $(LIBTCC_SO) ($$(wc -c < $(LIBTCC_SO)) bytes)"

# ── Embed libtcc.so into the kernel ELF as a raw binary section ──────────
#
# objcopy creates a relocatable object file with three symbols:
#   libtcc_start   — pointer to first byte of libtcc.so
#   libtcc_end     — pointer one past the last byte
#   libtcc_size    — size as a 4-byte integer (convenience)
#
# The kernel declares these as:
#   extern "C" uint8_t libtcc_start[];
#   extern "C" uint8_t libtcc_end[];
# and uses (libtcc_end - libtcc_start) for the byte count.
#
# The section is placed in .rodata so it's part of the kernel's read-only
# data segment and doesn't bloat the .text section.
#
$(TCC_OBJ_EMBED): $(LIBTCC_SO)
	@echo "[TCC] Embedding libtcc.so into kernel ELF..."
	objcopy \
	  --input-target  binary \
	  --output-target elf32-i386 \
	  --binary-architecture i386 \
	  --rename-section .data=.rodata.libtcc,alloc,load,readonly,data,contents \
	  $(LIBTCC_SO) $@
	@# objcopy names the symbols using the filename with slashes/dots
	@# replaced by underscores.  The default names are:
	@#   _binary_libtcc_so_start
	@#   _binary_libtcc_so_end
	@#   _binary_libtcc_so_size
	@# We rename them to the clean names our code expects.
	objcopy \
	  --redefine-sym _binary_libtcc_so_start=libtcc_start \
	  --redefine-sym _binary_libtcc_so_end=libtcc_end   \
	  --redefine-sym _binary_libtcc_so_size=libtcc_size  \
	  $@
	@echo "[TCC] $(TCC_OBJ_EMBED) ready"

# ── Compile tcc_glue.o ────────────────────────────────────────────────────
tcc_glue.o: tcc_glue.cpp tcc_glue.h
	$(CXX) $(CXXFLAGS) $(TCCFLAGS) -c tcc_glue.cpp -o $@

# ── Compile tcc_stub.o ────────────────────────────────────────────────────
tcc_stub.o: tcc_stub.cpp tcc_glue.h
	$(CXX) $(CXXFLAGS) -c tcc_stub.cpp -o $@

# ── Convenience targets ───────────────────────────────────────────────────
.PHONY: tcc-download tcc-clean tcc-distclean

tcc-download: $(LIBTCC_SO)

tcc-clean:
	rm -f $(TCC_OBJ_EMBED) $(TCC_GLUE_OBJ) tcc_stub.o

tcc-distclean: tcc-clean
	rm -rf $(TCC_SRCDIR) $(TCC_ARCHIVE) $(LIBTCC_SO)

# ── Usage summary ─────────────────────────────────────────────────────────
#
# In your main Makefile:
#
#   include Makefile.tcc
#
#   kernel.elf: kernel.o bochs_cstubs.o $(BOCHS_OBJ) $(TCC_LINK_OBJS) ...
#       $(LD) ... $^ -o $@
#
# Build with TCC support:
#   make TCC=1
#
# Build without TCC (uses tcc_stub.o, no download):
#   make TCC=0
#
# The TCC=1 build will:
#   1. wget/curl tcc-$(TCC_VERSION).tar.bz2 from savannah.gnu.org
#   2. ./configure && make libtcc.so (i386, stripped)
#   3. objcopy-embed it as libtcc_start/libtcc_end linker symbols
#   4. Compile tcc_glue.cpp with -DTCC_GLUE
#   5. Link both into the kernel ELF
# At kernel boot, call extract_libtcc_to_filesystem() to write libtcc.so
# to FAT32, then tcc_module_init() loads it on first `tcc` command.
