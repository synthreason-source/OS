// =====================================================================
// tcc_glue.cpp — host-side TCC glue, mirroring the bochs_glue pattern.
//
// Builds into libtcc_glue.so (host x86-64 shared library) and the
// standalone tcc_tool binary.  Invoked by the Makefile `cc` target:
//
//   make cc SRC=foo.c           # compile foo.c → foo on disk.img
//   make cc SRC=foo.c OUT=bar   # explicit output name
//
// Pipeline:
//   1. Obtain source: from host FS or extracted from disk.img via mtools.
//   2. i386-tcc -c  →  .o  (relocatable 32-bit i386 object)
//   3. ld -m elf_i386 -T tcc_guest.ld  →  ELF32 (code at 0x08002000,
//      safely past the Bochs slot stub/GDT/IDT injection zone).
//   4. mtools mcopy the ELF into disk.img.
//
// The .so exports tcc_glue_version() and tcc_glue_compile() so that
// host tooling can call them without spawning a subprocess, and so the
// symbol table mirrors the bochs_glue.so pattern.
// =====================================================================

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

// ── Version ────────────────────────────────────────────────────────────────

extern "C" int tcc_glue_version(void) { return 1; }

// ── Internal helpers ───────────────────────────────────────────────────────

static void err_append(char* buf, int cap, const char* fmt, ...) {
    if (!buf || cap <= 0) return;
    int used = (int)strlen(buf);
    if (used >= cap - 1) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + used, cap - used, fmt, ap);
    va_end(ap);
}

// Run a shell command, collecting stderr into errbuf.
// Returns 0 on success.
static int run_cmd(const char* cmd, char* errbuf, int errbuf_len) {
    char tmpfile[] = "/tmp/tcc_glue_err_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd >= 0) close(fd);

    char full[4096];
    snprintf(full, sizeof(full), "%s 2>>%s", cmd, tmpfile);
    int rc = system(full);   // NOLINT

    FILE* f = fopen(tmpfile, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f))
            err_append(errbuf, errbuf_len, "%s", line);
        fclose(f);
    }
    unlink(tmpfile);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
}

static bool host_file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// ── FAT32 image I/O via mtools ─────────────────────────────────────────────

// Extract file from FAT32 image to host path.
static int fat32_extract(const char* img, const char* fat_name,
                         const char* host_dst, char* errbuf, int elen) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "MTOOLS_SKIP_CHECK=1 mcopy -i '%s' '::%s' '%s'",
        img, fat_name, host_dst);
    return run_cmd(cmd, errbuf, elen);
}

// Inject host file into FAT32 image root.
static int fat32_inject(const char* img, const char* host_src,
                        const char* fat_name, char* errbuf, int elen) {
    // Remove old entry first (ignore failure).
    char del[1024];
    snprintf(del, sizeof(del),
        "MTOOLS_SKIP_CHECK=1 mdel -i '%s' '::%s' 2>/dev/null", img, fat_name);
    system(del);   // NOLINT

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "MTOOLS_SKIP_CHECK=1 mcopy -i '%s' '%s' '::%s'",
        img, host_src, fat_name);
    return run_cmd(cmd, errbuf, elen);
}

// ── Compilation pipeline ───────────────────────────────────────────────────

static int do_compile(const char* src_host, const char* obj_host,
                      const char* elf_host, const char* ld_script,
                      char* errbuf, int elen) {
    char cmd[4096];

    // Step 1: i386-tcc -c  →  .o
    //
    // -I. : src_host lives alone in a freshly mkdtemp'd staging dir (only
    // src.c is ever copied there — see tcc_glue_compile), so tcc's default
    // "search the source file's own directory first" rule finds nothing.
    // Guest programs commonly #include "comp.h" / "font.h" /
    // "bochs_drivers.h", which live in the project base dir instead. This
    // process never chdir()s, so its cwd is still wherever tcc_tool was
    // launched from (the base dir, per the Makefile's `./$(TCC_TOOL) ...`),
    // so "-I." lets tcc fall through to those headers there.
    snprintf(cmd, sizeof(cmd),
        "i386-tcc -c -nostdlib -I. -o '%s' '%s'",
        obj_host, src_host);
    if (run_cmd(cmd, errbuf, elen) != 0) {
        err_append(errbuf, elen, "tcc: compilation failed\n");
        return -1;
    }

    // Confirm the object is i386 (ELF e_machine == EM_386).
    //
    // Previously shelled out to `file '%s' | grep -q 'Intel 80386'`, which
    // is fragile: it fails identically (system() returns nonzero either
    // way) whether the object is genuinely the wrong arch OR `file` simply
    // isn't installed on this machine, OR its libmagic version phrases the
    // description differently ("80386" without "Intel", different word
    // order, etc — this text isn't stable across distros/versions). Read
    // the ELF header directly instead: e_machine lives at offset 18-19
    // (little-endian u16), and EM_386 is value 3. No external tools, no
    // text-matching, so this can't produce a false "not installed?" verdict
    // for reasons unrelated to i386-tcc actually being present.
    {
        FILE* of = fopen(obj_host, "rb");
        if (!of) {
            err_append(errbuf, elen,
                "tcc: could not open compiled object '%s' for verification\n",
                obj_host);
            return -1;
        }
        unsigned char hdr[20];
        size_t got = fread(hdr, 1, sizeof(hdr), of);
        fclose(of);

        bool is_elf = (got == sizeof(hdr) &&
                       hdr[0] == 0x7F && hdr[1] == 'E' &&
                       hdr[2] == 'L'  && hdr[3] == 'F');
        unsigned short e_machine = is_elf ? (unsigned short)(hdr[18] | (hdr[19] << 8)) : 0;

        if (!is_elf || e_machine != 3 /* EM_386 */) {
            err_append(errbuf, elen,
                "tcc: object is not 32-bit i386 (e_machine=%u) — is i386-tcc installed?\n",
                e_machine);
            return -1;
        }
    }

    // Step 2: ld -m elf_i386  →  ELF32
    if (ld_script && host_file_exists(ld_script)) {
        snprintf(cmd, sizeof(cmd),
            "ld -m elf_i386 -static -nostdlib --no-warn-rwx-segments -T '%s' -o '%s' '%s'",
            ld_script, elf_host, obj_host);
    } else {
        // No linker script: link at default TCC base (code at ~0x08048120).
        // This overlaps the Bochs stub zone so the program may misbehave
        // if the stub injection clobbers early instructions.  Warn the user.
        snprintf(cmd, sizeof(cmd),
            "ld -m elf_i386 -static -nostdlib --no-warn-rwx-segments -e _start -o '%s' '%s'",
            elf_host, obj_host);
        err_append(errbuf, elen,
            "warning: tcc_guest.ld not found — code may overlap Bochs stub zone\n");
    }
    if (run_cmd(cmd, errbuf, elen) != 0) {
        err_append(errbuf, elen, "ld: link failed\n");
        return -1;
    }
    return 0;
}

// ── Public API ─────────────────────────────────────────────────────────────

extern "C" int tcc_glue_compile(const char* disk_img,
                                const char* src_name,
                                const char* out_name,
                                const char* ld_script,
                                char* errbuf, int errbuf_len) {
    if (errbuf && errbuf_len > 0) errbuf[0] = '\0';

    if (!disk_img || !src_name) {
        err_append(errbuf, errbuf_len, "tcc_glue: NULL argument\n");
        return -1;
    }

    // Resolve output name.
    char out_buf[256];
    if (out_name && *out_name) {
        strncpy(out_buf, out_name, sizeof(out_buf) - 1);
        out_buf[sizeof(out_buf) - 1] = '\0';
    } else {
        // Strip directory and extension from src_name.
        const char* base = strrchr(src_name, '/');
        base = base ? base + 1 : src_name;
        strncpy(out_buf, base, sizeof(out_buf) - 1);
        out_buf[sizeof(out_buf) - 1] = '\0';
        char* dot = strrchr(out_buf, '.');
        if (dot) *dot = '\0';
    }

    // Resolve linker script.
    const char* ld_use = (ld_script && *ld_script) ? ld_script : "./tcc_guest.ld";

    // Temp workspace.
    char tmpdir[] = "/tmp/tcc_glue_XXXXXX";
    if (!mkdtemp(tmpdir)) {
        err_append(errbuf, errbuf_len, "tcc_glue: mkdtemp: %s\n", strerror(errno));
        return -1;
    }

    char src_host[512], obj_host[512], elf_host[512];
    snprintf(src_host, sizeof(src_host), "%s/src.c",   tmpdir);
    snprintf(obj_host, sizeof(obj_host), "%s/out.o",   tmpdir);
    snprintf(elf_host, sizeof(elf_host), "%s/out.elf", tmpdir);

    int rc = -1;

    // ── 1. Obtain source on host ──────────────────────────────────────────
    if (host_file_exists(src_name)) {
        // Use host file directly; also inject it into the image (as the
        // basename only, since FAT32 is flat) so the OS can cat/edit it.
        const char* src_base = strrchr(src_name, '/');
        src_base = src_base ? src_base + 1 : src_name;
        fat32_inject(disk_img, src_name, src_base, errbuf, errbuf_len);
        char cp[1024];
        snprintf(cp, sizeof(cp), "cp '%s' '%s'", src_name, src_host);
        system(cp);   // NOLINT
    } else {
        if (fat32_extract(disk_img, src_name, src_host, errbuf, errbuf_len) != 0) {
            err_append(errbuf, errbuf_len,
                "tcc_glue: '%s' not found on host or in '%s'\n",
                src_name, disk_img);
            goto cleanup;
        }
    }
    if (!host_file_exists(src_host)) {
        err_append(errbuf, errbuf_len, "tcc_glue: source not found after copy\n");
        goto cleanup;
    }

    // ── 2. Compile ────────────────────────────────────────────────────────
    rc = do_compile(src_host, obj_host, elf_host, ld_use, errbuf, errbuf_len);
    if (rc != 0) goto cleanup;

    // ── 3. Verify ELF magic ───────────────────────────────────────────────
    {
        FILE* ef = fopen(elf_host, "rb");
        if (!ef) {
            err_append(errbuf, errbuf_len, "tcc_glue: output ELF not created\n");
            rc = -1; goto cleanup;
        }
        unsigned char magic[4];
        bool ok = (fread(magic, 1, 4, ef) == 4 &&
                   magic[0] == 0x7F && magic[1] == 'E' &&
                   magic[2] == 'L'  && magic[3] == 'F');
        fclose(ef);
        if (!ok) {
            err_append(errbuf, errbuf_len, "tcc_glue: output is not a valid ELF\n");
            rc = -1; goto cleanup;
        }
    }

    // ── 4. Write ELF into disk.img ────────────────────────────────────────
    rc = fat32_inject(disk_img, elf_host, out_buf, errbuf, errbuf_len);
    if (rc == 0) {
        printf("tcc_glue: '%s' → '%s' written to %s\n",
               src_name, out_buf, disk_img);
    } else {
        err_append(errbuf, errbuf_len, "tcc_glue: failed to write ELF to image\n");
    }

cleanup:
    char rm[640];
    snprintf(rm, sizeof(rm), "rm -rf '%s'", tmpdir);
    system(rm);   // NOLINT
    return rc;
}

// ── CLI ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <disk.img> <source.c> [output_name] [linker_script]\n"
            "\n"
            "  disk.img      : FAT32 disk image (disk.img)\n"
            "  source.c      : C source — on host FS or already in the image\n"
            "  output_name   : ELF name to write into the image "
                              "(default: stem of source.c)\n"
            "  linker_script : path to tcc_guest.ld (default: ./tcc_guest.ld)\n"
            "\n"
            "Example:\n"
            "  %s disk.img hello.c\n"
            "  %s disk.img myprog.c myprog tcc_guest.ld\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    const char* disk_img  = argv[1];
    const char* src_name  = argv[2];
    const char* out_name  = (argc >= 4) ? argv[3] : nullptr;
    const char* ld_script = (argc >= 5) ? argv[4] : nullptr;

    char errbuf[4096] = {0};
    int rc = tcc_glue_compile(disk_img, src_name, out_name, ld_script,
                              errbuf, sizeof(errbuf));
    if (errbuf[0])
        fprintf(rc == 0 ? stdout : stderr, "%s", errbuf);
    return rc ? 1 : 0;
}
