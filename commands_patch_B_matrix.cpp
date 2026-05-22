// =====================================================================
// (B) Command handlers — paste this block inside handle_command(),
//     BEFORE the final `else { ... fall-through to ELF launch }` block
//     (~line 6770). Each is a standalone `else if` and slots in next to
//     the existing `bochs`, `compile`, `pself`, etc. handlers.
// =====================================================================

// ----- matrix --------------------------------------------------------
//   matrix help
//   matrix create <name> <rows> <cols> [perms=rwx]
//   matrix list                       (alias: matrix ls)
//   matrix show <name>
//   matrix gemm <A> <B> <C>           (C = A · B, blocked tile=4x4)
//   matrix perms <name> <rwxt>        (rewrite permission bits)
//   matrix rm <name>                  (frees the FAT32 file)
//
// File naming convention: .npa extension is automatically appended if
// the user doesn't provide one, so the array store lives alongside
// regular FAT32 files without colliding.
else if (strcmp(command, "matrix") == 0) {
    auto* term = this;  // for the NpaPrint adapter
    char* sub = get_arg(args, 0);
    if (!sub || strcmp(sub, "help") == 0) {
        term->console_print(
            "matrix: NumPy-style storage arrays + blocked GEMM\n"
            "  matrix create <name> <rows> <cols> [perms=rwx]\n"
            "  matrix list\n"
            "  matrix show   <name>\n"
            "  matrix gemm   <A> <B> <C>      # C = A . B  (i32, tile 4x4)\n"
            "  matrix perms  <name> <rwxt>    # set capability bits\n"
            "  matrix rm     <name>\n"
            "perms: r=read w=write x=kernel-exec t=transmit\n");
        return;
    }

    // Tiny helper: append ".npa" if missing. Writes into out_buf.
    auto with_ext = [](const char* n, char* out, int cap) -> const char* {
        if (!n || !*n) return nullptr;
        int len = 0; while (n[len] && len < cap - 5) len++;
        bool has_ext = false;
        if (len >= 4 && n[len-4] == '.' &&
            n[len-3] == 'n' && n[len-2] == 'p' && n[len-1] == 'a') has_ext = true;
        for (int i = 0; i < len; ++i) out[i] = n[i];
        if (!has_ext) { out[len++] = '.'; out[len++] = 'n'; out[len++] = 'p'; out[len++] = 'a'; }
        out[len] = '\0';
        return out;
    };

    if (strcmp(sub, "create") == 0) {
        char* name = get_arg(args, 1);
        char* rs   = get_arg(args, 2);
        char* cs   = get_arg(args, 3);
        char* ps   = get_arg(args, 4);
        if (!name || !rs || !cs) {
            term->console_print("Usage: matrix create <name> <rows> <cols> [perms=rwx]\n");
            return;
        }
        char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
        uint16_t perms = parse_perms(ps);
        int rc = npa_create(fn, (uint32_t)simple_atoi(rs), (uint32_t)simple_atoi(cs), perms, 0);
        if (rc == 0) { term->console_print("matrix: created "); term->console_print(fn); term->console_print("\n"); }
        else         { term->console_print("matrix: create failed (rc=");
                       char b[8]; int_to_string(rc, b); term->console_print(b); term->console_print(")\n"); }
        return;
    }

    if (strcmp(sub, "list") == 0 || strcmp(sub, "ls") == 0) {
        // We don't have a generic FAT32 directory enumerator exposed in
        // the public surface — but kernel.cpp's `ls` command does iterate
        // entries. Easiest path: probe a small set of common names. For
        // a proper listing, replace this with fat32 dir iteration.
        const char* names[] = { "A.npa", "B.npa", "C.npa", "D.npa", "E.npa", "F.npa", 0 };
        bool any = false;
        for (int i = 0; names[i]; ++i) {
            ArrayHeader h; void* d = nullptr;
            if (npa_load(names[i], &h, &d) == 0) {
                npa_print_header(npa_term_print, term, names[i], h);
                delete[] (uint8_t*)d;
                any = true;
            }
        }
        if (!any) term->console_print("matrix: no arrays found (try: matrix create A 8 8)\n");
        return;
    }

    if (strcmp(sub, "show") == 0) {
        char* name = get_arg(args, 1);
        if (!name) { term->console_print("Usage: matrix show <name>\n"); return; }
        char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
        ArrayHeader h; void* d = nullptr;
        int rc = npa_load(fn, &h, &d);
        if (rc != 0) { term->console_print("matrix: load failed\n"); return; }
        if (!npa_has(h, NPA_R)) {
            term->console_print("matrix: R denied on "); term->console_print(fn); term->console_print("\n");
            delete[] (uint8_t*)d; return;
        }
        npa_print_header(npa_term_print, term, fn, h);
        npa_print_data  (npa_term_print, term, h, d, 8, 8);
        delete[] (uint8_t*)d;
        return;
    }

    if (strcmp(sub, "gemm") == 0) {
        char* a = get_arg(args, 1), *b = get_arg(args, 2), *c = get_arg(args, 3);
        if (!a || !b || !c) { term->console_print("Usage: matrix gemm <A> <B> <C>\n"); return; }
        char ab[64], bb[64], cb[64];
        const char* fa = with_ext(a, ab, sizeof(ab));
        const char* fb = with_ext(b, bb, sizeof(bb));
        const char* fc = with_ext(c, cb, sizeof(cb));
        int rc = npa_gemm(fa, fb, fc);
        if (rc == 0) {
            term->console_print("matrix: gemm OK -> "); term->console_print(fc); term->console_print("\n");
        } else {
            term->console_print("matrix: gemm failed (rc=");
            char bf[8]; int_to_string(rc, bf); term->console_print(bf);
            term->console_print(")  -20=R-denied -21=shape -22=dtype -23=W-denied -24=C-shape\n");
        }
        return;
    }

    if (strcmp(sub, "perms") == 0) {
        char* name = get_arg(args, 1), *ps2 = get_arg(args, 2);
        if (!name || !ps2) { term->console_print("Usage: matrix perms <name> <rwxt>\n"); return; }
        char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
        ArrayHeader h; void* d = nullptr;
        if (npa_load(fn, &h, &d) != 0) { term->console_print("matrix: load failed\n"); return; }
        h.perms = parse_perms(ps2);
        h.ver_num++;
        int rc = npa_save(fn, &h, d);
        delete[] (uint8_t*)d;
        term->console_print(rc == 0 ? "matrix: perms updated\n" : "matrix: save failed\n");
        return;
    }

    if (strcmp(sub, "rm") == 0) {
        char* name = get_arg(args, 1);
        if (!name) { term->console_print("Usage: matrix rm <name>\n"); return; }
        char nbuf[64]; const char* fn = with_ext(name, nbuf, sizeof(nbuf));
        fat32_remove_file(fn);   // already exists in kernel.cpp
        term->console_print("matrix: removed "); term->console_print(fn); term->console_print("\n");
        return;
    }

    term->console_print("matrix: unknown subcommand. Try `matrix help`.\n");
}
