// =====================================================================
// (C) Remaining handlers — paste alongside the matrix handler.
// =====================================================================

// ----- recurse [n] ---------------------------------------------------
//   recurse [n]    spawn n Bochs windows running /bin/hello, each
//                  shifted down and to the right (the screenshot's
//                  inception-y "HELLO WOHELLO WO..." stack)
//
// Intended as both a stress test for the window manager and a quick
// demo. Caps at 10 to avoid eating MAX_ELF_PROCESSES.
else if (strcmp(command, "recurse") == 0) {
    int n = 5;
    char* na = get_arg(args, 0);
    if (na) n = simple_atoi(na);
    if (n < 1) n = 1;
    if (n > 10) n = 10;

    // Default to /bin/hello on disk (matches existing extract_hello path).
    // Allow override: `recurse 3 mybin`.
    char* elf = get_arg(args, 1);
    if (!elf || !*elf) elf = (char*)"hello";

    // Quick existence check so we fail loudly once, not n times.
    fat_dir_entry_t entry; uint32_t sec = 0, off = 0;
    if (fat32_find_entry(elf, &entry, &sec, &off) != 0) {
        console_print("recurse: '");
        console_print(elf);
        console_print("' not found on disk. Try: bochs hello\n");
        return;
    }

    static int recurse_idx = 0;
    char nbuf[8]; int_to_string(n, nbuf);
    console_print("recurse: spawning ");
    console_print(nbuf);
    console_print(" Bochs windows...\n");

    for (int i = 0; i < n; ++i) {
        // Cascade the windows down/right so they're distinguishable —
        // matches the prototype's recursive Bochs gag layout.
        int o = (recurse_idx++ % 8) * 28 + i * 36;
        wm.add_window(new TerminalWindow(180 + o, 110 + o,
                                         elf,
                                         /*emulator_mode=*/true));
    }
}

// ----- hello ---------------------------------------------------------
//   hello  shortcut for `bochs hello` so the demo path is one word.
else if (strcmp(command, "hello") == 0) {
    fat_dir_entry_t entry; uint32_t sec = 0, off = 0;
    if (fat32_find_entry("hello", &entry, &sec, &off) != 0) {
        console_print("hello: /bin/hello not on disk. Run `make` to (re)embed it.\n");
        return;
    }
    static int hello_idx = 0;
    int o = (hello_idx++ % 8) * 30;
    wm.add_window(new TerminalWindow(200 + o, 120 + o, "hello", /*emulator_mode=*/true));
    console_print("hello: launched in Bochs emulator window.\n");
}

// ----- about ---------------------------------------------------------
else if (strcmp(command, "about") == 0) {
    console_print(
        "storage-OS\n"
        "  build      0.3-bochs\n"
        "  cpu        i386 (single vCPU, Bochs-emulated)\n"
        "  filesystem FAT32 on /dev/sd[ab]\n"
        "  arrays     matrix.h  (NumPy-style, R/W/RX/TX caps, blocked GEMM)\n"
        "  windowing  ASCII compositor\n"
        "  exit       outb 0xE8\n"
        "Type `help` for commands or `matrix help` for the array API.\n");
}
