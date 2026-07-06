/* disk_tcc.c — example guest program showing the file-level FAT32 disk
 * wrapper added alongside the keyboard/terminal ABI in drivers.h.
 *
 * Build (on the host, before or after booting the OS):
 *   make cc SRC=disk_tcc.c
 *
 * Run (inside the OS terminal):
 *   disk_tcc
 *
 * Disk ABI (drivers.h)
 * --------------------
 *  kfwrite (name, buf, len)        -> create/overwrite a file, returns 0 or DISK_ERR_*
 *  kfread  (name, buf, buflen)     -> read a whole file, returns size or DISK_ERR_*
 *  kfstat  (name, &size_out)       -> look up a file's size without reading it
 *  kfremove(name)                  -> delete a file
 *
 * All four go straight through the kernel's own FAT32 driver against
 * the same disk.img the rest of the OS uses — writes are visible to
 * the host shell/file-explorer the instant the call returns, no sync
 * step needed.
 */

#include "drivers.h"

/* drivers.h is libc-free, so we need our own tiny strlen() for the
 * kfwrite() length argument. */
static unsigned int strlen_local(const char *s)
{
    unsigned int n = 0;
    while (s[n]) n++;
    return n;
}

static void put_int(int v)
{
    char buf[12];
    int  i = 0;
    unsigned int u = (v < 0) ? (unsigned int)(-v) : (unsigned int)v;
    if (v < 0) kputc('-');
    if (u == 0) { kputc('0'); return; }
    while (u) { buf[i++] = '0' + (u % 10); u /= 10; }
    while (i--) kputc(buf[i]);
}

void _start(void)
{
    const char *fname = "disktest.txt";
    const char *msg   = "Hello from the guest disk wrapper!\n";
    char        readback[128];

    kputs("=========================================\n");
    kputs("  FAT32 disk wrapper test (TCC-compiled)\n");
    kputs("=========================================\n\n");

    kputs("Writing '"); kputs(fname); kputs("' ... ");
    int wr = kfwrite(fname, msg, (unsigned int)strlen_local(msg));
    if (wr == DISK_OK) kputs("ok\n"); else { kputs("FAILED ("); put_int(wr); kputs(")\n"); kexit(1); }

    unsigned int size = 0;
    kputs("Stat: size = ");
    if (kfstat(fname, &size) == DISK_OK) { put_int((int)size); kputc('\n'); }
    else kputs("not found\n");

    kputs("Reading it back: ");
    int rd = kfread(fname, readback, sizeof(readback) - 1);
    if (rd >= 0) {
        readback[rd] = '\0';
        kputs("\"");
        kputs(readback);
        kputs("\"\n");
    } else {
        kputs("FAILED ("); put_int(rd); kputs(")\n");
    }

    kputs("Deleting it ... ");
    int rm = kfremove(fname);
    kputs(rm == DISK_OK ? "ok\n" : "FAILED\n");

    kputs("\nDone. Exiting with code 0.\n");
    kexit(0);
    for (;;) {}
}
