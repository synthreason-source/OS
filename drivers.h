/* bochs_drivers.h — guest ABI for in-kernel TCC programs */

/* port I/O helpers */
static inline void outb(unsigned short port, unsigned char val)
{
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline unsigned char inb(unsigned short port)
{
    unsigned char v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static inline void kputc(char c)   { outb(0xE9, (unsigned char)c); }
static inline void kexit(int code) { outb(0xE8, (unsigned char)code); }

static inline void kputs(const char *s)
{
    while (*s) kputc(*s++);
}

/* Blocking read of one keystroke from the guest's stdin queue — spins
 * on port 0xE7 until a non-zero byte is queued. Safe: the kernel yields
 * control back to the scheduler on every empty read instead of burning
 * the guest's instruction budget spinning (see bochs_guest_getc()). */
static inline char getch(void)
{
    unsigned char c;
    while ((c = inb(0xE7)) == 0) { /* wait for a keystroke */ }
    return c;
}

/* ── disk ABI: file-level FAT32 access ────────────────────────────────
 *
 * Guest programs share the SAME FAT32 filesystem (disk.img) that the
 * host kernel's own shell/file-explorer read and write — there is no
 * separate cache or shadow copy, so a file this program writes is
 * immediately visible from the kernel side (and vice versa) the moment
 * the call below returns.
 *
 * Protocol: fill in a disk_mailbox_t, then hand it to the kernel by
 * writing the little-endian bytes of its OWN address to ports
 * 0xE0-0xE3, followed by a command byte to 0xE4. That final outb()
 * does not return until the kernel has finished the entire file
 * operation and written the result (status, and buf_len for
 * READ/STAT) back into this same struct — there is no polling loop;
 * the call is synchronous, like a real blocking disk transaction.
 *
 * You normally don't need to touch disk_mailbox_t or the ports
 * directly — use kfread/kfwrite/kfremove/kfstat below.
 */

typedef struct {
    char         name[64];     /* filename, NUL-terminated            */
    unsigned int buf_addr;     /* guest address of the data buffer     */
    unsigned int buf_len;      /* IN: capacity (READ) / length (WRITE) */
                                /* OUT: actual size (READ/STAT/WRITE)   */
    int          status;       /* OUT: 0 = ok, else a DISK_ERR_* code  */
} disk_mailbox_t;

#define DISK_PORT_ADDR0 0xE0
#define DISK_PORT_ADDR1 0xE1
#define DISK_PORT_ADDR2 0xE2
#define DISK_PORT_ADDR3 0xE3
#define DISK_PORT_CMD   0xE4

#define DISK_CMD_READ   1
#define DISK_CMD_WRITE  2
#define DISK_CMD_DELETE 3
#define DISK_CMD_STAT   4

#define DISK_OK            0
#define DISK_ERR_NOTFOUND (-1)   /* no such file                        */
#define DISK_ERR_IO       (-2)   /* write/allocate failed (disk full?)  */
#define DISK_ERR_TOOBIG   (-3)   /* file is bigger than the buffer      */
#define DISK_ERR_BADCMD   (-4)   /* unknown command byte                */
#define DISK_ERR_BADNAME  (-5)   /* data buffer address out of range    */
#define DISK_ERR_UNREACHABLE (-6) /* kernel couldn't even resolve the   */
                                  /* mailbox itself (bad guest_ptr /     */
                                  /* wrong vaddr_base) -- command was    */
                                  /* dropped, not attempted              */

static inline void __disk_submit(disk_mailbox_t *mbox, int cmd)
{
    unsigned int addr = (unsigned int)(unsigned long)mbox;
    outb(DISK_PORT_ADDR0, (unsigned char)(addr & 0xFF));
    outb(DISK_PORT_ADDR1, (unsigned char)((addr >> 8)  & 0xFF));
    outb(DISK_PORT_ADDR2, (unsigned char)((addr >> 16) & 0xFF));
    outb(DISK_PORT_ADDR3, (unsigned char)((addr >> 24) & 0xFF));
    outb(DISK_PORT_CMD,   (unsigned char)cmd);
}

static inline void __disk_set_name(disk_mailbox_t *mbox, const char *name)
{
    unsigned int i = 0;
    for (; i < sizeof(mbox->name) - 1 && name[i]; i++) mbox->name[i] = name[i];
    mbox->name[i] = '\0';
}

/* Read an entire file into buf (capacity buflen bytes).
 * Returns the file size (>= 0) on success, or a negative DISK_ERR_*
 * code — DISK_ERR_TOOBIG means buf was too small; call kfstat() first
 * if you don't know the size in advance. */
static inline int kfread(const char *filename, void *buf, unsigned int buflen)
{
    static disk_mailbox_t mbox;
    __disk_set_name(&mbox, filename);
    mbox.buf_addr = (unsigned int)(unsigned long)buf;
    mbox.buf_len  = buflen;
    /* The kernel only writes mbox.status if it can resolve this very
     * mailbox's own guest address (see bochs_guest_disk_cmd's disk_guest_ptr
     * check in bochs_glue.cpp) -- if that resolution fails, the command is
     * dropped and status is left exactly as we set it here. Since DISK_OK
     * is 0, leaving status at its .bss zero-init would make a silently
     * dropped command indistinguishable from success; preset it to a real
     * error first so a dropped command is always reported as one. */
    mbox.status = DISK_ERR_UNREACHABLE;
    __disk_submit(&mbox, DISK_CMD_READ);
    if (mbox.status != DISK_OK) return mbox.status;
    return (int)mbox.buf_len;
}

/* Create (or overwrite) filename with the len bytes at buf.
 * Returns 0 on success, or a negative DISK_ERR_* code. */
static inline int kfwrite(const char *filename, const void *buf, unsigned int len)
{
    static disk_mailbox_t mbox;
    __disk_set_name(&mbox, filename);
    mbox.buf_addr = (unsigned int)(unsigned long)buf;
    mbox.buf_len  = len;
    mbox.status   = DISK_ERR_UNREACHABLE;  /* see kfread's comment */
    __disk_submit(&mbox, DISK_CMD_WRITE);
    return mbox.status;
}

/* Delete filename. Returns 0 on success, or DISK_ERR_NOTFOUND. */
static inline int kfremove(const char *filename)
{
    static disk_mailbox_t mbox;
    __disk_set_name(&mbox, filename);
    mbox.status = DISK_ERR_UNREACHABLE;  /* see kfread's comment */
    __disk_submit(&mbox, DISK_CMD_DELETE);
    return mbox.status;
}

/* Look up a file's size without reading it. On success returns 0 and
 * fills *size_out; on failure returns DISK_ERR_NOTFOUND. */
static inline int kfstat(const char *filename, unsigned int *size_out)
{
    static disk_mailbox_t mbox;
    __disk_set_name(&mbox, filename);
    mbox.status = DISK_ERR_UNREACHABLE;  /* see kfread's comment */
    __disk_submit(&mbox, DISK_CMD_STAT);
    if (mbox.status == DISK_OK && size_out) *size_out = mbox.buf_len;
    return mbox.status;
}
