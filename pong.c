/* pong.c — text-mode solo Pong for the TCC-compiled guest ABI.
 *
 * Build (inside the OS, at the shell prompt, same as `cc hello.c`):
 *
 *     cc pong.c
 *     pong
 *
 * Build (from the host, same as the other .c files here):
 *
 *     make cc SRC=pong.c
 *
 * Kernel ABI (see keyboard_tcc.c / tcc_guest.ld for the full writeup)
 * ---------------------------------------------------------------
 *  outb(0xE9, ch)   -> write character ch to the terminal
 *  outb(0xE8, n)    -> exit with code n  (n & 0xFF)
 *  inb (0xE7)       -> next queued keystroke, or 0 if none waiting yet
 *
 * Why this is turn-based, not real-time
 * --------------------------------------
 * The terminal this runs in is an append-only scrolling console — there
 * is no cursor-addressing / clear-screen escape support, and the guest
 * has no timer or non-blocking sleep. Given that, the design that
 * actually plays well here is: block on a keystroke, then advance the
 * game exactly one step and redraw. Every keypress is one "tick": 'w'
 * moves the paddle up, 's' moves it down, anything else just passes
 * the turn (the ball still moves). This also plays nicely with the
 * getch() blocking-read fix — the kernel yields cleanly while a tick
 * is waiting on you, instead of spinning.
 *
 * The ball bounces off the top wall, the bottom wall, and the right
 * wall, and off your paddle on the left. Missing the paddle ends the
 * game. Each frame is printed as a fresh block of text below the last
 * (since the console only scrolls) with a divider line between them.
 *
 * No libc, no startup files, no dynamic linking. _start is the entry
 * point (set by tcc_guest.ld).
 */

/* ── port I/O helpers ──────────────────────────────────────────────── */
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

static void kputc(char c)   { outb(0xE9, (unsigned char)c); }
static void kexit(int code) { outb(0xE8, (unsigned char)code); }

static void kputs(const char *s)
{
    while (*s) kputc(*s++);
}

static void kput_u32(unsigned int v)
{
    char buf[10];
    int  n = 0;
    if (v == 0) { kputc('0'); return; }
    while (v && n < 10) { buf[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (n) kputc(buf[--n]);
}

/* Blocking read of one keystroke — spins on an empty queue. Safe: the
 * kernel yields control back to the scheduler on every empty read
 * rather than burning the guest's whole instruction budget spinning. */
static char getch(void)
{
    unsigned char c;
    while ((c = inb(0xE7)) == 0) { /* wait for a keystroke */ }
    return c;
}

/* ── game state ───────────────────────────────────────────────────── */
#define W 30   /* playfield width, columns 0..W-1  */
#define H 12   /* playfield height, rows   0..H-1  */
#define PADDLE_H 3

static int paddle_top = (H - PADDLE_H) / 2;  /* row of paddle's top cell, col 0 */
static int ball_x, ball_y;
static int dx, dy;
static unsigned int score = 0;
static int game_over = 0;
static int miss = 0;

static void draw_border(void)
{
    kputc('+');
    for (int i = 0; i < W; i++) kputc('-');
    kputc('+');
    kputc('\n');
}

static void draw_frame(void)
{
    kputs("\n================================\n");
    kputs("Score: ");
    kput_u32(score);
    kputc('\n');

    draw_border();
    for (int y = 0; y < H; y++) {
        kputc('|');
        for (int x = 0; x < W; x++) {
            char c = ' ';
            if (x == 0 && y >= paddle_top && y < paddle_top + PADDLE_H) {
                c = '#';
            }
            if (x == ball_x && y == ball_y) {
                c = 'O';
            }
            kputc(c);
        }
        kputc('|');
        kputc('\n');
    }
    draw_border();
}

/* Advance the ball exactly one step, bouncing off walls and the
 * paddle. Sets `miss` if it got past the paddle uncaught. */
static void step_ball(void)
{
    int nx = ball_x + dx;
    int ny = ball_y + dy;

    if (ny < 0)      { ny = 0;     dy = -dy; }
    else if (ny >= H) { ny = H - 1; dy = -dy; }

    if (nx >= W - 1) { nx = W - 1; dx = -dx; }

    if (nx <= 0) {
        if (ny >= paddle_top && ny < paddle_top + PADDLE_H) {
            /* Caught it — bounce back into play just right of the paddle. */
            nx = 1;
            dx = -dx;
            score++;
        } else {
            miss = 1;
        }
    }

    ball_x = nx;
    ball_y = ny;
}

/* ── entry point ──────────────────────────────────────────────────── */
void _start(void)
{
    kputs("==================================\n");
    kputs("  PONG  (TCC-compiled guest)\n");
    kputs("==================================\n\n");
    kputs("Your paddle '#' is on the left edge.\n");
    kputs("Controls (press ENTER after each):\n");
    kputs("  w = paddle up\n");
    kputs("  s = paddle down\n");
    kputs("  anything else = pass the turn\n");
    kputs("  q = quit\n\n");
    kputs("Every keypress advances the ball one step. Don't miss it!\n");

    ball_x = W / 2;
    ball_y = H / 2;
    dx = -1;
    dy = 1;

    draw_frame();

    for (;;) {
        char c = getch();

        if (c == 'q') {
            kputs("\nQuit. Final score: ");
            kput_u32(score);
            kputc('\n');
            kexit(0);
        }

        if (c == 'w') {
            if (paddle_top > 0) paddle_top--;
        } else if (c == 's') {
            if (paddle_top < H - PADDLE_H) paddle_top++;
        }

        step_ball();

        if (miss) {
            draw_frame();
            kputs("\n*** MISSED! Game over. ***\nFinal score: ");
            kput_u32(score);
            kputc('\n');
            game_over = 1;
        } else {
            draw_frame();
        }

        if (game_over) break;
    }

    kputs("\nThanks for playing. Exiting with code 0.\n");
    kexit(0);
    for (;;) {}   /* should not reach here */
}
