# web — a web browser for the self-hosted TCC

`web.c` is a small browser written for this OS's own compiler. It opens local
HTML/text files from the FAT32 disk **and** plain `http://` pages over the
network, using a client-side TCP stack added to the kernel.

## Run it

    make BOCHS=1            # rebuild the kernel (needed: adds the network ABI)
    sh mkwebdisk.sh         # compile web/editf/driverkit and put everything on disk.img
    qemu-system-i386 ... -nic user,model=e1000 ...   # a NIC is required (rtl8139 also works)

Inside the OS terminal run `web`. Or build it there: `cc web.c` then `web`.
Try a host web server: `python3 -m http.server 8000` on the host, then in the
browser open `http://10.0.2.2:8000/` (10.0.2.2 is the host under QEMU user networking).

Note: `make` does not track `kernel_parts/*.h`; after editing them `touch kernel.cpp`.

## Using it

Toolbar: Back, Home, URL box, Go. Click a link to follow it. Type `example.com`
or `http://host:port/path` (or a file name like `about` / `web.c`) and press Go.
Keys (URL box not focused): Up/Down, Space / b page down/up, Home/End,
Backspace = back, h = home, g = focus URL box, q = quit.

Supported markup: h1-h6 p br hr div center blockquote pre code b i u a ul ol li
dl/dt/dd table (flattened) img (shown as [alt]) title, entities, comments;
script/style are skipped. Non-HTML text types (and local .txt/.c/.h) show as
plain monospace text. Redirects (301/302/303/307/308, up to 6), chunked
bodies, relative links (`../`, `//host`, `?q`) are handled.

## How the network path works

    web.c  --knet_http_get()-->  ports 0xD0-0xD4  --> bochs_infra.cpp
           (drivers.h)                              --> bochs_glue.cpp: bochs_guest_net_cmd()
                                                    --> kernel.cpp: net_guest_http_get()
                                                    --> 07b_network.h: DNS, tcp_connect, request, read-until-close

Same latch-then-trigger pattern as the disk ABI: the guest writes its
`net_mailbox_t` address to 0xD0-0xD3 and a command byte to 0xD4; that OUT
returns only when the fetch is complete. The guest gets the raw HTTP response.

The kernel TCP is deliberately minimal: one outgoing connection at a time,
active open only, in-order receive (gaps trigger duplicate ACKs), stop-and-wait
transmit, MSS 1460, 14600-byte window, retransmitted SYN/request, RST when the
caller's buffer fills, timeouts: 6 s idle / 25 s total.

## Limits

* **http:// only.** No TLS, so https sites cannot be opened (and many sites
  redirect http to https).
* The desktop **freezes while a page downloads** (blocking call, worst case ~25 s).
* Pages are cut at 48000 bytes ("[page truncated]"). No images, CSS or scripts.
* The URL box holds 63 characters (comp.h limit); the page keeps the full URL.
* Needs a NIC: `ifconfig` in the OS terminal must show an IP address.

## Testing notes

* `knet_http_get` returns `KNET_ERR_UNREACHABLE` on a kernel without the ABI;
  `web` then says to rebuild the kernel.
* `-DWEB_START_URL='"http://10.0.2.2:8000/"'` builds a copy that opens that URL
  at startup (useful where keyboard input isn't available).
* Known pre-existing kernel issue (also on the original ISO): running `ls` and
  then a graphics program in the same terminal session hangs the emulator at
  program start. Run graphics programs before `ls`, or open a fresh terminal.
* FAT names are case-insensitive: the repo's `EDITF.C` / `COMP.H` collide with
  `editf.c` / `comp.h`; `mkwebdisk.sh` ships the lowercase files.
