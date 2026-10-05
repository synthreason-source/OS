import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 53)); s.settimeout(60)
while True:
    try: data, addr = s.recvfrom(512)
    except socket.timeout: break
    qid = data[:2]
    # question section
    i = 12
    while data[i]: i += data[i] + 1
    q = data[12:i+5]
    # answers: CNAME (name ptr -> 0xC00C) then A record using compressed name
    cname_target = b"\x03www\x07example\x03com\x00"
    ans1 = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(cname_target)) + cname_target
    ans2 = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93,184,216,34])
    hdr = qid + struct.pack(">HHHHH", 0x8180, 1, 2, 0, 0)
    s.sendto(hdr + q + ans1 + ans2, addr)
    print("answered", data[12:i], flush=True)
