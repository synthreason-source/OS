import socket, struct, time, sys
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 12345)); srv.listen(1); srv.settimeout(30)
conn, _ = srv.accept(); conn.settimeout(0.5)
def send(fr): conn.sendall(struct.pack(">I", len(fr)) + fr)
def recv_all(t):
    out=[]; end=time.time()+t; buf=b""
    while time.time()<end:
        try: d=conn.recv(4096)
        except socket.timeout: continue
        if not d: break
        buf+=d
        while len(buf)>=4:
            n=struct.unpack(">I",buf[:4])[0]
            if len(buf)<4+n: break
            out.append(buf[4:4+n]); buf=buf[4+n:]
    return out
def csum(b):
    if len(b)%2: b+=b"\0"
    s=sum(struct.unpack(">%dH"%(len(b)//2),b)); 
    while s>>16: s=(s&0xffff)+(s>>16)
    return (~s)&0xffff
GM=bytes.fromhex("525400123456"); HM=bytes.fromhex("0a0b0c0d0e0f")
hip=bytes([10,0,2,2]); gip=bytes([10,0,2,15])
time.sleep(9)   # wait for guest init (DHCP times out, falls back to static)
# ARP request for guest
arp=struct.pack(">HHBBH",1,0x0800,6,4,1)+HM+hip+b"\0"*6+gip
send(b"\xff"*6+HM+b"\x08\x06"+arp)
# ICMP echo request, payload 1000 bytes
payload=bytes(range(256))*4; payload=payload[:1000]
ic=struct.pack(">BBHHH",8,0,0,0x1234,7)+payload; ic=ic[:2]+struct.pack(">H",csum(ic))+ic[4:]
ip=struct.pack(">BBHHHBBH",0x45,0,20+len(ic),99,0,64,1,0)+hip+gip; ip=ip[:10]+struct.pack(">H",csum(ip))+ip[12:]
send(GM+HM+b"\x08\x00"+ip+ic)
frames=recv_all(2.5)
ok_arp=ok_icmp=False
for f in frames:
    et=f[12:14]
    if et==b"\x08\x06" and struct.unpack(">H",f[20:22])[0]==2 and f[22:28]==GM and f[28:32]==gip: ok_arp=True; print("ARP reply OK from",f[22:28].hex())
    if et==b"\x08\x00" and f[23]==1 and f[34]==0:
        icmp=f[34:14+struct.unpack(">H",f[16:18])[0]]
        good = csum(f[14:34])==0 and csum(icmp)==0 and icmp[4:8]==struct.pack(">HH",0x1234,7) and icmp[8:]==payload
        print("ICMP echo reply: len",len(icmp),"csum+id+payload ok" if good else "BAD"); ok_icmp=good
print("RESULT", "PASS" if ok_arp and ok_icmp else "FAIL", "frames:",len(frames))
