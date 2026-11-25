from scapy.all import IP, IPv6, TCP, UDP, ICMP

IDLE_GAP = 30.0


def _info(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst, ttl = ip.src, ip.dst, int(ip.ttl)
        size = int(ip.len) if ip.len else len(bytes(ip))
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        src, dst, ttl = ip.src, ip.dst, int(ip.hlim)
        size = int(ip.plen) + 40
    else:
        return None
    if pkt.haslayer(TCP):
        proto, sport, dport = "tcp", int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        proto, sport, dport = "udp", int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        proto, sport, dport = "icmp", 0, 0
    else:
        proto, sport, dport = "other", 0, 0
    return proto, src, sport, dst, dport, ttl, size, float(pkt.time)


def _finish(f):
    ts = sorted(f["ts"])
    td = sorted(f["td"])
    spk, dpk = len(ts), len(td)
    sb, db = sum(f["sz_s"]), sum(f["sz_d"])
    alltimes = ts + td
    dur = max(alltimes) - min(alltimes)
    rate = (spk + dpk - 1) / dur if dur > 0 else 0.0
    sload = (sb - f["sz_s"][0]) * 8 / dur if dur > 0 and spk > 0 else 0.0
    dload = (db - f["sz_d"][0]) * 8 / dur if dur > 0 and dpk > 0 else 0.0
    sinpkt = (ts[-1] - ts[0]) / (spk - 1) * 1000 if spk > 1 else 0.0
    dinpkt = (td[-1] - td[0]) / (dpk - 1) * 1000 if dpk > 1 else 0.0
    return {
        "proto": f["proto"], "src": f["a"][0], "sport": f["a"][1],
        "dst": f["b"][0], "dport": f["b"][1], "start": min(alltimes),
        "dur": dur, "spkts": spk, "dpkts": dpk, "sbytes": sb, "dbytes": db,
        "rate": rate, "sttl": f["ttl_s"], "dttl": f["ttl_d"],
        "sload": sload, "dload": dload, "sinpkt": sinpkt, "dinpkt": dinpkt,
        "smean": sb / spk if spk else 0.0, "dmean": db / dpk if dpk else 0.0,
    }


def flows_from_packets(packets):
    active = {}
    done = []
    for pkt in packets:
        info = _info(pkt)
        if info is None:
            continue
        proto, src, sport, dst, dport, ttl, size, t = info
        a, b = (src, sport), (dst, dport)
        key = (proto,) + tuple(sorted([a, b]))
        f = active.get(key)
        if f is not None and t - f["last"] > IDLE_GAP:
            done.append(_finish(f))
            f = None
        if f is None:
            f = {"proto": proto, "a": a, "b": b, "ts": [], "td": [],
                 "sz_s": [], "sz_d": [], "ttl_s": ttl, "ttl_d": 0, "last": t}
            active[key] = f
        if (src, sport) == f["a"]:
            f["ts"].append(t)
            f["sz_s"].append(size)
        else:
            if not f["td"]:
                f["ttl_d"] = ttl
            f["td"].append(t)
            f["sz_d"].append(size)
        f["last"] = t
    for f in active.values():
        done.append(_finish(f))
    return done


def flows_from_pcap(path):
    from scapy.all import PcapReader
    with PcapReader(path) as r:
        return flows_from_packets(r)
