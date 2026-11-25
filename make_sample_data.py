"""Generate the simulated .pcap files used by the Network capture tab.
Usage:  python make_sample_data.py      (writes into ./data)
The traffic is simulated, so it only shows the pipeline works. It is not an accuracy measure."""
import os, sys, random
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
from scapy.all import IP, TCP, UDP, wrpcap
import flow_extractor as fe
import live_rules as lr

random.seed(5)
out_dir = os.path.join(HERE, "data")
os.makedirs(out_dir, exist_ok=True)

def mk(lst, p, tm):
    p.time = tm
    lst.append(p)

normal = []
client = "192.168.1.23"
for k in range(10):
    s = "93.184.216." + str(10 + k)
    sp = 40000 + k
    t0 = 1000.0 + k * 2.0
    mk(normal, IP(src=client, dst=s, ttl=64) / TCP(sport=sp, dport=443, flags="S"), t0)
    mk(normal, IP(src=s, dst=client, ttl=57) / TCP(sport=443, dport=sp, flags="SA"), t0 + 0.02)
    mk(normal, IP(src=client, dst=s, ttl=64) / TCP(sport=sp, dport=443, flags="A"), t0 + 0.021)
    for j in range(8):
        mk(normal, IP(src=client, dst=s, ttl=64) / TCP(sport=sp, dport=443, flags="PA") / (b"x" * 300), t0 + 0.05 + j * 0.05)
        mk(normal, IP(src=s, dst=client, ttl=57) / TCP(sport=443, dport=sp, flags="PA") / (b"y" * 1200), t0 + 0.07 + j * 0.05)
for k in range(5):
    t0 = 1030.0 + k
    mk(normal, IP(src=client, dst="192.168.1.1", ttl=64) / UDP(sport=50000 + k, dport=53) / (b"q" * 40), t0)
    mk(normal, IP(src="192.168.1.1", dst=client, ttl=64) / UDP(sport=53, dport=50000 + k) / (b"a" * 90), t0 + 0.01)

scan = []
for port in range(1, 201):
    t0 = 1100.0 + port * 0.005
    mk(scan, IP(src="192.168.1.45", dst="192.168.1.10", ttl=64) / TCP(sport=44444, dport=port, flags="S"), t0)
    fl = "SA" if port in (22, 80, 443) else "RA"
    mk(scan, IP(src="192.168.1.10", dst="192.168.1.45", ttl=64) / TCP(sport=port, dport=44444, flags=fl), t0 + 0.001)

flood = []
for k in range(300):
    mk(flood, IP(src="192.168.1.77", dst="192.168.1.10", ttl=64) / TCP(sport=30000 + k, dport=80, flags="S"), 1200.0 + k * 0.01)

files = {"normal_only.pcap": normal, "port_scan_only.pcap": scan, "flood_only.pcap": flood,
         "demo_capture.pcap": normal + scan + flood}
for name, pk in files.items():
    pk = sorted(pk, key=lambda p: p.time)
    path = os.path.join(out_dir, name)
    wrpcap(path, pk)
    fl_ = fe.flows_from_pcap(path)
    ev = lr.analyze(fl_)
    print("%-20s %5.1f KB | flows %3d | alerts %d %s" % (
        name, os.path.getsize(path) / 1024, len(fl_), len(ev), [e["type"] for e in ev]))
