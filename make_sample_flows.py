"""Builds data/sample_flows.csv (used by the 'Model replay (experiment)' tab)
from the public UNSW-NB15 training set. Needs internet access."""
import io, os, requests
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
url = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/UNSW_NB15_training-set.csv"
r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=300)
r.raise_for_status()
raw = pd.read_csv(io.BytesIO(r.content))

fields = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
          "sload", "dload", "sinpkt", "dinpkt", "smean", "dmean", "proto"]
plan = [("Normal browsing", "Normal", "192.168.1.23", "192.168.1.1"),
        ("Port scan", "Reconnaissance", "192.168.1.45", "192.168.1.10"),
        ("Flood (DoS)", "DoS", "192.168.1.77", "192.168.1.10"),
        ("Exploit attempt", "Exploits", "192.168.1.88", "192.168.1.10")]
parts = []
for name, cat, src, dst in plan:
    s = raw[raw["attack_cat"] == cat].sample(30, random_state=11)[fields].copy()
    s["scenario"], s["src"], s["dst"] = name, src, dst
    parts.append(s)
pd.concat(parts, ignore_index=True).to_csv(os.path.join(HERE, "data", "sample_flows.csv"), index=False)
print("wrote data/sample_flows.csv")
