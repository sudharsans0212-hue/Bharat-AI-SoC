import os, joblib
import numpy as np
import pandas as pd

MODEL_DIR = os.environ.get("SENTINEL_MODELS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models"))
_b = joblib.load(os.path.join(MODEL_DIR, "net_model.joblib"))
_model = _b["model"]
FEATURES = list(_b["features"])
CLASSES = list(_b["classes"])
HIGH_T = _b["high_t"]
MED_T = _b["medium_t"]

BASE_FIELDS = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
               "sload", "dload", "sinpkt", "dinpkt", "smean", "dmean"]


def _to_frame(flows):
    rows = []
    for f in flows:
        row = {k: float(f.get(k, 0) or 0) for k in BASE_FIELDS}
        proto = str(f.get("proto", "")).lower()
        row["proto_tcp"] = 1 if proto == "tcp" else 0
        row["proto_udp"] = 1 if proto == "udp" else 0
        row["proto_icmp"] = 1 if proto == "icmp" else 0
        rows.append(row)
    return pd.DataFrame(rows)[FEATURES]


def _facts(f, kind):
    facts = []
    src = f.get("src")
    dst = f.get("dst")
    if src and dst:
        facts.append("traffic from " + str(src) + " to " + str(dst))
    if float(f.get("dpkts", 0) or 0) == 0 and float(f.get("spkts", 0) or 0) >= 1:
        facts.append("the target sent no reply")
    if float(f.get("rate", 0) or 0) > 50000:
        facts.append("very high packet rate")
    if kind == "Scan":
        facts.append("pattern matches a device probing for open ports")
    return facts


def check_flows(flows):
    X = _to_frame(flows)
    pr = _model.predict_proba(X)
    i_norm = CLASSES.index("Normal")
    i_scan = CLASSES.index("Scan")
    i_att = CLASSES.index("Attack")
    out = []
    for k, f in enumerate(flows):
        p_norm = float(pr[k, i_norm])
        kind = "Scan" if pr[k, i_scan] > pr[k, i_att] else "Attack"
        level = "HIGH" if p_norm < HIGH_T else "MEDIUM" if p_norm < MED_T else "NONE"
        facts = _facts(f, kind) if level != "NONE" else []
        out.append({"type": "port_scan" if kind == "Scan" else "network_attack",
                    "confidence": round(1.0 - p_norm, 2),
                    "level": level,
                    "evidence": facts})
    return out


def check_flow(flow):
    return check_flows([flow])[0]
