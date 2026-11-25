import os, re, joblib
import numpy as np
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

MODEL_DIR = os.environ.get("SENTINEL_MODELS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models"))
HIGH_T, MED_T = 0.70, 0.50

_vec, _clf = joblib.load(os.path.join(MODEL_DIR, "sms_model.joblib"))
_names = np.array(_vec.get_feature_names_out())
_coefs = _clf.coef_[0]
_STOP = set(ENGLISH_STOP_WORDS) | {"http", "https", "www", "com", "hdfc", "sbi", "icici", "axis"}

SHORTENERS = ["bit.ly", "tinyurl", "cutt.ly", "rb.gy", "is.gd", "t.co"]
RISKY_TLD = re.compile(r"\.(xyz|top|click|tk|ml|ga|cf|gq|buzz|link)\b", re.I)
PRESSURE = re.compile(r"\b(urgent(ly)?|immediately|expire[sd]?|expiring|blocked|suspended|"
                      r"deactivated|disconnected|last chance|act now|"
                      r"within \d+ ?(hours?|hrs?|minutes?|mins?))\b", re.I)
PRIVATE = re.compile(r"\b(kyc|pan|aadhaar|aadhar|pin|password|cvv|bank details|card details)\b", re.I)
MONEY = re.compile(r"\b(lottery|won|prize|lakhs?|rewards?|refund|cashback|lucky draw)\b", re.I)


def _top_words(text, k=4):
    X = _vec.transform([text])
    idx = X.nonzero()[1]
    contrib = sorted(((_names[i], X[0, i] * _coefs[i]) for i in idx), key=lambda t: -t[1])
    out = []
    for w, c in contrib:
        if c <= 0:
            break
        if " " in w or w in _STOP or len(w) < 3 or w.isdigit():
            continue
        out.append(w)
        if len(out) == k:
            break
    return out


def check_sms(text):
    p = float(_clf.predict_proba(_vec.transform([text]))[0][1])
    level = "HIGH" if p >= HIGH_T else "MEDIUM" if p >= MED_T else "NONE"
    t = text.lower()
    facts = []
    if re.search(r"https?://|www\.", t):
        facts.append("contains a link")
    if any(s in t for s in SHORTENERS):
        facts.append("uses a shortened link that hides the real website")
    if RISKY_TLD.search(t):
        facts.append("link uses a suspicious domain ending")
    if PRESSURE.search(t):
        facts.append("creates pressure to act quickly")
    if PRIVATE.search(t):
        facts.append("asks for private or account details")
    if MONEY.search(t):
        facts.append("promises money or a prize")
    if level == "NONE":
        facts = []
    elif level == "MEDIUM" and not facts:
        facts = ["wording is similar to known scams, but no strong warning signs were found"]
    return {"type": "scam_sms", "confidence": round(p, 2), "level": level,
            "evidence": facts,
            "display_words": _top_words(text) if level != "NONE" else []}
