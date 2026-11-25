import os, re, joblib
import tldextract
from urllib.parse import urlparse

MODEL_DIR = os.environ.get("SENTINEL_MODELS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models"))
_b = joblib.load(os.path.join(MODEL_DIR, "url_model.joblib"))
_vec, _clf = _b["vec"], _b["clf"]
ALLOW = set(_b["allow"])

_ext = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def _reg(h):
    r = _ext(h)
    if r.suffix and r.domain:
        return r.domain + "." + r.suffix
    return r.suffix or r.domain


BRANDS = [
    (["sbi"], "SBI", ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"]),
    (["hdfc", "hdfcbank"], "HDFC Bank", ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcsec.com", "hdfcergo.com"]),
    (["icici", "icicibank"], "ICICI Bank", ["icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com"]),
    (["axisbank"], "Axis Bank", ["axisbank.com"]),
    (["kotak"], "Kotak Bank", ["kotak.com", "kotakbank.com"]),
    (["paytm"], "Paytm", ["paytm.com", "paytmbank.com", "paytmmall.com"]),
    (["phonepe"], "PhonePe", ["phonepe.com"]),
    (["irctc"], "IRCTC", ["irctc.co.in", "irctc.com"]),
    (["incometax", "incometaxindia"], "Income Tax Department", ["incometax.gov.in", "incometaxindia.gov.in"]),
    (["uidai", "aadhaar"], "Aadhaar (UIDAI)", ["uidai.gov.in"]),
    (["amazon"], "Amazon", ["amazon.in", "amazon.com"]),
    (["flipkart"], "Flipkart", ["flipkart.com"]),
    (["paypal"], "PayPal", ["paypal.com"]),
    (["whatsapp"], "WhatsApp", ["whatsapp.com", "whatsapp.net"]),
    (["netflix"], "Netflix", ["netflix.com"]),
    (["delhivery"], "Delhivery", ["delhivery.com"]),
    (["bluedart"], "Blue Dart", ["bluedart.com"]),
    (["indiapost"], "India Post", ["indiapost.gov.in"]),
]

SHARED = {"000webhostapp.com", "000webhost.com", "weebly.com", "wixsite.com", "wordpress.com",
          "amazonaws.com", "cloudfront.net", "azurewebsites.net", "web.app", "firebaseapp.com",
          "herokuapp.com", "github.io", "gitlab.io", "blogspot.com", "pages.dev", "netlify.app",
          "vercel.app", "workers.dev", "onrender.com", "glitch.me", "repl.co", "ngrok.io",
          "duckdns.org", "myshopify.com", "appspot.com", "run.app"}
SHORT = {"bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co", "shorturl.at",
         "tiny.cc", "goo.gl", "ow.ly", "bitly.com"}
HOST_EXCLUDE = SHORT | {"sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
                        "storage.googleapis.com", "firebasestorage.googleapis.com"}
RISKY_TLD = {"xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "buzz", "link", "rest",
             "icu", "cyou", "sbs", "cfd", "monster", "support", "work", "country"}


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_hit(h, rd):
    toks = [t for t in re.split(r"[^a-z]+", h) if t]
    for kws, name, official in BRANDS:
        if rd in official:
            continue
        for kw in kws:
            for t in toks:
                if t == kw or (len(kw) >= 5 and kw in t):
                    return name, official[0]
                limit = 2 if len(kw) >= 8 else 1 if len(kw) >= 6 else 0
                if limit and t != kw and abs(len(t) - len(kw)) <= 1 and _lev(t, kw) <= limit:
                    return name, official[0]
    return None


def _host_signs(h):
    r = _ext(h)
    s = []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
        s.append("uses a raw IP address instead of a website name")
    if "xn--" in h:
        s.append("uses disguised look-alike characters")
    if r.suffix.split(".")[-1] in RISKY_TLD:
        s.append("website ending is often used by scam sites")
    if h.count("-") >= 3:
        s.append("website name has many hyphens")
    if len(h) > 40:
        s.append("website name is very long")
    if r.subdomain and len(r.subdomain.split(".")) >= 2:
        s.append("many layers in front of the real site name")
    if re.search(r"\.(com|net|org|in)\.", h):
        s.append("puts a familiar ending inside the name to look real")
    if any(h.endswith("." + d) for d in SHARED):
        s.append("is on a free website host that anyone can use")
    return s


def check_url(url):
    if not re.match(r"^[a-z]+://", url, re.I):
        url = "http://" + url
    u = urlparse(url)
    h = (u.hostname or "").lower().strip(".")
    path = (u.path + "?" + (u.query or "")).lower()
    r = _ext(h)
    rd = _reg(h)
    ml = round(float(_clf.predict_proba(_vec.transform([h]))[0][1]), 2)
    trusted = (rd in ALLOW or r.suffix in {"gov.in", "nic.in"}) and h not in HOST_EXCLUDE
    if trusted:
        return {"type": "phishing_url", "host": h, "confidence": ml, "level": "NONE",
                "evidence": [], "why": "known legitimate site"}
    facts = []
    bh = _brand_hit(h, rd)
    if bh:
        facts.append("pretends to be " + bh[0] + "; the real site is " + bh[1])
    facts += _host_signs(h)
    apk = path.split("?")[0].endswith(".apk")
    if apk:
        facts.append("link downloads an app file (.apk)")
    if u.username:
        facts.append("contains an @ trick that hides the real website")
    short = h in SHORT
    if short:
        facts.append("shortened link that hides the real website")
    n = len(facts) - (1 if bh else 0)
    high = bool(bh) or apk or ml >= 0.9 or (ml >= 0.7 and n >= 1)
    medium = ml >= 0.7 or n >= 2 or short
    level = "HIGH" if high else "MEDIUM" if medium else "NONE"
    if level == "MEDIUM" and not facts:
        facts = ["the website name looks unusual, but no strong warning signs were found"]
    if level == "NONE":
        facts = []
    return {"type": "phishing_url", "host": h, "confidence": ml, "level": level,
            "evidence": facts, "why": "rules + model"}
