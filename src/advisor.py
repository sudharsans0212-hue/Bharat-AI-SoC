import os, re, sys, subprocess

PTE = os.environ.get("SENTINEL_PTE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "llama3_2_1b_8da4w.pte"))
PARAMS = os.environ.get("SENTINEL_PARAMS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "params.json"))
TOKENIZER = os.environ.get("SENTINEL_TOKENIZER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "tokenizer.model"))

PLAYBOOK = {
    "scam_sms": {
        "meaning": "A fake message that tries to trick you into clicking a link or sharing private details.",
        "steps": [
            "Do not click any link and do not reply.",
            "Never share your OTP, PIN, password or card details with anyone.",
            "Report it at cybercrime.gov.in or call 1930, then delete the message.",
        ],
        "high": "Likely scam. Do not click or reply.",
        "medium": "Suspicious message. Be careful.",
    },
    "phishing_url": {
        "meaning": "A fake website made to steal your login or payment details.",
        "steps": [
            "Do not open the link or enter any details.",
            "Open your bank or app by typing its official address yourself.",
            "Report it at cybercrime.gov.in or call 1930.",
        ],
        "high": "Dangerous link. Do not open it.",
        "medium": "Suspicious link. Be careful.",
    },
    "port_scan": {
        "meaning": "A device on your network is checking which doors into your network are open.",
        "steps": [
            "Find out which device has that address, and disconnect it if it is not yours.",
            "Change your router admin password.",
            "Turn off router settings you do not use, such as remote access.",
        ],
        "high": "Someone is probing your network.",
        "medium": "Unusual network activity.",
    },
    "network_attack": {
        "meaning": "A device is sending unusual traffic that looks like an attack on your network.",
        "steps": [
            "Find out which device has the address shown, and disconnect it if it is not yours.",
            "Change your router admin password and your Wi-Fi password.",
            "Restart the router and install any available updates.",
            "If it keeps happening, contact your internet provider.",
        ],
        "high": "Possible attack on your network.",
        "medium": "Unusual network activity.",
    },
}

MEDIUM_WHAT = {
    "scam_sms": "This message has some things in common with scam messages, but we are not sure it is one. Treat it with care.",
    "phishing_url": "This link has some things in common with fake websites, but we are not sure it is one. Treat it with care.",
    "port_scan": "Some network activity looks unusual, but we are not sure it is a problem.",
    "network_attack": "Some network activity looks unusual, but we are not sure it is a problem.",
}
LLAMA_TYPES = {"scam_sms", "phishing_url"}
MUST = {"scam_sms": ["scam", "fake", "trick", "private", "link"],
        "phishing_url": ["fake", "website", "steal", "login", "link"]}
FORBID = ["safe", "normal", "common", "harmless", "not a threat", "clicked", "nothing to worry"]
START = "Here is what this alert means: "


def _valid(s, etype):
    t = s.lower()
    if not (40 <= len(s) <= 320):
        return False
    if re.search(r"\b(i|i'm|i've|my|me)\b", t):
        return False
    if any(w in t for w in FORBID):
        return False
    if s.count(".") > 4:
        return False
    return any(k in t for k in MUST[etype])


def _llama_sentence(event, max_len=300):
    facts = "; ".join(event["evidence"])
    meaning = PLAYBOOK[event["type"]]["meaning"]
    system = "You explain security alerts to non-technical people in simple words."
    user = ("Alert: " + meaning + "\nFacts: <<<" + facts + ">>>\n"
            "Write 2 short sentences explaining this alert to the user. "
            "Speak to the user as 'you'. Never say it is safe or normal.")
    prompt = ("<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + system + "<|eot_id|>"
              "<|start_header_id|>user<|end_header_id|>\n\n" + user + "<|eot_id|>"
              "<|start_header_id|>assistant<|end_header_id|>\n\n" + START)
    cmd = [sys.executable, "-m", "executorch.examples.models.llama.runner.native",
           "--model", "llama3_2", "-f", PTE, "-p", PARAMS, "-t", TOKENIZER, "-kv",
           "--prompt", prompt, "--temperature", "0.2", "--max_len", str(max_len)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception:
        return ""
    text = r.stdout.split("Prefill time")[0].replace("Using Tiktokenizer", "").strip()
    for stop in ["<|eot_id|>", "<|start_header_id|>"]:
        text = text.split(stop)[0]
    return (START + text).strip()


def build_card(event, use_llama=False):
    t = event["type"]
    pb = PLAYBOOK[t]
    level = event["level"]
    if level == "NONE":
        return {"type": t, "level": "NONE", "headline": "No warning signs found",
                "what_happened": "", "what_to_do": [], "evidence": [],
                "confidence": event.get("confidence"), "source": "none"}
    what = MEDIUM_WHAT[t] if level == "MEDIUM" else pb["meaning"]
    source = "playbook"
    if t in LLAMA_TYPES:
        if use_llama and level == "HIGH" and event.get("evidence"):
            s = _llama_sentence(event)
            if s and _valid(s, t):
                what = s.replace(START, "").strip()
                source = "Llama"
    elif event.get("evidence"):
        what = what + " Details: " + "; ".join(event["evidence"]) + "."
        source = "template"
    return {"type": t, "level": level,
            "headline": pb["high"] if level == "HIGH" else pb["medium"],
            "what_happened": what, "what_to_do": pb["steps"],
            "evidence": event.get("evidence", []),
            "confidence": event.get("confidence"), "source": source}


def format_card(card):
    lines = ["[" + card["level"] + "] " + card["headline"]]
    if card["what_happened"]:
        lines.append("What happened: " + card["what_happened"])
    for i, s in enumerate(card["what_to_do"], 1):
        lines.append("  " + str(i) + ". " + s)
    lines.append("(source: " + card["source"] + ")")
    return "\n".join(lines)
