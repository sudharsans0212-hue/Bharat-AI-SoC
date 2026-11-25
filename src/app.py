import os, sys
os.environ["GRADIO_ANALYTICS_ENABLED"] = "False"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gradio as gr
import pandas as pd
import sms_detector, url_detector, network_detector, advisor
import flow_extractor as fe
import live_rules as lr

NL = chr(10)
USE_LLAMA = os.environ.get("SENTINEL_LLAMA", "0") == "1"
ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "NONE": "🟢"}
SAMPLE = os.path.join(HERE, "data", "sample_flows.csv")
DEMO_PCAP = os.path.join(HERE, "data", "demo_capture.pcap")
SCENARIOS = ["Normal browsing", "Port scan", "Flood (DoS)", "Exploit attempt"]
MIN_STRONG = 3
_flows = {}


def render(card):
    lvl = card["level"]
    parts = ["## " + ICON[lvl] + " " + card["headline"]]
    if lvl == "NONE":
        parts.append("*Our checks found nothing suspicious. This is not a guarantee. "
                     "If something still feels wrong, never share an OTP or PIN.*")
    if card["what_happened"]:
        parts.append("**What happened:** " + card["what_happened"])
    if card["what_to_do"]:
        steps = [str(i) + ". " + s for i, s in enumerate(card["what_to_do"], 1)]
        parts.append("**What to do:**" + NL + NL + NL.join(steps))
    if card["evidence"]:
        bullets = ["- " + e for e in card["evidence"]]
        parts.append("**Warning signs found:**" + NL + NL + NL.join(bullets))
    if card.get("confidence") is not None and lvl != "NONE":
        parts.append("*Detector score: " + str(card["confidence"]) +
                     " | explanation source: " + card["source"] + "*")
    return (NL + NL).join(parts)


def check_message(text):
    if not text or not text.strip():
        return "Paste a message first."
    ev = sms_detector.check_sms(text)
    return render(advisor.build_card(ev, use_llama=USE_LLAMA))


def check_link(url):
    if not url or not url.strip():
        return "Paste a link first."
    ev = url_detector.check_url(url.strip())
    return render(advisor.build_card(ev, use_llama=USE_LLAMA))


def check_capture(file):
    if file is None:
        path = DEMO_PCAP
        label = "the built-in demo capture (simulated traffic)"
    else:
        path = file if isinstance(file, str) else getattr(file, "name", None)
        if not path:
            return "Could not read that file."
        label = "your file " + os.path.basename(path)
    try:
        flows = fe.flows_from_pcap(path)
    except Exception:
        return "Could not read that file. Please upload a .pcap capture."
    events = lr.analyze(flows)
    head = ("*Analyzed " + label + ": " + str(len(flows)) + " connections, " +
            str(len(events)) + " alerts. Detection uses counting rules.*")
    if not events:
        quiet = {"type": "port_scan", "level": "NONE", "confidence": None, "evidence": []}
        body = render(advisor.build_card(quiet, use_llama=False))
    else:
        body = (NL + NL + "---" + NL + NL).join(
            render(advisor.build_card(e, use_llama=False)) for e in events)
    return (NL + NL).join([head, body])


def check_traffic(scenario):
    if "df" not in _flows:
        _flows["df"] = pd.read_csv(SAMPLE)
    sub = _flows["df"][_flows["df"]["scenario"] == scenario]
    flows = sub.to_dict("records")
    events = network_detector.check_flows(flows)
    n = len(events)
    high = sum(1 for e in events if e["level"] == "HIGH")
    med = sum(1 for e in events if e["level"] == "MEDIUM")
    none = n - high - med
    order = {"HIGH": 2, "MEDIUM": 1, "NONE": 0}
    best = max(events, key=lambda e: (order[e["level"]], e["confidence"]))
    head = ("*Experiment: a machine-learning model on recorded dataset flows. "
            "It scored well on its own dataset but did not hold up on live-style traffic, "
            "so live detection uses the counting rules in the Network capture tab.*")
    summary = ("**" + str(n) + " connections checked:** " + str(high) + " strong warnings, " +
               str(med) + " softer notices, " + str(none) + " with no alert.")
    if high >= MIN_STRONG:
        card_md = render(advisor.build_card(best, use_llama=False))
    else:
        quiet = {"type": "port_scan", "level": "NONE", "confidence": None, "evidence": []}
        card_md = render(advisor.build_card(quiet, use_llama=False))
        if med or high:
            card_md = card_md + NL + NL + ("*A few connections looked slightly unusual, "
                                            "but too few to count as a problem.*")
    return (NL + NL).join([head, summary, card_md])


with gr.Blocks(title="Sentinel") as demo:
    gr.Markdown("# Sentinel: on-device scam, phishing and network check" + NL + NL +
                "Everything runs on this device. Nothing is sent to the cloud.")
    with gr.Tab("Check a message"):
        msg = gr.Textbox(label="Paste the SMS or message", lines=5)
        b1 = gr.Button("Check message")
        out1 = gr.Markdown()
        b1.click(check_message, msg, out1)
    with gr.Tab("Check a link"):
        lnk = gr.Textbox(label="Paste the link", lines=1)
        b2 = gr.Button("Check link")
        out2 = gr.Markdown()
        b2.click(check_link, lnk, out2)
    with gr.Tab("Network capture"):
        gr.Markdown("Upload a small .pcap capture file, or leave it empty to analyze the built-in demo capture.")
        up = gr.File(label="Capture file (.pcap, optional)", file_types=[".pcap"])
        b4 = gr.Button("Analyze capture")
        out4 = gr.Markdown()
        b4.click(check_capture, up, out4)
    with gr.Tab("Model replay (experiment)"):
        sc = gr.Dropdown(SCENARIOS, value=SCENARIOS[1], label="Pick a recorded traffic scenario")
        b3 = gr.Button("Analyze traffic")
        out3 = gr.Markdown()
        b3.click(check_traffic, sc, out3)

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
