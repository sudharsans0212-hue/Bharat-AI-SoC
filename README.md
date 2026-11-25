# Sentinel: on-device scam, phishing and network-threat detection

Arm Bharat hackathon, PS3: on-device threat, phishing and scam detection.
Everything runs locally (target: Raspberry Pi 5, Arm64). Nothing is sent to the cloud.

## What it does
| Tab | Detector | Method |
|---|---|---|
| Check a message | `sms_detector.py` | TF-IDF + logistic regression, plus rule-based evidence (links, pressure, private-detail requests) |
| Check a link | `url_detector.py` | Lexical URL features + brand/typosquat rules, ML classifier |
| Network capture | `flow_extractor.py`, `live_rules.py` | `.pcap` to flows, then counting rules for port scans and floods |
| Model replay (experiment) | `network_detector.py` | ML model on UNSW-NB15 flows (did not hold up on live-style traffic; see report) |

`advisor.py` turns each alert into a plain-language card (what happened, what to do). Optional on-device
Llama 3.2 1B (ExecuTorch, 8da4w) writes the explanation for HIGH alerts only; otherwise a fixed playbook/template is used.

## Run it
```bash
pip install -r requirements.txt
python make_sample_data.py        # creates the demo .pcap files in data/
python src/app.py                 # opens on http://localhost:7860
```
Trained models are read from `models/` (`sms_model.joblib`, `url_model.joblib`, `net_model.joblib`).
Set `SENTINEL_LLAMA=1` to enable Llama explanations (needs the `.pte`, `tokenizer.model`, `params.json` in `models/`).
Optional: `python make_sample_flows.py` builds `data/sample_flows.csv` for the Model replay tab.

## Layout
```
src/        app + detectors + advisor
models/     trained .joblib models (large Llama files are not in git)
data/       sample captures (generated)
notebooks/  Colab notebooks used for training and the Llama export
```

## Honest limitations
- Network ML model scored well on its own dataset but failed on live-style traffic, so live detection uses counting rules.
- Sample captures are simulated; they show the pipeline works, not accuracy.
- Indian SMS training data is small and partly hand-written; treat scores as optimistic.
