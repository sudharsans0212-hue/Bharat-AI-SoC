from collections import defaultdict

SCAN_WINDOW = 10.0
SCAN_HIGH, SCAN_MED = 15, 8
FLOOD_WINDOW = 5.0
FLOOD_HIGH, FLOOD_MED = 100, 40


def _max_distinct(items, window):
    items = sorted(items)
    best, left = 0, 0
    counts = {}
    for right in range(len(items)):
        t, k = items[right]
        counts[k] = counts.get(k, 0) + 1
        while t - items[left][0] > window:
            kl = items[left][1]
            counts[kl] -= 1
            if counts[kl] == 0:
                del counts[kl]
            left += 1
        best = max(best, len(counts))
    return best


def _max_count(times, window):
    times = sorted(times)
    best, left = 0, 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(flows):
    pair = defaultdict(list)
    target = defaultdict(list)
    noreply = defaultdict(lambda: [0, 0])
    for f in flows:
        if f["proto"] not in ("tcp", "udp"):
            continue
        k = (f["src"], f["dst"])
        pair[k].append((f["start"], f["dport"]))
        target[(f["src"], f["dst"], f["dport"])].append(f["start"])
        noreply[k][1] += 1
        if f["dpkts"] == 0:
            noreply[k][0] += 1

    events = []
    for (src, dst), items in pair.items():
        n = _max_distinct(items, SCAN_WINDOW)
        if n >= SCAN_MED:
            level = "HIGH" if n >= SCAN_HIGH else "MEDIUM"
            ev = ["traffic from " + src + " to " + dst,
                  "tried " + str(n) + " different ports within " + str(int(SCAN_WINDOW)) + " seconds"]
            nr, tot = noreply[(src, dst)]
            if tot and nr / tot >= 0.8:
                ev.append("most of the attempts got no reply")
            else:
                ev.append("pattern matches a device probing for open ports")
            events.append({"type": "port_scan", "level": level,
                           "confidence": round(min(1.0, n / SCAN_HIGH), 2),
                           "src": src, "dst": dst, "evidence": ev})

    for (src, dst, dport), times in target.items():
        n = _max_count(times, FLOOD_WINDOW)
        if n >= FLOOD_MED:
            level = "HIGH" if n >= FLOOD_HIGH else "MEDIUM"
            ev = ["traffic from " + src + " to " + dst,
                  str(n) + " connections to port " + str(dport) + " within " + str(int(FLOOD_WINDOW)) + " seconds"]
            events.append({"type": "network_attack", "level": level,
                           "confidence": round(min(1.0, n / FLOOD_HIGH), 2),
                           "src": src, "dst": dst, "evidence": ev})

    order = {"HIGH": 0, "MEDIUM": 1}
    events.sort(key=lambda e: order[e["level"]])
    return events
