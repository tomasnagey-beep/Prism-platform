import statistics
import sys
import time

REPO = sys.argv[1]
RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 5
NET_LATENCY = 0.100
sys.path.insert(0, REPO)

import requests  # noqa: E402
import modules.url_scanner as url_scanner  # noqa: E402

url_scanner.VIRUSTOTAL_API_KEY = "bench-key"


class Resp:
    def __init__(self, payload, status_code=200):
        self._p, self.status_code = payload, status_code

    def json(self):
        return self._p


def install_fake_api(polls_until_done):
    calls = {"post": 0, "get": 0}

    def fake_post(*a, **kw):
        time.sleep(NET_LATENCY)
        calls["post"] += 1
        return Resp({"data": {"id": "analysis-1"}})

    def fake_get(*a, **kw):
        time.sleep(NET_LATENCY)
        calls["get"] += 1
        status = "completed" if calls["get"] >= polls_until_done else "queued"
        return Resp({"data": {"attributes": {
            "status": status,
            "stats": {"malicious": 1, "suspicious": 0, "harmless": 5, "undetected": 2},
            "categories": {},
        }}})

    requests.post, requests.get = fake_post, fake_get
    return calls


def run(name, polls_until_done):
    times = []
    for _ in range(RUNS):
        calls = install_fake_api(polls_until_done)
        t0 = time.perf_counter()
        res = url_scanner.URLScanner().scan("https://example.com/login")
        times.append(time.perf_counter() - t0)
        assert res["status"] == "completed" and res["malicious"] == 1, res
    print(f"{name:7s} runs={RUNS}  mean={statistics.mean(times):.3f}s  "
          f"min={min(times):.3f}s  max={max(times):.3f}s  "
          f"stdev={statistics.pstdev(times):.4f}s  "
          f"http: POST={calls['post']} GET={calls['get']}")


if __name__ == "__main__":
    run("cached", 1)
    run("fresh", 2)