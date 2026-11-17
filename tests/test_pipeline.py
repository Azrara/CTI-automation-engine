"""Tests hors ligne (aucun appel réseau) : python -m unittest discover -s tests"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cti_triage.analytics import detect_bursts, event_stats, triage_stats
from cti_triage.config import FlareSettings, JiraSettings, load_triage_config
from cti_triage.flare.client import FlareClient
from cti_triage.flare.ingest import iter_new_events
from cti_triage.jira.client import JiraExporter, build_issue_fields
from cti_triage.models import Category, Decision
from cti_triage.normalize import canonical_type, normalize
from cti_triage.storage import StateStore
from cti_triage.triage import dedup
from cti_triage.triage.anomaly import IsolationForest
from cti_triage.triage.engine import TriageEngine
from cti_triage.triage.learner import LogisticLearner, blend

FIXTURE = Path(__file__).parent / "fixtures" / "sample_feed.json"
NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)


def load_items():
    return json.loads(FIXTURE.read_text())["items"]


class NormalizeTests(unittest.TestCase):
    def test_type_aliases(self):
        self.assertEqual(canonical_type("lookalike_dns"), "lookalike")
        self.assertEqual(canonical_type("driller_source_code"), "source_code")
        self.assertEqual(canonical_type("cc"), "financial_data")

    def test_normalize_fields(self):
        ev = normalize(load_items()[0])
        self.assertEqual(ev.uid, "evt-001")
        self.assertEqual(ev.category, Category.INFECTED_DEVICE)
        self.assertEqual(ev.risk_score, 85)
        self.assertTrue(ev.attributes["has_session_cookies"])
        self.assertIn("jdoe@example.com", ev.attributes["emails"])

    def test_remediated_status(self):
        ev = normalize(load_items()[6])
        self.assertEqual(ev.status, "remediated")


class FakeFlare:
    """Transport factice : token, puis 2 pages, avec un 429 au milieu."""

    def __init__(self):
        self.calls = []
        self.feed_calls = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, json.loads(body) if body else None))
        if url.endswith("/tokens/generate"):
            assert "Bearer" not in headers["Authorization"]
            return 200, b'{"token": "t", "refresh_token_exp": 0}'
        if "/firework/v4/events/tenant/_search" in url:
            self.feed_calls += 1
            if self.feed_calls == 2:
                return 429, b'{"error": {"code": "RATELIMIT_REACHED"}}'
            req = json.loads(body)
            items = load_items()
            if "from" not in req:
                return 200, json.dumps({"items": items[:4], "next": "c1"}).encode()
            return 200, json.dumps({"items": items[4:], "next": None}).encode()
        if "/firework/v2/activities/" in url:
            return 200, b'{"activity": {"header": {}, "data": {}}}'
        return 404, b""


class FlareClientTests(unittest.TestCase):
    def test_paging_retry_and_cursor(self):
        transport = FakeFlare()
        client = FlareClient(FlareSettings(api_key="k", tenant_id=42), transport=transport, sleep=lambda s: None)
        store = StateStore()
        items = list(iter_new_events(client, store))
        self.assertEqual(len(items), 8)
        self.assertEqual(store.get_cursor(), "c1")
        token_call = transport.calls[0]
        self.assertEqual(token_call[2], {"tenant_id": 42})
        feed_bodies = [c[2] for c in transport.calls if "_search" in c[1]]
        # Tous les paramètres hors `from` restent identiques entre les pages.
        stripped = [{k: v for k, v in b.items() if k != "from"} for b in feed_bodies]
        self.assertTrue(all(s == stripped[0] for s in stripped))
        self.assertEqual(feed_bodies[0]["size"], 10)


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_triage_config()
        self.store = StateStore()
        self.engine = TriageEngine(self.cfg, self.store, now=NOW)
        self.results = {r.event.uid: r for r in (self.engine.triage(normalize(i)) for i in load_items())}

    def test_high_value_events_notified(self):
        for uid in ("evt-001", "evt-002", "evt-008"):
            self.assertEqual(self.results[uid].decision, Decision.NOTIFY, (uid, self.results[uid]))

    def test_noise_suppressed(self):
        self.assertEqual(self.results["evt-003"].decision, Decision.SUPPRESS)
        self.assertEqual(self.results["evt-007"].decision, Decision.SUPPRESS)  # remediated

    def test_duplicate_detected(self):
        self.assertEqual(self.results["evt-005"].duplicate_of, "evt-002")
        self.assertEqual(self.results["evt-005"].decision, Decision.SUPPRESS)

    def test_reasons_are_explained(self):
        self.assertTrue(any("cookies" in r for r in self.results["evt-001"].reasons))

    def test_stats(self):
        s = triage_stats(self.results.values())
        self.assertEqual(s["total"], 8)
        self.assertGreater(s["noise_reduction_ratio"], 0.3)
        e = event_stats(r.event for r in self.results.values())
        self.assertEqual(e["by_category"]["credential_exposure"], 3)


class DedupTests(unittest.TestCase):
    def test_simhash_near_duplicate(self):
        a = normalize(load_items()[1])
        b = normalize({**load_items()[1], "metadata": {**load_items()[1]["metadata"], "uid": "x"}})
        self.assertLessEqual(dedup.hamming(dedup.simhash(a), dedup.simhash(b)), 3)
        c = normalize(load_items()[7])
        self.assertGreater(dedup.hamming(dedup.simhash(a), dedup.simhash(c)), 3)


class AnalyticsTests(unittest.TestCase):
    def test_burst(self):
        from collections import Counter
        per_day = {f"2026-11-{d:02d}": Counter({"credential_exposure": 2}) for d in range(1, 15)}
        per_day["2026-11-15"] = Counter({"credential_exposure": 40})
        bursts = detect_bursts(per_day)
        self.assertEqual(bursts[0]["day"], "2026-11-15")


class LearningTests(unittest.TestCase):
    def test_logistic_learns_separable(self):
        X = [[1.0, 0.0]] * 20 + [[0.0, 1.0]] * 20
        y = [1] * 20 + [0] * 20
        m = LogisticLearner(n_features=2, epochs=50).fit(X, y)
        self.assertGreater(m.predict_proba([1.0, 0.0]), 0.8)
        self.assertLess(m.predict_proba([0.0, 1.0]), 0.2)

    def test_blend_weight_grows(self):
        p1, a1 = blend(0.2, 0.9, 10, 200)
        p2, a2 = blend(0.2, 0.9, 1000, 200)
        self.assertLess(a1, a2)
        self.assertLess(p1, p2)

    def test_isolation_forest_flags_outlier(self):
        import random
        rng = random.Random(0)
        X = [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(300)]
        f = IsolationForest(n_trees=50, sample_size=128).fit(X)
        self.assertGreater(f.score([8.0, 8.0]), f.score([0.0, 0.0]))


class JiraTests(unittest.TestCase):
    def test_dry_run_is_local_and_idempotent(self):
        cfg = load_triage_config()
        store = StateStore()
        res = TriageEngine(cfg, store, now=NOW).triage(normalize(load_items()[1]))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "jira.jsonl"
            calls = []
            exp = JiraExporter(JiraSettings("", "", "", "CTI", dry_run=True), store,
                               transport=lambda *a: calls.append(a) or (500, b""), dry_run_path=out)
            k1, k2 = exp.export(res), exp.export(res)
            self.assertEqual(k1, k2)
            self.assertEqual(calls, [])                      # rien n'est envoyé
            self.assertEqual(len(out.read_text().splitlines()), 1)

    def test_issue_fields(self):
        cfg = load_triage_config()
        res = TriageEngine(cfg, StateStore(), now=NOW).triage(normalize(load_items()[0]))
        f = build_issue_fields(res, JiraSettings("", "", "", "CTI"))
        self.assertIn("flare-evt-001", f["labels"])
        self.assertEqual(f["description"]["type"], "doc")


if __name__ == "__main__":
    unittest.main()
