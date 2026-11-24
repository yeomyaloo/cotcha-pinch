"""score.py 채점 규칙 테스트 (LLM 없이). python -m unittest discover -s benchmark"""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import score

EXPECTED = Path(__file__).resolve().parent / "bank-app.expected.json"

PROVIDER = "app/src/main/java/com/example/bank/data/StatementProvider.java"
REPO = "app/src/main/java/com/example/bank/data/TransactionRepository.java"
MANIFEST = "app/src/main/AndroidManifest.xml"


def result(cwe, *locs, verdict="CONFIRMED", title="발견"):
    locations = [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}} for uri, line in locs]
    r = {"ruleId": cwe, "message": {"text": title}, "locations": locations[:1], "properties": {"verdict": verdict}}
    if len(locations) > 1:
        r["relatedLocations"] = locations[1:]
    return r


def sarif(*results):
    return {"version": "2.1.0", "runs": [{"results": list(results)}]}


class ScoreTest(unittest.TestCase):

    def setUp(self):
        self.expected = score.load_json(EXPECTED)
        self.total = len(self.expected["vulnerabilities"])

    def test_위치와_CWE가_맞으면_맞힌_것이다(self):
        r = score.score_run(sarif(
            result("CWE-89", (MANIFEST, 74), (PROVIDER, 27)),
            result("CWE-489", ("/home/me/bank-app/" + MANIFEST, 14)),
        ), self.expected, False)
        self.assertEqual(r["found"], ["config-debuggable", "sql-statement-provider"])
        self.assertEqual(r["precision"], 1.0)
        self.assertAlmostEqual(r["recall"], 2 / self.total)

    def test_같은_줄_범위라도_CWE로_취약점을_구별한다(self):
        r = score.score_run(sarif(result("CWE-530", (MANIFEST, 12)), result("CWE-321", ("app/src/main/java/com/example/bank/crypto/PinCrypto.java", 19))),
                            self.expected, False)
        self.assertEqual(r["found"], ["config-allow-backup", "crypto-hardcoded-key"])

    def test_함정을_취약점이라_하면_함정_오탐이다(self):
        r = score.score_run(sarif(result("CWE-89", (REPO, 20))), self.expected, False)
        self.assertEqual(r["found"], [])
        self.assertEqual(r["trapped"], ["sql-transaction-bound"])
        self.assertEqual(r["precision"], 0.0)

    def test_CWE가_다르면_분류_틀림이고_정답에_없으면_기타_오탐이다(self):
        r = score.score_run(sarif(
            result("CWE-79", (PROVIDER, 27)),
            result("CWE-200", ("app/src/main/java/com/example/bank/BankApp.java", 5)),
        ), self.expected, False)
        self.assertEqual([f["item"] for f in r["wrongCwe"]], ["sql-statement-provider"])
        self.assertEqual(len(r["other"]), 1)

    def test_기각된_발견은_빼고_CONFIRMED만_세기도_한다(self):
        s = sarif(result("CWE-89", (PROVIDER, 27), verdict="REJECTED"), result("CWE-926", (MANIFEST, 76), verdict="UNCERTAIN"))
        self.assertEqual(score.score_run(s, self.expected, False)["found"], ["exported-statement-provider"])
        self.assertEqual(score.score_run(s, self.expected, True)["findings"], 0)

    def test_실행마다_결과가_다르면_일관성이_떨어진다(self):
        a = sarif(result("CWE-89", (PROVIDER, 27)), result("CWE-926", (MANIFEST, 76)))
        b = sarif(result("CWE-89", (PROVIDER, 27)), result("CWE-89", (REPO, 20)))
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, s in enumerate([a, a, b]):
                p = Path(d) / f"report-{i}.sarif"
                p.write_text(json.dumps(s), encoding="utf-8")
                paths.append(str(p))
            out = Path(d) / "score.json"
            with redirect_stdout(io.StringIO()) as text:
                code = score.main([str(EXPECTED), *paths, "--json", str(out), "--min-recall", "0.5"])
            report = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        c = report["consistency"]
        self.assertEqual(c["perItem"]["sql-statement-provider"]["hits"], 3)
        self.assertEqual(c["perItem"]["exported-statement-provider"]["hits"], 2)
        self.assertEqual(c["perItem"]["sql-transaction-bound"]["hits"], 1)
        self.assertEqual(c["stableItems"], c["totalItems"] - 2)
        self.assertIn("실행마다 달랐던 항목: exported-statement-provider(2/3), sql-transaction-bound(1/3)", text.getvalue())


if __name__ == "__main__":
    unittest.main()
