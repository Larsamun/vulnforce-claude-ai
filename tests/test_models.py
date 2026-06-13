from vulnforge.models import (
    Finding, Engine, Severity, Confidence, dedupe, sort_findings,
    severity_counts, mask_secret,
)


def _f(**kw):
    base = dict(source="semgrep", engine=Engine.SAST, category="injection",
               severity=Severity.HIGH, title="x")
    base.update(kw)
    return Finding(**base)


def test_severity_parse_aliases():
    assert Severity.parse("ERROR") is Severity.HIGH
    assert Severity.parse("warning") is Severity.MEDIUM
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse("nonsense") is Severity.MEDIUM
    assert Severity.parse(None) is Severity.MEDIUM


def test_fingerprint_stable_and_dedup():
    a = _f(file="a.py", line=10, rule_id="r1")
    b = _f(file="a.py", line=10, rule_id="r1", severity=Severity.CRITICAL)
    assert a.fingerprint() == b.fingerprint()
    out = dedupe([a, b])
    assert len(out) == 1
    # higher severity wins
    assert out[0].severity is Severity.CRITICAL


def test_sort_orders_by_severity_then_confidence():
    low = _f(severity=Severity.LOW, title="low")
    high_possible = _f(severity=Severity.HIGH, title="hp", confidence=Confidence.POSSIBLE, rule_id="a")
    high_confirmed = _f(severity=Severity.HIGH, title="hc", confidence=Confidence.CONFIRMED, rule_id="b")
    ordered = sort_findings([low, high_possible, high_confirmed])
    assert ordered[0].title == "hc"
    assert ordered[-1].title == "low"


def test_severity_counts():
    counts = severity_counts([_f(severity=Severity.HIGH), _f(severity=Severity.LOW, rule_id="z")])
    assert counts["high"] == 1 and counts["low"] == 1 and counts["critical"] == 0


def test_mask_secret_hides_value():
    m = mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" not in m
    assert "redacted" in m
