from pathlib import Path

from modules.authentication_checker import analyze_authentication, map_result
from modules.email_parser import parse_eml_bytes
from modules.pipeline import analyze_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def run(name):
    return analyze_email(parse_eml_bytes((SAMPLES / name).read_bytes(), name))


def test_all_pass():
    a = run("legitimate_email.eml")["auth"]
    assert (a["spf"].status, a["dkim"].status, a["dmarc"].status) == ("PASS", "PASS", "PASS")
    assert a["spf"].domain == "examplebank.example" and a["dkim"].domain == "examplebank.example"


def test_all_fail():
    a = run("phishing_email.eml")["auth"]
    assert (a["spf"].status, a["dkim"].status, a["dmarc"].status) == ("FAIL", "FAIL", "FAIL")


def test_incomplete_is_unknown_not_pass():
    a = run("suspicious_email.eml")["auth"]
    assert a["spf"].status == "NONE"
    assert a["dkim"].status == "UNKNOWN" and a["dmarc"].status == "UNKNOWN"


def test_missing_header_is_unknown_never_pass():
    a = analyze_authentication([], [], [])
    assert all(a[k].status == "UNKNOWN" for k in ("spf", "dkim", "dmarc"))
    assert a["has_auth_results_header"] is False


def test_dkim_signature_without_verdict_stays_unknown():
    a = analyze_authentication([], [], ["v=1; a=rsa-sha256; d=x.example; s=s1; b=abc"])
    assert a["dkim"].status == "UNKNOWN" and "x.example" in a["dkim"].detail


def test_softfail_maps_to_fail_and_neutral_to_none():
    assert map_result("softfail") == "FAIL" and map_result("neutral") == "NONE"
    assert map_result("temperror") == "UNKNOWN" and map_result("garbage") == "UNKNOWN"


def test_received_spf_fallback():
    a = analyze_authentication([], ["pass (domain of a@x.example designates 192.0.2.1 as permitted sender) receiver=mx"], [])
    assert a["spf"].status == "PASS" and "Received-SPF" in a["spf"].source


def test_only_topmost_authentication_results_used():
    forged = "evil.example; spf=pass smtp.mailfrom=a@x.example; dkim=pass header.d=x.example; dmarc=pass header.from=x.example"
    real = "mx.recipient.example; spf=fail smtp.mailfrom=a@x.example; dkim=fail header.d=x.example; dmarc=fail header.from=x.example"
    a = analyze_authentication([real, forged], [], [])
    assert a["spf"].status == "FAIL"
    assert any("different servers" in n for n in a["notes"])


def test_multiple_dkim_any_pass():
    h = "mx.example; dkim=fail header.d=a.example; dkim=pass header.d=b.example; spf=pass smtp.mailfrom=b.example"
    assert analyze_authentication([h], [], [])["dkim"].status == "PASS"


def test_semicolon_in_comment_does_not_break_parsing():
    h = "mx.example; spf=pass (sender ok; ip matched) smtp.mailfrom=a@x.example; dmarc=pass header.from=x.example"
    a = analyze_authentication([h], [], [])
    assert a["spf"].status == "PASS" and a["dmarc"].status == "PASS"


def test_risk_levels_for_samples():
    assert run("legitimate_email.eml")["risk"]["level"] == "LOW RISK"
    assert run("suspicious_email.eml")["risk"]["level"] == "MEDIUM RISK"
    assert run("phishing_email.eml")["risk"]["level"] == "HIGH RISK"


def test_phishing_sample_indicators():
    titles = " | ".join(i["title"] for i in run("phishing_email.eml")["indicators"])
    for expected in ("impersonation", "Reply-To", "SPF check failed", "DKIM check failed", "DMARC check failed", "does not connect"):
        assert expected in titles


def test_legit_domain_not_flagged_as_impersonation():
    titles = " ".join(i["title"] for i in run("legitimate_email.eml")["indicators"])
    assert "impersonation" not in titles


def test_pdf_report_generates_for_every_sample():
    from modules.report_generator import generate_pdf_report
    for n in ("legitimate_email.eml", "phishing_email.eml", "suspicious_email.eml"):
        assert generate_pdf_report(run(n)).startswith(b"%PDF")
