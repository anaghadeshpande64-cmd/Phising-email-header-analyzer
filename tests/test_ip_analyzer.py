from modules.ip_analyzer import (build_hops, classify_ip, extract_ips, identify_sender_ip,
                                 lookup_ip_intelligence, parse_received_header)


def test_classification():
    assert classify_ip("8.8.8.8").category == "public"
    assert classify_ip("10.1.2.3").category == "private"
    assert classify_ip("192.168.0.1").category == "private"
    assert classify_ip("127.0.0.1").category == "loopback"
    assert classify_ip("169.254.1.1").category == "link-local"
    assert classify_ip("100.64.0.1").category == "shared (CGNAT)"
    assert classify_ip("203.0.113.5").category == "documentation"
    assert classify_ip("::1").category == "loopback"
    assert classify_ip("2001:db8::1").category == "documentation"
    assert classify_ip("2606:4700:4700::1111").category == "public"
    assert classify_ip("8.8.8.8").is_public and not classify_ip("10.0.0.1").is_public


def test_extract_ips_ignores_times_and_garbage():
    text = "from x ([203.0.113.9]) at 09:15:03 version 999.1.1.1 and 10.0.0.1, ipv6 [2001:db8::5]"
    ips = extract_ips(text)
    assert "203.0.113.9" in ips and "10.0.0.1" in ips and "2001:db8::5" in ips
    assert "999.1.1.1" not in ips
    assert not any(i.startswith("09:") for i in ips)


def test_parse_received_header():
    h = parse_received_header("from mail.a.example (mail.a.example [203.0.113.7]) by mx.b.example with ESMTPS id 1; "
                              "Tue, 10 Nov 2026 09:15:03 +0000")
    assert h.helo == "mail.a.example" and h.from_ip == "203.0.113.7"
    assert h.by_host == "mx.b.example" and h.protocol == "ESMTPS"
    assert h.timestamp is not None


def test_unknown_rdns_flagged():
    h = parse_received_header("from [198.51.100.7] (unknown [198.51.100.7]) by relay.example.org with ESMTP; Tue, 10 Nov 2026 02:11:40 +0000")
    assert h.rdns_unknown and h.from_ip == "198.51.100.7"


def test_chronological_order():
    hops = build_hops(["from c (c [192.0.2.3]) by d; Tue, 10 Nov 2026 09:03:00 +0000",
                       "from a (a [192.0.2.1]) by b; Tue, 10 Nov 2026 09:01:00 +0000"])
    assert hops[0].by_host == "b" and hops[0].index == 1
    assert hops[1].timestamp > hops[0].timestamp


def test_time_reversal_detected():
    hops = build_hops(["from b (b [192.0.2.2]) by c; Tue, 10 Nov 2026 08:00:00 +0000",
                       "from a (a [192.0.2.1]) by b; Tue, 10 Nov 2026 10:00:00 +0000"])
    assert hops[1].time_ok is False


def test_chain_break_detected():
    hops = build_hops(["from other.example (other.example [192.0.2.2]) by c.example; Tue, 10 Nov 2026 10:05:00 +0000",
                       "from a.example (a.example [192.0.2.1]) by b.example; Tue, 10 Nov 2026 10:00:00 +0000"])
    assert hops[1].link_ok is False


def test_first_ip_is_not_assumed_sender():
    # Oldest hop is an internal client; the external IP is the handoff to the first outside-facing server.
    hops = build_hops(["from relay.example.com (relay.example.com [203.0.113.50]) by mx.example.org; Tue, 10 Nov 2026 10:00:05 +0000",
                       "from [10.0.0.5] (pc [10.0.0.5]) by relay.example.com; Tue, 10 Nov 2026 10:00:03 +0000"])
    res = identify_sender_ip(hops)
    assert res.ip == "203.0.113.50"
    assert "cannot be reliably determined" in res.origin_statement
    assert res.confidence != "Verified"


def test_no_external_ip_is_undetermined():
    hops = build_hops(["from a (a [10.0.0.9]) by b; Tue, 10 Nov 2026 10:00:00 +0000"])
    res = identify_sender_ip(hops)
    assert res.ip is None and res.confidence == "Undetermined"
    assert "cannot be reliably determined" in res.origin_statement


def test_no_received_headers():
    res = identify_sender_ip([])
    assert res.ip is None and res.confidence == "Undetermined"


def test_single_hop_is_low_confidence():
    res = identify_sender_ip(build_hops(["from a.example (a.example [203.0.113.9]) by b.example; Tue, 10 Nov 2026 10:00:00 +0000"]))
    assert res.ip == "203.0.113.9" and res.confidence == "Low"


def test_intel_not_configured_returns_no_invented_data(monkeypatch):
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr("modules.ip_analyzer._ENV_LOADED", True)
    r = lookup_ip_intelligence("8.8.8.8")
    assert r["status"] == "not_configured"
    assert r["geolocation"] is None and r["reputation"] is None


def test_intel_skips_private_ip():
    assert lookup_ip_intelligence("10.0.0.1")["status"] == "skipped"
