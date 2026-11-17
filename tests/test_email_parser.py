from pathlib import Path

import pytest

from modules.email_parser import EmailParseError, parse_eml_bytes, parse_raw_text

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return parse_eml_bytes((SAMPLES / name).read_bytes(), name)


def test_extracts_core_headers():
    p = load("legitimate_email.eml")
    assert p.from_addr == "statements@examplebank.example"
    assert p.from_domain == "examplebank.example"
    assert p.subject == "Your October statement is ready"
    assert p.return_path_addr == "bounce@examplebank.example"
    assert p.message_id_domain == "app-server.examplebank.example"
    assert p.date_dt is not None
    assert len(p.received) == 3
    assert len(p.authentication_results) == 1


def test_received_kept_newest_first():
    p = load("legitimate_email.eml")
    assert "filter.recipient.example" in p.received[0]
    assert "app-server.examplebank.example" in p.received[-1]


def test_reply_to_and_x_originating_ip():
    p = load("phishing_email.eml")
    assert p.reply_to_addrs == ["support-desk@secure-verify.example.net"]
    assert p.x_originating_ip == ["[198.51.100.77]"]


def test_missing_headers_are_reported_not_invented():
    p = load("suspicious_email.eml")
    assert p.x_originating_ip == []
    assert dict(p.metadata_rows())["X-Originating-IP"] == "(not present)"


def test_paste_raw_headers():
    p = parse_raw_text("From: A <a@x.example>\nSubject: Hi\nReceived: from a (a [192.0.2.1]) by b; Tue, 10 Nov 2026 09:00:00 +0000\n")
    assert p.from_addr == "a@x.example"
    assert len(p.received) == 1


def test_encoded_subject_decoded():
    p = parse_raw_text("From: a@x.example\nSubject: =?utf-8?B?SGVsbG8gV29ybGQ=?=\n")
    assert p.subject == "Hello World"


@pytest.mark.parametrize("data", [b"", b"\x00\x01\x02binary", b"just some random text with no headers"])
def test_invalid_input_rejected(data):
    with pytest.raises(EmailParseError):
        parse_eml_bytes(data)


def test_empty_paste_rejected():
    with pytest.raises(EmailParseError):
        parse_raw_text("   \n ")


def test_oversized_file_rejected():
    with pytest.raises(EmailParseError):
        parse_eml_bytes(b"From: a@b.example\n" + b"x" * (11 * 1024 * 1024))


def test_malformed_date_does_not_crash():
    p = parse_raw_text("From: a@x.example\nDate: not a date\n")
    assert p.date_dt is None
    assert any("Date" in w for w in p.warnings)


def test_attachment_listed_not_decoded():
    raw = ("From: a@x.example\nSubject: s\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=B\n\n"
           "--B\nContent-Type: text/plain\n\nhi\n--B\nContent-Type: application/octet-stream\n"
           "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\nContent-Transfer-Encoding: base64\n\nTVqQAAMAAAA=\n--B--\n")
    p = parse_raw_text(raw)
    assert p.attachments[0]["filename"] == "invoice.pdf.exe"
    assert p.attachments[0]["double_extension"] is True


def test_duplicate_from_flagged():
    p = parse_raw_text("From: a@x.example\nFrom: b@y.example\nSubject: s\n")
    assert p.from_count == 2
