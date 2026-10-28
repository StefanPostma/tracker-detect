"""Tests voor trackerscan. Draaien met: python -m pytest

Alles hier werkt met nagemaakte advertenties; er is geen Bluetooth voor nodig.
"""

import argparse
import io
import json

import pytest
from bleak.backends.scanner import AdvertisementData
from rich.console import Console

import trackerscan as ts

FD5A = ts.full_uuid(0xFD5A)
FEAA = ts.full_uuid(0xFEAA)


def adv(rssi=-60, name=None, md=None, sd=None, su=None):
    return AdvertisementData(name, md or {}, sd or {}, su or [], None, rssi, ())


class FakeBLEDevice:
    def __init__(self, address, name=None):
        self.address = address
        self.name = name


@pytest.fixture
def clock(monkeypatch):
    """Bestuurbare klok voor alles wat time.time() gebruikt."""
    now = [1_000_000.0]
    monkeypatch.setattr(ts.time, "time", lambda: now[0])
    return now


def make_args(*extra, tmp_path=None):
    args = ts.parse_args(["--web", "8765", *extra])
    if tmp_path is not None:
        args.baseline_file = tmp_path / "baseline.json"
    return args


def classify(**kwargs):
    state = ts.ScanState("scan", [], None, None)
    state.on_advert(FakeBLEDevice("X"), adv(**kwargs))
    return state.devices["X"]


# ---------------------------------------------------------------------------
# Hulpjes
# ---------------------------------------------------------------------------


def test_uuid_helpers():
    assert ts.full_uuid(0xFEED) == "0000feed-0000-1000-8000-00805f9b34fb"
    assert ts.short_uuid("0000FEED-0000-1000-8000-00805F9B34FB") == "0xFEED"
    assert ts.short_uuid("12345678-1234-1234-1234-123456789abc") == "12345678-1234-1234-1234-123456789abc"
    assert ts.norm_id("1a2b-3c:4d") == "1A2B3C4D"


@pytest.mark.parametrize("value", ["1A2B3C4D", "1a2b3c4d-0000", "AA:BB:CC:DD"])
def test_ignore_prefix_accepts_addresses(value):
    assert ts.ignore_prefix(value) == ts.norm_id(value)


@pytest.mark.parametrize("value", ["AirTag", "12", "xyz!"])
def test_ignore_prefix_rejects_garbage(value):
    with pytest.raises(argparse.ArgumentTypeError):
        ts.ignore_prefix(value)


# ---------------------------------------------------------------------------
# Herkenning
# ---------------------------------------------------------------------------

SMARTTAG_TAIL = bytes(11)  # bytes 1..11; byte 12 = vlaggen

CASES = [
    # (advertentie, label, stuk detailtekst of None, los van eigenaar)
    (dict(md={0x004C: bytes([0x12, 0x19, 0x10]) + bytes(23)}),
     "AirTag / Find My-tag (mogelijk)", "AirTag, batterij vol", True),
    (dict(md={0x004C: bytes([0x12, 0x02, 0x50, 0x01])}),
     "AirTag / Find My-tag (mogelijk)", "eigenaar dichtbij, AirTag, batterij half", False),
    (dict(sd={FD5A: bytes([0x14]) + SMARTTAG_TAIL + bytes([0x03])}), "Samsung SmartTag", "eigenaar dichtbij", False),
    (dict(sd={FD5A: bytes([0x11]) + SMARTTAG_TAIL + bytes([0x02])}), "Samsung SmartTag", "net los van eigenaar", False),
    (dict(sd={FD5A: bytes([0x12]) + SMARTTAG_TAIL + bytes([0x07])}), "Samsung SmartTag", "met UWB", True),
    (dict(sd={FD5A: bytes([0x13]) + SMARTTAG_TAIL + bytes([0x00])}), "Samsung SmartTag", "(al lang)", True),
    (dict(sd={FD5A: bytes([0x42, 0x00])}), "Samsung SmartTag (waarschijnlijk)", None, False),
    (dict(md={0x0075: b"\x02\x18"}), "Samsung SmartTag (mogelijk)", None, False),
    (dict(su=[ts.full_uuid(0xFEED)]), "Tile", None, False),
    (dict(md={0x067C: b"\x01"}), "Tile", None, False),
    (dict(su=[ts.full_uuid(0xFE33)]), "Chipolo", None, False),
    (dict(md={0x08C3: b"\x01"}), "Chipolo", None, False),
    (dict(name="Chipolo ONE"), "Chipolo", None, False),
    (dict(sd={FEAA: b"\x41" + bytes(20)}), "Google Find Hub-tag (mogelijk)", "unwanted-tracking-modus", True),
    (dict(sd={FEAA: b"\x40" + bytes(20)}), "Google Find Hub-tag (mogelijk)", "normale modus", False),
    (dict(sd={FEAA: b"\x10\x00"}), "Eddystone-beacon", None, False),
    (dict(md={0x004C: b"\x02\x15" + bytes(21)}), "iBeacon", None, False),
    (dict(name="iTAG            "), "iTag-sleutelvinder", "geen netwerk", False),
    (dict(name="MLE-15"), "iTag-sleutelvinder", "geen netwerk", False),
    (dict(md={0x004C: b"\x07\x19\x01"}), "Apple AirPods/Beats", None, False),
    (dict(md={0x004C: b"\x10\x05\x01"}), "Apple-apparaat (iPhone/iPad/Mac/Watch)", None, False),
    (dict(name="Smart Tag"), ts.UNKNOWN_LABEL, None, False),
    (dict(name="Vitag speaker"), ts.UNKNOWN_LABEL, None, False),
    (dict(), ts.UNKNOWN_LABEL, None, False),
]


@pytest.mark.parametrize("advert, label, detail, separated", CASES)
def test_classification(advert, label, detail, separated):
    dev = classify(**advert)
    assert dev.label == label
    if detail:
        assert detail in dev.detail
    assert (ts.SEPARATED in dev.detail) is separated


def test_label_is_sticky():
    """Een later pakket met minder informatie mag een tracker niet 'degraderen'."""
    state = ts.ScanState("scan", [], None, None)
    state.on_advert(FakeBLEDevice("X"), adv(md={0x004C: bytes([0x12, 0x19, 0x10]) + bytes(23)}))
    state.on_advert(FakeBLEDevice("X"), adv(md={0x004C: b"\x10\x05\x01"}))
    dev = state.devices["X"]
    assert dev.kind == "tracker"
    assert ts.SEPARATED in dev.detail


def test_rule_without_criteria_never_matches():
    assert not ts.Rule("leeg", "info").matches(ts.Device("X", first_seen=0))


# ---------------------------------------------------------------------------
# Signaalsterkte
# ---------------------------------------------------------------------------


def test_rssi_statistics_ignore_unavailable_values():
    state = ts.ScanState("scan", [], None, None)
    for rssi in (-60, -70, -50, 127):  # 127 = "niet beschikbaar" volgens CoreBluetooth
        state.on_advert(FakeBLEDevice("X"), adv(rssi=rssi))
    dev = state.devices["X"]
    assert (dev.rssi, dev.rssi_min, dev.rssi_max) == (-50, -70, -50)
    assert dev.rssi_avg == pytest.approx(-60)
    assert dev.rssi_smooth == pytest.approx(-60)
    assert dev.count == 4


@pytest.mark.parametrize("samples, expected", [
    ([-80, -80, -80, -70, -70, -70], 1),
    ([-60, -60, -60, -70, -70, -70], -1),
    ([-60, -61, -60, -61, -60, -61], 0),
    ([-60, -50], 0),  # te weinig metingen
])
def test_trend(samples, expected):
    state = ts.ScanState("scan", [], None, None)
    for rssi in samples:
        state.on_advert(FakeBLEDevice("X"), adv(rssi=rssi))
    assert state.devices["X"].trend == expected


def test_ignore_by_prefix():
    state = ts.ScanState("scan", [ts.ignore_prefix("1a2b3c4d")], None, None)
    state.on_advert(FakeBLEDevice("1A2B3C4D-0000-0000-0000-000000000000"), adv())
    state.on_advert(FakeBLEDevice("FFFF0000-0000-0000-0000-000000000000"), adv())
    assert list(state.devices) == ["FFFF0000-0000-0000-0000-000000000000"]
    assert len(state.ignored) == 1


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_baseline_roundtrip(tmp_path):
    state = ts.ScanState("baseline", [], None, None)
    state.on_advert(FakeBLEDevice("aaaa"), adv(name="Iets"))
    path = tmp_path / "baseline.json"
    ts.save_baseline(path, state.devices, 60)
    baseline = ts.load_baseline(path)
    assert baseline.addresses == {"AAAA"}
    assert json.loads(path.read_text())["apparaten"]["AAAA"]["naam"] == "Iets"


def test_capture_baseline_marks_only_later_devices_new(tmp_path):
    state = ts.ScanState("scan", [], None, None)
    state.on_advert(FakeBLEDevice("OUD"), adv())
    ts.capture_baseline(state, tmp_path / "baseline.json")
    state.on_advert(FakeBLEDevice("NIEUW"), adv())
    assert state.devices["OUD"].is_new is False
    assert state.devices["NIEUW"].is_new is True


# ---------------------------------------------------------------------------
# Rit: "rijdt mee"
# ---------------------------------------------------------------------------


def drive(state, clock, address, seconds, every=10, rssi=-80):
    for _ in range(int(seconds // every)):
        clock[0] += every
        state.on_advert(FakeBLEDevice(address), adv(rssi=rssi))


def test_device_present_for_whole_drive_rides_along(clock):
    state = ts.ScanState("scan", [], None, None, follow_after=300)
    state.drive_start = clock[0]
    drive(state, clock, "TAG", 6 * 60)
    dev = state.devices["TAG"]
    assert state.ride_seconds(dev, clock[0]) >= 300
    assert state.rides_along(dev, clock[0])


def test_gap_restarts_the_streak(clock):
    state = ts.ScanState("scan", [], None, None, follow_after=300)
    state.drive_start = clock[0]
    drive(state, clock, "AUTO", 4 * 60)
    clock[0] += ts.PRESENCE_GAP + 30  # even uit beeld, bv. een auto die voor het stoplicht stond
    drive(state, clock, "AUTO", 2 * 60)
    assert not state.rides_along(state.devices["AUTO"], clock[0])


def test_presence_before_drive_start_does_not_count(clock):
    """Wat thuis al te zien was, telt pas mee vanaf de start van de rit."""
    state = ts.ScanState("scan", [], None, None, follow_after=300)
    drive(state, clock, "THUIS", 30 * 60)
    state.drive_start = clock[0]
    drive(state, clock, "THUIS", 60)
    assert state.ride_seconds(state.devices["THUIS"], clock[0]) == pytest.approx(60)
    assert not state.rides_along(state.devices["THUIS"], clock[0])


def test_device_out_of_range_no_longer_rides(clock):
    state = ts.ScanState("scan", [], None, None, follow_after=300)
    state.drive_start = clock[0]
    drive(state, clock, "TAG", 6 * 60)
    clock[0] += ts.PRESENCE_GAP + 1
    assert not state.rides_along(state.devices["TAG"], clock[0])


def test_no_drive_means_nothing_rides(clock):
    state = ts.ScanState("scan", [], None, None, follow_after=300)
    drive(state, clock, "TAG", 30 * 60)
    assert not state.rides_along(state.devices["TAG"], clock[0])


def test_riders_sort_first(clock):
    state = ts.ScanState("scan", [], None, None, follow_after=60)
    state.drive_start = clock[0]
    drive(state, clock, "ZWAK_MEE", 120, rssi=-90)
    state.on_advert(FakeBLEDevice("STERK_VOORBIJ"), adv(rssi=-40))
    order = [d.address for d in ts.visible_devices(state, make_args(), clock[0])]
    assert order == ["ZWAK_MEE", "STERK_VOORBIJ"]


# ---------------------------------------------------------------------------
# Minimaal signaal
# ---------------------------------------------------------------------------


def test_min_rssi_hides_weak_devices_but_never_riders(clock):
    state = ts.ScanState("scan", [], None, None, follow_after=60)
    state.drive_start = clock[0]
    drive(state, clock, "ZWAKKE_TRACKER", 120, rssi=-90)
    state.on_advert(FakeBLEDevice("VER_WEG"), adv(rssi=-90))
    state.on_advert(FakeBLEDevice("DICHTBIJ"), adv(rssi=-50))
    visible = {d.address for d in ts.visible_devices(state, make_args("--min-rssi", "-75"), clock[0])}
    assert visible == {"ZWAKKE_TRACKER", "DICHTBIJ"}


@pytest.mark.parametrize("seconds, text", [(30, "30 s"), (59.6, "60 s"), (60, "1 min"), (330, "5 min")])
def test_fmt_minutes(seconds, text):
    assert ts.fmt_minutes(seconds) == text


@pytest.mark.parametrize("value", ["0", "5", "-200", "abc"])
def test_min_rssi_rejects_nonsense(value):
    with pytest.raises(SystemExit):
        ts.parse_args(["--min-rssi", value])


def test_render_smoke(clock):
    """De terminaltabel bouwt zonder fouten op, ook met rit, filter en baseline."""
    state = ts.ScanState("scan", [], ts.Baseline(set(), "nu"), None, follow_after=60)
    state.drive_start = clock[0]
    drive(state, clock, "TAG", 120)
    state.on_advert(FakeBLEDevice("APPLE"), adv(md={0x004C: bytes([0x12, 0x19, 0x10]) + bytes(23)}))
    console = Console(file=io.StringIO(), width=160, height=40)
    console.print(ts.render(state, console, make_args("--min-rssi", "-95"), ts.Text("test")))
    output = console.file.getvalue()
    assert "rijden mee" in output and "MEE" in output and "NIEUW" in output


# ---------------------------------------------------------------------------
# Leveranciers
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_vendors(monkeypatch):
    table = ts.Vendors(companies={0x0006: "Microsoft"}, uuids={0xFCF1: "Google LLC"},
                       oui={"A4C138": "Telink", "70B3D5": "IEEE Registration Authority", "70B3D51AB": "Klein blok"})
    monkeypatch.setattr(ts, "vendors", lambda: table)
    return table


def test_vendor_hints(fake_vendors):
    dev = ts.Device("X", first_seen=0)
    dev.manufacturer_data = {0x0006: b"\x01", 0xABCD: b"\x01", 0xFFFF: b"\x01"}
    dev.service_uuids = {ts.full_uuid(0xFCF1)}
    dev.mac = "A4:C1:38:00:00:01"
    hints = ts.vendor_hints(dev)
    assert "Microsoft (company-ID 0x0006)" in hints
    assert "onbekend bedrijf (company-ID 0xABCD)" in hints
    assert any(h.startswith("geen (testwaarde 0xFFFF") for h in hints)
    assert "Google LLC (service 0xFCF1)" in hints
    assert any(h.startswith("Telink (MAC-prefix A4:C1:38") for h in hints)
    assert ts.vendor_text(dev, with_source=False).startswith("leverancier: Microsoft; onbekend bedrijf")


def test_oui_prefers_most_specific_block(fake_vendors):
    assert ts.oui_vendor("70:B3:D5:1A:B0:00") == "Klein blok"
    assert ts.oui_vendor("70:B3:D5:FF:00:00") == "IEEE Registration Authority"
    assert ts.oui_vendor("12:34:56:00:00:00") is None


def test_parse_sig_pairs():
    text = """uuids:
  - uuid: 0xFEED
    name: "Tile, Inc."
  - uuid: 0xFE33
    name: CHIPOLO d.o.o.
company_identifiers:
  - value: 0x08C3
    name: 'O''Brien Labs'
"""
    assert ts.parse_sig_pairs(text, "uuid") == {"FEED": "Tile, Inc.", "FE33": "CHIPOLO d.o.o."}
    assert ts.parse_sig_pairs(text, "value") == {"08C3": "O'Brien Labs"}


def test_parse_oui():
    text = ("# commentaar\n"
            "00:00:00\t00:00:00\tOfficially Xerox\n"
            "A4:C1:38\tTelink\tTelink Semiconductor\n"
            "00:55:DA:A0:00:00/28\tKort\n"
            "70:B3:D5:1A:B0:00/36\tACS\tAccess Control Systems\n")
    assert ts.parse_oui(text) == {"A4C138": "Telink Semiconductor", "0055DAA": "Kort", "70B3D51AB": "Access Control Systems"}


# ---------------------------------------------------------------------------
# CSV-log
# ---------------------------------------------------------------------------


def test_csv_log_writes_header_once(tmp_path):
    path = tmp_path / "scan.csv"
    state = ts.ScanState("scan", [], None, None)
    for _ in range(2):
        log = ts.CsvLog(path)
        state.log = log
        state.on_advert(FakeBLEDevice("X"), adv(md={0x004C: b"\x10\x05\x01"}))
        log.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0].split(",") == ts.CSV_FIELDS
    assert len(lines) == 3 and not lines[2].startswith("timestamp")


# ---------------------------------------------------------------------------
# Webpagina: routering en beveiliging
# ---------------------------------------------------------------------------


def request(method, path, host="127.0.0.1:8765", **headers):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"] + [f"{k.replace('_', '-')}: {v}" for k, v in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


OWN = {"X_Trackerscan": "1", "Origin": "http://127.0.0.1:8765"}


@pytest.fixture
def web(tmp_path):
    state = ts.ScanState("scan", [], None, None)
    state.on_advert(FakeBLEDevice("X"), adv())
    return state, make_args(tmp_path=tmp_path)


def test_web_get_page_and_state(web):
    state, args = web
    assert ts.handle_request(request("GET", "/"), state, args)[0] == "200 OK"
    status, content_type, body = ts.handle_request(request("GET", "/api/state"), state, args)
    assert status == "200 OK" and content_type == "application/json"
    data = json.loads(body)
    assert data["devices"][0]["address"] == "X" and data["drive"] is None


@pytest.mark.parametrize("raw, expected", [
    (request("GET", "/api/state", host="evil.example:8765"), "403 Forbidden"),  # DNS-rebinding
    (request("PUT", "/api/state"), "405 Method Not Allowed"),
    (request("GET", "/bestaat-niet"), "404 Not Found"),
    (b"onzin\r\n\r\n", "400 Bad Request"),
])
def test_web_rejects_bad_requests(web, raw, expected):
    state, args = web
    assert ts.handle_request(raw, state, args)[0] == expected


@pytest.mark.parametrize("path", sorted(ts.POST_ACTIONS))
@pytest.mark.parametrize("headers", [
    {},
    {"X_Trackerscan": "1"},
    {"X_Trackerscan": "1", "Origin": "https://evil.example"},
    {"Origin": "http://127.0.0.1:8765"},
])
def test_web_actions_require_own_page(web, path, headers):
    """CSRF: zonder eigen header en Origin mag geen enkele actie iets veranderen."""
    state, args = web
    assert ts.handle_request(request("POST", path, **headers), state, args)[0] == "403 Forbidden"
    assert state.baseline is None and state.drive_start is None
    assert not args.baseline_file.exists()


def test_web_capture_baseline(web):
    state, args = web
    status, _, body = ts.handle_request(request("POST", "/api/baseline", **OWN), state, args)
    assert status == "200 OK" and json.loads(body)["count"] == 1
    assert args.baseline_file.exists() and state.devices["X"].is_new is False


def test_web_drive_start_and_stop(web):
    state, args = web
    assert ts.handle_request(request("POST", "/api/drive/start", **OWN), state, args)[0] == "200 OK"
    assert state.drive_start is not None
    assert json.loads(ts.state_json(state, args))["drive"]["follow_after"] == 300
    assert ts.handle_request(request("POST", "/api/drive/stop", **OWN), state, args)[0] == "200 OK"
    assert state.drive_start is None


def test_web_actions_blocked_during_baseline_phase(web):
    state, args = web
    state.phase = "baseline"
    assert ts.handle_request(request("POST", "/api/drive/start", **OWN), state, args)[0] == "409 Conflict"
