#!/usr/bin/env python3
"""trackerscan — BLE-trackerscanner voor macOS (bleak + CoreBluetooth).

Scant continu naar Bluetooth Low Energy-advertisers en herkent bekende trackers
(AirTag/Find My, Samsung SmartTag, Tile, Chipolo, Google Find Hub) en beacons
aan hun advertisement-data. Bedoeld om te controleren of er een onbekende
tracker in of aan je auto zit.

    python3 trackerscan.py                     live scannen
    python3 trackerscan.py --baseline 60       eerst 60 s baseline (ver van de auto)
    python3 trackerscan.py --log scan.csv      alle samples naar CSV
    python3 trackerscan.py --ignore 1A2B3C4D   apparaat negeren (ID-prefix volstaat)
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import functools
import json
import re
import sys
import time
import urllib.request
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import fmean
from typing import Callable

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    from bleak.exc import BleakError
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.markup import escape
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:
    sys.exit(f"Ontbrekende module '{exc.name}'. Installeer eerst: pip install -r requirements.txt")


# ---------------------------------------------------------------------------
# UUID-hulpjes
# ---------------------------------------------------------------------------

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def full_uuid(value: int | str) -> str:
    """0xFEED of een volledige UUID → volledige lowercase UUID, zoals bleak die levert."""
    if isinstance(value, int):
        return f"0000{value:04x}{BASE_UUID_SUFFIX}"
    return value.lower()


def short_uuid(uuid: str) -> str:
    """Volledige UUID → '0xFEED' als het een Bluetooth SIG-basis-UUID is, anders ongewijzigd."""
    u = uuid.lower()
    if u.startswith("0000") and u.endswith(BASE_UUID_SUFFIX):
        return "0x" + u[4:8].upper()
    return u


def norm_id(value: str) -> str:
    """Adres/UUID zonder streepjes of dubbele punten, in hoofdletters (voor prefix-vergelijking)."""
    return re.sub(r"[^0-9A-F]", "", value.upper())


# ---------------------------------------------------------------------------
# Per apparaat bijgehouden toestand
# ---------------------------------------------------------------------------

UNKNOWN_LABEL = "onbekend BLE-apparaat"
RSSI_WINDOW = 10  # aantal samples voor het gemiddelde en de trend


@dataclass
class Device:
    address: str  # op macOS een door CoreBluetooth toegekende UUID, geen MAC-adres
    first_seen: float
    last_seen: float = 0.0
    count: int = 0
    name: str | None = None
    rssi: int | None = None
    rssi_min: int | None = None
    rssi_max: int | None = None
    samples: deque[int] = field(default_factory=lambda: deque(maxlen=RSSI_WINDOW))
    # Advertentiedata wordt over alle pakketten samengevoegd (advertisement + scan response).
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_uuids: set[str] = field(default_factory=set)
    service_data: dict[str, bytes] = field(default_factory=dict)
    tx_power: int | None = None
    rule_index: int | None = None  # beste (laagste) regel die ooit matchte; blijft staan
    detail: str = ""
    is_new: bool | None = None  # None = geen baseline geladen
    mac: str | None = None  # echt Bluetooth-adres, als macOS het prijsgeeft
    mac_tries: int = 0

    def update(self, adv: AdvertisementData, fallback_name: str | None, now: float) -> None:
        self.count += 1
        self.last_seen = now
        self.name = adv.local_name or fallback_name or self.name
        self.manufacturer_data.update(adv.manufacturer_data)
        self.service_uuids.update(u.lower() for u in adv.service_uuids)
        self.service_data.update({u.lower(): d for u, d in adv.service_data.items()})
        if adv.tx_power is not None:
            self.tx_power = adv.tx_power
        rssi = adv.rssi
        # CoreBluetooth meldt 127 als de RSSI niet beschikbaar is.
        if rssi is not None and -127 < rssi < 20:
            self.rssi = rssi
            self.samples.append(rssi)
            self.rssi_min = rssi if self.rssi_min is None else min(self.rssi_min, rssi)
            self.rssi_max = rssi if self.rssi_max is None else max(self.rssi_max, rssi)

    @property
    def all_uuids(self) -> set[str]:
        return self.service_uuids.union(self.service_data)

    @property
    def rule(self) -> Rule | None:
        return RULES[self.rule_index] if self.rule_index is not None else None

    @property
    def label(self) -> str:
        return self.rule.label if self.rule else UNKNOWN_LABEL

    @property
    def kind(self) -> str:
        return self.rule.kind if self.rule else "onbekend"

    @property
    def rssi_avg(self) -> float | None:
        """Gemiddelde over de laatste RSSI_WINDOW samples."""
        return fmean(self.samples) if self.samples else None

    @property
    def rssi_smooth(self) -> float | None:
        """Gemiddelde van de laatste 3 samples: reageert snel maar springt minder dan één sample."""
        return fmean(list(self.samples)[-3:]) if self.samples else None

    @property
    def trend(self) -> int:
        """+1 = warmer (signaal sterker), -1 = kouder, 0 = gelijk/onbekend."""
        if len(self.samples) < 6:
            return 0
        s = list(self.samples)
        diff = fmean(s[-3:]) - fmean(s[:-3])
        return 1 if diff >= 3 else -1 if diff <= -3 else 0


# ---------------------------------------------------------------------------
# Payload-decoders voor extra uitleg (heuristisch, op basis van publiek
# reverse-engineeringwerk: OpenHaystack / AirGuard / Google FMDN-spec)
# ---------------------------------------------------------------------------

APPLE = 0x004C
SAMSUNG = 0x0075
TILE_CO = 0x067C
CHIPOLO_CO = 0x08C3

SEPARATED = "LOS VAN EIGENAAR"  # in detail-tekst; wordt extra opvallend getoond
# Waarde 2 is in de praktijk gezien bij AirPods Pro; derden (bv. Chipolo Spot) vallen hier vermoedelijk ook onder.
FINDMY_TYPES = {0: "Apple-apparaat", 1: "AirTag", 2: "AirPods of Find My-accessoire", 3: "Find My-accessoire"}
FINDMY_BATTERY = {0: "vol", 1: "half", 2: "laag", 3: "bijna leeg"}


def findmy_detail(dev: Device) -> str:
    """Apple Find My (type 0x12): [0x12][lengte][status][...].

    Lengte 0x19 = volledige publieke sleutel → het apparaat is LOS VAN ZIJN
    EIGENAAR (dat is wat een tracker van iemand anders in jouw auto doet).
    Lengte 0x02 = korte 'nearby'-vorm → de iPhone van de eigenaar is dichtbij.
    Statusbyte: bits 4-5 = soort apparaat, bits 6-7 = batterij.
    """
    p = dev.manufacturer_data.get(APPLE, b"")
    if len(p) < 3 or p[0] != 0x12:
        return dev.detail
    length, status = p[1], p[2]
    state = SEPARATED if length >= 0x19 else "eigenaar dichtbij"
    return f"{state}, {FINDMY_TYPES[(status >> 4) & 0x03]}, batterij {FINDMY_BATTERY[status >> 6]}"


def findhub_detail(dev: Device) -> str:
    """Google Find Hub / FMDN (service data 0xFEAA, frame 0x40/0x41).

    Frame 0x41 = 'unwanted tracking protection'-modus, die de tag aanzet
    wanneer hij een tijd van zijn eigenaar gescheiden is.
    """
    frame = dev.service_data.get(full_uuid(0xFEAA), b"")[:1]
    if frame == b"\x41":
        return f"{SEPARATED} (unwanted-tracking-modus)"
    if frame == b"\x40":
        return "normale modus"
    return dev.detail


# Samsung SmartTag (service data 0xFD5A), volgens AirGuard (SamsungTracker.kt):
#   byte 0:  bits 3-7 = 0b00010 voor een tag (byte & 0xF8 == 0x10); Samsung-telefoons
#            gebruiken een andere UUID (0xFD69). Bits 0-2 = verbindingsstatus.
#   byte 12: bit 2 = UWB (SmartTag+/SmartTag 2), bits 0-1 = batterij.
SMARTTAG_PREFIXES = tuple(bytes([b]) for b in range(0x10, 0x18))
SMARTTAG_STATES = {1: "net los van eigenaar", 2: SEPARATED, 3: f"{SEPARATED} (al lang)"}
SMARTTAG_BATTERY = {3: "vol", 2: "half", 1: "laag", 0: "bijna leeg"}


def smarttag_detail(dev: Device) -> str:
    """'Net los' (premature offline) is nog normaal na kort weglopen; 'los' en
    'al lang los' (offline / overmature offline) zijn de toestanden waarin een
    tag van iemand anders zich in jouw auto zou bevinden."""
    data = dev.service_data.get(full_uuid(0xFD5A), b"")
    if not data or data[0] & 0xF8 != 0x10:
        return dev.detail
    parts = [SMARTTAG_STATES.get(data[0] & 0x07, "eigenaar dichtbij")]
    if len(data) > 12:
        if data[12] & 0x04:
            parts.append("met UWB (SmartTag+ of SmartTag 2)")
        parts.append(f"batterij {SMARTTAG_BATTERY[data[12] & 0x03]}")
    return ", ".join(parts)


def itag_detail(dev: Device) -> str:
    return "geen netwerk: werkt alleen binnen bereik van de telefoon van de eigenaar"


# ---------------------------------------------------------------------------
# Herkenningsregels — breid hier uit.
#
# Volgorde = prioriteit: de eerste regel die matcht bepaalt het label. Een
# apparaat houdt het beste label dat het ooit kreeg, ook als een later pakket
# minder informatie bevat.
#
# Binnen één regel moeten alle opgegeven criteria kloppen (EN); criteria die
# je weglaat tellen niet mee:
#   manufacturer_id       Bluetooth company ID (0x004C = Apple, 0x0075 = Samsung)
#   manufacturer_prefix   manufacturer-payload (zonder company ID) begint hiermee;
#                         bytes of tuple van bytes (één ervan volstaat)
#   service_uuids         minstens één van deze UUID's wordt geadverteerd (als
#                         service-UUID of als service-data); 16-bit int of volledige string
#   service_data_prefix   service-data van zo'n UUID begint hiermee
#   name_pattern          regex op de geadverteerde naam (hoofdletterongevoelig)
#   detail                optionele functie die extra uitleg uit de payload haalt
#
# kind: "tracker" en "beacon" worden gemarkeerd; "info" zijn bekende
# niet-trackers, alleen om ruis te herkennen.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    label: str
    kind: str
    manufacturer_id: int | None = None
    manufacturer_prefix: bytes | tuple[bytes, ...] = b""
    service_uuids: tuple[int | str, ...] = ()
    service_data_prefix: bytes | tuple[bytes, ...] = b""
    name_pattern: str | None = None
    detail: Callable[[Device], str] | None = None

    def matches(self, dev: Device) -> bool:
        if self.manufacturer_id is None and not self.service_uuids and not self.name_pattern:
            return False
        if self.manufacturer_id is not None:
            payload = dev.manufacturer_data.get(self.manufacturer_id)
            if payload is None or not payload.startswith(self.manufacturer_prefix):
                return False
        if self.service_uuids:
            wanted = {full_uuid(u) for u in self.service_uuids}
            if self.service_data_prefix:
                if not any(dev.service_data.get(u, b"").startswith(self.service_data_prefix) for u in wanted):
                    return False
            elif not wanted & dev.all_uuids:
                return False
        if self.name_pattern:
            if not dev.name or not re.search(self.name_pattern, dev.name, re.IGNORECASE):
                return False
        return True


RULES: list[Rule] = [
    # --- Trackers ----------------------------------------------------------
    Rule("AirTag / Find My-tag (mogelijk)", "tracker",
         manufacturer_id=APPLE, manufacturer_prefix=b"\x12", detail=findmy_detail),
    Rule("Samsung SmartTag", "tracker",
         service_uuids=(0xFD5A,), service_data_prefix=SMARTTAG_PREFIXES, detail=smarttag_detail),
    Rule("Samsung SmartTag (waarschijnlijk)", "tracker", service_uuids=(0xFD5A,)),
    Rule("Tile", "tracker", service_uuids=(0xFEED, 0xFEEC, 0xFD84)),
    Rule("Tile", "tracker", manufacturer_id=TILE_CO),
    Rule("Chipolo", "tracker", service_uuids=(0xFE33,)),
    Rule("Chipolo", "tracker", manufacturer_id=CHIPOLO_CO),
    Rule("Chipolo", "tracker", name_pattern=r"chipolo"),
    # Goedkope anti-verlies-sleutelhangers; geen crowd-netwerk, dus niet op afstand te volgen.
    Rule("iTag-sleutelvinder", "tracker", name_pattern=r"^\s*(i-?tag|mle-15)\b", detail=itag_detail),
    Rule("Google Find Hub-tag (mogelijk)", "tracker",
         service_uuids=(0xFEAA,), service_data_prefix=(b"\x40", b"\x41"), detail=findhub_detail),
    # Let op: ook Samsung-telefoons, -oordopjes en -tv's gebruiken 0x0075.
    Rule("Samsung SmartTag (mogelijk)", "tracker", manufacturer_id=SAMSUNG),
    # --- Generieke beacons -------------------------------------------------
    Rule("iBeacon", "beacon", manufacturer_id=APPLE, manufacturer_prefix=b"\x02\x15"),
    Rule("Eddystone-beacon", "beacon", service_uuids=(0xFEAA,)),
    # --- Bekende niet-trackers ---------------------------------------------
    Rule("Apple AirPods/Beats", "info", manufacturer_id=APPLE, manufacturer_prefix=b"\x07"),
    Rule("Apple-apparaat (iPhone/iPad/Mac/Watch)", "info", manufacturer_id=APPLE),
]

FLAGGED_KINDS = ("tracker", "beacon")


def classify(dev: Device) -> None:
    for i, rule in enumerate(RULES):
        if dev.rule_index is not None and i > dev.rule_index:
            return
        if rule.matches(dev):
            dev.rule_index = i
            if rule.detail:
                dev.detail = rule.detail(dev)
            return


# ---------------------------------------------------------------------------
# Formattering
# ---------------------------------------------------------------------------


def fmt_manufacturer(md: dict[int, bytes]) -> str:
    return ";".join(f"{cid:04X}:{data.hex()}" for cid, data in sorted(md.items()))


def fmt_service_data(sd: dict[str, bytes]) -> str:
    return ";".join(f"{short_uuid(u)}:{data.hex()}" for u, data in sorted(sd.items()))


def compact_data(dev: Device) -> str:
    parts = [f"{cid:04X}:{data[:5].hex()}{'…' if len(data) > 5 else ''}"
             for cid, data in sorted(dev.manufacturer_data.items())]
    parts += sorted(short_uuid(u) for u in dev.all_uuids)
    return " ".join(parts)


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def fmt_rssi(value: float | None) -> str:
    return "–" if value is None else f"{value:.0f}"


# ---------------------------------------------------------------------------
# Leverancier herleiden
#
# Drie bronnen, van betrouwbaar naar minder betrouwbaar:
#   1. company-ID in de manufacturer data (Bluetooth SIG-register)
#   2. 16-bit service-UUID's die aan een bedrijf zijn toegekend (SIG-register)
#   3. de eerste bytes van het MAC-adres (IEEE-OUI, via Wireshark). Alleen zinvol
#      bij een vast (publiek) adres; de meeste BLE-apparaten gebruiken een
#      willekeurig adres en dan zegt het prefix niets.
# De registers staan lokaal in vendors.json (werkt offline in de auto) en zijn
# bij te werken met --update-vendors.
# ---------------------------------------------------------------------------

VENDOR_FILE = Path(__file__).with_name("vendors.json")
VENDOR_SOURCES = {
    "companies": "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml",
    "uuids": "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/uuids/member_uuids.yaml",
    "oui": "https://www.wireshark.org/download/automated/data/manuf",
}


@dataclass
class Vendors:
    companies: dict[int, str]
    uuids: dict[int, str]
    oui: dict[str, str]  # hex-prefix van 6, 7 of 9 tekens (MA-L, MA-M, MA-S) → naam


@functools.cache
def vendors() -> Vendors:
    try:
        data = json.loads(VENDOR_FILE.read_text(encoding="utf-8"))
        return Vendors({int(k, 16): v for k, v in data["companies"].items()},
                       {int(k, 16): v for k, v in data["uuids"].items()},
                       data["oui"])
    except (OSError, ValueError, KeyError):
        return Vendors({}, {}, {})


def oui_vendor(mac: str) -> str | None:
    hex_mac = norm_id(mac)
    table = vendors().oui
    for length in (9, 7, 6):  # kleinste (meest specifieke) blok eerst
        if name := table.get(hex_mac[:length]):
            return name
    return None


def vendor_hints(dev: Device) -> list[str]:
    """Mogelijke leveranciers met de bron erbij, zonder dubbele namen."""
    v = vendors()
    hints: dict[str, str] = {}
    for cid in sorted(dev.manufacturer_data):
        if cid == 0xFFFF:  # door de SIG gereserveerd voor tests; vaak gebruikt door goedkope chips
            hints.setdefault("geen (testwaarde 0xFFFF, vaak goedkope chip)", "")
        else:
            hints.setdefault(v.companies.get(cid, "onbekend bedrijf"), f"company-ID 0x{cid:04X}")
    for uuid in sorted(dev.all_uuids):
        short = short_uuid(uuid)
        if short.startswith("0x") and (name := v.uuids.get(int(short, 16))):
            hints.setdefault(name, f"service {short}")
    if dev.mac and (name := oui_vendor(dev.mac)):
        hints.setdefault(name, f"MAC-prefix {dev.mac[:8]}, alleen geldig bij een vast adres")
    return [f"{name} ({source})" if source else name for name, source in hints.items()]


def vendor_text(dev: Device, with_source: bool = True) -> str:
    hints = vendor_hints(dev)
    if not with_source:  # smalle terminal: alleen de namen
        hints = [h.split(" (")[0] for h in hints]
    return "leverancier: " + "; ".join(hints) if hints else ""


def update_vendors(console: Console) -> int:
    def fetch(url: str) -> str:
        request = urllib.request.Request(url, headers={"User-Agent": "trackerscan"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8", errors="replace")

    def sig_pairs(text: str, key: str) -> dict[str, str]:
        # De SIG-bestanden zijn simpele lijsten "- key: 0x1234 / name: ..."; geen YAML-library nodig.
        pairs = {}
        for value, name in re.findall(rf"{key}:\s*(0x[0-9A-Fa-f]+)\s*\n\s*name:\s*(.+)", text):
            name = name.strip()
            if len(name) >= 2 and name[0] == name[-1] and name[0] in "'\"":
                name = name[1:-1].replace("''", "'") if name[0] == "'" else name[1:-1]
            pairs[f"{int(value, 16):04X}"] = name
        return pairs

    def oui_entries(text: str) -> dict[str, str]:
        entries = {}
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            prefix, *names = [f.strip() for f in line.split("\t")]
            names = [n for n in names if n]
            bits = int(prefix.split("/")[1]) if "/" in prefix else 24
            hex_prefix = norm_id(prefix.split("/")[0])[: bits // 4]
            if names and hex_prefix.strip("0"):  # 00:00:00 is geen echte fabrikant
                entries[hex_prefix] = names[-1]  # lange naam als die er is
        return entries

    console.print("Leverancierslijsten downloaden…")
    try:
        data = {
            "bijgewerkt": datetime.now().astimezone().isoformat(timespec="seconds"),
            "bronnen": VENDOR_SOURCES,
            "companies": sig_pairs(fetch(VENDOR_SOURCES["companies"]), "value"),
            "uuids": sig_pairs(fetch(VENDOR_SOURCES["uuids"]), "uuid"),
            "oui": oui_entries(fetch(VENDOR_SOURCES["oui"])),
        }
    except OSError as exc:
        console.print(f"[red]Download mislukt:[/] {escape(str(exc))}")
        return 1
    if not all(data[k] for k in ("companies", "uuids", "oui")):
        console.print("[red]Een van de lijsten is leeg; is het bronformaat veranderd? Bestand niet overschreven.[/]")
        return 1
    VENDOR_FILE.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    console.print(f"[green]{VENDOR_FILE.name} bijgewerkt:[/] {len(data['companies'])} company-ID's, "
                  f"{len(data['uuids'])} service-UUID's, {len(data['oui'])} MAC-prefixen")
    return 0


# ---------------------------------------------------------------------------
# CSV-log
# ---------------------------------------------------------------------------

CSV_FIELDS = ["timestamp", "fase", "adres", "mac", "naam", "rssi", "label", "soort", "nieuw", "leverancier",
              "manufacturer_data", "service_uuids", "service_data", "tx_power"]


class CsvLog:
    """Schrijft elk ontvangen advertentiepakket als één regel (bestand wordt aangevuld)."""

    def __init__(self, path: Path) -> None:
        write_header = not path.exists() or path.stat().st_size == 0
        self._fh = path.open("a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._fh)
        if write_header:
            self._writer.writerow(CSV_FIELDS)

    def write(self, now: float, phase: str, dev: Device, adv: AdvertisementData) -> None:
        self._writer.writerow([
            datetime.fromtimestamp(now).astimezone().isoformat(timespec="milliseconds"),
            phase,
            dev.address,
            dev.mac or "",
            adv.local_name or dev.name or "",
            adv.rssi,
            dev.label,
            dev.kind,
            "" if dev.is_new is None else ("ja" if dev.is_new else "nee"),
            "; ".join(vendor_hints(dev)),
            fmt_manufacturer(adv.manufacturer_data),
            ";".join(short_uuid(u) for u in adv.service_uuids),
            fmt_service_data(adv.service_data),
            "" if adv.tx_power is None else adv.tx_power,
        ])

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


@dataclass
class Baseline:
    addresses: set[str]
    created: str


def save_baseline(path: Path, devices: dict[str, Device], duration: float) -> None:
    data = {
        "aangemaakt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "duur_s": duration,
        "apparaten": {
            addr: {"naam": d.name, "label": d.label, "rssi_max": d.rssi_max, "aantal": d.count}
            for addr, d in sorted(devices.items())
        },
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> Baseline:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Baseline({a.upper() for a in data.get("apparaten", {})}, data.get("aangemaakt", "?"))


# ---------------------------------------------------------------------------
# Scanner-toestand
# ---------------------------------------------------------------------------


class ScanState:
    def __init__(self, phase: str, ignore: list[str], baseline: Baseline | None, log: CsvLog | None) -> None:
        self.phase = phase  # "baseline" of "scan"
        self.ignore = ignore  # genormaliseerde prefixen
        self.baseline = baseline
        self.log = log
        self.devices: dict[str, Device] = {}
        self.ignored: set[str] = set()
        self.samples = 0
        self.started = time.time()
        self.resolve_mac: Callable[[AdvertisementData], str | None] | None = None

    def on_advert(self, device: BLEDevice, adv: AdvertisementData) -> None:
        addr = device.address.upper()
        if addr in self.ignored:
            return
        now = time.time()
        dev = self.devices.get(addr)
        if dev is None:
            if any(norm_id(addr).startswith(p) for p in self.ignore):
                self.ignored.add(addr)
                return
            dev = self.devices[addr] = Device(addr, first_seen=now)
            if self.baseline is not None:
                dev.is_new = addr not in self.baseline.addresses
        dev.update(adv, device.name, now)
        if dev.mac is None and dev.mac_tries < 3 and self.resolve_mac:
            dev.mac_tries += 1
            dev.mac = self.resolve_mac(adv)
        classify(dev)
        self.samples += 1
        if self.log:
            self.log.write(now, self.phase, dev, adv)


# ---------------------------------------------------------------------------
# Terminal-UI
# ---------------------------------------------------------------------------

RSSI_FLOOR, RSSI_CEIL = -100, -35  # lege resp. volle balk


def signal_bar(rssi: float | None, width: int) -> Text:
    if rssi is None:
        return Text("·" * width, style="grey35")
    frac = min(1.0, max(0.0, (rssi - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)))
    filled = round(frac * width)
    color = "green" if rssi >= -60 else "yellow" if rssi >= -75 else "red"
    return Text("█" * filled, style=color) + Text("░" * (width - filled), style="grey35")


TREND = {1: Text(" ▲", style="bold green"), -1: Text(" ▼", style="bold red"), 0: Text("  ")}


def row_style(dev: Device, stale: bool) -> str:
    if stale:
        return "dim"
    if dev.kind == "tracker":
        return "yellow" if dev.is_new is False else "bold red"
    if dev.kind == "beacon":
        return "magenta"
    return ""


def sort_devices(devs: list[Device], now: float, stale_after: float) -> list[Device]:
    """Sterkste signaal bovenaan (gladgestreken over 3 samples, zodat rijen niet
    elke seconde van plek wisselen); apparaten zonder recent signaal onderaan."""
    return sorted(devs, key=lambda d: (now - d.last_seen > stale_after,
                                       -(d.rssi_smooth if d.rssi_smooth is not None else -999)))


def detail_style(dev: Device) -> str:
    return "bold reverse" if SEPARATED in dev.detail else "italic"


def render(state: ScanState, console: Console, args: argparse.Namespace, banner: Text) -> Table:
    now = time.time()
    width, height = console.size
    # Smalle terminals: eerst #/Eerst/Advertentiedata weglaten, daarna min/gem/max en Naam.
    wide, medium = width >= 150, width >= 100

    devs = list(state.devices.values())
    n_total = len(devs)
    n_flagged = sum(d.kind in FLAGGED_KINDS for d in devs)
    n_new = sum(bool(d.is_new) for d in devs)
    if args.only_trackers:
        devs = [d for d in devs if d.kind in FLAGGED_KINDS]
    if args.only_new and state.baseline is not None:
        devs = [d for d in devs if d.is_new]
    devs = sort_devices(devs, now, args.stale)

    stats = [f"{n_total} apparaten", f"{n_flagged} trackers/beacons"]
    if state.baseline is not None:
        stats.append(f"{n_new} nieuw t.o.v. baseline ({state.baseline.created})")
    if state.ignored:
        stats.append(f"{len(state.ignored)} genegeerd")
    stats.append(f"{state.samples} samples")
    title = banner + Text("\n" + " · ".join(stats), style="")

    caption = ["Ctrl+C = stoppen", "warmer ▲ / kouder ▼", "--ignore <ID> negeert een apparaat"]
    if args.log:
        caption.append(f"log: {args.log}")
    if args.web:
        caption.append(f"web: {web_url(args)}")
    if not vendors().companies:
        caption.append(f"geen {VENDOR_FILE.name}: draai --update-vendors voor leveranciers")
    if state.samples == 0 and now - state.started > 5:
        caption = ["Nog niets ontvangen — staat Bluetooth aan en heeft je terminal Bluetooth-toegang? (zie README)"]

    table = Table(title=title, title_justify="left", caption=" · ".join(caption), caption_justify="left",
                  box=box.SIMPLE_HEAD, expand=True, pad_edge=False, header_style="bold")
    show_new = state.baseline is not None
    if show_new:
        table.add_column("", no_wrap=True, width=5)
    table.add_column("Signaal", no_wrap=True)
    table.add_column("RSSI", justify="right", no_wrap=True)
    if medium:
        table.add_column("min/gem/max", justify="right", no_wrap=True)
    table.add_column("Type", ratio=4, no_wrap=True, overflow="ellipsis")
    if medium:
        table.add_column("Naam", ratio=2, no_wrap=True, overflow="ellipsis")
    table.add_column("ID", no_wrap=True)
    if wide:
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("Eerst", no_wrap=True)
    table.add_column("Laatst", justify="right", no_wrap=True)
    if wide:
        table.add_column("Advertentiedata", ratio=2, no_wrap=True, overflow="ellipsis")

    budget = max(3, height - 9)  # beschikbare regels; een rij met detail kost er twee
    shown = 0
    for dev in devs:
        detail = dev.detail or (vendor_text(dev, with_source=wide) if dev.kind == "onbekend" else "")
        lines = 2 if detail else 1
        if budget < lines:
            break
        budget -= lines
        shown += 1
        stale = now - dev.last_seen > args.stale
        type_cell = Text(dev.label)
        if detail:
            type_cell.append(f"\n  {detail}", style=detail_style(dev) if dev.detail else "grey50")
        cells: list[Text] = []
        if show_new:
            cells.append(Text("NIEUW", style="bold white on red") if dev.is_new else Text(""))
        cells += [
            signal_bar(dev.rssi_smooth, 16 if medium else 10) + TREND[dev.trend],
            Text(fmt_rssi(dev.rssi)),
        ]
        if medium:
            cells.append(Text(f"{fmt_rssi(dev.rssi_min)}/{fmt_rssi(dev.rssi_avg)}/{fmt_rssi(dev.rssi_max)}"))
        cells.append(type_cell)
        if medium:
            cells.append(Text(dev.name or ""))
        cells.append(Text(dev.address[:8]))
        if wide:
            cells += [Text(str(dev.count)), Text(fmt_time(dev.first_seen))]
        cells.append(Text(f"{now - dev.last_seen:.0f}s"))
        if wide:
            cells.append(Text(compact_data(dev), style="grey50"))
        table.add_row(*cells, style=row_style(dev, stale))
    if shown < len(devs):
        caption.insert(0, f"… en nog {len(devs) - shown} (groter venster of --only-trackers)")
        table.caption = " · ".join(caption)
    return table


def mac_resolver(scanner: BleakScanner) -> Callable[[AdvertisementData], str | None] | None:
    """Echt Bluetooth-adres via dezelfde ongedocumenteerde CoreBluetooth-aanroep die
    bleak voor cb={"use_bdaddr": True} gebruikt. Die optie laat apparaten zonder
    opvraagbaar adres weg; zo houden we ze en is het MAC-adres alleen extra info.
    Werkt het niet (andere bleak- of macOS-versie), dan gewoon geen MAC."""
    try:
        retrieve = scanner._backend._manager.central_manager.retrieveAddressForPeripheral_  # bleak-internals
    except AttributeError:
        return None

    def resolve(adv: AdvertisementData) -> str | None:
        try:
            raw = retrieve(adv.platform_data[0])
        except Exception:  # ongedocumenteerde API: mag de scan nooit laten crashen
            return None
        return bytes(raw).hex(":").upper() if raw else None

    return resolve


async def scan(state: ScanState, console: Console, args: argparse.Namespace, duration: float | None = None) -> None:
    scanner = BleakScanner(detection_callback=state.on_advert)
    state.resolve_mac = mac_resolver(scanner)
    async with scanner:
        server = await start_web(state, args) if args.web else None
        async with server if server else contextlib.nullcontext():
            if server and not getattr(args, "web_opened", False):
                webbrowser.open(web_url(args))
                args.web_opened = True
            await run_live(state, console, args, duration)


async def run_live(state: ScanState, console: Console, args: argparse.Namespace, duration: float | None) -> None:
    start = time.monotonic()
    with Live(console=console, screen=True, auto_refresh=False) as live:
        while True:
            elapsed = time.monotonic() - start
            if duration is not None and elapsed >= duration:
                break
            if duration is None:
                banner = Text("trackerscan · scannen", style="bold")
            else:
                banner = Text(f"trackerscan · BASELINE — nog {duration - elapsed:.0f} s · blijf ver van de auto",
                              style="bold black on yellow")
            live.update(render(state, console, args, banner), refresh=True)
            if state.log:
                state.log.flush()
            await asyncio.sleep(1.0 if duration is None else min(1.0, duration - elapsed))


# ---------------------------------------------------------------------------
# Webpagina (--web): lokale HTTP-server, alleen bereikbaar vanaf deze Mac.
# De pagina (trackerscan_web.html) haalt elke seconde /api/state op.
# ---------------------------------------------------------------------------

WEB_PAGE = Path(__file__).with_name("trackerscan_web.html")
WEB_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
           "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class WebError(Exception):
    pass


def web_url(args: argparse.Namespace) -> str:
    return f"http://127.0.0.1:{args.web}/"


def device_json(dev: Device, now: float, stale_after: float) -> dict:
    return {
        "address": dev.address,
        "id": dev.address[:8],
        "name": dev.name,
        "label": dev.label,
        "kind": dev.kind,
        "detail": dev.detail,
        "separated": SEPARATED in dev.detail,
        "is_new": dev.is_new,
        "rssi": dev.rssi,
        "rssi_smooth": dev.rssi_smooth,
        "rssi_avg": dev.rssi_avg,
        "rssi_min": dev.rssi_min,
        "rssi_max": dev.rssi_max,
        "samples": list(dev.samples),
        "trend": dev.trend,
        "count": dev.count,
        "first_seen": dev.first_seen,
        "age": now - dev.last_seen,
        "stale": now - dev.last_seen > stale_after,
        "data": compact_data(dev),
        "mac": dev.mac,
        "vendor": vendor_text(dev),
    }


def state_json(state: ScanState, args: argparse.Namespace) -> bytes:
    now = time.time()
    devs = sort_devices(list(state.devices.values()), now, args.stale)
    baseline = state.baseline
    return json.dumps({
        "phase": state.phase,
        "now": now,
        "samples": state.samples,
        "ignored": len(state.ignored),
        "baseline": {"created": baseline.created, "count": len(baseline.addresses)} if baseline else None,
        "defaults": {"only_trackers": args.only_trackers, "only_new": args.only_new},
        "devices": [device_json(d, now, args.stale) for d in devs],
    }).encode()


async def start_web(state: ScanState, args: argparse.Namespace) -> asyncio.Server:
    # Alleen deze Host-headers: voorkomt dat een website via DNS-rebinding meeleest.
    allowed_hosts = {f"127.0.0.1:{args.web}", f"localhost:{args.web}"}

    def route(head: bytes) -> tuple[str, str, bytes]:
        text_type = "text/plain; charset=utf-8"
        try:
            request_line, *header_lines = head.decode("latin-1").split("\r\n")
            method, target, _ = request_line.split(" ", 2)
        except ValueError:
            return "400 Bad Request", text_type, b"bad request"
        headers = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in header_lines if h)}
        if headers.get("host") not in allowed_hosts:
            return "403 Forbidden", text_type, b"forbidden"
        if method != "GET":
            return "405 Method Not Allowed", text_type, b"method not allowed"
        if target == "/":
            try:
                return "200 OK", "text/html; charset=utf-8", WEB_PAGE.read_bytes()
            except OSError:
                return "500 Internal Server Error", text_type, f"{WEB_PAGE.name} ontbreekt".encode()
        if target == "/api/state":
            return "200 OK", "application/json", state_json(state, args)
        return "404 Not Found", text_type, b"not found"

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError):
            writer.close()
            return
        status, content_type, body = route(head)
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
            f"Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
            f"Content-Security-Policy: {WEB_CSP}\r\nConnection: close\r\n\r\n".encode() + body
        )
        try:
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    try:
        return await asyncio.start_server(handle, "127.0.0.1", args.web)
    except OSError as exc:
        raise WebError(f"Kan de webpagina niet starten op poort {args.web}: {exc.strerror or exc}") from exc


# ---------------------------------------------------------------------------
# Samenvatting en foutmeldingen
# ---------------------------------------------------------------------------


def print_summary(console: Console, state: ScanState) -> None:
    devs = sorted(state.devices.values(), key=lambda d: -(d.rssi_max if d.rssi_max is not None else -999))
    hits = [d for d in devs if d.kind in FLAGGED_KINDS]
    minutes = (time.time() - state.started) / 60
    console.print(f"\n[bold]Samenvatting:[/] {len(devs)} apparaten, {state.samples} samples in {minutes:.1f} min.")
    if state.baseline is not None:
        console.print(f"{sum(bool(d.is_new) for d in devs)} apparaten zaten niet in de baseline.")
    if not hits:
        console.print("[green]Geen trackers of beacons herkend.[/]")
        return
    table = Table(title="Herkende trackers/beacons", title_justify="left", box=box.SIMPLE_HEAD)
    for col in ("Adres/UUID", "Type", "Naam", "Nieuw", "Max", "Gem", "Aantal", "Eerst", "Laatst"):
        table.add_column(col, justify="right" if col in ("Max", "Gem", "Aantal") else "left")
    for d in hits:
        type_cell = Text(d.label) + (Text(f" · {d.detail}", style=detail_style(d)) if d.detail else Text(""))
        new = "" if d.is_new is None else ("ja" if d.is_new else "nee")
        table.add_row(Text(d.address), type_cell, Text(d.name or ""), new, fmt_rssi(d.rssi_max),
                      fmt_rssi(d.rssi_avg), str(d.count), fmt_time(d.first_seen), fmt_time(d.last_seen),
                      style=row_style(d, stale=False))
    console.print(table)


BLUETOOTH_HELP = """[bold red]Bluetooth niet beschikbaar:[/] {error}

Controleer:
  1. Bluetooth staat aan (menubalk of Systeeminstellingen → Bluetooth).
  2. Je terminal-app heeft Bluetooth-toegang:
     Systeeminstellingen → Privacy en beveiliging → Bluetooth → zet Terminal (of iTerm2 / VS Code) aan.
     Sluit daarna de terminal-app volledig af (⌘Q) en open hem opnieuw.
  3. Nooit een toestemmingsvraag gezien? Reset hem en start opnieuw:
     tccutil reset Bluetooth com.apple.Terminal"""


# ---------------------------------------------------------------------------
# Opstarten
# ---------------------------------------------------------------------------


def ignore_prefix(value: str) -> str:
    if not re.fullmatch(r"[0-9A-Fa-f:\-]+", value) or len(norm_id(value)) < 4:
        raise argparse.ArgumentTypeError(f"'{value}' is geen adres/UUID (minstens 4 hex-tekens, bv. 1A2B3C4D)")
    return norm_id(value)


def positive_seconds(value: str) -> float:
    seconds = float(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("moet groter dan 0 zijn")
    return seconds


def port(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("poort moet tussen 1 en 65535 liggen")
    return number


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="BLE-trackerscanner: zoekt AirTags/Find My-tags, Samsung SmartTags, Tiles, "
                    "Chipolo's, Google Find Hub-tags en beacons in de buurt.")
    p.add_argument("--ignore", action="append", default=[], type=ignore_prefix, metavar="ADRES",
                   help="negeer dit apparaat: volledige UUID of prefix uit de ID-kolom (mag vaker)")
    p.add_argument("--baseline", type=positive_seconds, metavar="SECONDEN",
                   help="scan eerst zo lang ver van de auto, sla alles op in --baseline-file en markeer "
                        "daarna alleen apparaten die daar niet in zitten als NIEUW")
    p.add_argument("--baseline-file", type=Path, default=Path("baseline.json"), metavar="BESTAND",
                   help="baseline-bestand; wordt automatisch geladen als het bestaat (standaard: baseline.json)")
    p.add_argument("--log", type=Path, metavar="BESTAND",
                   help="schrijf alle samples als CSV (een bestaand bestand wordt aangevuld)")
    p.add_argument("--web", type=port, nargs="?", const=8765, metavar="POORT",
                   help="toon ook een live webpagina op http://127.0.0.1:POORT (standaard 8765) en open die")
    p.add_argument("--only-trackers", action="store_true", help="toon alleen trackers en beacons")
    p.add_argument("--only-new", action="store_true", help="toon alleen apparaten die niet in de baseline zitten")
    p.add_argument("--stale", type=positive_seconds, default=30, metavar="SECONDEN",
                   help="zonder signaal na zoveel seconden wordt een apparaat grijs en zakt het weg (standaard 30)")
    p.add_argument("--update-vendors", action="store_true",
                   help=f"download de leverancierslijsten opnieuw naar {VENDOR_FILE.name} en stop")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    console = Console()
    if args.update_vendors:
        return update_vendors(console)
    try:
        log = CsvLog(args.log) if args.log else None
    except OSError as exc:
        console.print(f"[red]Kan logbestand niet openen:[/] {escape(str(exc))}")
        return 1

    state: ScanState | None = None
    try:
        if args.baseline:
            base_state = ScanState("baseline", args.ignore, None, log)
            asyncio.run(scan(base_state, console, args, duration=args.baseline))
            save_baseline(args.baseline_file, base_state.devices, args.baseline)
            console.print(f"[green]Baseline opgeslagen:[/] {len(base_state.devices)} apparaten → {args.baseline_file}")
            input("Neem de laptop mee naar de auto en druk op Enter om te beginnen (Ctrl+C = stoppen)… ")

        baseline = None
        if args.baseline_file.exists():
            try:
                baseline = load_baseline(args.baseline_file)
            except (OSError, ValueError) as exc:
                console.print(f"[red]Baseline onleesbaar, ik scan zonder:[/] {escape(str(exc))}")
        elif args.only_new:
            console.print(f"[yellow]--only-new genegeerd: {args.baseline_file} bestaat niet (maak er een met --baseline).[/]")

        state = ScanState("scan", args.ignore, baseline, log)
        asyncio.run(scan(state, console, args))
    except KeyboardInterrupt:
        if state is None:
            console.print("\nAfgebroken; baseline niet opgeslagen.")
    except BleakError as exc:
        console.print(BLUETOOTH_HELP.format(error=escape(str(exc))))
        return 1
    except WebError as exc:
        console.print(f"[red]{escape(str(exc))}[/] Kies een andere poort, bv. --web 8766.")
        return 1
    finally:
        if log:
            log.close()

    if state is not None:
        print_summary(console, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
