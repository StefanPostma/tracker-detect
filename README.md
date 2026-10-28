# trackerscan

Commandline-scanner voor macOS die continu naar Bluetooth Low Energy-apparaten
zoekt en bekende trackers herkent: AirTag en andere Find My-tags, Samsung
SmartTag, Tile, Chipolo, Google Find Hub-tags en generieke beacons
(iBeacon/Eddystone). Bedoeld om te controleren of er een onbekende tracker in of
aan je auto zit.

## Installatie

Vereist Python 3.9+ (getest met 3.14 en bleak 3.0 op een MacBook Air M-serie).

```bash
cd tracker-detect
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 trackerscan.py --update-vendors   # leverancierslijsten downloaden (eenmalig)
```

Activeer de venv voortaan met `source .venv/bin/activate` voordat je
`python3 trackerscan.py` draait.

## Bluetooth-toestemming (macOS)

macOS geeft Bluetooth-toegang per app. De app is hier je terminal (Terminal,
iTerm2 of VS Code), niet Python.

1. Zet Bluetooth aan (menubalk → Bluetooth).
2. Start `python3 trackerscan.py`. De eerste keer vraagt macOS: *"Terminal wil
   Bluetooth gebruiken"* → **Sta toe**.
3. Geen vraag gekregen of per ongeluk geweigerd?
   **Systeeminstellingen → Privacy en beveiliging → Bluetooth** → zet je
   terminal-app aan. Staat hij er niet tussen, voeg hem dan toe met **+**. Sluit
   daarna de terminal-app helemaal af (⌘Q) en open hem opnieuw.
4. Nog steeds niets? Reset de toestemming, zodat macOS het opnieuw vraagt:
   `tccutil reset Bluetooth com.apple.Terminal` (iTerm2: `com.googlecode.iterm2`).

Als het mislukt, zegt het script wat er mis is (uitgeschakeld of geweigerd).
Komt er na 5 seconden nog niets binnen, dan staat er een hint onder de tabel.

## Gebruik

```bash
python3 trackerscan.py                            # live scannen
python3 trackerscan.py --baseline 120             # eerst 2 min baseline, daarna Enter → scannen in de auto
python3 trackerscan.py --only-new --only-trackers # alleen nieuwe trackers tonen
python3 trackerscan.py --ignore 1A2B3C4D --ignore 5E6F7A8B   # eigen AirPods/AirTag negeren
python3 trackerscan.py --log scan.csv             # alle samples als CSV wegschrijven
python3 trackerscan.py --web                      # plus live webpagina op http://127.0.0.1:8765
```

| Optie | Betekenis |
|---|---|
| `--ignore ADRES` | Negeer een apparaat. Een prefix uit de ID-kolom volstaat; je mag de optie vaker gebruiken. |
| `--baseline SEC` | Scan eerst SEC seconden, sla alles op in `baseline.json` en wacht op Enter. Daarna krijgen apparaten die niet in de baseline zitten de markering **NIEUW**. |
| `--baseline-file F` | Ander baselinebestand. Bestaat het bestand, dan wordt het bij elke start automatisch geladen. |
| `--log F` | CSV met per ontvangen pakket: timestamp, fase, adres, mac, naam, rssi, label, soort, nieuw, leverancier, manufacturer_data, service_uuids, service_data, tx_power. Een bestaand bestand wordt aangevuld. |
| `--update-vendors` | Download de leverancierslijsten opnieuw naar `vendors.json` en stop. |
| `--web [POORT]` | Start daarnaast een live webpagina (standaardpoort 8765) en opent die in je browser. |
| `--only-trackers` / `--only-new` | Filter de tabel. |
| `--stale SEC` | Na hoeveel seconden zonder signaal een apparaat grijs wordt en naar onderen zakt (standaard 30). |

Maak het terminalvenster groot (of schermvullend), dan zie je alle kolommen:
aantal keer gezien, eerst gezien en de ruwe advertentiedata. Bij Ctrl+C krijg je
een samenvatting met de volledige UUID's van alle herkende trackers.

## Leverancier van onbekende apparaten

Voor apparaten die geen bekende tracker zijn, toont het script de vermoedelijke
leverancier. Daarvoor gebruikt het drie bronnen, van betrouwbaar naar minder
betrouwbaar:

1. **Company-ID** in de advertentie, bijvoorbeeld 0x0006 = Microsoft (Bluetooth
   SIG-register). 0xFFFF is een testwaarde die vaak in goedkope chips zit.
2. **Service-UUID's** die aan een bedrijf zijn toegekend, bijvoorbeeld 0xFCF1 =
   Google.
3. **MAC-prefix (OUI)**: macOS verbergt het echte adres. Het script vraagt het
   op via een ongedocumenteerde CoreBluetooth-aanroep. Lukt dat niet, dan scant
   het gewoon zonder MAC. Het prefix zegt alleen iets bij een **vast** adres. De
   meeste BLE-apparaten gebruiken een willekeurig adres, en een treffer is dan
   toeval. Daarom staat er "alleen geldig bij een vast adres" bij.

De lijsten staan in `vendors.json` (± 2 MB, werkt offline). Je maakt dat
bestand aan en werkt het bij met `python3 trackerscan.py --update-vendors`
(bronnen: Bluetooth SIG en Wireshark). Wireshark vraagt hun lijst hooguit eens
per week te downloaden. Het bestand staat niet in git.
Een leverancier is vaak de chipmaker en niet het merk op de verpakking. Bij
goedkope apparaten zie je bijvoorbeeld Telink of Beken.

## Webpagina

Met `--web` draait er naast de terminal-tabel een webpagina. Die toont per
apparaat elke seconde de laatste signaalsterkte, met een balk, het verloop van
de laatste 10 metingen en ▲/▼ voor warmer of kouder.

- **Klik op een apparaat** om het groot te volgen. Dat is handig als je met de
  laptop door de auto loopt.
- Met de vinkjes filter je op trackers/beacons of op apparaten die nieuw zijn
  t.o.v. de baseline.
- **Baseline vastleggen** legt alles vast wat de scanner tot nu toe zag, zonder
  herstart. Doe dat ver van de auto. Het wordt opgeslagen in `baseline.json`
  (of `--baseline-file`); daarna krijgen nieuwe apparaten ● NIEUW en werkt
  "Alleen nieuw". Een bestaande baseline vervangen vraagt een tweede klik.
- **Signalen tijdelijk verbergen:** vink een apparaat aan in de kolom *Verb.*,
  of klik op **Verberg alles wat nu zichtbaar is**. Doe dat voordat de auto in
  de buurt komt. Daarna verschijnen alleen nieuwe signalen, zoals dat van de
  auto. **Toon verborgen** laat ze vervaagd weer zien, **Alles weer tonen**
  herstelt alles. Verbergen geldt alleen voor deze browsertab en vervalt na een
  herstart van de scanner. Telefoons wisselen ongeveer elk kwartier van adres en
  duiken dan als "nieuw" signaal weer op.
- Zolang je de muis over de tabel beweegt, blijft de volgorde staan, zodat je
  niet mis klikt.
- De pagina is alleen bereikbaar vanaf deze Mac (127.0.0.1). Het ontwerp staat
  in `trackerscan_web.html`. Na een aanpassing volstaat het om de pagina te
  herladen.

## Werkwijze in de auto

1. **Baseline**: doe `--baseline 120` op ruime afstand van de auto,
   bijvoorbeeld binnen in huis en minstens 20–30 m weg. Sta je te dichtbij, dan
   komt een eventuele tracker in de baseline terecht.
2. Druk op Enter, loop naar de auto en ga erin zitten. Laat je eigen telefoon
   eventueel even in huis.
3. Beweeg de laptop langzaam langs de plekken waar trackers vaak zitten: onder
   en tussen de stoelen, achterbank, kofferbak en reservewiel, deurvakken,
   handschoenenkastje, OBD-poort, bumpers, wielkasten en de onderkant van de
   auto (buitenom lopen). De balk en ▲/▼ laten zien of je warmer of kouder
   wordt. Bij ongeveer −45 dBm of sterker zit je er meestal binnen een halve
   meter vanaf.
4. Let vooral op **NIEUW** + rode tracker-regels. Bij Find My-, Find Hub- en
   Samsung SmartTag-tags betekent **LOS VAN EIGENAAR** dat de eigenaar niet in de
   buurt is. Zo gedraagt een tracker van iemand anders zich in jouw auto. Een
   SmartTag kent ook "net los van eigenaar": de eigenaar is kort geleden
   weggegaan. Dat is nog normaal.

## Beperkingen

- macOS laat geen echte MAC-adressen zien. Elk apparaat krijgt een UUID die
  CoreBluetooth per Mac toekent. Trackers en telefoons wisselen ook regelmatig
  van adres (telefoons ongeveer elk kwartier, een AirTag die los is van zijn
  eigenaar ongeveer eens per dag). Een apparaat uit de baseline kan dus later als
  NIEUW terugkomen. Kijk daarom ook naar het type en de status.
- "AirTag / Find My-tag (mogelijk)" geldt ook voor je eigen iPhone, Mac en
  AirPods. Je eigen AirPods staan op "LOS VAN EIGENAAR" als je iPhone niet in de
  buurt is. Herken ze aan de naam en zet ze op `--ignore`.
- Samsung kent drie niveaus:
  - **"Samsung SmartTag"**: service-data 0xFD5A met een tag-typebyte. Hier
    worden ook de status en de batterij uitgelezen.
  - **"(waarschijnlijk)"**: 0xFD5A met een ander typebyte.
  - **"(mogelijk)"**: alleen Samsung company-ID 0x0075. Dat ID gebruiken ook
    Samsung-telefoons, -oordopjes en -tv's.
- "iTag-sleutelvinder" herkent goedkope anti-verlies-hangers aan hun naam (iTAG,
  MLE-15). Die werken alleen binnen bereik van de telefoon van de eigenaar en
  kunnen je auto dus niet op afstand volgen.
- De status- en batterijuitleg van Find My en SmartTag komt uit
  reverse-engineering (OpenHaystack/AirGuard) en is een heuristiek.
- **GPS-trackers met een simkaart (4G/LTE) gebruiken geen Bluetooth.** Die vind je
  hiermee niet. Daarvoor heb je een fysieke inspectie of een RF-detector nodig.
  iPhones en Android-telefoons waarschuwen ook zelf voor onbekende trackers die
  met je meereizen. Zet die meldingen aan als extra controle.

## Herkenningsregels uitbreiden

In `trackerscan.py` staat de tabel `RULES` (sectie *Herkenningsregels*). Elke `Rule` heeft een label, een
soort (`tracker`/`beacon`/`info`) en criteria: `manufacturer_id`,
`manufacturer_prefix`, `service_uuids`, `service_data_prefix` en `name_pattern`.
De eerste regel die matcht wint. Via de kolom Advertentiedata of de CSV-log
vind je de bytes voor een nieuwe regel.

## Licentie

MIT, zie [LICENSE](LICENSE).
