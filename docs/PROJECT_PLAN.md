# AetherDeck — Project Plan

**A headless ESP32-S3 Wi-Fi & BLE security toolkit, driven entirely from a self-hosted web dashboard — no screen required.**

> ⚠️ For authorized security testing and education only. Use exclusively on networks and devices you own or have explicit written permission to assess. Transmitting modules (beacon spam, karma, captive portal, deauth) are illegal to use against third parties in most jurisdictions.

---

## 1. Objective
University Information Security project. Build a single-board (ESP32-S3, **no attached screen**) wireless security research tool whose **entire interface is a web dashboard the board hosts itself**. It brings common Wi-Fi/BLE recon and attack modules together behind a browser UI instead of the usual TFT + buttons.

## 2. Why it's different
Comparable ESP32/M5 wireless tools are screen-first (TFT + physical buttons), with a web server as a bolt-on. **AetherDeck inverts that: there is no screen; the web dashboard is the only interface.** That re-architecture, together with a **defensive KARMA / rogue-AP detection module**, is the project's contribution.

## 3. Scope & ethics (graded constraint)
- **Lab-only.** Run against your own AP/clients or an authorized test network.
- **Active/transmitting modules are OFF by default**, gated behind an explicit "Authorized mode" toggle in the UI.
- Captured credentials/handshakes **stay on-device**, downloadable only over the local AP.
- A visible disclaimer ships in the README and the dashboard.

## 4. Hardware
- **ESP32-S3 dev board** (default build target: `esp32-s3-devkitc-1`). Dual-core, Wi-Fi + BLE 5.
- **No display, no buttons.** The control device is your laptop/phone browser.
- Optional later: SD card for larger capture storage; external antenna; GPS module for wardriving.

## 5. Architecture
```
  Browser (laptop/phone)                 ESP32-S3
 ┌──────────────────────┐        ┌──────────────────────────────┐
 │  Dashboard (HTML/JS) │        │  SoftAP  (192.168.4.1)        │
 │   REST  ⇄  WebSocket │  Wi-Fi │  AsyncWebServer + WebSocket   │
 └──────────┬───────────┘ <────> │  LittleFS (web assets+captures)│
            │                    │  Module manager                │
            │                    │   ├─ esp_wifi (promisc/raw)     │
            │                    │   └─ NimBLE                     │
            └────────────────────┴──────────────────────────────┘
```
- **HTTP/REST** serves pages and one-shot commands; **WebSocket** streams live scan/sniff data to the browser.
- The module manager owns the radio; the web layer never touches `esp_wifi` directly.

## 6. Tech stack
- **Build:** PlatformIO + Arduino-ESP32 core. (Adaptable to Arduino IDE if preferred.)
- **Web:** ESPAsyncWebServer + AsyncTCP, LittleFS, ArduinoJson.
- **Wi-Fi:** `esp_wifi` promiscuous mode + raw-frame APIs.
- **BLE:** NimBLE-Arduino.

## 7. Module map (combined, grouped)
| Group | Modules |
|---|---|
| **Passive recon** | AP scan, station scan, probe-request sniff, beacon sniff, packet monitor, channel analyzer, signal/RSSI monitor |
| **Capture** | EAPOL / PMKID handshake capture → PCAP; probe & SSID logging; wardrive CSV (GPS optional) |
| **Active (gated, lab-only)** | Beacon spam, SSID flood, AP clone, Evil Portal (captive portal + credential capture), Karma |
| **Defense (IS contribution)** | KARMA / rogue-AP detector (bait-probe method), evil-twin detector (beacon-timestamp / clock-drift), deauth-flood detector |
| **BLE** | Scan / enumerate, BLE spam (gated), AirTag / FindMy sniff |

## 8. Web dashboard (pages)
- **Dashboard** — status, radio state, module toggles, Authorized-mode switch.
- **Wi-Fi** — live scan tables (AP / station), channel view.
- **Capture** — handshakes / probes list, download PCAP/CSV.
- **Attacks** — gated active modules.
- **Detect** — rogue-AP / karma / deauth alerts (the defensive view).
- **BLE** — scan + gated spam.
- **Settings** — AP SSID/password, Authorized-mode, persistence.

## 9. Milestones — each step is one commit + push
| Step | Deliverable | "Done" = |
|---|---|---|
| **0** | Scaffold: repo, docs, PlatformIO skeleton, minimal boot | this commit builds & pushes |
| **1** | SoftAP + web dashboard shell + live WebSocket log | connect to AP, open `192.168.4.1`, see live log |
| **2** | Wi-Fi AP scanner → live table | scan button fills SSID/BSSID/RSSI/ch/enc |
| **3** | Promiscuous sniffer: probe requests + stations | live probe/station feed in UI |
| **4** | Packet monitor + channel hopping + beacon list | per-channel counts, beacon list |
| **5** | Handshake / PMKID capture → downloadable PCAP | capture + download opens in Wireshark |
| **6** | Evil Portal / captive portal (gated) | lab credential-capture demo |
| **7** | KARMA + **KARMA detection** (defense) | detector flags a rogue AP in lab |
| **8** | BLE scan/spam + polish: dashboard auth, config persistence, demo script | final demo run |

## 10. Known constraints
- **Deauth TX:** recent Espressif SDK blocks deauthentication frames; some tools patch the SDK to bypass this. AetherDeck treats deauth as **advanced/optional (Step 8+)** and ships *detection* rather than attack by default.
- **Memory:** raw capture buffering benefits from PSRAM — enable `BOARD_HAS_PSRAM` on R-variant S3 boards.
- **Single radio:** can't transmit and reliably monitor multiple channels at once; channel hopping is time-sliced.
- **Legal:** see §3.

## 11. Repo structure
```
AetherDeck/
├── platformio.ini        # build config (target board)
├── src/
│   └── main.cpp          # firmware entry
├── data/                 # web dashboard assets (LittleFS) — added Step 1
├── docs/
│   └── PROJECT_PLAN.md   # this file
├── README.md
├── LICENSE
└── .gitignore            # excludes secrets and build output
```

## 12. Report / grading angle
Present the **defensive detection modules (Step 7)** as the core research contribution; the offensive modules exist to *demonstrate the attacks the detector catches*, in a controlled lab. Deliverables: this plan, the firmware, a demo video/script, and a short write-up on the KARMA/evil-twin detection method and its limits.
