# AetherDeck

**A headless ESP32-S3 Wi-Fi & BLE security toolkit, driven entirely from a self-hosted web dashboard — no screen required.**

AetherDeck is a Wi-Fi & BLE security toolkit for the ESP32-S3, re-architected so the **only interface is a web dashboard the board hosts itself** — no screen, no buttons. You connect your laptop or phone to the board's Wi-Fi and control everything from the browser.

> ⚠️ **For authorized security testing and education only.** Use exclusively on networks and devices you own or have explicit written permission to assess. Transmitting modules are OFF by default and gated behind an "Authorized mode" toggle. Misuse against third parties is illegal in most jurisdictions.

## Hardware
- An **ESP32-S3** dev board (default target: `esp32-s3-devkitc-1`). No display or buttons needed.
- Your laptop/phone as the control device.

## Build & flash (PlatformIO)
```
pio run                 # build
pio run -t uploadfs     # flash the web dashboard (data/) to LittleFS
pio run -t upload       # flash the firmware to the connected ESP32-S3
pio device monitor      # serial monitor @ 115200
```
If your board is a different S3 variant, change `board` in [`platformio.ini`](platformio.ini).

## Usage
1. Flash the firmware and power the board.
2. From your laptop/phone, join the board's Wi-Fi AP — **SSID `AetherDeck`, password `aetherdeck`** (WPA2; change it in Settings later).
3. Open **`http://192.168.4.1`** in a browser — that's the dashboard.

## Status
**Step 7 — passive detection.** The dashboard at `192.168.4.1` provides scans, monitoring, PCAP capture, an Authorized mode gated lab portal that records only redacted field lengths, and alerts for multiple SSIDs from one BSSID, duplicate SSIDs, and deauthentication bursts. See [`docs/DETECTION.md`](docs/DETECTION.md) for detection limits and [`docs/PROJECT_PLAN.md`](docs/PROJECT_PLAN.md) for the roadmap.

## License
MIT — see [`LICENSE`](LICENSE).
