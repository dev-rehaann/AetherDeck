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
pio run -t upload       # flash the firmware to the connected ESP32-S3
pio run -t uploadfs     # flash the web dashboard (data/) to LittleFS
pio device monitor      # serial monitor @ 115200
```
If your board is a different S3 variant, change `board` in [`platformio.ini`](platformio.ini).

## Usage
1. Flash the firmware and power the board.
2. From your laptop/phone, join the board's Wi-Fi AP — default **SSID `AetherDeck`, password `aetherdeck`**.
3. Open **`http://192.168.4.1`**. At the dashboard password prompt, use username `admin` and default password `aetherdeck`. Change the passwords in Settings for your lab.

## Status
**Complete toolkit.** The dashboard provides Wi-Fi and passive BLE scans, Wi-Fi monitoring and detection, PCAP capture, an Authorized-mode gated redacted portal demo, password access control, and persistent settings. Follow the [lab demo](docs/DEMO.md) and read the [detection limits](docs/DETECTION.md). The [project plan](docs/PROJECT_PLAN.md) records the roadmap.

## License
MIT — see [`LICENSE`](LICENSE).
