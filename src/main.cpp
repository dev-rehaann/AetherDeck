#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <esp_timer.h>

// Default AP credentials — meant to be known so you can connect (WPA2, >=8
// chars). Made configurable in Settings (Step 8).
static const char *AP_SSID = "AetherDeck";
static const char *AP_PASS = "aetherdeck";

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

static volatile bool scanRequested = false;
static bool scanning = false;
static volatile bool sniffStartRequested = false;
static volatile bool sniffStopRequested = false;
static volatile int channelRequested = 0;
static volatile int hopRequested = -1;
static bool sniffing = false;
static bool hopping = false;
static volatile uint8_t sniffChannel = 1;
static unsigned long lastHop = 0;
static unsigned long lastStaUpdate = 0;

struct Device {
  uint8_t mac[6];
  char ssid[33];
  uint8_t bssid[6];
  bool hasSsid;
  bool hasBssid;
  int8_t rssi;
  uint32_t seen;
};

// shortcut: 64 devices can evict quiet clients, raise the cap if captures need longer retention.
static Device devices[64];
static size_t deviceCount = 0;
static portMUX_TYPE deviceMux = portMUX_INITIALIZER_UNLOCKED;

struct Beacon {
  uint8_t bssid[6];
  char ssid[33];
  uint8_t channel;
  int8_t rssi;
  bool privacy;
  bool rsn;
  uint32_t seen;
};

// shortcut: 48 beacons can evict quiet APs, raise the cap if captures need longer retention.
static Beacon beacons[48];
static size_t beaconCount = 0;
static uint32_t packetCounts[14][3] = {};

static volatile bool capStartRequested = false;
static volatile bool capStopRequested = false;
static volatile bool capsListRequested = false;
static bool fsReady = false;
static volatile bool capturing = false;
static File capFile;
static char capName[24] = "";
static bool capCorrupt = false;
static uint32_t capEapol = 0, capPmkid = 0, capDropped = 0;
static constexpr size_t CAP_FRAME_MAX = 2560;
static constexpr size_t CAP_RING_SIZE = 8;
// shortcut: eight 2560-byte slots drop burst traffic, increase only if lab captures show overflow.
struct CaptureFrame { uint64_t us; uint16_t len; uint8_t bytes[CAP_FRAME_MAX]; };
static CaptureFrame capRing[CAP_RING_SIZE];
static CaptureFrame capPending;
static size_t capHead = 0, capTail = 0, capCount = 0;
static portMUX_TYPE capMux = portMUX_INITIALIZER_UNLOCKED;

static void put16(uint8_t *out, uint16_t value) {
  out[0] = value;
  out[1] = value >> 8;
}

static void put32(uint8_t *out, uint32_t value) {
  for (int i = 0; i < 4; i++) out[i] = value >> (8 * i);
}

static size_t globalHeader(uint8_t *out) {
  memset(out, 0, 24);
  put32(out, 0xA1B2C3D4);
  put16(out + 4, 2);
  put16(out + 6, 4);
  put32(out + 16, 65535);
  put32(out + 20, 105);
  return 24;
}

static size_t packetHeader(uint8_t *out, uint64_t us, uint32_t len) {
  put32(out, us / 1000000);
  put32(out + 4, us % 1000000);
  put32(out + 8, len);
  put32(out + 12, len);
  return 16;
}

static uint8_t pmkidsInEapol(const uint8_t *eapol, size_t len) {
  if (len < 99 || eapol[1] != 3) return 0;
  size_t body = ((size_t)eapol[2] << 8) | eapol[3];
  if (body < 95 || body > len - 4 || eapol[4] != 2) return 0;
  uint16_t info = ((uint16_t)eapol[5] << 8) | eapol[6];
  if (!(info & 0x0008) || !(info & 0x0080) || (info & 0x0100)) return 0;
  size_t dataLen = ((size_t)eapol[97] << 8) | eapol[98];
  if (dataLen > body - 95) return 0;
  size_t end = 99 + dataLen;
  uint8_t found = 0;
  for (size_t pos = 99; pos + 2 <= end;) {
    uint8_t id = eapol[pos++];
    uint8_t size = eapol[pos++];
    if (size > end - pos) return found;
    if (id == 221 && size == 20 && !memcmp(eapol + pos, "\x00\x0f\xac\x04", 4)) found++;
    pos += size;
  }
  return found;
}

static bool parseSsid(const uint8_t *tags, size_t len, char *ssid) {
  for (size_t pos = 0; pos + 2 <= len;) {
    uint8_t id = tags[pos++];
    uint8_t size = tags[pos++];
    if (size > len - pos) return false;
    if (id == 0) {
      size_t n = min((size_t)size, (size_t)32);
      for (size_t i = 0; i < n; i++) ssid[i] = tags[pos + i] ? tags[pos + i] : '?';
      ssid[n] = '\0';
      return true;
    }
    pos += size;
  }
  return false;
}

static String macText(const uint8_t *mac) {
  char out[18];
  snprintf(out, sizeof(out), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(out);
}

static void onPacket(void *buffer, wifi_promiscuous_pkt_type_t kind) {
  auto *packet = (wifi_promiscuous_pkt_t *)buffer;
  uint8_t channel = packet->rx_ctrl.channel;
  if (channel < 1 || channel > 13) channel = sniffChannel;
  int cls = kind == WIFI_PKT_MGMT ? 0 : kind == WIFI_PKT_DATA ? 1 : kind == WIFI_PKT_CTRL ? 2 : -1;
  if (channel >= 1 && channel <= 13 && cls >= 0) {
    portENTER_CRITICAL(&deviceMux);
    packetCounts[channel][cls]++;
    portEXIT_CRITICAL(&deviceMux);
  }
  if (kind != WIFI_PKT_MGMT && kind != WIFI_PKT_DATA) return;
  const uint8_t *frame = packet->payload;
  size_t len = packet->rx_ctrl.sig_len;
  // sig_len includes the four-byte FCS, which is not part of the tagged parameters.
  if (len < 4) return;
  len -= 4;
  if (len < 24) return;
  uint8_t subtype = frame[0] >> 4;
  if (kind == WIFI_PKT_DATA && !(frame[1] & 0x40)) {
    size_t header = 24 + ((frame[1] & 3) == 3 ? 6 : 0);
    if (subtype & 8) header += 2;
    if ((subtype & 8) && (frame[1] & 0x80)) header += 4;
    if (len >= header + 8 && !memcmp(frame + header, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) {
      const uint8_t *eapol = frame + header + 8;
      uint8_t pmkids = pmkidsInEapol(eapol, len - header - 8);
      portENTER_CRITICAL(&capMux);
      if (capturing) {
        capEapol++;
        capPmkid += pmkids;
        if (len > CAP_FRAME_MAX || capCount == CAP_RING_SIZE) capDropped++;
        else {
          CaptureFrame &entry = capRing[capTail];
          entry.us = esp_timer_get_time();
          entry.len = len;
          memcpy(entry.bytes, frame, len);
          capTail = (capTail + 1) % CAP_RING_SIZE;
          capCount++;
        }
      }
      portEXIT_CRITICAL(&capMux);
    }
  }
  if (kind == WIFI_PKT_MGMT && subtype == 8) {
    if (len < 36) return;
    char name[33] = {};
    if (!parseSsid(frame + 36, len - 36, name)) return;
    uint8_t apChannel = channel;
    bool rsn = false;
    for (size_t pos = 36; pos + 2 <= len;) {
      uint8_t id = frame[pos++];
      uint8_t size = frame[pos++];
      if (size > len - pos) return;
      if (id == 3 && size >= 1 && frame[pos] >= 1 && frame[pos] <= 13) apChannel = frame[pos];
      if (id == 48) rsn = true;
      pos += size;
    }
    const uint8_t *ap = frame + 16;
    portENTER_CRITICAL(&deviceMux);
    size_t slot = 0;
    while (slot < beaconCount && memcmp(beacons[slot].bssid, ap, 6)) slot++;
    if (slot == beaconCount) {
      if (beaconCount < 48) beaconCount++;
      else {
        slot = 0;
        uint32_t now = millis();
        for (size_t i = 1; i < beaconCount; i++)
          if ((uint32_t)(now - beacons[i].seen) > (uint32_t)(now - beacons[slot].seen)) slot = i;
      }
    }
    Beacon &b = beacons[slot];
    memcpy(b.bssid, ap, 6);
    memcpy(b.ssid, name, sizeof(name));
    b.channel = apChannel;
    b.rssi = packet->rx_ctrl.rssi;
    b.privacy = frame[34] & 0x10;
    b.rsn = rsn;
    b.seen = millis();
    portEXIT_CRITICAL(&deviceMux);
    return;
  }
  const uint8_t *client = nullptr;
  const uint8_t *bssid = nullptr;
  char ssid[33] = {};
  bool probe = kind == WIFI_PKT_MGMT && subtype == 4;
  if (probe) {
    if (!parseSsid(frame + 24, len - 24, ssid)) return;
    client = frame + 10;
  } else if (kind == WIFI_PKT_MGMT && (subtype == 0 || subtype == 2)) {
    client = frame + 10;
    bssid = frame + 16;
  } else if (kind == WIFI_PKT_MGMT && (subtype == 1 || subtype == 3)) {
    client = frame + 4;
    bssid = frame + 16;
  } else if (kind == WIFI_PKT_DATA) {
    uint8_t ds = frame[1] & 3;
    if (ds == 1) { client = frame + 10; bssid = frame + 4; }
    if (ds == 2) { client = frame + 4; bssid = frame + 10; }
  }
  if (!client || (client[0] & 1)) return;

  portENTER_CRITICAL(&deviceMux);
  size_t slot = 0;
  while (slot < deviceCount && memcmp(devices[slot].mac, client, 6)) slot++;
  if (slot == deviceCount) {
    if (deviceCount < 64) deviceCount++;
    else {
      slot = 0;
      uint32_t now = millis();
      for (size_t i = 1; i < deviceCount; i++)
        if ((uint32_t)(now - devices[i].seen) > (uint32_t)(now - devices[slot].seen)) slot = i;
    }
    devices[slot] = {};
    memcpy(devices[slot].mac, client, 6);
  }
  Device &d = devices[slot];
  if (probe) { memcpy(d.ssid, ssid, sizeof(ssid)); d.hasSsid = true; }
  if (bssid) { memcpy(d.bssid, bssid, 6); d.hasBssid = true; d.hasSsid = false; }
  d.rssi = packet->rx_ctrl.rssi;
  d.seen = millis();
  portEXIT_CRITICAL(&deviceMux);
}

static void wsLog(const String &line) {
  Serial.println(line);
  ws.textAll(line);
}

static void sendSniffState(AsyncWebSocketClient *client = nullptr);

static bool validCapName(const String &name) {
  if (!name.startsWith("cap-") || !name.endsWith(".pcap") || name.length() <= 9) return false;
  for (size_t i = 4; i < name.length() - 5; i++) if (!isDigit(name[i])) return false;
  return true;
}

static void sendCapState(AsyncWebSocketClient *client = nullptr) {
  uint32_t eapol, pmkid, dropped;
  bool on;
  char name[sizeof(capName)];
  portENTER_CRITICAL(&capMux);
  eapol = capEapol;
  pmkid = capPmkid;
  dropped = capDropped;
  on = capturing;
  memcpy(name, capName, sizeof(name));
  portEXIT_CRITICAL(&capMux);
  JsonDocument doc;
  doc["type"] = "cap";
  doc["on"] = on;
  doc["file"] = name;
  doc["eapol"] = eapol;
  doc["pmkid"] = pmkid;
  doc["dropped"] = dropped;
  String out;
  serializeJson(doc, out);
  if (client) client->text(out);
  else ws.textAll(out);
}

static void sendCaps() {
  JsonDocument doc;
  doc["type"] = "caps";
  JsonArray list = doc["files"].to<JsonArray>();
  if (fsReady) {
    File dir = LittleFS.open("/caps");
    File file = dir ? dir.openNextFile() : File();
    while (file) {
      String name = String(file.name());
      name = name.substring(name.lastIndexOf('/') + 1);
      if (validCapName(name) && !(capturing && name == capName)) {
        JsonObject item = list.add<JsonObject>();
        item["name"] = name;
        item["size"] = file.size();
      }
      file = dir.openNextFile();
    }
  }
  String out;
  serializeJson(doc, out);
  ws.textAll(out);
}

static bool flushCapture() {
  bool wrote = false;
  while (true) {
    portENTER_CRITICAL(&capMux);
    if (!capCount) { portEXIT_CRITICAL(&capMux); break; }
    memcpy(&capPending, &capRing[capHead], sizeof(CaptureFrame));
    capHead = (capHead + 1) % CAP_RING_SIZE;
    capCount--;
    portEXIT_CRITICAL(&capMux);
    size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
    if (total < used || total - used < capPending.len + 16 + 4096) {
      portENTER_CRITICAL(&capMux);
      capDropped++;
      portEXIT_CRITICAL(&capMux);
      return false;
    }
    uint8_t header[16];
    packetHeader(header, capPending.us, capPending.len);
    if (capFile.write(header, sizeof(header)) != sizeof(header) ||
        capFile.write(capPending.bytes, capPending.len) != capPending.len) {
      portENTER_CRITICAL(&capMux);
      capDropped++;
      portEXIT_CRITICAL(&capMux);
      capCorrupt = true;
      return false;
    }
    wrote = true;
  }
  if (wrote) capFile.flush();
  return true;
}

static void stopCapture(const char *reason, bool drain = true) {
  portENTER_CRITICAL(&capMux);
  capturing = false;
  portEXIT_CRITICAL(&capMux);
  if (drain && !flushCapture()) reason = "capture stopped: storage full or write failed";
  portENTER_CRITICAL(&capMux);
  capDropped += capCount;
  capCount = 0;
  capHead = capTail = 0;
  portEXIT_CRITICAL(&capMux);
  capFile.close();
  if (capCorrupt) {
    LittleFS.remove(String("/caps/") + capName);
    portENTER_CRITICAL(&capMux);
    capName[0] = '\0';
    portEXIT_CRITICAL(&capMux);
    capCorrupt = false;
    reason = "capture stopped: file write failed";
  }
  wsLog(reason);
  sendCapState();
  sendCaps();
}

static void startCapture() {
  if (!fsReady) { wsLog("capture refused: filesystem unavailable"); sendCapState(); return; }
  if (!sniffing || scanning) { wsLog("capture refused: sniffer unavailable"); sendCapState(); return; }
  size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
  if (total < used || total - used < 16384) { wsLog("capture refused: storage nearly full"); sendCapState(); return; }
  if (!LittleFS.exists("/caps") && !LittleFS.mkdir("/caps")) {
    wsLog("capture refused: cannot create capture directory"); sendCapState(); return;
  }
  String path;
  for (uint32_t n = 1; n <= 9999; n++) {
    path = "/caps/cap-" + String(n) + ".pcap";
    if (!LittleFS.exists(path)) break;
    path = "";
  }
  if (!path.length()) { wsLog("capture refused: file limit reached"); sendCapState(); return; }
  capFile = LittleFS.open(path, "w");
  uint8_t header[24];
  globalHeader(header);
  if (!capFile || capFile.write(header, sizeof(header)) != sizeof(header)) {
    capFile.close();
    LittleFS.remove(path);
    wsLog("capture refused: cannot write file"); sendCapState(); return;
  }
  hopping = false;
  capCorrupt = false;
  portENTER_CRITICAL(&capMux);
  snprintf(capName, sizeof(capName), "%s", path.c_str() + 6);
  capEapol = capPmkid = capDropped = 0;
  capHead = capTail = capCount = 0;
  capturing = true;
  portEXIT_CRITICAL(&capMux);
  wsLog("capture started: " + path);
  sendSniffState();
  sendCapState();
}

static void sendSniffState(AsyncWebSocketClient *client) {
  JsonDocument doc;
  doc["type"] = "sniff";
  doc["on"] = sniffing;
  doc["ch"] = sniffChannel;
  doc["hop"] = hopping;
  String out;
  serializeJson(doc, out);
  if (client) client->text(out);
  else ws.textAll(out);
}

static void sendDevices() {
  Device snapshot[64];
  size_t count;
  portENTER_CRITICAL(&deviceMux);
  count = deviceCount;
  memcpy(snapshot, devices, count * sizeof(Device));
  portEXIT_CRITICAL(&deviceMux);
  JsonDocument doc;
  doc["type"] = "sta";
  JsonArray list = doc["devices"].to<JsonArray>();
  uint32_t now = millis();
  for (size_t i = 0; i < count; i++) {
    JsonObject d = list.add<JsonObject>();
    d["mac"] = macText(snapshot[i].mac);
    d["target"] = snapshot[i].hasSsid ? snapshot[i].ssid : snapshot[i].hasBssid ? macText(snapshot[i].bssid) : "";
    d["probe"] = snapshot[i].hasSsid;
    d["rssi"] = snapshot[i].rssi;
    d["seen"] = (now - snapshot[i].seen) / 1000;
  }
  String out;
  serializeJson(doc, out);
  ws.textAll(out);
}

static void sendBeacons() {
  Beacon snapshot[48];
  size_t count;
  portENTER_CRITICAL(&deviceMux);
  count = beaconCount;
  memcpy(snapshot, beacons, count * sizeof(Beacon));
  portEXIT_CRITICAL(&deviceMux);
  JsonDocument doc;
  doc["type"] = "beacons";
  JsonArray list = doc["aps"].to<JsonArray>();
  uint32_t now = millis();
  for (size_t i = 0; i < count; i++) {
    JsonObject ap = list.add<JsonObject>();
    ap["ssid"] = snapshot[i].ssid;
    ap["bssid"] = macText(snapshot[i].bssid);
    ap["ch"] = snapshot[i].channel;
    ap["rssi"] = snapshot[i].rssi;
    // Best-effort label: privacy and RSN bits do not fully identify authentication.
    ap["enc"] = snapshot[i].rsn ? "WPA2" : snapshot[i].privacy ? "WPA/2" : "OPEN";
    ap["seen"] = (now - snapshot[i].seen) / 1000;
  }
  String out;
  serializeJson(doc, out);
  ws.textAll(out);
}

static void sendPacketMonitor() {
  uint32_t counts[3];
  uint8_t channel = sniffChannel;
  portENTER_CRITICAL(&deviceMux);
  memcpy(counts, packetCounts[channel], sizeof(counts));
  portEXIT_CRITICAL(&deviceMux);
  JsonDocument doc;
  doc["type"] = "pktmon";
  doc["ch"] = channel;
  doc["mgmt"] = counts[0];
  doc["data"] = counts[1];
  doc["ctrl"] = counts[2];
  doc["total"] = counts[0] + counts[1] + counts[2];
  String out;
  serializeJson(doc, out);
  ws.textAll(out);
}

static const char *encName(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/2";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/3";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
    default: return "?";
  }
}

static void sendScanResults(int n) {
  // ArduinoJson escapes SSIDs safely (they're untrusted and may contain quotes).
  JsonDocument doc;
  doc["type"] = "scan";
  JsonArray nets = doc["nets"].to<JsonArray>();
  for (int i = 0; i < n; i++) {
    JsonObject o = nets.add<JsonObject>();
    o["ssid"] = WiFi.SSID(i);
    o["bssid"] = WiFi.BSSIDstr(i);
    o["rssi"] = WiFi.RSSI(i);
    o["ch"] = WiFi.channel(i);
    o["enc"] = encName(WiFi.encryptionType(i));
  }
  String out;
  serializeJson(doc, out);
  ws.textAll(out);
  wsLog("scan done: " + String(n) + " networks");
}

static void onWsEvent(AsyncWebSocket *, AsyncWebSocketClient *client,
                      AwsEventType type, void *arg, uint8_t *data, size_t len) {
  if (type == WS_EVT_CONNECT) {
    wsLog("client connected: #" + String(client->id()));
    sendSniffState(client);
    sendCapState(client);
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo *info = (AwsFrameInfo *)arg;
    if (info->final && info->index == 0 && info->len == len &&
        info->opcode == WS_TEXT) {
      String command((char *)data, len);
      if (command == "scan") scanRequested = true;
      else if (command == "sniff:start") sniffStartRequested = true;
      else if (command == "sniff:stop") sniffStopRequested = true;
      else if (command == "hop:on") hopRequested = 1;
      else if (command == "hop:off") hopRequested = 0;
      else if (command == "cap:start") capStartRequested = true;
      else if (command == "cap:stop") capStopRequested = true;
      else if (command == "caps:list") capsListRequested = true;
      else if (command.startsWith("chan:")) {
        String number = command.substring(5);
        int ch = number.toInt();
        if (ch >= 1 && ch <= 13 && number == String(ch)) channelRequested = ch;
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);

  char checked[33];
  const uint8_t wildcard[] = {0, 0};
  const uint8_t overrun[] = {0, 3, 'A'};
  uint8_t beaconStyle[41] = {};
  beaconStyle[36] = 0;
  beaconStyle[37] = 3;
  memcpy(beaconStyle + 38, "Lab", 3);
  if (!parseSsid(wildcard, sizeof(wildcard), checked) || checked[0] != '\0' ||
      parseSsid(overrun, sizeof(overrun), checked) ||
      !parseSsid(beaconStyle + 36, sizeof(beaconStyle) - 36, checked) ||
      strcmp(checked, "Lab") ||
      parseSsid(beaconStyle + 36, 4, checked)) {
    Serial.println("SSID parser self-check failed");
    abort();
  }

  uint8_t pcap[24], record[16];
  const uint8_t expected[24] = {
      0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0xff, 0xff, 0, 0, 105, 0, 0, 0};
  const uint8_t expectedRecord[16] = {1, 0, 0, 0, 1, 0, 0, 0, 42, 0, 0, 0, 42, 0, 0, 0};
  uint8_t key[121] = {};
  key[1] = 3;
  key[3] = 117;
  key[4] = 2;
  key[6] = 0x88;
  key[98] = 22;
  key[99] = 221;
  key[100] = 20;
  memcpy(key + 101, "\x00\x0f\xac\x04", 4);
  if (globalHeader(pcap) != sizeof(pcap) || memcmp(pcap, expected, sizeof(pcap)) ||
      packetHeader(record, 1000001, 42) != sizeof(record) ||
      memcmp(record, expectedRecord, sizeof(record)) ||
      pmkidsInEapol(key, sizeof(key)) != 1 || pmkidsInEapol(key, sizeof(key) - 1)) {
    Serial.println("capture self-check failed");
    abort();
  }

  fsReady = LittleFS.begin(false);
  if (!fsReady) {
    Serial.println("LittleFS mount failed — dashboard assets won't serve");
  }

  WiFi.mode(WIFI_AP_STA);  // AP serves the dashboard; STA lets us scan
  bool ok = WiFi.softAP(AP_SSID, AP_PASS);
  Serial.printf("SoftAP \"%s\" -> %s\n", AP_SSID,
                ok ? WiFi.softAPIP().toString().c_str() : "FAILED");

  ws.onEvent(onWsEvent);
  server.addHandler(&ws);
  server.on(AsyncURIMatcher::dir("/caps"), HTTP_GET, [](AsyncWebServerRequest *r) {
    String name = r->url().substring(6);
    String path = "/caps/" + name;
    if (!validCapName(name) || !LittleFS.exists(path) || (capturing && name == capName)) {
      r->send(404, "text/plain", "not found");
      return;
    }
    r->send(LittleFS, path, "application/vnd.tcpdump.pcap", true);
  });
  server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html");
  server.onNotFound(
      [](AsyncWebServerRequest *r) { r->send(404, "text/plain", "not found"); });
  server.begin();
  Serial.println("web server up -> http://192.168.4.1");
}

unsigned long lastBeat = 0;

void loop() {
  ws.cleanupClients();

  if (capStopRequested) {
    capStopRequested = false;
    if (capturing) stopCapture("capture stopped");
    else sendCapState();
  }

  if (sniffStopRequested) {
    sniffStopRequested = false;
    sniffStartRequested = false;
    if (sniffing) {
      if (capturing) stopCapture("capture stopped");
      esp_err_t err = esp_wifi_set_promiscuous(false);
      if (err == ESP_OK) { sniffing = false; hopping = false; wsLog("sniffer stopped"); sendSniffState(); }
      else { wsLog("sniffer stop failed: " + String(esp_err_to_name(err))); sendSniffState(); }
    }
  }

  // Scanning channel-hops the radio, so the AP/clients briefly stall then
  // resume (the dashboard's WebSocket auto-reconnects). Run it from loop(),
  // not the async WS callback, to avoid blocking the server task.
  if (scanRequested && !scanning) {
    scanRequested = false;
    if (sniffing) wsLog("scan refused: stop the sniffer first");
    else {
      scanning = true;
      wsLog("scanning...");
      WiFi.scanNetworks(true);  // async
    }
  }

  if (channelRequested) {
    int ch = channelRequested;
    channelRequested = 0;
    hopRequested = -1;
    if (capturing) { wsLog("channel change refused: stop capture first"); sendSniffState(); }
    else if (scanning) { wsLog("channel change refused: scan in progress"); sendSniffState(); }
    else {
      hopping = false;
      esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      if (err == ESP_OK) { sniffChannel = ch; wsLog("channel " + String(ch)); sendSniffState(); }
      else { wsLog("channel change failed: " + String(esp_err_to_name(err))); sendSniffState(); }
    }
  }
  if (hopRequested != -1) {
    int requested = hopRequested;
    hopRequested = -1;
    if (requested && capturing) wsLog("hop refused: stop capture first");
    else if (requested && !sniffing) wsLog("hop refused: start the sniffer first");
    else {
      hopping = requested;
      lastHop = millis();
      wsLog(hopping ? "channel hopping started" : "channel hopping stopped");
    }
    sendSniffState();
  }
  if (capStartRequested && !sniffing && !scanning && !scanRequested) sniffStartRequested = true;
  if (sniffStartRequested) {
    sniffStartRequested = false;
    if (scanning || scanRequested) { wsLog("sniffer refused: scan in progress"); sendSniffState(); }
    else if (!sniffing) {
      wifi_promiscuous_filter_t filter = {};
      filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL;
      esp_err_t err = esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
      if (err == ESP_OK) err = esp_wifi_set_promiscuous_filter(&filter);
      if (err == ESP_OK) err = esp_wifi_set_promiscuous_rx_cb(onPacket);
      if (err == ESP_OK) {
        portENTER_CRITICAL(&deviceMux);
        memset(packetCounts, 0, sizeof(packetCounts));
        portEXIT_CRITICAL(&deviceMux);
      }
      if (err == ESP_OK) err = esp_wifi_set_promiscuous(true);
      if (err == ESP_OK) { sniffing = true; lastStaUpdate = millis(); wsLog("sniffer started on channel " + String(sniffChannel)); sendSniffState(); }
      else { wsLog("sniffer start failed: " + String(esp_err_to_name(err))); sendSniffState(); }
    }
  }
  if (capStartRequested) {
    capStartRequested = false;
    if (!capturing) startCapture();
    else sendCapState();
  }
  if (sniffing && hopping && millis() - lastHop >= 250) {
    lastHop = millis();
    uint8_t next = sniffChannel == 13 ? 1 : sniffChannel + 1;
    esp_err_t err = esp_wifi_set_channel(next, WIFI_SECOND_CHAN_NONE);
    if (err == ESP_OK) { sniffChannel = next; sendSniffState(); }
    else { hopping = false; wsLog("channel hop failed: " + String(esp_err_to_name(err))); sendSniffState(); }
  }
  if (sniffing && millis() - lastStaUpdate >= 1000) {
    lastStaUpdate = millis();
    sendDevices();
    sendBeacons();
    sendPacketMonitor();
    if (capturing) sendCapState();
  }
  if (capturing && !flushCapture()) stopCapture("capture stopped: storage full or write failed", false);
  if (capsListRequested) { capsListRequested = false; sendCaps(); }
  if (scanning) {
    int n = WiFi.scanComplete();
    if (n >= 0) {
      sendScanResults(n);
      WiFi.scanDelete();
      scanning = false;
    } else if (n == WIFI_SCAN_FAILED) {
      wsLog("scan failed");
      ws.textAll("{\"type\":\"scan\",\"nets\":[]}");
      scanning = false;
    }
  }

  if (millis() - lastBeat >= 2000) {
    lastBeat = millis();
    wsLog("uptime " + String(millis() / 1000) +
          "s | stations: " + String(WiFi.softAPgetStationNum()));
  }
}
