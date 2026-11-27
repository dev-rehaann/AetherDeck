#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

// Step 2: SoftAP + dashboard (Step 1) plus a Wi-Fi AP scanner. The browser
// sends "scan" over the WebSocket; results go back as JSON for a live table.

// Default AP credentials — meant to be known so you can connect (WPA2, >=8
// chars). Made configurable in Settings (Step 8).
static const char *AP_SSID = "AetherDeck";
static const char *AP_PASS = "aetherdeck";

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

static bool scanRequested = false;
static bool scanning = false;

static void wsLog(const String &line) {
  Serial.println(line);
  ws.textAll(line);
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
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo *info = (AwsFrameInfo *)arg;
    if (info->final && info->index == 0 && info->len == len &&
        info->opcode == WS_TEXT) {
      if (String((char *)data, len) == "scan") scanRequested = true;
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);

  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS mount failed — dashboard assets won't serve");
  }

  WiFi.mode(WIFI_AP_STA);  // AP serves the dashboard; STA lets us scan
  bool ok = WiFi.softAP(AP_SSID, AP_PASS);
  Serial.printf("SoftAP \"%s\" -> %s\n", AP_SSID,
                ok ? WiFi.softAPIP().toString().c_str() : "FAILED");

  ws.onEvent(onWsEvent);
  server.addHandler(&ws);
  server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html");
  server.onNotFound(
      [](AsyncWebServerRequest *r) { r->send(404, "text/plain", "not found"); });
  server.begin();
  Serial.println("web server up -> http://192.168.4.1");
}

unsigned long lastBeat = 0;

void loop() {
  ws.cleanupClients();

  // Scanning channel-hops the radio, so the AP/clients briefly stall then
  // resume (the dashboard's WebSocket auto-reconnects). Run it from loop(),
  // not the async WS callback, to avoid blocking the server task.
  if (scanRequested && !scanning) {
    scanRequested = false;
    scanning = true;
    wsLog("scanning...");
    WiFi.scanNetworks(true);  // async
  }
  if (scanning) {
    int n = WiFi.scanComplete();
    if (n >= 0) {
      sendScanResults(n);
      WiFi.scanDelete();
      scanning = false;
    } else if (n == WIFI_SCAN_FAILED) {
      wsLog("scan failed");
      scanning = false;
    }
  }

  if (millis() - lastBeat >= 2000) {
    lastBeat = millis();
    wsLog("uptime " + String(millis() / 1000) +
          "s | stations: " + String(WiFi.softAPgetStationNum()));
  }
}
