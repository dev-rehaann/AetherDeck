#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>

// Step 1: boot a SoftAP, serve the dashboard from LittleFS, and stream a live
// log to the browser over WebSocket.

// Default AP credentials. These are meant to be known so you can connect; the
// password is WPA2 (>=8 chars). Made configurable in Settings (Step 8).
static const char *AP_SSID = "AetherDeck";
static const char *AP_PASS = "aetherdeck";

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

static void wsLog(const String &line) {
  Serial.println(line);
  ws.textAll(line);
}

static void onWsEvent(AsyncWebSocket *, AsyncWebSocketClient *client,
                      AwsEventType type, void *, uint8_t *, size_t) {
  if (type == WS_EVT_CONNECT) {
    wsLog("client connected: #" + String(client->id()));
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);

  if (!LittleFS.begin(true)) {  // format on first run so the mount succeeds
    Serial.println("LittleFS mount failed — dashboard assets won't serve");
  }

  WiFi.mode(WIFI_AP);
  bool ok = WiFi.softAP(AP_SSID, AP_PASS);
  Serial.printf("SoftAP \"%s\" -> %s\n", AP_SSID,
                ok ? WiFi.softAPIP().toString().c_str() : "FAILED");

  ws.onEvent(onWsEvent);
  server.addHandler(&ws);
  server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html");
  server.onNotFound(
      [](AsyncWebServerRequest *r) { r->send(404, "text/plain", "not found"); });
  server.begin();
  Serial.println("web server up — open http://192.168.4.1");
}

unsigned long lastBeat = 0;

void loop() {
  ws.cleanupClients();
  if (millis() - lastBeat >= 2000) {
    lastBeat = millis();
    wsLog("uptime " + String(millis() / 1000) +
          "s | stations: " + String(WiFi.softAPgetStationNum()));
  }
}
