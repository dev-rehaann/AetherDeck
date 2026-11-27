#include <Arduino.h>

// Step 0: minimal boot so the toolchain builds clean. The SoftAP + web
// dashboard arrive in Step 1.
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("AetherDeck boot (Step 0)");
}

void loop() {}
