# Passive Wi-Fi detection

Start the sniffer in the dashboard to monitor the selected channel, or enable channel hopping to sample channels 1–13 when the SoftAP has no connected client. The radio cannot change channels while a dashboard client is associated, so connected operators can monitor the current AP channel. Detection is available without Authorized mode. Alerts appear in the Detect card and over the WebSocket as `{"type":"alert","kind":...,"detail":...,"ts":...}`. The timestamp is seconds since boot. The board does not transmit detection traffic.

## Many SSIDs from one BSSID

The receiver records distinct nonempty SSIDs in beacons and probe responses from each BSSID. It alerts when one BSSID reaches the selected threshold (three by default; the dashboard accepts 1–16). A device intentionally answering many directed probes may produce this pattern. Some legitimate equipment advertises multiple SSIDs from one radio address. The table retains 16 names for each of 32 BSSIDs; older entries can be evicted on busy channels, and names beyond the cap are not counted.

## Duplicate SSID

The receiver compares recent beacons (seen within 30 seconds). When two BSSIDs advertise the same nonempty SSID, the alert lists both BSSIDs, channels, and received signal strengths. This is an indicator, not proof of impersonation: managed networks, repeaters, and mesh systems routinely share an SSID. Beacon clock comparison is not included because the available samples may be separated by channel hopping and are not a reliable identity check here.

## Deauthentication or disassociation burst

The receiver counts management deauthentication and disassociation frames. More than 20 frames in an approximately one-second window produces an alert with the source and target addresses from the most recent frame in that window. This identifies a burst, not its cause or sender authenticity. Normal reconnects and network maintenance can also create bursts; MAC addresses in unprotected management frames can be forged.

Alerts for the same indicator repeat no more than once every 30 seconds. A change in the number of distinct SSIDs can produce another alert sooner. Detection requires the sniffer to be running on the traffic's channel; channel hopping can miss short events. Received frames and SSIDs are bounded by the existing capture tables and packet length checks.
