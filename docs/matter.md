# Matter 1.5 Camera Integration

Thingino includes native support for exposing cameras via the **Matter 1.5**
specification, designed specifically for Home Assistant and Matter-compatible
controllers.

## Architecture

Following the UNIX philosophy of Thingino, `thingino-matter` is composed of:

1. **`matterd` (Pure C Daemon)**:
   - A lightweight background daemon (~22KB binary footprint) running directly
     on the Ingenic SoC.
   - **DNS-SD / mDNS Responder**: Advertises `_matterc._udp.local` (commissionable)
     and `_matter._tcp.local` (operational) service records with Matter Camera
     device type (`DT=0x51`).
   - **Matter Protocol Listener**: Listens on UDP port 5540 for Matter Session
     and Interaction Model messages.
   - **WebRTC Transport Provider Cluster (`0x0551`)**: Bridges SDP offer/answer
     signaling between the Matter controller and the camera's streamer backend.

2. **Streamer WebRTC Signaling Bridge**:
   - **Raptor**: Connects directly to Raptor's native WebRTC/WHIP endpoint
     (`/x/webrtc-whip.cgi`).
   - **TIMPS**: Connects directly to TIMPS's native WHEP endpoint (`/webrtc/whep`).
   - Auto-detection selects the active streamer backend automatically.

3. **Subsystem Event & Control Callbacks**:
   - Outbound commands (e.g. night vision, IR-cut, privacy mode) map to
     `agentctl` and Thingino's standard tools (`daynight`, `privacy`).
   - Inbound events (motion triggers from RMD, night mode switches from photosensors)
     are fed to `matterd` via `/run/matter/cmd.fifo` or `/usr/sbin/matter-event`,
     which in turn emits Matter Attribute Reports to subscribed controllers.

## Pairing with Home Assistant

1. In the Thingino Web UI, navigate to **Settings -> Matter**.
2. Enable the Matter Camera Service.
3. Note the **Manual Pairing Code** (e.g., `12345678901`).
4. In **Home Assistant**:
   - Go to **Settings -> Devices & Services -> Integrations**.
   - Click **Add Integration** and choose **Matter**.
   - When prompted, select **No, it's not on the network / Enter setup code**.
   - Enter the 11-digit manual pairing code displayed in the Web UI.
   - Home Assistant will commission the device, attach the live WebRTC stream,
     and expose control entities for night mode, privacy, and motion detection.

## CLI Usage

The `matterctl` helper allows inspecting and controlling the Matter service:

```bash
# Check status and pairing credentials
matterctl status

# Get the 11-digit manual pairing code
matterctl pairing-code

# Re-broadcast mDNS discovery announcement
matterctl announce

# Trigger night vision or privacy mode
matterctl nightmode on
matterctl privacy on
```

## Sending Events from Custom Scripts

Any script or hook can emit asynchronous events into Matter:

```bash
matter-event motion 1
matter-event motion 0
matter-event nightmode on
matter-event privacy off
```
