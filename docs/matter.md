# Matter 1.5 Camera Integration

Thingino includes native support for exposing cameras via the **Matter 1.5**
specification, designed specifically for Home Assistant and Matter-compatible
controllers.

## Architecture & UNIX Philosophy

Following the UNIX philosophy of Thingino, `thingino-matter` is composed of:

1. **`matterd` (Pure C Daemon)**:
   - A lightweight background daemon (~30KB binary footprint) running directly
     on the Ingenic SoC.
   - **Dual-Stack IPv6 / IPv4 UDP Listener**: Listens on port 5540 (`[::]:5540`)
     and responds to Matter Session and Interaction Model messages.
   - **Matter 1.5 DNS-SD / mDNS Responder**: Advertises `_matterc._udp.local`
     (commissionable) and `_matter._tcp.local` (operational) service records
     with mandatory Matter 1.5 Camera discovery keys (`VP`, `D`, `CM`, `DT=0x51`,
     `DN`, `SII`, `SAI`, `T`, `CRI`) over IPv6 multicast (`ff02::fb`) and IPv4.
   - **Framing & Matter TLV**: Implements Matter framing and Type-Length-Value
     (TLV) encoding/decoding.
   - **PASE & Session Cryptography**: Implements Password-Authenticated Session
     Establishment (PASE) and session cryptography backed by `mbedTLS`.
   - **WebRTC Transport Provider Cluster (`0x0551`)**: Bridges SDP offer/answer
     signaling between the Matter controller and the camera's streamer backend.
   - **Camera Settings Cluster (`0x0550`)**: Exposes night vision, privacy mode,
     and motion detection attributes and commands.

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
4. Ensure your Home Assistant host and camera have IPv6 connectivity enabled.
5. In **Home Assistant**:
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
