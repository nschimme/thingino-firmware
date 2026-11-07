# Matter 1.5 Camera Integration

Thingino includes native support for exposing cameras via the **Matter 1.5**
specification, designed specifically for Home Assistant and Matter-compatible
controllers.

## Architecture & UNIX Philosophy

Following the UNIX philosophy of Thingino, `thingino-matter` integrates the
standards-compliant pure C99 Matter protocol stack (`esp-dev/matter-c`, Apache-2.0):

1. **`matterd` (Pure C Matter Node)**:
   - A standalone, spec-compliant C99 Matter node running on the Ingenic SoC.
   - **Pure IPv6 UDP Transport**: Communicates on port 5540 and IPv6 mDNS (`ff02::fb`).
   - **Compliant Cryptographic Protocols**:
     - Spec-compliant **SPAKE2+** (Core Section 3.10) with PBKDF2 HMAC SHA-256
       and points $M$ and $N$ on curve `secp256r1`.
     - Spec-compliant **CASE (SIGMA-I / SIGMA-II)** operational sessions with
       X.509 Node Operational Certificate (NOC) and resumption caching.
     - Section 4.4.5 compliant 13-byte Nonce AES-128-CCM transport encryption.
   - **Interaction Model**: Complete Read, Write, Invoke, and Subscribe engine.
   - **WebRTC Transport Provider Cluster (`0x0551`)**: Bridges SDP offer/answer
     signaling directly to Raptor (`/x/webrtc-whip.cgi`) or TIMPS (`/webrtc/whep`).
   - **Camera Settings Cluster (`0x0550`)**: Exposes night vision, privacy mode,
     and motion detection attributes and commands mapped to `agentctl`.

2. **Streamer Profile Discovery (`S96matter_discovery`)**:
   - Mirrors the ONVIF streamer discovery architecture (`S96onvif_discovery`).
   - Detects active streamer (Raptor WHIP or TIMPS WHEP) and configures runtime parameters automatically.

3. **Subsystem Event & Control Callbacks**:
   - Outbound commands (night vision, IR-cut, privacy mode) map to `agentctl` and Thingino's standard tools (`daynight`, `privacy`).
   - Inbound events: Automatically monitors `/run/motion` alarm flags and accepts async events via `matter-event`, emitting Matter Attribute Reports to subscribed controllers.

## Pairing with Home Assistant

1. In the Thingino Web UI, navigate to **Settings -> Matter**.
2. Enable the Matter Camera Service.
3. Note the **11-Digit Manual Pairing Code** (e.g., `17598012333`).
4. Ensure your Home Assistant host and camera have IPv6 connectivity on the local subnet.
5. In **Home Assistant**:
   - Go to **Settings -> Devices & Services -> Integrations**.
   - Click **Add Integration** and choose **Matter**.
   - Select **No, it's not on the network / Enter setup code**.
   - Enter the 11-digit manual pairing code.
   - Home Assistant will commission the device over IPv6, establish session security,
     negotiate the live WebRTC stream, and expose entities for night mode, privacy,
     and motion detection.

## CLI Usage

The `matterctl` helper allows inspecting and controlling the Matter service:

```bash
# Check status and pairing credentials
matterctl status
matterctl status --json

# Get the verified 11-digit manual pairing code with Verhoeff checksum
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
