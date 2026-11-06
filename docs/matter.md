# Matter 1.5 Camera Integration

Thingino includes native support for exposing cameras via the **Matter 1.5**
specification, designed specifically for Home Assistant and Matter-compatible
controllers.

## Architecture & UNIX Philosophy

Following the UNIX philosophy of Thingino, `thingino-matter` is composed of:

1. **`matterd` (Pure C Daemon)**:
   - A lightweight background daemon (~43KB stripped binary, ~14KB compressed)
     running directly on the Ingenic SoC.
   - **Pure IPv6 UDP Transport**: Listens on port 5540 (`[::]:5540`) using strict
     IPv6 socket configuration (`IPV6_V6ONLY=1`), adhering to Matter specifications.
   - **Matter 1.5 DNS-SD / mDNS Responder**: Advertises `_matterc._udp.local`
     (commissionable) and `_matter._tcp.local` (operational) service records
     with mandatory Matter 1.5 Camera discovery keys (`VP`, `D`, `CM`, `DT=0x51`,
     `DN`, `SII`, `SAI`, `T`, `CRI`) over IPv6 multicast (`ff02::fb:5353`).
   - **Endpoint 0 (Root Node)**:
     - `Descriptor` Cluster (`0x001D`): Exposes Root Node Device Type (`0x0016`).
     - `General Commissioning` (`0x0030`): ArmFailSafe, CommissioningComplete.
     - `Operational Credentials` (`0x003E`): Real DER CSR generation via `mbedtls_x509write_csr`.
   - **Endpoint 1 (Camera Device Type 0x0051)**:
     - `Descriptor` Cluster (`0x001D`): Exposes Camera Device Type (`0x0051`).
     - `WebRTC Transport Provider` Cluster (`0x0551`):
       - Attributes: `SupportedCodecs` (`video/H264;audio/opus`), `MaxConcurrentSessions` (2), `CurrentSessions`.
       - Commands: `ProvideOffer`, `ProvideAnswer`, `ProvideICECandidates`, `EndSession`.
     - `Camera Settings` Cluster (`0x0550`):
       - Attributes: `NightMode` (`0x0001`), `PrivacyMode` (`0x0002`), `MotionDetected` (`0x0003`).
   - **PASE & Session Cryptography**:
     - SPAKE2+ key agreement on `secp256r1` with PBKDF2 HMAC SHA-256 (32-bit LE passcode)
       and points $M$ and $N$ ($pB = Y + w_0 \cdot N$).
     - Section 4.4.5 compliant 13-byte Nonce AES-128-CCM session encryption and decryption.
   - **Valid 11-Digit Pairing Code**: Calculates setup codes using the standard
     Verhoeff checksum algorithm per Matter specification Section 5.1.4.1.
   - **In-Process WebRTC Signaling Bridge**: Extracts the real SDP offer from
     the controller's TLV request and negotiates directly in-process over non-blocking
     HTTP sockets without invoking external shell tools like `curl`.

2. **Streamer Profile Discovery (`S96matter_discovery`)**:
   - Mirrors the ONVIF streamer discovery architecture (`S96onvif_discovery`).
   - Detects active streamer (Raptor WHIP `/x/webrtc-whip.cgi` or TIMPS WHEP
     `/webrtc/whep`) and configures runtime parameters automatically.

3. **Subsystem Event & Control Callbacks**:
   - Outbound commands (e.g. night vision, IR-cut, privacy mode) map to
     `agentctl` and Thingino's standard tools (`daynight`, `privacy`).
   - Inbound events: Automatically monitors `/run/motion` alarm flags and
     accepts async events via `/run/matter/cmd.fifo` or `/usr/sbin/matter-event`,
     emitting Matter Attribute Reports to subscribed controllers.

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
