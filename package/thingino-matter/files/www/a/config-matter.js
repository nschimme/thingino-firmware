document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("matter-form");
  const badge = document.getElementById("matter-status-badge");
  const pairingCodeEl = document.getElementById("matter_pairing_code");

  function loadConfig() {
    fetch("/x/json-config-matter.cgi")
      .then((res) => res.json())
      .then((data) => {
        const cfg = data.matter || {};
        document.getElementById("matter_enabled").checked = !!cfg.enabled;
        document.getElementById("matter_device_name").value =
          cfg.device_name || "Thingino Matter Camera";
        document.getElementById("matter_streamer_backend").value =
          cfg.streamer_backend || "auto";
        document.getElementById("matter_port").value = cfg.port || 5540;
        document.getElementById("matter_discriminator").value =
          cfg.discriminator || 3840;
        document.getElementById("matter_passcode").value =
          cfg.passcode || 20202021;
        document.getElementById("matter_enable_nightmode").checked =
          cfg.enable_nightmode !== false;
        document.getElementById("matter_enable_privacy").checked =
          cfg.enable_privacy !== false;
        document.getElementById("matter_enable_motion").checked =
          cfg.enable_motion !== false;

        if (data.status) {
          if (data.status.running) {
            badge.className = "badge bg-success";
            badge.textContent = "Running";
          } else {
            badge.className = "badge bg-secondary";
            badge.textContent = "Stopped";
          }
          if (data.status.pairing_code) {
            pairingCodeEl.textContent = data.status.pairing_code;
          }
        }
      })
      .catch((err) => {
        console.error("Failed to load Matter configuration", err);
      });
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const btn = document.getElementById("btn-save");
    btn.disabled = true;

    const payload = {
      matter: {
        enabled: document.getElementById("matter_enabled").checked,
        device_name: document.getElementById("matter_device_name").value,
        streamer_backend: document.getElementById("matter_streamer_backend")
          .value,
        port: parseInt(document.getElementById("matter_port").value, 10),
        discriminator: parseInt(
          document.getElementById("matter_discriminator").value,
          10,
        ),
        passcode: parseInt(
          document.getElementById("matter_passcode").value,
          10,
        ),
        enable_nightmode: document.getElementById("matter_enable_nightmode")
          .checked,
        enable_privacy: document.getElementById("matter_enable_privacy")
          .checked,
        enable_motion: document.getElementById("matter_enable_motion").checked,
      },
    };

    fetch("/x/json-config-matter.cgi", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then((res) => res.json())
      .then(() => {
        btn.disabled = false;
        loadConfig();
      })
      .catch((err) => {
        btn.disabled = false;
        alert("Failed to save Matter configuration: " + err);
      });
  });

  loadConfig();
});
