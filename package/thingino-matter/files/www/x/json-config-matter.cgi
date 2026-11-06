#!/bin/sh
# shellcheck disable=SC1091,SC2018,SC2019,SC2329,SC3043

if [ -f /var/www/x/auth.sh ]; then
	. /var/www/x/auth.sh
	require_auth
fi

CONFIG_FILE="/etc/thingino.json"

send_json() {
	status="${2:-200 OK}"
	printf 'Status: %s\r\n' "$status"
	printf 'Content-Type: application/json\r\n'
	printf 'Cache-Control: no-store\r\n\r\n'
	printf '%s\n' "$1"
	exit 0
}

get_status_json() {
	if pidof matterd >/dev/null 2>&1; then
		running="true"
	else
		running="false"
	fi
	pairing_code=$(matterctl pairing-code 2>/dev/null || echo "00000000000")
	printf '{"running":%s,"pairing_code":"%s"}' "$running" "$pairing_code"
}

if [ "$REQUEST_METHOD" = "POST" ]; then
	REQ_BODY=$(mktemp /tmp/matter_req.XXXXXX)
	cat >"$REQ_BODY"

	# If jq or jct is available, save into thingino.json
	if command -v jct >/dev/null 2>&1; then
		val_enabled=$(sed -n 's/.*"enabled"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$REQ_BODY")
		val_port=$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$REQ_BODY")
		val_disc=$(sed -n 's/.*"discriminator"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$REQ_BODY")
		val_pass=$(sed -n 's/.*"passcode"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$REQ_BODY")
		val_backend=$(sed -n 's/.*"streamer_backend"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REQ_BODY")

		[ -n "$val_enabled" ] && jct "$CONFIG_FILE" set matter.enabled "$val_enabled"
		[ -n "$val_port" ] && jct "$CONFIG_FILE" set matter.port "$val_port"
		[ -n "$val_disc" ] && jct "$CONFIG_FILE" set matter.discriminator "$val_disc"
		[ -n "$val_pass" ] && jct "$CONFIG_FILE" set matter.passcode "$val_pass"
		[ -n "$val_backend" ] && jct "$CONFIG_FILE" set matter.streamer_backend "$val_backend"

		# Restart service if enabled
		if [ "$val_enabled" = "true" ]; then
			/etc/init.d/S94matter restart >/dev/null 2>&1 || true
		else
			/etc/init.d/S94matter stop >/dev/null 2>&1 || true
		fi
	fi
	rm -f "$REQ_BODY"
	send_json '{"status":"ok"}'
fi

# GET request: Return configuration and status
matter_json=""
if command -v jct >/dev/null 2>&1; then
	matter_json=$(jct "$CONFIG_FILE" get matter 2>/dev/null)
fi
if [ -z "$matter_json" ]; then
	matter_json='{"enabled":false,"port":5540,"discriminator":3840,"passcode":20202021,"streamer_backend":"auto"}'
fi

status_json=$(get_status_json)
send_json "{\"matter\":$matter_json,\"status\":$status_json}"
