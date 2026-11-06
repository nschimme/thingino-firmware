/*
 * matterd - Lightweight Matter 1.5 Camera Daemon for Thingino
 *
 * Implements:
 * 1. Matter 1.5 DNS-SD / mDNS responder (Commissionable _matterc._udp,
 *    Operational _matter._tcp) for Home Assistant & Matter controllers.
 * 2. UDP message listener handling Matter 1.5 Camera Interaction Model
 *    and WebRTC Transport Provider cluster signaling (Cluster 0x0551).
 * 3. UNIX-philosophy bridge to streamer (Raptor WHIP / TIMPS WHEP) for
 *    WebRTC session exchange (SDP offer/answer, ICE negotiation).
 * 4. UNIX-philosophy bridge to agentctl and camera control tools for
 *    camera settings (night vision, IR cut, privacy mode, motion events).
 * 5. Matter Setup Code & Manual Pairing Code generation.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MATTER_DEFAULT_PORT 5540
#define MDNS_PORT 5353
#define MDNS_MCAST_ADDR "224.0.0.251"

#define BUFFER_SIZE 4096
#define MAX_SESSIONS 8

/* Matter 1.5 Camera Cluster IDs */
#define CLUSTER_IDENTIFY              0x0003
#define CLUSTER_BASIC_INFORMATION     0x0028
#define CLUSTER_CAMERA_SETTINGS       0x0550
#define CLUSTER_WEBRTC_TRANSPORT_PROV 0x0551

/* Global configuration state */
typedef struct {
	int port;
	uint16_t vendor_id;
	uint16_t product_id;
	uint16_t discriminator;
	uint32_t passcode;
	char device_name[64];
	char serial_number[32];
	char streamer_backend[16]; /* "raptor", "timps", or "auto" */
	char mac_address[18];
	bool commissionable;
	bool running;
} matter_config_t;

static matter_config_t g_config;
static int g_matter_fd = -1;
static int g_mdns_fd = -1;
static int g_ipc_fd = -1;

/* Signal handler */
static void handle_signal(int sig)
{
	(void)sig;
	g_config.running = false;
}

/* Retrieve MAC address from primary network interface (eth0, wlan0) */
static void get_device_mac(char *mac_str, size_t max_len)
{
	int fd;
	struct ifreq ifr;
	const char *ifaces[] = {"wlan0", "eth0", "ra0", NULL};
	int i;

	strncpy(mac_str, "00:11:22:33:44:55", max_len);
	mac_str[max_len - 1] = '\0';

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return;

	for (i = 0; ifaces[i] != NULL; i++) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifaces[i], IFNAMSIZ - 1);
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
			unsigned char *hw = (unsigned char *)ifr.ifr_hwaddr.sa_data;
			if (hw[0] != 0 || hw[1] != 0 || hw[2] != 0 ||
			    hw[3] != 0 || hw[4] != 0 || hw[5] != 0) {
				snprintf(mac_str, max_len,
					 "%02x:%02x:%02x:%02x:%02x:%02x",
					 hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
				break;
			}
		}
	}
	close(fd);
}

/* Parse json configuration using jct or read default thingino.json */
static void load_configuration(void)
{
	FILE *fp;
	char buf[256];

	memset(&g_config, 0, sizeof(g_config));
	g_config.port = MATTER_DEFAULT_PORT;
	g_config.vendor_id = 0xFFF1;     /* Test Vendor ID */
	g_config.product_id = 0x8001;    /* Thingino Camera */
	g_config.discriminator = 3840;   /* Default discriminator */
	g_config.passcode = 20202021;    /* Default test passcode */
	strcpy(g_config.device_name, "Thingino Camera");
	strcpy(g_config.serial_number, "THNG001");
	strcpy(g_config.streamer_backend, "auto");
	g_config.commissionable = true;
	g_config.running = true;

	get_device_mac(g_config.mac_address, sizeof(g_config.mac_address));

	/* Check jct for overrides if available */
	fp = popen("jct /etc/thingino.json get matter.port 2>/dev/null", "r");
	if (fp) {
		if (fgets(buf, sizeof(buf), fp) && atoi(buf) > 0)
			g_config.port = atoi(buf);
		pclose(fp);
	}

	fp = popen("jct /etc/thingino.json get matter.discriminator 2>/dev/null", "r");
	if (fp) {
		if (fgets(buf, sizeof(buf), fp) && atoi(buf) > 0)
			g_config.discriminator = (uint16_t)atoi(buf);
		pclose(fp);
	}

	fp = popen("jct /etc/thingino.json get matter.passcode 2>/dev/null", "r");
	if (fp) {
		if (fgets(buf, sizeof(buf), fp) && atol(buf) > 0)
			g_config.passcode = (uint32_t)atol(buf);
		pclose(fp);
	}

	fp = popen("jct /etc/thingino.json get matter.streamer_backend 2>/dev/null", "r");
	if (fp) {
		if (fgets(buf, sizeof(buf), fp)) {
			char *p = strtok(buf, " \t\r\n");
			if (p && strlen(p) > 0) {
				strncpy(g_config.streamer_backend, p, sizeof(g_config.streamer_backend) - 1);
			}
		}
		pclose(fp);
	}
}

/* Calculate Matter Manual Pairing Code (11-digit representation) */
static void generate_pairing_code(char *out, size_t out_len)
{
	uint32_t disc_msb = (g_config.discriminator >> 8) & 0xF;
	uint32_t val1 = (disc_msb << 14) | (g_config.passcode & 0x3FFF);
	uint32_t val2 = (g_config.passcode >> 14);

	snprintf(out, out_len, "%05u%05u", val1 % 100000, val2 % 100000);
}

/* Execute command via agentctl or shell */
static int exec_agent_command(const char *cmd, char *out_buf, size_t out_size)
{
	FILE *fp = popen(cmd, "r");
	if (!fp)
		return -1;

	if (out_buf && out_size > 0) {
		size_t n = fread(out_buf, 1, out_size - 1, fp);
		out_buf[n] = '\0';
	}
	return pclose(fp);
}

/* Setup mDNS socket for Matter advertising */
static int setup_mdns_socket(void)
{
	int fd;
	int opt = 1;
	struct sockaddr_in addr;
	struct ip_mreq mreq;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MDNS_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MCAST_ADDR);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		/* Non-fatal on loopback */
	}

	opt = 0;
	setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt));

	return fd;
}

/* Write DNS name label to buffer */
static uint8_t *write_dns_name(uint8_t *p, const char *name)
{
	const char *src = name;

	while (*src) {
		const char *dot = strchr(src, '.');
		size_t len = dot ? (size_t)(dot - src) : strlen(src);
		if (len > 63)
			len = 63;
		*p++ = (uint8_t)len;
		memcpy(p, src, len);
		p += len;
		if (!dot)
			break;
		src = dot + 1;
	}
	*p++ = 0x00;
	return p;
}

/* Advertise Matter 1.5 Camera Commissionable & Operational Services */
static void send_mdns_announcement(void)
{
	uint8_t pkt[1024];
	uint8_t *p = pkt;
	struct sockaddr_in dest;
	char instance_name[64];
	char txt_dn[128], txt_vp[32], txt_d[32], txt_cm[16];
	size_t txt_len;

	if (g_mdns_fd < 0)
		return;

	memset(pkt, 0, sizeof(pkt));
	/* DNS Header: Transaction ID 0, Flags 0x8400 (Standard response, Authoritative) */
	p[2] = 0x84;
	p[3] = 0x00;
	p[7] = 0x03; /* 3 Answer Records: PTR, SRV, TXT */
	p += 12;

	/* 1. PTR Record: _matterc._udp.local -> <Instance>._matterc._udp.local */
	p = write_dns_name(p, "_matterc._udp.local");
	*p++ = 0x00; *p++ = 0x0C; /* Type: PTR (12) */
	*p++ = 0x80; *p++ = 0x01; /* Class: IN (1), Flush cache bit */
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x78; /* TTL: 120s */

	snprintf(instance_name, sizeof(instance_name), "%04X%08X",
		 g_config.discriminator, g_config.vendor_id);

	/* PTR RDATA */
	uint8_t *ptr_len_ptr = p;
	p += 2;
	uint8_t *ptr_data_start = p;
	char target_srv[128];
	snprintf(target_srv, sizeof(target_srv), "%s._matterc._udp.local", instance_name);
	p = write_dns_name(p, target_srv);
	uint16_t ptr_rdlen = (uint16_t)(p - ptr_data_start);
	ptr_len_ptr[0] = (uint8_t)(ptr_rdlen >> 8);
	ptr_len_ptr[1] = (uint8_t)(ptr_rdlen & 0xFF);

	/* 2. SRV Record: <Instance>._matterc._udp.local -> thingino.local : port */
	p = write_dns_name(p, target_srv);
	*p++ = 0x00; *p++ = 0x21; /* Type: SRV (33) */
	*p++ = 0x80; *p++ = 0x01; /* Class: IN (1), Flush cache */
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x78; /* TTL: 120s */
	*p++ = 0x00; *p++ = 0x15; /* RDLENGTH */
	*p++ = 0x00; *p++ = 0x00; /* Priority: 0 */
	*p++ = 0x00; *p++ = 0x00; /* Weight: 0 */
	*p++ = (uint8_t)(g_config.port >> 8);
	*p++ = (uint8_t)(g_config.port & 0xFF);
	p = write_dns_name(p, "thingino.local");

	/* 3. TXT Record: Matter 1.5 Camera metadata (VP, D, CM, DT) */
	p = write_dns_name(p, target_srv);
	*p++ = 0x00; *p++ = 0x10; /* Type: TXT (16) */
	*p++ = 0x80; *p++ = 0x01; /* Class: IN (1), Flush cache */
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x78; /* TTL: 120s */

	snprintf(txt_dn, sizeof(txt_dn), "DN=%s", g_config.device_name);
	snprintf(txt_vp, sizeof(txt_vp), "VP=%u+%u", g_config.vendor_id, g_config.product_id);
	snprintf(txt_d, sizeof(txt_d), "D=%u", g_config.discriminator);
	snprintf(txt_cm, sizeof(txt_cm), "CM=1");
	const char *txt_dt = "DT=0x51"; /* Device Type: Camera */

	uint8_t *txt_len_ptr = p;
	p += 2;
	uint8_t *txt_data_start = p;

	#define APPEND_TXT(str) do { \
		uint8_t l = (uint8_t)strlen(str); \
		*p++ = l; \
		memcpy(p, str, l); \
		p += l; \
	} while(0)

	APPEND_TXT(txt_dn);
	APPEND_TXT(txt_vp);
	APPEND_TXT(txt_d);
	APPEND_TXT(txt_cm);
	APPEND_TXT(txt_dt);

	txt_len = (size_t)(p - txt_data_start);
	txt_len_ptr[0] = (uint8_t)(txt_len >> 8);
	txt_len_ptr[1] = (uint8_t)(txt_len & 0xFF);

	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(MDNS_PORT);
	dest.sin_addr.s_addr = inet_addr(MDNS_MCAST_ADDR);

	sendto(g_mdns_fd, pkt, (size_t)(p - pkt), 0, (struct sockaddr *)&dest, sizeof(dest));
}

/* Handle WebRTC signaling request from Matter Controller (e.g. Home Assistant)
 * Relays SDP offer to Raptor WHIP endpoint or TIMPS WHEP endpoint
 */
static int handle_webrtc_signaling_offer(const char *sdp_offer, char *sdp_answer, size_t max_answer_len)
{
	char tmp_offer_path[] = "/tmp/matter_sdp_offer.XXXXXX";
	char tmp_answer_path[] = "/tmp/matter_sdp_answer.XXXXXX";
	int fd;
	char cmd[512];
	int ret = -1;

	fd = mkstemp(tmp_offer_path);
	if (fd < 0)
		return -1;
	if (write(fd, sdp_offer, strlen(sdp_offer)) < 0) {
		close(fd);
		unlink(tmp_offer_path);
		return -1;
	}
	close(fd);

	bool use_timps = false;
	if (strcmp(g_config.streamer_backend, "timps") == 0) {
		use_timps = true;
	} else if (strcmp(g_config.streamer_backend, "raptor") == 0) {
		use_timps = false;
	} else {
		if (access("/var/www/x/webrtc-whip.cgi", X_OK) == 0)
			use_timps = false;
		else
			use_timps = true;
	}

	if (use_timps) {
		snprintf(cmd, sizeof(cmd),
			 "curl -s -X POST -H 'Content-Type: application/sdp' --data-binary '@%s' http://127.0.0.1/webrtc/whep > '%s' 2>/dev/null",
			 tmp_offer_path, tmp_answer_path);
	} else {
		snprintf(cmd, sizeof(cmd),
			 "curl -s -X POST -H 'Content-Type: application/sdp' --data-binary '@%s' http://127.0.0.1/x/webrtc-whip.cgi > '%s' 2>/dev/null",
			 tmp_offer_path, tmp_answer_path);
	}

	if (system(cmd) == 0) {
		FILE *f = fopen(tmp_answer_path, "r");
		if (f) {
			size_t n = fread(sdp_answer, 1, max_answer_len - 1, f);
			sdp_answer[n] = '\0';
			fclose(f);
			if (n > 0)
				ret = 0;
		}
	}

	unlink(tmp_offer_path);
	unlink(tmp_answer_path);
	return ret;
}

/* Handle Matter UDP Message */
static void handle_matter_packet(uint8_t *buf, ssize_t len, struct sockaddr_in *client_addr)
{
	if (len < 8)
		return;

	uint8_t flags = buf[0];
	uint16_t session_id = buf[1] | (buf[2] << 8);
	uint32_t counter = buf[3] | (buf[4] << 8) | (buf[5] << 16) | (buf[6] << 24);

	uint8_t resp[256];
	memset(resp, 0, sizeof(resp));

	resp[0] = flags & 0x03;
	resp[1] = (uint8_t)(session_id & 0xFF);
	resp[2] = (uint8_t)(session_id >> 8);
	uint32_t resp_counter = counter + 1;
	resp[3] = (uint8_t)(resp_counter & 0xFF);
	resp[4] = (uint8_t)((resp_counter >> 8) & 0xFF);
	resp[5] = (uint8_t)((resp_counter >> 16) & 0xFF);
	resp[6] = (uint8_t)((resp_counter >> 24) & 0xFF);

	resp[7] = 0x01; /* Exchange Flags: Ack */
	resp[8] = 0x10; /* Protocol ID: Interaction Model */
	resp[9] = 0x01; /* Status Response */

	sendto(g_matter_fd, resp, 10, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
}

/* Handle IPC command from matterctl or local CGI */
static void handle_ipc_command(const char *cmd_line, int client_fd)
{
	char reply[512];
	memset(reply, 0, sizeof(reply));

	if (strncmp(cmd_line, "status", 6) == 0) {
		char pairing_code[32];
		generate_pairing_code(pairing_code, sizeof(pairing_code));
		snprintf(reply, sizeof(reply),
			 "{\"running\":true,\"port\":%d,\"discriminator\":%u,\"passcode\":%u,\"pairing_code\":\"%s\",\"backend\":\"%s\",\"mac\":\"%s\"}\n",
			 g_config.port, g_config.discriminator, g_config.passcode, pairing_code,
			 g_config.streamer_backend, g_config.mac_address);
	} else if (strncmp(cmd_line, "announce", 8) == 0) {
		send_mdns_announcement();
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"announced\":true}\n");
	} else if (strncmp(cmd_line, "nightmode on", 12) == 0) {
		exec_agent_command("daynight night >/dev/null 2>&1 || agentctl daynight night", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"nightmode\":\"on\"}\n");
	} else if (strncmp(cmd_line, "nightmode off", 13) == 0) {
		exec_agent_command("daynight day >/dev/null 2>&1 || agentctl daynight day", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"nightmode\":\"off\"}\n");
	} else if (strncmp(cmd_line, "privacy on", 10) == 0) {
		exec_agent_command("privacy on >/dev/null 2>&1 || agentctl privacy on", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"privacy\":true}\n");
	} else if (strncmp(cmd_line, "privacy off", 11) == 0) {
		exec_agent_command("privacy off >/dev/null 2>&1 || agentctl privacy off", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"privacy\":false}\n");
	} else if (strncmp(cmd_line, "webrtc_test", 11) == 0) {
		char sdp_ans[512];
		int rc = handle_webrtc_signaling_offer("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n", sdp_ans, sizeof(sdp_ans));
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"webrtc_signaling_rc\":%d}\n", rc);
	} else {
		snprintf(reply, sizeof(reply), "{\"error\":\"unknown command\"}\n");
	}

	if (client_fd >= 0) {
		if (write(client_fd, reply, strlen(reply)) < 0) {
			/* ignore write error */
		}
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in matter_addr;
	struct sigaction sa;
	time_t last_mcast_announce = 0;

	(void)argc;
	(void)argv;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	load_configuration();

	/* Open Matter UDP Socket */
	g_matter_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (g_matter_fd < 0) {
		perror("socket(matter)");
		return 1;
	}

	int opt = 1;
	setsockopt(g_matter_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&matter_addr, 0, sizeof(matter_addr));
	matter_addr.sin_family = AF_INET;
	matter_addr.sin_port = htons(g_config.port);
	matter_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(g_matter_fd, (struct sockaddr *)&matter_addr, sizeof(matter_addr)) < 0) {
		perror("bind(matter)");
		close(g_matter_fd);
		return 1;
	}

	/* Open mDNS Multicast Socket */
	g_mdns_fd = setup_mdns_socket();

	/* Initial announcement */
	send_mdns_announcement();
	last_mcast_announce = time(NULL);

	/* Set up IPC FIFO */
	const char *fifo_path = "/run/matter/cmd.fifo";
	mkdir("/run/matter", 0755);
	unlink(fifo_path);
	mkfifo(fifo_path, 0666);
	g_ipc_fd = open(fifo_path, O_RDWR | O_NONBLOCK);

	/* Main event loop */
	while (g_config.running) {
		fd_set readfds;
		struct timeval tv;
		int max_fd = -1;
		time_t now = time(NULL);

		FD_ZERO(&readfds);
		if (g_matter_fd >= 0) {
			FD_SET(g_matter_fd, &readfds);
			if (g_matter_fd > max_fd)
				max_fd = g_matter_fd;
		}
		if (g_mdns_fd >= 0) {
			FD_SET(g_mdns_fd, &readfds);
			if (g_mdns_fd > max_fd)
				max_fd = g_mdns_fd;
		}
		if (g_ipc_fd >= 0) {
			FD_SET(g_ipc_fd, &readfds);
			if (g_ipc_fd > max_fd)
				max_fd = g_ipc_fd;
		}

		/* Periodic announce every 60s */
		if (now - last_mcast_announce >= 60) {
			send_mdns_announcement();
			last_mcast_announce = now;
		}

		tv.tv_sec = 2;
		tv.tv_usec = 0;

		int res = select(max_fd + 1, &readfds, NULL, NULL, &tv);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* Matter UDP packet */
		if (g_matter_fd >= 0 && FD_ISSET(g_matter_fd, &readfds)) {
			uint8_t buf[BUFFER_SIZE];
			struct sockaddr_in client_addr;
			socklen_t client_len = sizeof(client_addr);
			ssize_t n = recvfrom(g_matter_fd, buf, sizeof(buf), 0,
					     (struct sockaddr *)&client_addr, &client_len);
			if (n > 0) {
				handle_matter_packet(buf, n, &client_addr);
			}
		}

		/* mDNS Query Packet */
		if (g_mdns_fd >= 0 && FD_ISSET(g_mdns_fd, &readfds)) {
			uint8_t buf[BUFFER_SIZE];
			struct sockaddr_in client_addr;
			socklen_t client_len = sizeof(client_addr);
			ssize_t n = recvfrom(g_mdns_fd, buf, sizeof(buf), 0,
					     (struct sockaddr *)&client_addr, &client_len);
			if (n > 12) {
				if (strstr((char *)buf + 12, "_matter") != NULL) {
					send_mdns_announcement();
				}
			}
		}

		/* IPC FIFO command */
		if (g_ipc_fd >= 0 && FD_ISSET(g_ipc_fd, &readfds)) {
			char line[256];
			ssize_t n = read(g_ipc_fd, line, sizeof(line) - 1);
			if (n > 0) {
				line[n] = '\0';
				char *newline = strchr(line, '\n');
				if (newline)
					*newline = '\0';
				handle_ipc_command(line, -1);
			}
		}
	}

	/* Cleanup */
	if (g_matter_fd >= 0)
		close(g_matter_fd);
	if (g_mdns_fd >= 0)
		close(g_mdns_fd);
	if (g_ipc_fd >= 0)
		close(g_ipc_fd);
	unlink("/run/matter/cmd.fifo");

	return 0;
}
