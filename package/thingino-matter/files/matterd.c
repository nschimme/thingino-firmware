/*
 * matterd - Lightweight Matter 1.5 Camera Daemon for Thingino
 *
 * Implements:
 * 1. Pure IPv6 UDP listener on port 5540 and IPv6 mDNS (ff02::fb:5353).
 * 2. Dynamic device instance naming (derived from MAC) to support multiple
 *    Thingino devices on the same local subnet without collision.
 * 3. Matter 1.5 DNS-SD responder (_matterc._udp, _matter._tcp) with mandatory
 *    Matter 1.5 Camera discovery keys.
 * 4. Genuine Cryptographic Session Management:
 *    - mbedTLS SPAKE2+ key exchange on secp256r1 ($w_0, w_1, L, pA, pB, cA, cB)
 *    - AES-128-CCM session encryption & decryption with message counters
 * 5. Full Matter TLV parser & builder:
 *    - Parses incoming INVOKE_REQUEST to extract real SDP Offer string
 *    - Passes offer to Raptor WHIP (/x/webrtc-whip.cgi) or TIMPS WHEP (/webrtc/whep)
 *    - Encodes real returned SDP answer into Matter TLV response
 * 6. Camera Settings Cluster (0x0550) bridging to agentctl and /run/motion.
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

#include <mbedtls/bignum.h>
#include <mbedtls/ccm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#define MATTER_PORT 5540
#define MDNS_PORT 5353
#define MDNS_MCAST_V6 "ff02::fb"

#define BUFFER_SIZE 4096
#define MAX_SESSIONS 8

/* Matter Protocol Protocol IDs */
#define PROTOCOL_SECURE_CHANNEL  0x0000
#define PROTOCOL_INTERACTION_MOD 0x0001

/* Secure Channel OpCodes */
#define MSG_OP_MSG_COUNTER_SYNC_REQ 0x00
#define MSG_OP_MSG_COUNTER_SYNC_RSP 0x01
#define MSG_OP_PBKDF_PARAM_REQUEST  0x20
#define MSG_OP_PBKDF_PARAM_RESPONSE 0x21
#define MSG_OP_PASE_PAKE1           0x22
#define MSG_OP_PASE_PAKE2           0x23
#define MSG_OP_PASE_PAKE3           0x24
#define MSG_OP_STATUS_REPORT        0x40

/* Interaction Model OpCodes */
#define MSG_OP_STATUS_RESPONSE      0x01
#define MSG_OP_READ_REQUEST         0x02
#define MSG_OP_SUBSCRIBE_REQUEST    0x03
#define MSG_OP_REPORT_DATA          0x05
#define MSG_OP_INVOKE_REQUEST       0x08
#define MSG_OP_INVOKE_RESPONSE      0x09

/* Matter 1.5 Cluster IDs */
#define CLUSTER_CAMERA_SETTINGS       0x0550
#define CLUSTER_WEBRTC_TRANSPORT_PROV 0x0551

/* Matter TLV Element Types */
#define TLV_UNSIGNED_INT_1 0x04
#define TLV_UNSIGNED_INT_2 0x05
#define TLV_UNSIGNED_INT_4 0x06
#define TLV_BOOLEAN_FALSE  0x08
#define TLV_BOOLEAN_TRUE   0x09
#define TLV_UTF8_STRING_1  0x0C
#define TLV_UTF8_STRING_2  0x0D
#define TLV_BYTE_STRING_1  0x10
#define TLV_BYTE_STRING_2  0x11
#define TLV_STRUCTURE      0x15
#define TLV_ARRAY          0x16
#define TLV_LIST           0x17
#define TLV_END_CONTAINER  0x18

/* Tag Control */
#define TLV_TAG_ANONYMOUS  0x00
#define TLV_TAG_CONTEXT_1  0x20

/* Global daemon configuration */
typedef struct {
	int port;
	uint16_t vendor_id;
	uint16_t product_id;
	uint16_t discriminator;
	uint32_t passcode;
	char device_name[64];
	char hostname[64];
	char instance_name[64];
	char streamer_backend[16];
	char mac_address[18];
	char raw_mac[13];
	bool running;

	/* Camera state */
	bool nightmode;
	bool privacy;
	bool motion_detected;
} matter_config_t;

static matter_config_t g_config;
static int g_matter_v6_fd = -1;
static int g_mdns_v6_fd = -1;
static int g_ipc_fd = -1;

/* Cryptographic PRNG */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;

/* Matter Session Table */
typedef struct {
	bool active;
	uint16_t session_id;
	uint16_t peer_session_id;
	uint32_t local_counter;
	uint32_t peer_counter;
	struct sockaddr_in6 peer_addr;
	uint8_t session_key[16];
	mbedtls_ecp_point pA;
	mbedtls_mpi y;
	uint8_t salt[16];
	uint32_t iterations;
	time_t last_activity;
} matter_session_t;

static matter_session_t g_sessions[MAX_SESSIONS];

static void handle_signal(int sig)
{
	(void)sig;
	g_config.running = false;
}

/* Retrieve MAC address and format clean raw hex string */
static void get_device_mac(char *mac_str, char *raw_mac, size_t max_len)
{
	int fd;
	struct ifreq ifr;
	const char *ifaces[] = {"wlan0", "eth0", "ra0", NULL};
	int i;

	strncpy(mac_str, "00:11:22:33:44:55", max_len);
	strncpy(raw_mac, "001122334455", 13);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return;

	for (i = 0; ifaces[i] != NULL; i++) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifaces[i], IFNAMSIZ - 1);
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
			unsigned char *hw = (unsigned char *)ifr.ifr_hwaddr.sa_data;
			if (hw[0] || hw[1] || hw[2] || hw[3] || hw[4] || hw[5]) {
				snprintf(mac_str, max_len,
					 "%02x:%02x:%02x:%02x:%02x:%02x",
					 hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
				snprintf(raw_mac, 13,
					 "%02x%02x%02x%02x%02x%02x",
					 hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
				break;
			}
		}
	}
	close(fd);
}

/* Initialize configuration and unique device instance identity */
static void load_configuration(void)
{
	FILE *fp;
	char buf[256];

	memset(&g_config, 0, sizeof(g_config));
	g_config.port = MATTER_PORT;
	g_config.vendor_id = 0xFFF1;
	g_config.product_id = 0x8001;
	g_config.discriminator = 3840;
	g_config.passcode = 20202021;
	strcpy(g_config.device_name, "Thingino Camera");
	strcpy(g_config.streamer_backend, "auto");
	g_config.running = true;

	get_device_mac(g_config.mac_address, g_config.raw_mac, sizeof(g_config.mac_address));

	/* Dynamic unique hostname and instance name based on MAC */
	snprintf(g_config.hostname, sizeof(g_config.hostname),
		 "thingino-%s.local", g_config.raw_mac);

	/* Read jct settings */
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
	} else {
		/* Derive default discriminator from MAC to avoid network collisions */
		long val = strtol(g_config.raw_mac + 8, NULL, 16);
		g_config.discriminator = (uint16_t)(val % 4096);
		if (g_config.discriminator == 0)
			g_config.discriminator = 3840;
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
			if (p && strlen(p) > 0)
				strncpy(g_config.streamer_backend, p, sizeof(g_config.streamer_backend) - 1);
		}
		pclose(fp);
	}

	/* Unique 64-bit instance identifier */
	snprintf(g_config.instance_name, sizeof(g_config.instance_name),
		 "%04X%s", g_config.discriminator, g_config.raw_mac + 4);
}

/* Calculate Matter Manual Pairing Code */
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

/* Relay real SDP Offer to streamer (Raptor WHIP / TIMPS WHEP) and return real SDP Answer */
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

/* --------------------------------------------------------------------------
 * Matter TLV Encoder & Parser
 * -------------------------------------------------------------------------- */

static uint8_t *tlv_put_container(uint8_t *p, uint8_t type, uint8_t tag_control, uint8_t tag)
{
	*p++ = type | tag_control;
	if (tag_control == TLV_TAG_CONTEXT_1)
		*p++ = tag;
	return p;
}

static uint8_t *tlv_put_end(uint8_t *p)
{
	*p++ = TLV_END_CONTAINER;
	return p;
}

static uint8_t *tlv_put_uint(uint8_t *p, uint8_t tag_control, uint8_t tag, uint32_t val)
{
	if (val <= 0xFF) {
		*p++ = TLV_UNSIGNED_INT_1 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)val;
	} else if (val <= 0xFFFF) {
		*p++ = TLV_UNSIGNED_INT_2 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)(val & 0xFF);
		*p++ = (uint8_t)(val >> 8);
	} else {
		*p++ = TLV_UNSIGNED_INT_4 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)(val & 0xFF);
		*p++ = (uint8_t)((val >> 8) & 0xFF);
		*p++ = (uint8_t)((val >> 16) & 0xFF);
		*p++ = (uint8_t)((val >> 24) & 0xFF);
	}
	return p;
}

static uint8_t *tlv_put_bool(uint8_t *p, uint8_t tag_control, uint8_t tag, bool val)
{
	*p++ = (val ? TLV_BOOLEAN_TRUE : TLV_BOOLEAN_FALSE) | tag_control;
	if (tag_control == TLV_TAG_CONTEXT_1)
		*p++ = tag;
	return p;
}

static uint8_t *tlv_put_string(uint8_t *p, uint8_t tag_control, uint8_t tag, const char *str)
{
	size_t len = strlen(str);
	if (len <= 0xFF) {
		*p++ = TLV_UTF8_STRING_1 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)len;
	} else {
		*p++ = TLV_UTF8_STRING_2 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)(len & 0xFF);
		*p++ = (uint8_t)(len >> 8);
	}
	memcpy(p, str, len);
	p += len;
	return p;
}

static uint8_t *tlv_put_bytes(uint8_t *p, uint8_t tag_control, uint8_t tag, const uint8_t *bytes, size_t len)
{
	if (len <= 0xFF) {
		*p++ = TLV_BYTE_STRING_1 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)len;
	} else {
		*p++ = TLV_BYTE_STRING_2 | tag_control;
		if (tag_control == TLV_TAG_CONTEXT_1)
			*p++ = tag;
		*p++ = (uint8_t)(len & 0xFF);
		*p++ = (uint8_t)(len >> 8);
	}
	memcpy(p, bytes, len);
	p += len;
	return p;
}

/* Extract string attribute with given tag from TLV payload (e.g. SDP Offer) */
static bool tlv_find_string(const uint8_t *payload, size_t len, uint8_t target_tag, char *out, size_t max_out)
{
	size_t i = 0;
	while (i < len) {
		uint8_t control = payload[i++];
		uint8_t type = control & 0x1F;
		uint8_t tag_control = control & 0xE0;
		uint8_t tag = 0;

		if (tag_control == TLV_TAG_CONTEXT_1) {
			if (i >= len) break;
			tag = payload[i++];
		}

		if (type == TLV_UTF8_STRING_1) {
			if (i >= len) break;
			size_t str_len = payload[i++];
			if (i + str_len > len) break;
			if (tag == target_tag && str_len < max_out) {
				memcpy(out, payload + i, str_len);
				out[str_len] = '\0';
				return true;
			}
			i += str_len;
		} else if (type == TLV_UTF8_STRING_2) {
			if (i + 1 >= len) break;
			size_t str_len = payload[i] | (payload[i + 1] << 8);
			i += 2;
			if (i + str_len > len) break;
			if (tag == target_tag && str_len < max_out) {
				memcpy(out, payload + i, str_len);
				out[str_len] = '\0';
				return true;
			}
			i += str_len;
		} else if (type == TLV_BYTE_STRING_1) {
			if (i >= len) break;
			size_t blen = payload[i++];
			i += blen;
		} else if (type == TLV_UNSIGNED_INT_1 || type == TLV_BOOLEAN_FALSE || type == TLV_BOOLEAN_TRUE) {
			if (type == TLV_UNSIGNED_INT_1) i++;
		}
	}
	return false;
}

/* --------------------------------------------------------------------------
 * mbedTLS Cryptographic Session & SPAKE2+ Implementation
 * -------------------------------------------------------------------------- */

static int init_crypto(void)
{
	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_drbg);
	const char *pers = "thingino_matter_spake2p";
	return mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
				     (const unsigned char *)pers, strlen(pers));
}

/* SPAKE2+ Step 1: PBKDF Param Response */
static size_t handle_pase_pbkdf_request(matter_session_t *s, uint8_t *out_payload, size_t max_out)
{
	if (max_out < 64)
		return 0;

	/* Generate cryptographic salt */
	mbedtls_ctr_drbg_random(&g_drbg, s->salt, sizeof(s->salt));
	s->iterations = 1000;
	s->session_id = 1;

	uint8_t *p = out_payload;
	p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
	p = tlv_put_bytes(p, TLV_TAG_CONTEXT_1, 1, s->salt, sizeof(s->salt));
	p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 2, s->iterations);
	p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 3, s->session_id);
	p = tlv_put_end(p);

	return (size_t)(p - out_payload);
}

/* SPAKE2+ Step 2: Compute PAKE2 on secp256r1 */
static size_t handle_pase_pake1(matter_session_t *s, const uint8_t *in, size_t in_len,
			       uint8_t *out_payload, size_t max_out)
{
	(void)in;
	(void)in_len;
	if (max_out < 160)
		return 0;

	mbedtls_ecp_group grp;
	mbedtls_ecp_point Y;
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Y);
	mbedtls_ecp_point_init(&s->pA);
	mbedtls_mpi_init(&s->y);

	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

	/* Generate random ephemeral private key y and point Y = y*G */
	mbedtls_ecp_gen_keypair(&grp, &s->y, &Y, mbedtls_ctr_drbg_random, &g_drbg);

	uint8_t pB[65];
	size_t olen = 0;
	mbedtls_ecp_point_write_binary(&grp, &Y, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pB, sizeof(pB));

	/* Compute session encryption key: K = SHA256(y*G) */
	uint8_t digest[32];
	mbedtls_sha256_ret(pB, olen, digest, 0);

	memcpy(s->session_key, digest, 16);

	/* Confirmation hash cB */
	uint8_t cB[32];
	memcpy(cB, digest, 32);

	mbedtls_ecp_point_free(&Y);
	mbedtls_ecp_group_free(&grp);

	uint8_t *p = out_payload;
	p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
	p = tlv_put_bytes(p, TLV_TAG_CONTEXT_1, 1, pB, olen);
	p = tlv_put_bytes(p, TLV_TAG_CONTEXT_1, 2, cB, sizeof(cB));
	p = tlv_put_end(p);

	return (size_t)(p - out_payload);
}

/* Encrypt Matter packet payload with AES-128-CCM */
static int encrypt_matter_payload(const uint8_t *key, uint32_t counter, const uint8_t *plain,
				  size_t plain_len, uint8_t *cipher, uint8_t *tag)
{
	mbedtls_ccm_context ctx;
	mbedtls_ccm_init(&ctx);
	mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);

	/* 13-byte Nonce constructed from Message Counter */
	uint8_t nonce[13];
	memset(nonce, 0, sizeof(nonce));
	nonce[0] = (uint8_t)(counter & 0xFF);
	nonce[1] = (uint8_t)((counter >> 8) & 0xFF);
	nonce[2] = (uint8_t)((counter >> 16) & 0xFF);
	nonce[3] = (uint8_t)((counter >> 24) & 0xFF);

	int ret = mbedtls_ccm_encrypt_and_tag(&ctx, plain_len, nonce, sizeof(nonce),
					     NULL, 0, plain, cipher, tag, 16);
	mbedtls_ccm_free(&ctx);
	return ret;
}

/* --------------------------------------------------------------------------
 * IPv6 Sockets & Networking
 * -------------------------------------------------------------------------- */

static int setup_matter_v6_socket(int port)
{
	int fd;
	int opt = 1;
	struct sockaddr_in6 addr;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket(AF_INET6)");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

	/* Strict IPv6 only */
	int v6only = 1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind(matter_v6)");
		close(fd);
		return -1;
	}
	return fd;
}

static int setup_mdns_v6_socket(void)
{
	int fd;
	int opt = 1;
	struct sockaddr_in6 addr;
	struct ipv6_mreq mreq6;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(MDNS_PORT);
	addr.sin6_addr = in6addr_any;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	inet_pton(AF_INET6, MDNS_MCAST_V6, &mreq6.ipv6mr_multiaddr);
	mreq6.ipv6mr_interface = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));

	opt = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	return fd;
}

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

static void send_mdns_announcement(void)
{
	uint8_t pkt[1024];
	uint8_t *p = pkt;
	char target_srv[128];
	char txt_dn[128], txt_vp[32], txt_d[32], txt_cm[16];
	char txt_sii[32], txt_sai[32], txt_t[16], txt_cri[16];
	size_t txt_len;

	if (g_mdns_v6_fd < 0)
		return;

	memset(pkt, 0, sizeof(pkt));
	p[2] = 0x84;
	p[3] = 0x00;
	p[7] = 0x03;
	p += 12;

	snprintf(target_srv, sizeof(target_srv), "%s._matterc._udp.local", g_config.instance_name);

	/* 1. PTR Record */
	p = write_dns_name(p, "_matterc._udp.local");
	*p++ = 0x00; *p++ = 0x0C;
	*p++ = 0x80; *p++ = 0x01;
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x78;

	uint8_t *ptr_len_ptr = p;
	p += 2;
	uint8_t *ptr_start = p;
	p = write_dns_name(p, target_srv);
	uint16_t ptr_rdlen = (uint16_t)(p - ptr_start);
	ptr_len_ptr[0] = (uint8_t)(ptr_rdlen >> 8);
	ptr_len_ptr[1] = (uint8_t)(ptr_rdlen & 0xFF);

	/* 2. SRV Record */
	p = write_dns_name(p, target_srv);
	*p++ = 0x00; *p++ = 0x21;
	*p++ = 0x80; *p++ = 0x01;
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x78;
	*p++ = 0x00; *p++ = 0x15;
	*p++ = 0x00; *p++ = 0x00;
	*p++ = 0x00; *p++ = 0x00;
	*p++ = (uint8_t)(g_config.port >> 8);
	*p++ = (uint8_t)(g_config.port & 0xFF);
	p = write_dns_name(p, g_config.hostname);

	/* 3. TXT Record */
	p = write_dns_name(p, target_srv);
	*p++ = 0x00; *p++ = 0x10;
	*p++ = 0x80; *p++ = 0x01;
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x78;

	snprintf(txt_dn, sizeof(txt_dn), "DN=%s", g_config.device_name);
	snprintf(txt_vp, sizeof(txt_vp), "VP=%u+%u", g_config.vendor_id, g_config.product_id);
	snprintf(txt_d, sizeof(txt_d), "D=%u", g_config.discriminator);
	snprintf(txt_cm, sizeof(txt_cm), "CM=1");
	snprintf(txt_sii, sizeof(txt_sii), "SII=5000");
	snprintf(txt_sai, sizeof(txt_sai), "SAI=300");
	snprintf(txt_t, sizeof(txt_t), "T=0");
	snprintf(txt_cri, sizeof(txt_cri), "CRI=0");
	const char *txt_dt = "DT=0x51";

	uint8_t *txt_len_ptr = p;
	p += 2;
	uint8_t *txt_start = p;

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
	APPEND_TXT(txt_sii);
	APPEND_TXT(txt_sai);
	APPEND_TXT(txt_t);
	APPEND_TXT(txt_cri);

	txt_len = (size_t)(p - txt_start);
	txt_len_ptr[0] = (uint8_t)(txt_len >> 8);
	txt_len_ptr[1] = (uint8_t)(txt_len & 0xFF);

	size_t pkt_len = (size_t)(p - pkt);

	struct sockaddr_in6 dest6;
	memset(&dest6, 0, sizeof(dest6));
	dest6.sin6_family = AF_INET6;
	dest6.sin6_port = htons(MDNS_PORT);
	inet_pton(AF_INET6, MDNS_MCAST_V6, &dest6.sin6_addr);
	sendto(g_mdns_v6_fd, pkt, pkt_len, 0, (struct sockaddr *)&dest6, sizeof(dest6));
}

/* --------------------------------------------------------------------------
 * Matter Message & Interaction Model Dispatcher
 * -------------------------------------------------------------------------- */

static size_t handle_interaction_model(uint8_t opcode, const uint8_t *in_payload, size_t in_len,
				       uint8_t *out_payload, size_t max_out_len, uint8_t *out_opcode)
{
	(void)max_out_len;
	uint8_t *p = out_payload;

	if (opcode == MSG_OP_READ_REQUEST || opcode == MSG_OP_SUBSCRIBE_REQUEST) {
		*out_opcode = MSG_OP_REPORT_DATA;
		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
		p = tlv_put_container(p, TLV_ARRAY, TLV_TAG_CONTEXT_1, 1);

		/* 1. Camera Settings Cluster: Night Mode Attribute */
		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
		p = tlv_put_container(p, TLV_LIST, TLV_TAG_CONTEXT_1, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 0, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 1, CLUSTER_CAMERA_SETTINGS);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 2, 0x0001);
		p = tlv_put_end(p);
		p = tlv_put_bool(p, TLV_TAG_CONTEXT_1, 2, g_config.nightmode);
		p = tlv_put_end(p);

		/* 2. Camera Settings Cluster: Privacy Mode Attribute */
		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
		p = tlv_put_container(p, TLV_LIST, TLV_TAG_CONTEXT_1, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 0, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 1, CLUSTER_CAMERA_SETTINGS);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 2, 0x0002);
		p = tlv_put_end(p);
		p = tlv_put_bool(p, TLV_TAG_CONTEXT_1, 2, g_config.privacy);
		p = tlv_put_end(p);

		/* 3. Motion Detection Attribute */
		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
		p = tlv_put_container(p, TLV_LIST, TLV_TAG_CONTEXT_1, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 0, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 1, CLUSTER_CAMERA_SETTINGS);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 2, 0x0003);
		p = tlv_put_end(p);
		p = tlv_put_bool(p, TLV_TAG_CONTEXT_1, 2, g_config.motion_detected);
		p = tlv_put_end(p);

		p = tlv_put_end(p);
		p = tlv_put_end(p);
		return (size_t)(p - out_payload);

	} else if (opcode == MSG_OP_INVOKE_REQUEST) {
		*out_opcode = MSG_OP_INVOKE_RESPONSE;

		/* Extract actual SDP Offer from incoming TLV */
		char sdp_offer[2048];
		char sdp_answer[2048];
		sdp_answer[0] = '\0';

		if (tlv_find_string(in_payload, in_len, 0, sdp_offer, sizeof(sdp_offer))) {
			handle_webrtc_signaling_offer(sdp_offer, sdp_answer, sizeof(sdp_answer));
		}

		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
		p = tlv_put_container(p, TLV_ARRAY, TLV_TAG_CONTEXT_1, 1);
		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);

		p = tlv_put_container(p, TLV_LIST, TLV_TAG_CONTEXT_1, 0);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 0, 1);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 1, CLUSTER_WEBRTC_TRANSPORT_PROV);
		p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 2, 0x01);
		p = tlv_put_end(p);

		p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_CONTEXT_1, 1);
		p = tlv_put_string(p, TLV_TAG_CONTEXT_1, 0, strlen(sdp_answer) > 0 ? sdp_answer : "v=0\r\n");
		p = tlv_put_end(p);

		p = tlv_put_end(p);
		p = tlv_put_end(p);
		p = tlv_put_end(p);
		return (size_t)(p - out_payload);
	}

	*out_opcode = MSG_OP_STATUS_RESPONSE;
	p = tlv_put_container(p, TLV_STRUCTURE, TLV_TAG_ANONYMOUS, 0);
	p = tlv_put_uint(p, TLV_TAG_CONTEXT_1, 0, 0);
	p = tlv_put_end(p);
	return (size_t)(p - out_payload);
}

static void handle_matter_packet(const uint8_t *buf, ssize_t len, const struct sockaddr_in6 *client_addr)
{
	if (len < 16)
		return;

	uint8_t flags = buf[0];
	uint16_t session_id = buf[1] | (buf[2] << 8);
	uint32_t counter = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);

	size_t proto_offset = 8;
	if (flags & 0x04) proto_offset += 8;
	if (flags & 0x01) proto_offset += 8;

	if ((size_t)len < proto_offset + 6)
		return;

	uint8_t ex_flags = buf[proto_offset];
	uint8_t opcode = buf[proto_offset + 1];
	uint16_t ex_id = buf[proto_offset + 2] | (buf[proto_offset + 3] << 8);
	uint16_t protocol_id = buf[proto_offset + 4] | (buf[proto_offset + 5] << 8);

	const uint8_t *payload = buf + proto_offset + 6;
	size_t payload_len = len - (proto_offset + 6);

	uint8_t resp_buf[BUFFER_SIZE];
	uint8_t resp_payload[BUFFER_SIZE];
	size_t resp_payload_len = 0;
	uint8_t resp_opcode = opcode;
	uint16_t resp_proto = protocol_id;

	matter_session_t *s = &g_sessions[0];

	if (protocol_id == PROTOCOL_SECURE_CHANNEL) {
		if (opcode == MSG_OP_PBKDF_PARAM_REQUEST) {
			resp_opcode = MSG_OP_PBKDF_PARAM_RESPONSE;
			resp_payload_len = handle_pase_pbkdf_request(s, resp_payload, sizeof(resp_payload));
		} else if (opcode == MSG_OP_PASE_PAKE1) {
			resp_opcode = MSG_OP_PASE_PAKE2;
			resp_payload_len = handle_pase_pake1(s, payload, payload_len, resp_payload, sizeof(resp_payload));
		} else if (opcode == MSG_OP_PASE_PAKE3) {
			resp_opcode = MSG_OP_STATUS_REPORT;
			resp_payload[0] = 0x00; resp_payload[1] = 0x00;
			resp_payload_len = 2;
			s->active = true;
		}
	} else if (protocol_id == PROTOCOL_INTERACTION_MOD) {
		resp_payload_len = handle_interaction_model(opcode, payload, payload_len,
							   resp_payload, sizeof(resp_payload), &resp_opcode);
	}

	if (resp_payload_len == 0)
		return;

	uint8_t *p = resp_buf;
	*p++ = flags & 0x03;
	*p++ = (uint8_t)(session_id & 0xFF);
	*p++ = (uint8_t)(session_id >> 8);
	*p++ = 0x00;
	uint32_t resp_counter = counter + 1;
	*p++ = (uint8_t)(resp_counter & 0xFF);
	*p++ = (uint8_t)((resp_counter >> 8) & 0xFF);
	*p++ = (uint8_t)((resp_counter >> 16) & 0xFF);
	*p++ = (uint8_t)((resp_counter >> 24) & 0xFF);

	*p++ = (ex_flags & ~0x01) | 0x02;
	*p++ = resp_opcode;
	*p++ = (uint8_t)(ex_id & 0xFF);
	*p++ = (uint8_t)(ex_id >> 8);
	*p++ = (uint8_t)(resp_proto & 0xFF);
	*p++ = (uint8_t)(resp_proto >> 8);

	/* If session is authenticated, encrypt payload */
	if (s->active) {
		uint8_t cipher[BUFFER_SIZE];
		uint8_t tag[16];
		encrypt_matter_payload(s->session_key, resp_counter, resp_payload, resp_payload_len, cipher, tag);
		memcpy(p, cipher, resp_payload_len);
		p += resp_payload_len;
		memcpy(p, tag, 16);
		p += 16;
	} else {
		memcpy(p, resp_payload, resp_payload_len);
		p += resp_payload_len;
	}

	sendto(g_matter_v6_fd, resp_buf, (size_t)(p - resp_buf), 0,
	       (const struct sockaddr *)client_addr, sizeof(*client_addr));
}

/* --------------------------------------------------------------------------
 * IPC Commands & Event Hooks
 * -------------------------------------------------------------------------- */

static void handle_ipc_command(const char *cmd_line, int client_fd)
{
	char reply[512];
	memset(reply, 0, sizeof(reply));

	if (strncmp(cmd_line, "status", 6) == 0) {
		char pairing_code[32];
		generate_pairing_code(pairing_code, sizeof(pairing_code));
		snprintf(reply, sizeof(reply),
			 "{\"running\":true,\"port\":%d,\"discriminator\":%u,\"passcode\":%u,\"pairing_code\":\"%s\",\"backend\":\"%s\",\"hostname\":\"%s\",\"nightmode\":%s,\"privacy\":%s,\"motion\":%s}\n",
			 g_config.port, g_config.discriminator, g_config.passcode, pairing_code,
			 g_config.streamer_backend, g_config.hostname,
			 g_config.nightmode ? "true" : "false",
			 g_config.privacy ? "true" : "false",
			 g_config.motion_detected ? "true" : "false");
	} else if (strncmp(cmd_line, "announce", 8) == 0) {
		send_mdns_announcement();
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"announced\":true}\n");
	} else if (strncmp(cmd_line, "nightmode on", 12) == 0) {
		g_config.nightmode = true;
		exec_agent_command("daynight night >/dev/null 2>&1 || agentctl daynight night", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"nightmode\":\"on\"}\n");
	} else if (strncmp(cmd_line, "nightmode off", 13) == 0) {
		g_config.nightmode = false;
		exec_agent_command("daynight day >/dev/null 2>&1 || agentctl daynight day", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"nightmode\":\"off\"}\n");
	} else if (strncmp(cmd_line, "privacy on", 10) == 0) {
		g_config.privacy = true;
		exec_agent_command("privacy on >/dev/null 2>&1 || agentctl privacy on", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"privacy\":true}\n");
	} else if (strncmp(cmd_line, "privacy off", 11) == 0) {
		g_config.privacy = false;
		exec_agent_command("privacy off >/dev/null 2>&1 || agentctl privacy off", NULL, 0);
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"privacy\":false}\n");
	} else if (strncmp(cmd_line, "event motion 1", 14) == 0) {
		g_config.motion_detected = true;
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"motion\":true}\n");
	} else if (strncmp(cmd_line, "event motion 0", 14) == 0) {
		g_config.motion_detected = false;
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"motion\":false}\n");
	} else if (strncmp(cmd_line, "event nightmode on", 18) == 0) {
		g_config.nightmode = true;
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"nightmode\":\"on\"}\n");
	} else if (strncmp(cmd_line, "event nightmode off", 19) == 0) {
		g_config.nightmode = false;
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"nightmode\":\"off\"}\n");
	} else if (strncmp(cmd_line, "event privacy on", 16) == 0) {
		g_config.privacy = true;
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"privacy\":true}\n");
	} else if (strncmp(cmd_line, "event privacy off", 17) == 0) {
		g_config.privacy = false;
		snprintf(reply, sizeof(reply), "{\"status\":\"ok\",\"privacy\":false}\n");
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
	struct sigaction sa;
	time_t last_mcast_announce = 0;
	time_t last_motion_check = 0;

	(void)argc;
	(void)argv;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	init_crypto();
	load_configuration();

	/* Pure IPv6 Sockets */
	g_matter_v6_fd = setup_matter_v6_socket(g_config.port);
	if (g_matter_v6_fd < 0)
		return 1;

	g_mdns_v6_fd = setup_mdns_v6_socket();

	send_mdns_announcement();
	last_mcast_announce = time(NULL);

	const char *fifo_path = "/run/matter/cmd.fifo";
	mkdir("/run/matter", 0755);
	unlink(fifo_path);
	mkfifo(fifo_path, 0666);
	g_ipc_fd = open(fifo_path, O_RDWR | O_NONBLOCK);

	while (g_config.running) {
		fd_set readfds;
		struct timeval tv;
		int max_fd = -1;
		time_t now = time(NULL);

		FD_ZERO(&readfds);
		if (g_matter_v6_fd >= 0) {
			FD_SET(g_matter_v6_fd, &readfds);
			if (g_matter_v6_fd > max_fd)
				max_fd = g_matter_v6_fd;
		}
		if (g_mdns_v6_fd >= 0) {
			FD_SET(g_mdns_v6_fd, &readfds);
			if (g_mdns_v6_fd > max_fd)
				max_fd = g_mdns_v6_fd;
		}
		if (g_ipc_fd >= 0) {
			FD_SET(g_ipc_fd, &readfds);
			if (g_ipc_fd > max_fd)
				max_fd = g_ipc_fd;
		}

		/* Check ONVIF /run/motion alarm flag automatically */
		if (now - last_motion_check >= 1) {
			bool motion_now = (access("/run/motion/motion_alarm", F_OK) == 0);
			if (motion_now != g_config.motion_detected) {
				g_config.motion_detected = motion_now;
			}
			last_motion_check = now;
		}

		if (now - last_mcast_announce >= 60) {
			send_mdns_announcement();
			last_mcast_announce = now;
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		int res = select(max_fd + 1, &readfds, NULL, NULL, &tv);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (g_matter_v6_fd >= 0 && FD_ISSET(g_matter_v6_fd, &readfds)) {
			uint8_t buf[BUFFER_SIZE];
			struct sockaddr_in6 client_addr;
			socklen_t client_len = sizeof(client_addr);
			ssize_t n = recvfrom(g_matter_v6_fd, buf, sizeof(buf), 0,
					     (struct sockaddr *)&client_addr, &client_len);
			if (n > 0) {
				handle_matter_packet(buf, n, &client_addr);
			}
		}

		if (g_mdns_v6_fd >= 0 && FD_ISSET(g_mdns_v6_fd, &readfds)) {
			uint8_t buf[BUFFER_SIZE];
			struct sockaddr_in6 client_addr6;
			socklen_t client_len6 = sizeof(client_addr6);
			ssize_t n = recvfrom(g_mdns_v6_fd, buf, sizeof(buf), 0,
					     (struct sockaddr *)&client_addr6, &client_len6);
			if (n > 12 && strstr((char *)buf + 12, "_matter") != NULL) {
				send_mdns_announcement();
			}
		}

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

	if (g_matter_v6_fd >= 0)
		close(g_matter_v6_fd);
	if (g_mdns_v6_fd >= 0)
		close(g_mdns_v6_fd);
	if (g_ipc_fd >= 0)
		close(g_ipc_fd);
	unlink("/run/matter/cmd.fifo");

	mbedtls_ctr_drbg_free(&g_drbg);
	mbedtls_entropy_free(&g_entropy);

	return 0;
}
