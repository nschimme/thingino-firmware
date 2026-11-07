/*
 * matter_camera_app.c - Thingino Matter 1.5 Camera Application Daemon
 *
 * Implements:
 * - Matter Node with Endpoint 1: Camera Device Type (0x0051)
 * - WebRTC Transport Provider Cluster (0x0551)
 * - Camera Settings Cluster (0x0550)
 * - Matter network UDP IPv6 listener and mDNS discovery
 * - IPC Command listener: /run/matter/cmd.fifo for matterctl and motion events
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "matter_camera_cluster.h"
#include "matter_host_platform.h"
#include "matter_host_limits.h"
#include "matter_server.h"
#include "matter_mdns_windows.h"
#include "matter_resolver_windows.h"
#include "matter_udp_windows.h"
#include "matter_discovery.h"
#include "clusters/matter_root.h"

typedef struct {
    char backend[32];
    bool running;

    /* Matter runtime handles */
    Matter_T owner;
    Matter_Udp_Windows_T udp;
    Matter_Resolver_Windows_T resolver;
    Matter_Server_T server;
    Matter_Root_T root;
    Matter_Events_T events;
    Matter_Mdns_Windows_T mdns;
    Matter_Discovery_T discovery;
    Matter_Mdns_Windows_Interface_T iface;

    Matter_Cluster_T camera_cluster;
    Matter_Cluster_T webrtc_cluster;

    uint16_t discriminator;
    uint32_t pin;
    uint32_t port;
    uint32_t interface_index;
    uint8_t random[8];
    uint8_t discovery_mac[6];
} CameraAppContext;

static CameraAppContext g_app;

static void handle_signal(int sig)
{
    (void)sig;
    g_app.running = false;
}

static int inprocess_http_post(const char *path, int port, const char *body, char *response, size_t max_resp)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(s, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        close(s);
        return -1;
    }

    char req[512];
    size_t blen = strlen(body);
    snprintf(req, sizeof(req),
             "POST %s HTTP/1.1\r\n"
             "Host: 127.0.0.1:%d\r\n"
             "Content-Type: application/sdp\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n",
             path, port, blen);

    if (write(s, req, strlen(req)) < 0 || write(s, body, blen) < 0) {
        close(s);
        return -1;
    }

    char buf[4096];
    ssize_t n = read(s, buf, sizeof(buf) - 1);
    close(s);

    if (n <= 0) return -1;
    buf[n] = '\0';

    char *body_start = strstr(buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(response, body_start, max_resp - 1);
        response[max_resp - 1] = '\0';
        return 0;
    }
    return -1;
}

static int camera_signaling_offer(void* user, const char* sdp_offer, char* sdp_answer, size_t max_ans)
{
    (void)user;
    bool use_timps = (strcmp(g_app.backend, "timps") == 0);
    if (strcmp(g_app.backend, "auto") == 0) {
        use_timps = (access("/var/www/x/webrtc-whip.cgi", X_OK) != 0);
    }
    const char *endpoint = use_timps ? "/webrtc/whep" : "/x/webrtc-whip.cgi";
    return inprocess_http_post(endpoint, 80, sdp_offer, sdp_answer, max_ans);
}

static int camera_set_nightmode(void* user, bool on)
{
    (void)user;
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", on ? "daynight night >/dev/null 2>&1 || agentctl daynight night" : "daynight day >/dev/null 2>&1 || agentctl daynight day", NULL);
        _exit(1);
    }
    return 0;
}

static int camera_set_privacy(void* user, bool on)
{
    (void)user;
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", on ? "privacy on >/dev/null 2>&1 || agentctl privacy on" : "privacy off >/dev/null 2>&1 || agentctl privacy off", NULL);
        _exit(1);
    }
    return 0;
}

static void handle_ipc_command(const char *cmd)
{
    if (strncmp(cmd, "nightmode on", 12) == 0) {
        camera_set_nightmode(NULL, true);
        if (g_app.server) matter_server_changed(g_app.server);
    } else if (strncmp(cmd, "nightmode off", 13) == 0) {
        camera_set_nightmode(NULL, false);
        if (g_app.server) matter_server_changed(g_app.server);
    } else if (strncmp(cmd, "privacy on", 10) == 0) {
        camera_set_privacy(NULL, true);
        if (g_app.server) matter_server_changed(g_app.server);
    } else if (strncmp(cmd, "privacy off", 11) == 0) {
        camera_set_privacy(NULL, false);
        if (g_app.server) matter_server_changed(g_app.server);
    } else if (strncmp(cmd, "event motion 1", 14) == 0) {
        matter_camera_settings_set_motion(g_app.camera_cluster, true);
        if (g_app.server) matter_server_changed(g_app.server);
    } else if (strncmp(cmd, "event motion 0", 14) == 0) {
        matter_camera_settings_set_motion(g_app.camera_cluster, false);
        if (g_app.server) matter_server_changed(g_app.server);
    } else if (strncmp(cmd, "announce", 8) == 0) {
        if (g_app.server) matter_server_changed(g_app.server);
    }
}

static void udp_received(void* user, const Matter_Udp_Datagram_T* dgram)
{
    CameraAppContext* app = (CameraAppContext*)user;
    if (app->server) {
        matter_server_received(app->server, dgram);
    }
}

static void udp_sent(void* user, uint64_t token, Matter_Operation_Result_T result)
{
    CameraAppContext* app = (CameraAppContext*)user;
    if (app->server) {
        matter_server_sent(app->server, token, result);
    }
}

static Matter_Result_T event_load(void* u, uint64_t* out) {
    CameraAppContext* app = (CameraAppContext*)u;
    if (app->server) return matter_store_host_event_load(matter_server_store(app->server), out);
    *out = 0;
    return MATTER_OK;
}

static Matter_Result_T event_store(void* u, uint64_t high) {
    CameraAppContext* app = (CameraAppContext*)u;
    if (app->server) return matter_store_host_event_store(matter_server_store(app->server), high);
    return MATTER_OK;
}

static void set_text(Matter_Root_Text_T* t, const char* str) {
    t->size = strlen(str);
    if (t->size > sizeof(t->data)) t->size = sizeof(t->data);
    memcpy(t->data, str, t->size);
}

static bool init_matter_stack(CameraAppContext* app, const char* cred_dir, const char* state_file)
{
    uint64_t now = matter_host_now();

    if (matter_mdns_windows_interface(app->interface_index, &app->iface) != MATTER_OK) {
        fprintf(stderr, "Matter: failed to find IPv6 on interface %u\n", app->interface_index);
        return false;
    }

    app->owner = matter_new(NULL);
    if (!app->owner || matter_start(app->owner) != MATTER_OK) return false;

    Matter_Udp_Address_T bind_addr = { .port = (uint16_t)app->port };
    Matter_Udp_Listener_T listener = {
        .user = app,
        .received = udp_received,
        .sent = udp_sent
    };
    app->udp = matter_udp_windows_new(app->owner, &bind_addr, app->interface_index, &listener);
    if (!app->udp || matter_udp_start(matter_udp_windows_module(app->udp)) != MATTER_OK) return false;

    matter_host_random(app->random, sizeof(app->random));
    memcpy(app->discovery_mac, app->iface.mac, sizeof(app->discovery_mac));

    /* Root Node Configuration */
    Matter_Root_Config_T root_cfg;
    memset(&root_cfg, 0, sizeof(root_cfg));
    set_text(&root_cfg.vendor_name, "Thingino");
    set_text(&root_cfg.product_name, "Thingino Camera");
    set_text(&root_cfg.hardware_string, "mips");
    set_text(&root_cfg.software_string, "1.5.0");
    set_text(&root_cfg.unique_id, "thingino-camera-01");

    root_cfg.vendor_id = 0xFFF1; /* Test VID */
    root_cfg.product_id = 0x8000; /* Test PID */
    root_cfg.hardware_version = 1;
    root_cfg.software_version = 1;
    root_cfg.configuration_version = 1;
    root_cfg.descriptor_version = 1;
    root_cfg.basic_version = 1;
    root_cfg.capabilities = (Matter_Root_Capabilities_T)MATTER_HOST_CAPABILITIES;
    root_cfg.capabilities.subscriptions = 5;

    Matter_Server_Sim_Options_T options = {
        .wifi_connected = true,
        .network = { NULL, NULL }
    };

    app->server = matter_server_new_sim(cred_dir, state_file, &root_cfg, app->pin, now, &options);
    if (!app->server) {
        fprintf(stderr, "Matter: matter_server_new_sim failed\n");
        return false;
    }

    app->root = matter_server_root(app->server);
    if (!app->root) return false;

    Matter_Events_Port_T ev_port = { app, event_load, event_store };
    app->events = matter_events_new(&ev_port);
    if (!app->events || matter_root_startup(app->root, app->events, now) != MATTER_OK) return false;

    /* Endpoint 1: Camera Device Type (0x0051) */
    Matter_Root_Endpoint_Config_T ep_cam = {
        .endpoint = 1,
        .revision = 1,
        .device_type = MATTER_DEVICE_TYPE_CAMERA,
        .data_version = 1
    };
    if (matter_root_add_endpoint(app->root, &ep_cam) != MATTER_OK) return false;

    /* Attach Camera Clusters to Endpoint 1 */
    Matter_Camera_Port_T port = {
        .user = app,
        .signaling_offer = camera_signaling_offer,
        .set_nightmode = camera_set_nightmode,
        .set_privacy = camera_set_privacy
    };

    app->camera_cluster = matter_camera_settings_new(&port);
    app->webrtc_cluster = matter_webrtc_cluster_new(&port);

    if (!app->camera_cluster || !app->webrtc_cluster) return false;

    if (matter_root_attach_cluster_at(app->root, 1, app->camera_cluster) != MATTER_OK) return false;
    if (matter_root_attach_cluster_at(app->root, 1, app->webrtc_cluster) != MATTER_OK) return false;

    /* Start Resolver and Server */
    app->resolver = matter_resolver_windows_new(&app->iface);
    if (app->resolver) {
        Matter_Resolver_Port_T rport = matter_resolver_windows_port(app->resolver);
        matter_server_set_resolver(app->server, &rport);
    }

    Matter_Udp_Path_T outbound = { .local = bind_addr, .interface_id = app->interface_index };
    memcpy(outbound.local.address, app->iface.ipv6, 16);
    matter_server_set_outbound(app->server, &outbound);

    if (matter_server_start(app->server, app->owner, matter_udp_windows_module(app->udp), app->events) != MATTER_OK) {
        fprintf(stderr, "Matter: failed to start server\n");
        return false;
    }

    /* Start mDNS Discovery */
    uint16_t disc = app->discriminator;
    uint8_t mode = matter_server_commissioning_mode(app->server, &disc);
    app->discovery = matter_discovery_commissionable(app->discovery_mac, app->random, disc, mode, (uint16_t)app->port);
    if (app->discovery) {
        app->mdns = matter_mdns_windows_new(app->owner, &app->iface, matter_discovery_record(app->discovery));
        if (app->mdns) {
            matter_mdns_start(matter_mdns_windows_module(app->mdns));
        }
    }

    printf("Matter Camera daemon initialized: interface=%u port=%u disc=%u pin=%u\n",
           app->interface_index, app->port, app->discriminator, app->pin);
    return true;
}

int main(int argc, char **argv)
{
    memset(&g_app, 0, sizeof(g_app));
    strcpy(g_app.backend, "auto");
    g_app.discriminator = 3840;
    g_app.pin = 20202021;
    g_app.port = 5540;
    g_app.interface_index = 1;
    g_app.running = true;

    const char *cred_dir = "/etc/matter/credentials";
    const char *state_file = "/etc/matter/matter_state.bin";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--interface") && i + 1 < argc) {
            g_app.interface_index = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--discriminator") && i + 1 < argc) {
            g_app.discriminator = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--pin") && i + 1 < argc) {
            g_app.pin = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            g_app.port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--credentials") && i + 1 < argc) {
            cred_dir = argv[++i];
        } else if (!strcmp(argv[i], "--state") && i + 1 < argc) {
            state_file = argv[++i];
        } else if (!strcmp(argv[i], "--backend") && i + 1 < argc) {
            strncpy(g_app.backend, argv[++i], sizeof(g_app.backend) - 1);
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGCHLD, SIG_IGN);

    mkdir("/run/matter", 0755);
    const char *fifo_path = "/run/matter/cmd.fifo";
    unlink(fifo_path);
    mkfifo(fifo_path, 0666);
    int fifo_fd = open(fifo_path, O_RDWR | O_NONBLOCK);

    /* Initialize Matter stack */
    bool matter_online = init_matter_stack(&g_app, cred_dir, state_file);
    if (!matter_online) {
        fprintf(stderr, "Warning: Matter network stack running in IPC-only fallback mode\n");
    }

    while (g_app.running) {
        uint64_t now = matter_host_now();

        /* Poll Matter network UDP */
        if (g_app.udp) {
            matter_udp_windows_poll(g_app.udp);
        }
        if (g_app.resolver) {
            matter_resolver_windows_poll(g_app.resolver, now);
        }
        if (g_app.server) {
            matter_server_process(g_app.server, now);
        }
        if (g_app.mdns) {
            matter_mdns_process(matter_mdns_windows_module(g_app.mdns));
            matter_mdns_windows_poll(g_app.mdns, now);
        }

        /* Check IPC FIFO */
        if (fifo_fd >= 0) {
            char line[256];
            ssize_t n = read(fifo_fd, line, sizeof(line) - 1);
            if (n > 0) {
                line[n] = '\0';
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                handle_ipc_command(line);
            }
        }

        matter_host_sleep(10);
    }

    if (g_app.server) {
        matter_server_stop(g_app.server, matter_host_now());
        matter_server_delete(g_app.server);
    }
    if (fifo_fd >= 0) close(fifo_fd);
    unlink(fifo_path);
    return 0;
}
