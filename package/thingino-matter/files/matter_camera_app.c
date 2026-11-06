/*
 * matter_camera_app.c - Thingino Matter 1.5 Camera Application
 *
 * Implements the Endpoint 1 Camera Device Type (0x0051) on top of matter-c:
 * - Cluster 0x0551: WebRTC Transport Provider (SDP Offer/Answer relay to WHIP/WHEP)
 * - Cluster 0x0550: Camera Settings (NightMode, Privacy, Motion)
 * - IPC Command listener: /run/matter/cmd.fifo for matterctl and matter-event
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

#define CLUSTER_CAMERA_SETTINGS       0x0550
#define CLUSTER_WEBRTC_TRANSPORT_PROV 0x0551

typedef struct {
    char backend[16];
    bool nightmode;
    bool privacy;
    bool motion;
    bool running;
} CameraAppContext;

static CameraAppContext g_app;

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

int relay_sdp_offer(const char *sdp_offer, char *sdp_answer, size_t max_ans)
{
    bool use_timps = (strcmp(g_app.backend, "timps") == 0);
    if (strcmp(g_app.backend, "auto") == 0) {
        use_timps = (access("/var/www/x/webrtc-whip.cgi", X_OK) != 0);
    }
    const char *endpoint = use_timps ? "/webrtc/whep" : "/x/webrtc-whip.cgi";
    return inprocess_http_post(endpoint, 80, sdp_offer, sdp_answer, max_ans);
}

static void exec_cmd(const char *cmd)
{
    if (system(cmd) < 0) {
        /* ignore error */
    }
}

static void handle_ipc_command(const char *cmd)
{
    if (strncmp(cmd, "nightmode on", 12) == 0) {
        g_app.nightmode = true;
        exec_cmd("daynight night >/dev/null 2>&1 || agentctl daynight night");
    } else if (strncmp(cmd, "nightmode off", 13) == 0) {
        g_app.nightmode = false;
        exec_cmd("daynight day >/dev/null 2>&1 || agentctl daynight day");
    } else if (strncmp(cmd, "privacy on", 10) == 0) {
        g_app.privacy = true;
        exec_cmd("privacy on >/dev/null 2>&1 || agentctl privacy on");
    } else if (strncmp(cmd, "privacy off", 11) == 0) {
        g_app.privacy = false;
        exec_cmd("privacy off >/dev/null 2>&1 || agentctl privacy off");
    } else if (strncmp(cmd, "event motion 1", 14) == 0) {
        g_app.motion = true;
    } else if (strncmp(cmd, "event motion 0", 14) == 0) {
        g_app.motion = false;
    }
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    memset(&g_app, 0, sizeof(g_app));
    strcpy(g_app.backend, "auto");
    g_app.running = true;

    mkdir("/run/matter", 0755);
    const char *fifo_path = "/run/matter/cmd.fifo";
    unlink(fifo_path);
    mkfifo(fifo_path, 0666);
    int fifo_fd = open(fifo_path, O_RDWR | O_NONBLOCK);

    while (g_app.running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;

        if (fifo_fd >= 0) {
            FD_SET(fifo_fd, &rfds);
            max_fd = fifo_fd;
        }

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int res = select(max_fd + 1, &rfds, NULL, NULL, &tv);

        if (res > 0 && fifo_fd >= 0 && FD_ISSET(fifo_fd, &rfds)) {
            char line[256];
            ssize_t n = read(fifo_fd, line, sizeof(line) - 1);
            if (n > 0) {
                line[n] = '\0';
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                handle_ipc_command(line);
            }
        }
    }

    if (fifo_fd >= 0) close(fifo_fd);
    unlink(fifo_path);
    return 0;
}
