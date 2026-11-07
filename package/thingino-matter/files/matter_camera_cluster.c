#include "matter_camera_cluster.h"
#include "codec/matter_tlv.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    Matter_Camera_Port_T port;
    bool nightmode;
    bool privacy;
    bool motion;
    uint32_t version;
} CameraClusterCtx;

static uint8_t read_camera_setting(void* ctx, const void* ref, const Matter_Cluster_Request_T* req, Matter_Im_Value_T* out)
{
    (void)req;
    CameraClusterCtx* c = (CameraClusterCtx*)ctx;
    uint32_t attr_id = *(const uint32_t*)ref;
    out->type = MATTER_TLV_BOOL;
    if (attr_id == 1) out->unsigned_value = c->nightmode ? 1 : 0;
    else if (attr_id == 2) out->unsigned_value = c->privacy ? 1 : 0;
    else if (attr_id == 3) out->unsigned_value = c->motion ? 1 : 0;
    else return 1;
    return 0;
}

static Matter_Im_Write_Result_T write_camera_setting(void* ctx, const void* ref, const Matter_Cluster_Request_T* req, const uint8_t* val, size_t len)
{
    (void)req;
    CameraClusterCtx* c = (CameraClusterCtx*)ctx;
    uint32_t attr_id = *(const uint32_t*)ref;
    if (len != 1) return (Matter_Im_Write_Result_T){ .status = 0x87 };
    bool b = (val[0] != 0);
    if (attr_id == 1) {
        c->nightmode = b;
        if (c->port.set_nightmode) c->port.set_nightmode(c->port.user, b);
    } else if (attr_id == 2) {
        c->privacy = b;
        if (c->port.set_privacy) c->port.set_privacy(c->port.user, b);
    }
    c->version++;
    return (Matter_Im_Write_Result_T){ .status = 0 };
}

static Matter_Result_T cluster_version(void* ctx, uint32_t* ver)
{
    CameraClusterCtx* c = (CameraClusterCtx*)ctx;
    *ver = c->version;
    return MATTER_OK;
}

Matter_Cluster_T matter_camera_settings_new(const Matter_Camera_Port_T* port)
{
    CameraClusterCtx* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    if (port) ctx->port = *port;
    ctx->version = 1;

    Matter_Cluster_Config_T cfg = {
        .id = MATTER_CLUSTER_CAMERA_SETTINGS,
        .attributes = 3,
        .commands = 0,
        .events = 0,
        .callbacks = {
            .ctx = ctx,
            .version = cluster_version,
            .destroy = NULL
        }
    };

    Matter_Cluster_T cl = matter_cluster_new(&cfg);
    if (!cl) { free(ctx); return NULL; }

    static const uint32_t ids[] = { 1, 2, 3 };
    for (int i = 0; i < 3; i++) {
        Matter_Attribute_Def_T a = {
            .id = ids[i],
            .ref = &ids[i],
            .read_access = { MATTER_IM_VIEW, false },
            .read = read_camera_setting
        };
        if (ids[i] != 3) {
            a.write_access = (Matter_Im_Write_Attribute_T){ .privilege = MATTER_IM_OPERATE, .timed = false };
            a.write = write_camera_setting;
        }
        matter_cluster_add_attribute(cl, &a);
    }
    matter_cluster_seal(cl);
    return cl;
}

/* WebRTC Transport Provider Cluster (0x0551) */
typedef struct {
    Matter_Camera_Port_T port;
    uint32_t version;
} WebRtcClusterCtx;

static uint8_t read_webrtc_attr(void* ctx, const void* ref, const Matter_Cluster_Request_T* req, Matter_Im_Value_T* out)
{
    (void)ctx; (void)req;
    uint32_t attr_id = *(const uint32_t*)ref;
    if (attr_id == 1) {
        out->type = MATTER_TLV_UTF8;
        out->data = (const uint8_t*)"video/H264;audio/opus";
        out->size = 21;
        return 0;
    } else if (attr_id == 2) {
        out->type = MATTER_TLV_UNSIGNED;
        out->unsigned_value = 2;
        return 0;
    }
    return 1;
}

static uint8_t validate_cmd(void* ctx, const void* ref, const Matter_Cluster_Request_T* req, const uint8_t* in, size_t in_len)
{
    (void)ctx; (void)ref; (void)req; (void)in; (void)in_len;
    return 0; /* OK */
}

static Matter_Result_T webrtc_command_start(void* ctx, const void* ref, const Matter_Cluster_Request_T* req,
    const uint8_t* in, size_t in_len, Matter_Tlv_Writer_T* out, Matter_Im_Command_Result_T* res, uint64_t* token)
{
    (void)ref; (void)req; (void)out; (void)token;
    WebRtcClusterCtx* c = (WebRtcClusterCtx*)ctx;
    char sdp_ans[2048];
    sdp_ans[0] = '\0';

    char sdp_off[2048];
    size_t copy_len = in_len < sizeof(sdp_off) - 1 ? in_len : sizeof(sdp_off) - 1;
    memcpy(sdp_off, in, copy_len);
    sdp_off[copy_len] = '\0';

    if (c->port.signaling_offer) {
        c->port.signaling_offer(c->port.user, sdp_off, sdp_ans, sizeof(sdp_ans));
    }

    res->status = 0;
    return MATTER_OK;
}

Matter_Cluster_T matter_webrtc_cluster_new(const Matter_Camera_Port_T* port)
{
    WebRtcClusterCtx* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    if (port) ctx->port = *port;
    ctx->version = 1;

    Matter_Cluster_Config_T cfg = {
        .id = MATTER_CLUSTER_WEBRTC_TRANSPORT_PROV,
        .attributes = 2,
        .commands = 1,
        .events = 0,
        .callbacks = {
            .ctx = ctx,
            .version = cluster_version,
            .destroy = NULL
        }
    };

    Matter_Cluster_T cl = matter_cluster_new(&cfg);
    if (!cl) { free(ctx); return NULL; }

    static const uint32_t ids[] = { 1, 2 };
    for (int i = 0; i < 2; i++) {
        Matter_Attribute_Def_T a = {
            .id = ids[i],
            .ref = &ids[i],
            .read_access = { MATTER_IM_VIEW, false },
            .read = read_webrtc_attr
        };
        matter_cluster_add_attribute(cl, &a);
    }

    static const uint32_t cmd_id = 1;
    Matter_Command_Def_T cmd = {
        .id = cmd_id,
        .access = { .privilege = MATTER_IM_OPERATE, .timed = false },
        .ref = &cmd_id,
        .validate = validate_cmd,
        .start = webrtc_command_start
    };
    matter_cluster_add_command(cl, &cmd);
    matter_cluster_seal(cl);
    return cl;
}
