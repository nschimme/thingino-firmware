#ifndef MATTER_CAMERA_CLUSTER_H_INCLUDED
#define MATTER_CAMERA_CLUSTER_H_INCLUDED 1

#include "model/matter_cluster.h"

#define MATTER_CLUSTER_CAMERA_SETTINGS       0x0550
#define MATTER_CLUSTER_WEBRTC_TRANSPORT_PROV 0x0551

#define MATTER_DEVICE_TYPE_CAMERA            0x0051

typedef struct {
    void* user;
    int (*signaling_offer)(void* user, const char* sdp_offer, char* sdp_answer, size_t max_ans);
    int (*set_nightmode)(void* user, bool on);
    int (*set_privacy)(void* user, bool on);
} Matter_Camera_Port_T;

Matter_Cluster_T matter_camera_settings_new(const Matter_Camera_Port_T* port);
Matter_Cluster_T matter_webrtc_cluster_new(const Matter_Camera_Port_T* port);

void matter_camera_settings_set_motion(Matter_Cluster_T cl, bool motion_detected);
void matter_camera_settings_set_nightmode(Matter_Cluster_T cl, bool nightmode);
void matter_camera_settings_set_privacy(Matter_Cluster_T cl, bool privacy);

#endif
