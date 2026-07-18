/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __DETECTOR_H
#define __DETECTOR_H

#include "uthash.h"

struct ip_track {
    uint32_t src_ip;        // KEY — must be first or clearly marked
    time_t first_connection_ts;
    uint16_t port_list[30];
    int port_count;
    bool alerted;
    time_t first_alert_ts;
    UT_hash_handle hh;      // makes this struct hashable — required by uthash
};
void detect_portscan(uint32_t src_ip, uint16_t dst_port);

#endif /* __DETECTOR_H */