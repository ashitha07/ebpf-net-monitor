// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>     
#include <stdbool.h>  
#include "detector.h" 



struct ip_track *table = NULL;  // your hash table — starts empty

void detect_portscan(uint32_t src_ip, uint16_t dst_port){
    struct ip_track *entry;
    HASH_FIND_INT(table, &src_ip, entry);
    // Check if the entry exists in the hash table
    if(entry == NULL) {
        entry = malloc(sizeof(struct ip_track));
        entry->src_ip = src_ip;
        entry->port_count = 1;
        entry->port_list[0] = dst_port;
        entry->alerted = false;
        entry->first_connection_ts = time(NULL);
        entry->first_alert_ts = 0;
        HASH_ADD_INT(table, src_ip, entry);
    } else {
        // Check if the time since the first connection is less than 10 seconds
        if(time(NULL)-entry->first_connection_ts > 10) {  // Assuming 10 seconds as the time window for a port scan
            HASH_DEL(table, entry);
            free(entry);
            entry = malloc(sizeof(struct ip_track));
            entry->src_ip = src_ip;
            entry->port_count = 1;
            entry->port_list[0] = dst_port;
            entry->alerted = false;
            entry->first_connection_ts = time(NULL);
            entry->first_alert_ts = 0;
            HASH_ADD_INT(table, src_ip, entry);
        }else {
            // Check if the port is already in the list
            // iterate through the port list to see if the port is already present
            int already_preset = 0;
            for(int i = 0; i < entry->port_count; i++) {
                if(entry->port_list[i] == dst_port) {
                    already_preset = 1;
                    break;
                }
            }
              
            if(!already_preset){
                // Check   if the port count is greater than 20
                if(entry->port_count >= 15) {  // Assuming 20 ports as the threshold for a port scan
                // Check if alerted is false then print and add port to the list
                    if(!entry->alerted) {
                        entry->alerted = true;
                        entry->first_alert_ts = time(NULL);
                        printf("Ports greater than threshold for IP: %u.%u.%u.%u\n",
                            (src_ip >> 24) & 0xFF,
                            (src_ip >> 16) & 0xFF,
                            (src_ip >> 8) & 0xFF,
                            src_ip & 0xFF);
                        //add the port to the list
                        if(entry->port_count < 30) {
                            entry->port_list[entry->port_count] = dst_port;
                            entry->port_count++;
                        }
                    }else{
                        // Check if the time since the first alert is less than 3 seconds
                        if(time(NULL)-entry->first_alert_ts < 3) {  // Assuming 3 seconds as the time window for a port scan
                            if(entry->port_count < 30) {
                                entry->port_list[entry->port_count] = dst_port;
                                entry->port_count++;
                            }
                        }else {
                            // Reset alerted and first_alert_ts
                            entry->alerted = false;
                            entry->first_alert_ts = time(NULL);
                            //reset the port list and add the new port
                            HASH_DEL(table, entry);
                            free(entry);
                            entry = malloc(sizeof(struct ip_track));
                            entry->src_ip = src_ip;
                            entry->port_count = 1;
                            entry->port_list[0] = dst_port;
                            entry->alerted = false;
                            entry->first_alert_ts = 0;
                            entry->first_connection_ts = time(NULL);
                            HASH_ADD_INT(table, src_ip, entry);
                        }
                    }
                }else{
                    //add the port to the list
                    if(entry->port_count < 30) {
                        entry->port_list[entry->port_count] = dst_port;
                        entry->port_count++;
                    }
                }
            }
        }
    }
}