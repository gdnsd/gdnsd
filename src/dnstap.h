#pragma once

#include "dnstap.pb-c.h"

#include <gdnsd/vscf.h>

#include <sys/socket.h>
#include <fstrm.h>
#include <stdbool.h>
#include <protobuf-c/protobuf-c.h>

/*! \brief Frame Streams "Content Type" value for dnstap. */
#define DNSTAP_CONTENT_TYPE     "protobuf:dnstap.Dnstap"

// Dnstap contex object per TCP/UDP working thread
typedef struct {
    // fstrm iothread  
    struct fstrm_iothr* iothread;
    // fstrm iothrhead queue unique for every TCP/UDP working thread
    struct fstrm_iothr_queue *ioqueue;
    // 
    bool isUDP;
} dnstap_ctx_t;

typedef struct {
    bool enable;
    const char* sink;
    const char* identity;
    const char* version;
    bool        unix_sink;
    bool        log_queries;
    bool        log_responses;
    size_t      identity_len;
    size_t      version_len;
    bool        queue_model_mpsc;
	unsigned int buffer_hint;
	unsigned int input_queue_size;
	unsigned int flush_timeout;
} dnstap_cfg_t;

void dnstap_conf_load(const vscf_data_t* cfg_root);

dnstap_ctx_t* dnstap_ctx_init(bool isUDP);
void dnstap_ctx_cleanup(dnstap_ctx_t** pctx);

void* dnstap_start(unsigned num_threads);
void dnstap_stop();

void dnstap_log_query_message(dnstap_ctx_t* dnstap_ctx, const struct sockaddr* sa, uint8_t* packet, const unsigned packet_len);
void dnstap_log_response_message(dnstap_ctx_t* dnstap_ctx, const struct sockaddr* sa, uint8_t* packet, const unsigned packet_len);
