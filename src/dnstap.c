#include <config.h>

#include "dnstap.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <time.h>
#include <pthread.h>

#define DNSTAP_INITIAL_BUF_SIZE         256

static pthread_mutex_t threadnum_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_threadnum = 0;

static struct fstrm_iothr* giothread = NULL;
static dnstap_cfg_t* gdnstap_cfg = NULL;

// The "default defaults" for dnstap settings
static const dnstap_cfg_t dnstap_cfg_defaults = {
    .enable = false,
    .sink = NULL,
    .identity = NULL,
    .version = NULL,
	.unix_sink = true,
    .log_queries = false,
    .log_responses = false,
	.identity_len = 0,
	.version_len = 0,
	.queue_model_mpsc = false,
	.buffer_hint = 0,
	.input_queue_size = 0,
	.flush_timeout = 0
};

/*!
 * \brief Translation between real and Dnstap value.
 */
typedef struct mapping {
	int real;
	int dnstap;
} mapping_t;

/*!
 * \brief Mapping for network family.
 */
static const mapping_t SOCKET_FAMILY_MAPPING[] = {
	{ AF_INET,  DNSTAP__SOCKET_FAMILY__INET },
	{ AF_INET6, DNSTAP__SOCKET_FAMILY__INET6 },
	{ 0 }
};

/*!
 * \brief Mapping from network protocol.
 */
static const mapping_t SOCKET_PROTOCOL_MAPPING[] = {
	{ IPPROTO_UDP, DNSTAP__SOCKET_PROTOCOL__UDP },
	{ IPPROTO_TCP, DNSTAP__SOCKET_PROTOCOL__TCP },
	{ 0 }
};

/*!
 * \brief Get Dnstap value for a given real value.
 */
static int encode(const mapping_t *mapping, int real)
{
	for (const mapping_t *m = mapping; m->real != 0; m += 1) {
		if (m->real == real) {
			return m->dnstap;
		}
	}

	return 0;
}

/*!
 * \brief Get real value for a given Dnstap value.
 */
static int decode(const mapping_t *mapping, int dnstap)
{
	for (const mapping_t *m = mapping; m->real != 0; m += 1) {
		if (m->dnstap == dnstap) {
			return m->real;
		}
	}

	return 0;
}

/* -- public API ----------------------------------------------------------- */

Dnstap__SocketFamily dt_family_encode(int family)
{
	return encode(SOCKET_FAMILY_MAPPING, family);
}

int dt_family_decode(Dnstap__SocketFamily dnstap_family)
{
	return decode(SOCKET_FAMILY_MAPPING, dnstap_family);
}

Dnstap__SocketProtocol dt_protocol_encode(int protocol)
{
	return encode(SOCKET_PROTOCOL_MAPPING, protocol);
}

int dt_protocol_decode(Dnstap__SocketProtocol dnstap_protocol)
{
	return decode(SOCKET_PROTOCOL_MAPPING, dnstap_protocol);
}

bool dt_message_type_is_query(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
		return true;
	default:
		return false;
	}
}

bool dt_message_type_is_response(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		return true;
	default:
		return false;
	}
}

bool dt_message_role_is_initiator(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
		return false;
	default:
		return true;
	}
}

static void set_address(const struct sockaddr *sockaddr,
                        ProtobufCBinaryData   *addr,
                        protobuf_c_boolean    *has_addr,
                        uint32_t              *port,
                        protobuf_c_boolean    *has_port)
{
	if (sockaddr == NULL) {
		*has_addr = 0;
		*has_port = 0;
		return;
	}

	*has_addr = 1;
	*has_port = 1;

	if (sockaddr->sa_family == AF_INET) {
		const struct sockaddr_in *sai;
		sai = (const struct sockaddr_in *)sockaddr;
		addr->len = sizeof(sai->sin_addr);
		addr->data = (uint8_t *)&sai->sin_addr.s_addr;
		*port = ntohs(sai->sin_port);
	} else if (sockaddr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sai6;
		sai6 = (const struct sockaddr_in6 *)sockaddr;
		addr->len = sizeof(sai6->sin6_addr);
		addr->data = (uint8_t *)&sai6->sin6_addr.s6_addr;
		*port = ntohs(sai6->sin6_port);
	}
}

static int get_family(const struct sockaddr *query_sa,
	              const struct sockaddr *response_sa)
{
	const struct sockaddr *source = query_sa ? query_sa : response_sa;
	if (source == NULL) {
		return 0;
	}

	return dt_family_encode(source->sa_family);
}

static uint8_t* dt_pack(const Dnstap__Dnstap *d, uint8_t **buf, size_t *sz)
{
	ProtobufCBufferSimple sbuf = { { NULL } };

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL) {
		return NULL;
	}
	sbuf.must_free_data = 1;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	*buf = sbuf.data;
	return *buf;
}

/*! \brief Create a UNIX socket sink. */
static struct fstrm_writer* dnstap_unix_writer(const char *path)
{
	struct fstrm_unix_writer_options *opt = NULL;
	struct fstrm_writer_options *wopt = NULL;
	struct fstrm_writer *writer = NULL;

	opt = fstrm_unix_writer_options_init();
	if (opt == NULL) {
		goto finish;
	}
	fstrm_unix_writer_options_set_socket_path(opt, path);

	wopt = fstrm_writer_options_init();
	if (wopt == NULL) {
		goto finish;
	}
	fstrm_writer_options_add_content_type(wopt, DNSTAP_CONTENT_TYPE,
	                                      strlen(DNSTAP_CONTENT_TYPE));
	writer = fstrm_unix_writer_init(opt, wopt);

finish:
	fstrm_unix_writer_options_destroy(&opt);
	fstrm_writer_options_destroy(&wopt);
	return writer;
}

/*! \brief Create a file sink. */
static struct fstrm_writer* dnstap_file_writer(const char *path)
{
	struct fstrm_file_options *fopt = NULL;
	struct fstrm_writer_options *wopt = NULL;
	struct fstrm_writer *writer = NULL;

	fopt = fstrm_file_options_init();
	if (fopt == NULL) {
		goto finish;
	}
	fstrm_file_options_set_file_path(fopt, path);

	wopt = fstrm_writer_options_init();
	if (wopt == NULL) {
		goto finish;
	}
	fstrm_writer_options_add_content_type(wopt, DNSTAP_CONTENT_TYPE,
	                                      strlen(DNSTAP_CONTENT_TYPE));
	writer = fstrm_file_writer_init(fopt, wopt);

finish:
	fstrm_file_options_destroy(&fopt);
	fstrm_writer_options_destroy(&wopt);
	return writer;
}

void dt_message_fill(Dnstap__Message             *m,
                    const Dnstap__Message__Type type,
                    const struct sockaddr       *query_sa,
                    const struct sockaddr       *response_sa,
                    const int                   protocol,
                    const void                  *wire,
                    const size_t                len_wire,
                    const struct timespec       *mtime)
{
	if (m == NULL) {
		return;
	}

	memset(m, 0, sizeof(*m));

	m->base.descriptor = &dnstap__message__descriptor;

	// Message.type
	m->type = type;

	// Message.socket_family
	m->socket_family = get_family(query_sa, response_sa);
	m->has_socket_family = m->socket_family != 0;

	// Message.socket_protocol
	m->socket_protocol = dt_protocol_encode(protocol);
	m->has_socket_protocol = m->socket_protocol != 0;

	// Message addresses
	set_address(query_sa, &m->query_address, &m->has_query_address,
	            &m->query_port, &m->has_query_port);
	set_address(response_sa, &m->response_address, &m->has_response_address,
	            &m->response_port, &m->has_response_port);

	if (dt_message_type_is_query(type)) {
		// Message.query_message
		m->query_message.len = len_wire;
		m->query_message.data = (uint8_t *)wire;
		m->has_query_message = 1;
		// Message.query_time_sec, Message.query_time_nsec
		if (mtime != NULL) {
			m->query_time_sec = mtime->tv_sec;
			m->query_time_nsec = mtime->tv_nsec;
			m->has_query_time_sec = 1;
			m->has_query_time_nsec = 1;
		}
	} else if (dt_message_type_is_response(type)) {
		// Message.response_message
		m->response_message.len = len_wire;
		m->response_message.data = (uint8_t *)wire;
		m->has_response_message = 1;
		// Message.response_time_sec, Message.response_time_nsec
		if (mtime != NULL) {
			m->response_time_sec = mtime->tv_sec;
			m->response_time_nsec = mtime->tv_nsec;
			m->has_response_time_sec = 1;
			m->has_response_time_nsec = 1;
		}
	}
}

static void dnstap_log_message(dnstap_ctx_t* dnstap_ctx, bool isQUERY, const struct sockaddr* sa, uint8_t* packet, const unsigned packet_len)
{
    if(dnstap_ctx == NULL || dnstap_ctx->iothread == NULL || dnstap_ctx->ioqueue == NULL)
        return;

    //struct timespec current_time;
    //clock_gettime(CLOCK_REALTIME, &current_time);
	struct timespec tv = { .tv_sec = time(NULL) };

	/* Determine query / response. */
	Dnstap__Message__Type msgtype = DNSTAP__MESSAGE__TYPE__AUTH_QUERY;
	if (!isQUERY) {
		msgtype = DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE;
	}

	/* Determine whether we run on UDP/TCP. */
	int protocol = IPPROTO_TCP;
	if (dnstap_ctx->isUDP) {
		protocol = IPPROTO_UDP;
	}

	/* Create a dnstap message. */
	Dnstap__Message msg;
	dt_message_fill(&msg, msgtype,
	                          sa,
	                          NULL, /* todo: fill me! */
				  protocol, packet, packet_len, &tv);

	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = &msg;

	// Set message version and identity.
	if (gdnstap_cfg->identity != NULL) {
		dnstap.identity.data = (uint8_t *)gdnstap_cfg->identity;
		dnstap.identity.len = gdnstap_cfg->identity_len;
		dnstap.has_identity = 1;
	}
	if (gdnstap_cfg->version != NULL) {
		dnstap.version.data = (uint8_t *)gdnstap_cfg->version;
		dnstap.version.len = gdnstap_cfg->version_len;
		dnstap.has_version = 1;
	}

	/* Pack the message. */
	uint8_t *frame = NULL;
	size_t size = 0;
	dt_pack(&dnstap, &frame, &size);
	if (frame == NULL) {
		return;
	}

	/* Submit a request. */
	fstrm_res res = fstrm_iothr_submit(dnstap_ctx->iothread, dnstap_ctx->ioqueue, frame, size,
	                                   fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success) {
		free(frame);
		return;
	}
}

#define CFG_OPT_BOOL_ALTSTORE(_opt_set, _gconf_loc, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
        bool _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        _store = _val; \
        } \
    } while (0)

#define CFG_OPT_STR_ALTSTORE(_opt_set, _gconf_loc, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            if (!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_gconf_loc); \
            _store = xstrdup(vscf_simple_get_data(_opt_setting)); \
        } \
    } while (0)

#define CFG_OPT_UINT_ALTSTORE(_opt_set, _gconf_loc, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            unsigned long _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            _store = (unsigned int) _val; \
        } \
    } while (0)

void dnstap_conf_load(const vscf_data_t* cfg_root)
{
    gdnsd_assert(!cfg_root || vscf_is_hash(cfg_root));

    dnstap_cfg_t* dnstap_cfg = xmalloc(sizeof(*dnstap_cfg));
    memcpy(dnstap_cfg, &dnstap_cfg_defaults, sizeof(*dnstap_cfg));

    vscf_data_t* dnstap_opt = NULL;

    const vscf_data_t* options = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "options", true) : NULL;
    if (options) {
        dnstap_opt = vscf_hash_get_data_byconstkey(options, "dnstap", true);
    }

    if (dnstap_opt){
        CFG_OPT_BOOL_ALTSTORE(dnstap_opt, enable, dnstap_cfg->enable);
        CFG_OPT_STR_ALTSTORE(dnstap_opt, sink, dnstap_cfg->sink);
        CFG_OPT_STR_ALTSTORE(dnstap_opt, identity, dnstap_cfg->identity);
        CFG_OPT_STR_ALTSTORE(dnstap_opt, version, dnstap_cfg->version);
		CFG_OPT_BOOL_ALTSTORE(dnstap_opt, unix_sink, dnstap_cfg->unix_sink);
        CFG_OPT_BOOL_ALTSTORE(dnstap_opt, log_queries, dnstap_cfg->log_queries);
        CFG_OPT_BOOL_ALTSTORE(dnstap_opt, log_responses, dnstap_cfg->log_responses);
		CFG_OPT_BOOL_ALTSTORE(dnstap_opt, queue_model_mpsc, dnstap_cfg->queue_model_mpsc);
		CFG_OPT_UINT_ALTSTORE(dnstap_opt, buffer_hint, dnstap_cfg->buffer_hint);
		CFG_OPT_UINT_ALTSTORE(dnstap_opt, input_queue_size, dnstap_cfg->input_queue_size);
		CFG_OPT_UINT_ALTSTORE(dnstap_opt, flush_timeout, dnstap_cfg->flush_timeout);
    }

	if (dnstap_cfg->identity){
    	dnstap_cfg->identity_len = strlen(dnstap_cfg->identity);
	}

	if (dnstap_cfg->version){
    	dnstap_cfg->version_len = strlen(dnstap_cfg->version);
	}
    
    log_info("Dnstap config loaded; sink= %s", dnstap_cfg->sink);

    gdnstap_cfg = dnstap_cfg;
}

dnstap_ctx_t* dnstap_ctx_init(bool isUDP)
{
	unsigned threadnum = 0;
	pthread_mutex_lock(&threadnum_lock);
	threadnum = g_threadnum;
	g_threadnum++;
	pthread_mutex_unlock(&threadnum_lock);

    if(giothread == NULL)
        return NULL;

    dnstap_ctx_t* ctx = xcalloc(sizeof(*ctx));
    ctx->iothread = giothread;
    ctx->ioqueue = fstrm_iothr_get_input_queue_idx(giothread, threadnum);
    ctx->isUDP = isUDP;

    return ctx;
}

void dnstap_ctx_cleanup(dnstap_ctx_t** pctx)
{
    if(pctx == NULL || *pctx == NULL)
        return;

    dnstap_ctx_t* ctx = *pctx;

    free(ctx);
    *pctx = NULL;
}

void* dnstap_start(unsigned num_threads)
{
    if (!gdnstap_cfg->enable) {
        return NULL;
    }

    /* Initialize the writer and the options. */
	struct fstrm_writer *writer = NULL;
	if(gdnstap_cfg->unix_sink){
		writer = dnstap_unix_writer(gdnstap_cfg->sink);
	} else {
		writer = dnstap_file_writer(gdnstap_cfg->sink);
	}
	if (writer == NULL) {
		return NULL;
	}

    struct fstrm_iothr_options *opt = fstrm_iothr_options_init();
	if (opt == NULL) {
		fstrm_writer_destroy(&writer);
		return NULL;
	}

	fstrm_res res = fstrm_iothr_options_set_num_input_queues(opt, num_threads);
	if (res != fstrm_res_success){
		fstrm_writer_destroy(&writer);
		fstrm_iothr_options_destroy(&opt);
		log_err("Dnstap error: fstrm_iothr_options_set_num_input_queues failed");
		return NULL;
	}

	if (gdnstap_cfg->queue_model_mpsc){
		res = fstrm_iothr_options_set_queue_model(opt, FSTRM_IOTHR_QUEUE_MODEL_MPSC);
		if (res != fstrm_res_success){
			fstrm_writer_destroy(&writer);
			fstrm_iothr_options_destroy(&opt);
			return NULL;
		}
	}

	if (gdnstap_cfg->buffer_hint){
    	res = fstrm_iothr_options_set_buffer_hint(opt, gdnstap_cfg->buffer_hint);
		if (res != fstrm_res_success){
			fstrm_writer_destroy(&writer);
			fstrm_iothr_options_destroy(&opt);
			log_err("Dnstap error: fstrm_iothr_options_set_buffer_hint failed");
			return NULL;
		}
	}
    
	if (gdnstap_cfg->input_queue_size){
		res = fstrm_iothr_options_set_input_queue_size(opt, gdnstap_cfg->input_queue_size);
		if (res != fstrm_res_success){
			fstrm_writer_destroy(&writer);
			fstrm_iothr_options_destroy(&opt);
			log_err("Dnstap error: fstrm_iothr_options_set_input_queue_size failed");
			return NULL;
		}
	}

	if (gdnstap_cfg->flush_timeout){
    	res = fstrm_iothr_options_set_flush_timeout(opt, gdnstap_cfg->flush_timeout);
		if (res != fstrm_res_success){
			fstrm_writer_destroy(&writer);
			fstrm_iothr_options_destroy(&opt);
			log_err("Dnstap error: fstrm_iothr_options_set_flush_timeout failed");
			return NULL;
		}
	}

	/* Create the I/O thread. */
	giothread = fstrm_iothr_init(opt, &writer);
	fstrm_iothr_options_destroy(&opt);
	if (giothread == NULL) {
		fstrm_writer_destroy(&writer);
		return NULL;
	}

    return giothread;
}

void dnstap_stop()
{
    if (giothread != NULL) {
        fstrm_iothr_destroy(&giothread);
    }

	if (gdnstap_cfg != NULL) {
		if (gdnstap_cfg->identity != NULL) {
			free((void*)gdnstap_cfg->identity);
		}

		if (gdnstap_cfg->version != NULL) {
			free((void*)gdnstap_cfg->version);
		}

		free(gdnstap_cfg);
		gdnstap_cfg = NULL;
	}
}

void dnstap_log_query_message(dnstap_ctx_t* dnstap_ctx, const struct sockaddr* sa, uint8_t* packet, const unsigned packet_len)
{
    if (gdnstap_cfg->enable && gdnstap_cfg->log_queries) {
        dnstap_log_message(dnstap_ctx, true, sa, packet, packet_len);
    }
}

void dnstap_log_response_message(dnstap_ctx_t* dnstap_ctx, const struct sockaddr* sa, uint8_t* packet, const unsigned packet_len)
{
    if (gdnstap_cfg->enable && gdnstap_cfg->log_responses) {
        dnstap_log_message(dnstap_ctx, false, sa, packet, packet_len);
    }
}