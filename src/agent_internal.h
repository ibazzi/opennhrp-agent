// SPDX-License-Identifier: MIT
#ifndef AGENT_INTERNAL_H
#define AGENT_INTERNAL_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "jsmn.h"

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "opennhrp-agent requires OpenSSL 1.1.1 or newer"
#endif

#define AGENT_VERSION "1.0.0"
#define MAX_WS_MESSAGE (4U * 1024U * 1024U)
#define MAX_COMMAND_ARGS 64
#define MAX_PENDING_COMMANDS 32
#define HEARTBEAT_MS 500
#define CORE_REFRESH_MS 2000
#define RECONNECT_MS 3000
#define SOCKET_TIMEOUT_MS 3000

struct buffer {
	char *data;
	size_t len;
	size_t cap;
};

struct json_doc {
	const char *text;
	jsmntok_t *tokens;
	int count;
};

struct config {
	char server[2048];
	char node_id[256];
	char node_type[16];
	char token[2048];
	char core_socket[PATH_MAX];
	char ha_socket[PATH_MAX];
	char ctl_path[PATH_MAX];
	char config_path[PATH_MAX];
	char state_dir[PATH_MAX];
};
extern volatile sig_atomic_t stopping;

struct cluster_result {
	char cluster_id[256];
	char member_id[256];
	char member_state[32];
	char primary[256];
	char leader[256];
	char advertised_ip[256];
	char local_role[32];
	char digest[256];
	uint64_t term;
	uint64_t commit_index;
	uint64_t manifest_revision;
	bool network_health;
	bool service_available;
	char *witness_json;
	char *status_json;
};

struct ws_url {
	bool tls;
	char host[256];
	char port[8];
	char path[1536];
};

struct transport {
	int fd;
	bool tls;
	SSL_CTX *ctx;
	SSL *ssl;
	short want_events;
};

struct websocket;
typedef bool (*ws_message_fn)(void *opaque, const char *message, size_t len);

struct websocket {
	struct transport transport;
	struct buffer input;
	struct buffer message;
	unsigned int fragment_opcode;
	ws_message_fn on_message;
	void *opaque;
};

struct command_request {
	struct agent *agent;
	uint64_t generation;
	char *id;
	char *target;
	char *command;
	char **args;
	size_t argc;
};

struct command_response {
	uint64_t generation;
	char *id;
	bool success;
	char *text;
	struct command_response *next;
};

struct log_reader {
	pid_t pid;
	int fd;
	struct buffer partial;
	int64_t retry_at;
};

struct queued_log {
	char *json;
	struct queued_log *next;
};

struct agent {
	struct config config;
	struct websocket websocket;
	uint64_t generation;
	pthread_mutex_t command_lock;
	pthread_cond_t command_done;
	unsigned int active_commands;
	struct command_response *responses_head;
	struct command_response *responses_tail;
	struct log_reader logs;
	struct queued_log *logs_head;
	struct queued_log *logs_tail;
	size_t logs_count;
	bool core_available;
	size_t peer_count;
	size_t spoke_count;
	int64_t last_core_refresh;
	bool heartbeat_ready;
	char *heartbeat;
};

int64_t monotonic_ms(void);
uint64_t realtime_ns(void);
void timestamp(char out[40]);
void log_message(const char *level, const char *fmt, ...);
bool buffer_reserve(struct buffer *b, size_t extra);
bool buffer_addn(struct buffer *b, const void *data, size_t len);
bool buffer_add(struct buffer *b, const char *text);
bool buffer_addf(struct buffer *b, const char *fmt, ...);
void buffer_reset(struct buffer *b);
void buffer_free(struct buffer *b);
char *buffer_take(struct buffer *b);
bool json_quote(struct buffer *b, const char *text);
void json_doc_free(struct json_doc *doc);
bool json_parse(struct json_doc *doc, const char *text);
bool token_equal(const struct json_doc *doc, int index, const char *text);
int object_get(const struct json_doc *doc, int object, const char *key);
char *token_string(const struct json_doc *doc, int index);
bool token_copy(const struct json_doc *doc, int index, char *out, size_t out_size);
bool token_bool(const struct json_doc *doc, int index, bool fallback);
uint64_t token_u64(const struct json_doc *doc, int index);
int token_int(const struct json_doc *doc, int index);
bool add_json_token(struct buffer *out, const struct json_doc *doc, int index);
bool copy_setting(char *dst, size_t size, const char *value, const char *name);
const char *env_or(const char *name, const char *fallback);
bool read_secret_file(char *out, size_t size, const char *path);
bool valid_header_value(const char *value);
bool add_field_string(struct buffer *out, const char *name, const char *value, bool *first);
bool add_field_bool(struct buffer *out, const char *name, bool value, bool *first);
bool add_field_u64(struct buffer *out, const char *name, uint64_t value, bool *first);
char *trim(char *text);
void peer_field(char *dst, size_t size, const char *src);
int wait_fd(int fd, short events, int64_t deadline);

void cluster_result_free(struct cluster_result *result);
bool transform_cluster(const char *raw, const char *default_node_id,
                       const char *state_dir, struct cluster_result *result);
char *parse_peers(const char *raw, size_t *peer_count);
void *heartbeat_worker(void *opaque);

bool parse_ws_url(const char *text, struct ws_url *url);
char *websocket_accept(const char *key);
bool ws_send_text(struct websocket *ws, const char *text);
int ws_read_available(struct websocket *ws);
bool ws_connect(struct websocket *ws, const struct config *config,
                ws_message_fn on_message, void *opaque);
void ws_close(struct websocket *ws);

bool socket_command(const char *path, const char *command,
                    int timeout_ms, char **output, char **error_text);
void command_request_free(struct command_request *request);
struct command_request *parse_command_request(struct agent *agent,
                                              const struct json_doc *doc, int root);
bool agent_on_message(void *opaque, const char *message, size_t len);
void command_response_free(struct command_response *response);
void free_command_responses(struct agent *agent);
bool flush_command_responses(struct agent *agent);

bool start_log_reader(struct log_reader *reader);
void stop_log_reader(struct log_reader *reader);
void read_logs(struct agent *agent);
bool flush_logs(struct agent *agent);
void free_logs(struct agent *agent);

#endif
