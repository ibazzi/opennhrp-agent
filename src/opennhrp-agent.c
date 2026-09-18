// SPDX-License-Identifier: MIT
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

static volatile sig_atomic_t stopping;

static int64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint64_t realtime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void timestamp(char out[40])
{
	struct timespec ts;
	struct tm tm;
	size_t n;

	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);
	n = strftime(out, 40, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(out + n, 40 - n, ".%09ldZ", ts.tv_nsec);
}

static void log_message(const char *level, const char *fmt, ...)
{
	char when[40];
	va_list ap;

	timestamp(when);
	fprintf(stderr, "%s [%s] ", when, level);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static bool buffer_reserve(struct buffer *b, size_t extra)
{
	size_t need;
	size_t cap;
	char *data;

	if (extra > SIZE_MAX - b->len - 1)
		return false;
	need = b->len + extra + 1;
	if (need <= b->cap)
		return true;
	cap = b->cap ? b->cap : 256;
	while (cap < need) {
		if (cap > SIZE_MAX / 2) {
			cap = need;
			break;
		}
		cap *= 2;
	}
	data = realloc(b->data, cap);
	if (data == NULL)
		return false;
	b->data = data;
	b->cap = cap;
	return true;
}

static bool buffer_addn(struct buffer *b, const void *data, size_t len)
{
	if (!buffer_reserve(b, len))
		return false;
	memcpy(b->data + b->len, data, len);
	b->len += len;
	b->data[b->len] = '\0';
	return true;
}

static bool buffer_add(struct buffer *b, const char *text)
{
	return buffer_addn(b, text, strlen(text));
}

static bool buffer_addf(struct buffer *b, const char *fmt, ...)
{
	va_list ap;
	va_list copy;
	int n;

	va_start(ap, fmt);
	va_copy(copy, ap);
	n = vsnprintf(NULL, 0, fmt, copy);
	va_end(copy);
	if (n < 0 || !buffer_reserve(b, (size_t)n)) {
		va_end(ap);
		return false;
	}
	vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	b->len += (size_t)n;
	return true;
}

static void buffer_reset(struct buffer *b)
{
	b->len = 0;
	if (b->data != NULL)
		b->data[0] = '\0';
}

static void buffer_free(struct buffer *b)
{
	free(b->data);
	memset(b, 0, sizeof(*b));
}

static char *buffer_take(struct buffer *b)
{
	char *data;

	if (b->data == NULL) {
		data = strdup("");
	} else {
		data = b->data;
	}
	b->data = NULL;
	b->len = b->cap = 0;
	return data;
}

static bool json_quote(struct buffer *b, const char *text)
{
	const unsigned char *p = (const unsigned char *)text;

	if (!buffer_addn(b, "\"", 1))
		return false;
	for (; *p != '\0'; p++) {
		switch (*p) {
		case '"': if (!buffer_add(b, "\\\"")) return false; break;
		case '\\': if (!buffer_add(b, "\\\\")) return false; break;
		case '\b': if (!buffer_add(b, "\\b")) return false; break;
		case '\f': if (!buffer_add(b, "\\f")) return false; break;
		case '\n': if (!buffer_add(b, "\\n")) return false; break;
		case '\r': if (!buffer_add(b, "\\r")) return false; break;
		case '\t': if (!buffer_add(b, "\\t")) return false; break;
		default:
			if (*p < 0x20) {
				if (!buffer_addf(b, "\\u%04x", *p))
					return false;
			} else if (!buffer_addn(b, p, 1)) {
				return false;
			}
		}
	}
	return buffer_addn(b, "\"", 1);
}

static void json_doc_free(struct json_doc *doc)
{
	free(doc->tokens);
	memset(doc, 0, sizeof(*doc));
}

static bool json_parse(struct json_doc *doc, const char *text)
{
	unsigned int count = 256;

	memset(doc, 0, sizeof(*doc));
	doc->text = text;
	while (count <= 131072) {
		jsmn_parser parser;
		int result;
		jsmntok_t *tokens = calloc(count, sizeof(*tokens));

		if (tokens == NULL)
			return false;
		jsmn_init(&parser);
		result = jsmn_parse(&parser, text, strlen(text), tokens, count);
		if (result > 0) {
			doc->tokens = tokens;
			doc->count = result;
			return true;
		}
		free(tokens);
		if (result == 0)
			return false;
		if (result != JSMN_ERROR_NOMEM)
			return false;
		count *= 2;
	}
	return false;
}

static bool token_equal(const struct json_doc *doc, int index,
			const char *text)
{
	const jsmntok_t *tok;
	size_t len;

	if (index < 0 || index >= doc->count)
		return false;
	tok = &doc->tokens[index];
	len = (size_t)(tok->end - tok->start);
	return strlen(text) == len &&
	       memcmp(doc->text + tok->start, text, len) == 0;
}

static int object_get(const struct json_doc *doc, int object,
		      const char *key)
{
	int i;
	const jsmntok_t *obj;

	if (object < 0 || object >= doc->count ||
	    doc->tokens[object].type != JSMN_OBJECT)
		return -1;
	obj = &doc->tokens[object];
	for (i = object + 1; i + 1 < doc->count; i++) {
		const jsmntok_t *tok = &doc->tokens[i];

		if (tok->start >= obj->end)
			break;
		if (tok->parent == object && tok->type == JSMN_STRING &&
		    token_equal(doc, i, key))
			return i + 1;
	}
	return -1;
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static bool append_utf8(struct buffer *b, uint32_t cp)
{
	unsigned char out[4];
	size_t len;

	if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
		return false;
	if (cp <= 0x7f) {
		out[0] = (unsigned char)cp;
		len = 1;
	} else if (cp <= 0x7ff) {
		out[0] = 0xc0 | (unsigned char)(cp >> 6);
		out[1] = 0x80 | (unsigned char)(cp & 0x3f);
		len = 2;
	} else if (cp <= 0xffff) {
		out[0] = 0xe0 | (unsigned char)(cp >> 12);
		out[1] = 0x80 | (unsigned char)((cp >> 6) & 0x3f);
		out[2] = 0x80 | (unsigned char)(cp & 0x3f);
		len = 3;
	} else {
		out[0] = 0xf0 | (unsigned char)(cp >> 18);
		out[1] = 0x80 | (unsigned char)((cp >> 12) & 0x3f);
		out[2] = 0x80 | (unsigned char)((cp >> 6) & 0x3f);
		out[3] = 0x80 | (unsigned char)(cp & 0x3f);
		len = 4;
	}
	return buffer_addn(b, out, len);
}

static char *token_string(const struct json_doc *doc, int index)
{
	const jsmntok_t *tok;
	struct buffer out = {0};
	int i;

	if (index < 0 || index >= doc->count ||
	    doc->tokens[index].type != JSMN_STRING)
		return NULL;
	tok = &doc->tokens[index];
	for (i = tok->start; i < tok->end; i++) {
		unsigned char c = (unsigned char)doc->text[i];
		if (c != '\\') {
			if (c == 0 || !buffer_addn(&out, &c, 1))
				goto fail;
			continue;
		}
		if (++i >= tok->end)
			goto fail;
		switch (doc->text[i]) {
		case '"': c = '"'; break;
		case '\\': c = '\\'; break;
		case '/': c = '/'; break;
		case 'b': c = '\b'; break;
		case 'f': c = '\f'; break;
		case 'n': c = '\n'; break;
		case 'r': c = '\r'; break;
		case 't': c = '\t'; break;
		case 'u': {
			uint32_t cp = 0;
			int j;
			for (j = 0; j < 4; j++) {
				int h;
				if (++i >= tok->end || (h = hex_value(doc->text[i])) < 0)
					goto fail;
				cp = (cp << 4) | (uint32_t)h;
			}
			if (cp >= 0xd800 && cp <= 0xdbff) {
				uint32_t low = 0;
				if (i + 6 >= tok->end || doc->text[i + 1] != '\\' ||
				    doc->text[i + 2] != 'u')
					goto fail;
				i += 2;
				for (j = 0; j < 4; j++) {
					int h = hex_value(doc->text[++i]);
					if (h < 0) goto fail;
					low = (low << 4) | (uint32_t)h;
				}
				if (low < 0xdc00 || low > 0xdfff)
					goto fail;
				cp = 0x10000 + ((cp - 0xd800) << 10) +
				     (low - 0xdc00);
			}
			if (!append_utf8(&out, cp))
				goto fail;
			continue;
		}
		default:
			goto fail;
		}
		if (!buffer_addn(&out, &c, 1))
			goto fail;
	}
	return buffer_take(&out);
fail:
	buffer_free(&out);
	return NULL;
}

static bool token_copy(const struct json_doc *doc, int index, char *out,
		       size_t out_size)
{
	char *value = token_string(doc, index);
	size_t len;

	if (value == NULL)
		return false;
	len = strlen(value);
	if (len >= out_size) {
		free(value);
		return false;
	}
	memcpy(out, value, len + 1);
	free(value);
	return true;
}

static bool token_bool(const struct json_doc *doc, int index, bool fallback)
{
	if (token_equal(doc, index, "true")) return true;
	if (token_equal(doc, index, "false")) return false;
	return fallback;
}

static uint64_t token_u64(const struct json_doc *doc, int index)
{
	char number[32];
	size_t len;
	char *end;
	unsigned long long value;

	if (index < 0 || index >= doc->count)
		return 0;
	len = (size_t)(doc->tokens[index].end - doc->tokens[index].start);
	if (len == 0 || len >= sizeof(number))
		return 0;
	memcpy(number, doc->text + doc->tokens[index].start, len);
	number[len] = '\0';
	errno = 0;
	value = strtoull(number, &end, 10);
	return errno == 0 && *end == '\0' ? (uint64_t)value : 0;
}

static int token_int(const struct json_doc *doc, int index)
{
	uint64_t value = token_u64(doc, index);
	return value > INT_MAX ? INT_MAX : (int)value;
}

static bool add_json_token(struct buffer *out, const struct json_doc *doc,
			   int index)
{
	const jsmntok_t *tok;

	if (index < 0 || index >= doc->count)
		return false;
	tok = &doc->tokens[index];
	return buffer_addn(out, doc->text + tok->start,
			   (size_t)(tok->end - tok->start));
}

static bool copy_setting(char *dst, size_t size, const char *value,
			 const char *name)
{
	if (value == NULL || strlen(value) >= size) {
		log_message("ERROR", "%s is too long", name);
		return false;
	}
	strcpy(dst, value);
	return true;
}

static const char *env_or(const char *name, const char *fallback)
{
	const char *value = getenv(name);
	return value != NULL && *value != '\0' ? value : fallback;
}

static bool read_secret_file(char *out, size_t size, const char *path)
{
	FILE *file;
	size_t len;

	if (path == NULL || *path == '\0')
		return false;
	file = fopen(path, "r");
	if (file == NULL)
		return false;
	if (fgets(out, (int)size, file) == NULL) {
		fclose(file);
		return false;
	}
	fclose(file);
	len = strlen(out);
	while (len > 0 && isspace((unsigned char)out[len - 1]))
		out[--len] = '\0';
	return len > 0;
}

static bool valid_header_value(const char *value)
{
	return value != NULL && strchr(value, '\r') == NULL &&
	       strchr(value, '\n') == NULL;
}

static void on_signal(int signum)
{
	(void)signum;
	stopping = 1;
}

struct member_ref {
	int object;
	int priority;
	uint64_t match_index;
	char id[256];
};

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

static void cluster_result_free(struct cluster_result *result)
{
	free(result->witness_json);
	free(result->status_json);
	memset(result, 0, sizeof(*result));
}

static int member_compare(const void *left, const void *right)
{
	const struct member_ref *a = left;
	const struct member_ref *b = right;

	if (a->priority != b->priority)
		return a->priority > b->priority ? -1 : 1;
	return strcmp(a->id, b->id);
}

static bool add_field_string(struct buffer *out, const char *name,
			     const char *value, bool *first)
{
	if (!*first && !buffer_addn(out, ",", 1)) return false;
	*first = false;
	return json_quote(out, name) && buffer_addn(out, ":", 1) &&
	       json_quote(out, value);
}

static bool add_field_bool(struct buffer *out, const char *name, bool value,
			   bool *first)
{
	if (!*first && !buffer_addn(out, ",", 1)) return false;
	*first = false;
	return json_quote(out, name) && buffer_addn(out, ":", 1) &&
	       buffer_add(out, value ? "true" : "false");
}

static bool add_field_u64(struct buffer *out, const char *name, uint64_t value,
			  bool *first)
{
	if (!*first && !buffer_addn(out, ",", 1)) return false;
	*first = false;
	return json_quote(out, name) && buffer_addn(out, ":", 1) &&
	       buffer_addf(out, "%llu", (unsigned long long)value);
}

static bool member_addresses(const struct json_doc *doc, int member,
			     struct buffer *out, char observed[256],
			     char first_advertised[256])
{
	int addresses = object_get(doc, member, "addresses");
	bool first = true;
	int i;

	if (!buffer_addn(out, "[", 1))
		return false;
	if (addresses >= 0 && doc->tokens[addresses].type == JSMN_ARRAY) {
		for (i = addresses + 1; i < doc->count; i++) {
			char address[256] = "";
			char origin[32] = "";
			if (doc->tokens[i].start >= doc->tokens[addresses].end)
				break;
			if (doc->tokens[i].parent != addresses ||
			    doc->tokens[i].type != JSMN_OBJECT)
				continue;
			token_copy(doc, object_get(doc, i, "address"), address,
				   sizeof(address));
			token_copy(doc, object_get(doc, i, "origin"), origin,
				   sizeof(origin));
			if (address[0] == '\0')
				continue;
			if (strcmp(origin, "observed") == 0) {
				if (observed[0] == '\0')
					strcpy(observed, address);
				continue;
			}
			if (first_advertised[0] == '\0')
				strcpy(first_advertised, address);
			if (!first && !buffer_addn(out, ",", 1)) return false;
			first = false;
			if (!json_quote(out, address)) return false;
		}
	}
	return buffer_addn(out, "]", 1);
}

static bool append_members(struct buffer *out, const struct json_doc *doc,
			   int members, struct member_ref *refs,
			   size_t ref_count, const char *leader,
			   uint64_t max_match, struct cluster_result *result)
{
	size_t n;
	struct buffer addresses = {0};

	if (!buffer_addn(out, "[", 1))
		return false;
	for (n = 0; n < ref_count; n++) {
		int object = refs[n].object;
		char state[32] = "";
		char observed[256] = "";
		char first_advertised[256] = "";
		bool first = true;
		bool connected = token_bool(doc, object_get(doc, object, "connected"), false);
		bool authenticated = token_bool(doc, object_get(doc, object, "authenticated"), false);
		uint64_t lag = max_match >= refs[n].match_index ?
			max_match - refs[n].match_index : 0;

		(void)members;
		token_copy(doc, object_get(doc, object, "state"), state,
			   sizeof(state));
		if (!member_addresses(doc, object, &addresses, observed,
				      first_advertised))
			goto fail;
		if (strcmp(refs[n].id, result->member_id) == 0) {
			memcpy(result->member_state, state, sizeof(result->member_state));
			memcpy(result->advertised_ip, first_advertised, sizeof(result->advertised_ip));
		}
		if (n > 0 && !buffer_addn(out, ",", 1)) goto fail;
		if (!buffer_addn(out, "{", 1) ||
		    !add_field_string(out, "member_id", refs[n].id, &first) ||
		    !add_field_u64(out, "priority", (uint64_t)refs[n].priority, &first) ||
		    !add_field_string(out, "state", state, &first) ||
		    !add_field_bool(out, "is_leader",
				    leader[0] != '\0' && strcmp(refs[n].id, leader) == 0,
				    &first))
			goto fail;
		if (!buffer_add(out, ",\"advertised_addresses\":") ||
		    !buffer_addn(out, addresses.data ? addresses.data : "[]",
				 addresses.data ? addresses.len : 2))
			goto fail;
		if (observed[0] != '\0' &&
		    !add_field_string(out, "observed_address", observed, &first))
			goto fail;
		if (!add_field_u64(out, "match_index", refs[n].match_index, &first) ||
		    !add_field_u64(out, "lag", lag, &first) ||
		    !add_field_bool(out, "connected", connected, &first) ||
		    !add_field_bool(out, "authenticated", authenticated, &first) ||
		    !buffer_addn(out, "}", 1))
			goto fail;
		buffer_free(&addresses);
	}
	return buffer_addn(out, "]", 1);
fail:
	buffer_free(&addresses);
	return false;
}

static bool append_health_targets(struct buffer *out,
				  const struct json_doc *doc, int targets,
				  int interval)
{
	bool first_target = true;
	int i;

	if (!buffer_addn(out, "[", 1))
		return false;
	if (targets >= 0 && doc->tokens[targets].type == JSMN_ARRAY) {
		for (i = targets + 1; i < doc->count; i++) {
			char address[256] = "";
			bool first = true;
			bool success;
			if (doc->tokens[i].start >= doc->tokens[targets].end)
				break;
			if (doc->tokens[i].parent != targets ||
			    doc->tokens[i].type != JSMN_OBJECT)
				continue;
			token_copy(doc, object_get(doc, i, "address"), address,
				   sizeof(address));
			if (address[0] == '\0')
				token_copy(doc, object_get(doc, i, "target_ip"), address,
					   sizeof(address));
			success = token_bool(doc, object_get(doc, i, "last_success"), false);
			if (!first_target && !buffer_addn(out, ",", 1)) return false;
			first_target = false;
			if (!buffer_addn(out, "{", 1) ||
			    !add_field_string(out, "target_ip", address, &first) ||
			    !add_field_bool(out, "last_success", success, &first) ||
			    !add_field_u64(out, "interval_sec", (uint64_t)interval, &first) ||
			    !buffer_addn(out, "}", 1))
				return false;
		}
	}
	return buffer_addn(out, "]", 1);
}

static bool transform_cluster(const char *raw, const char *default_node_id,
			      const char *state_dir, struct cluster_result *result)
{
	const char *json = strchr(raw, '{');
	struct json_doc doc;
	struct buffer status = {0};
	struct buffer members_json = {0};
	struct buffer targets_json = {0};
	struct member_ref *refs = NULL;
	size_t ref_count = 0;
	uint64_t max_match = 0;
	char health_status[32] = "unknown";
	char witness_mode[32] = "";
	bool witness_quorum = false;
	bool isolated;
	bool first = true;
	int members;
	int witness;
	int health;
	int interval;
	int i;

	memset(result, 0, sizeof(*result));
	if (json == NULL || !json_parse(&doc, json))
		return false;
	if (doc.tokens[0].type != JSMN_OBJECT) {
		json_doc_free(&doc);
		return false;
	}
	token_copy(&doc, object_get(&doc, 0, "cluster_id"), result->cluster_id,
		   sizeof(result->cluster_id));
	token_copy(&doc, object_get(&doc, 0, "local_member"), result->member_id,
		   sizeof(result->member_id));
	if (result->member_id[0] == '\0')
		copy_setting(result->member_id, sizeof(result->member_id),
			     default_node_id, "node id");
	token_copy(&doc, object_get(&doc, 0, "primary"), result->primary,
		   sizeof(result->primary));
	token_copy(&doc, object_get(&doc, 0, "leader"), result->leader,
		   sizeof(result->leader));
	token_copy(&doc, object_get(&doc, 0, "digest"), result->digest,
		   sizeof(result->digest));
	result->term = token_u64(&doc, object_get(&doc, 0, "term"));
	result->commit_index = token_u64(&doc, object_get(&doc, 0, "commit_index"));
	result->manifest_revision = token_u64(&doc,
		object_get(&doc, 0, "manifest_revision"));
	result->service_available = token_bool(&doc,
		object_get(&doc, 0, "service_available"), false);
	isolated = token_bool(&doc, object_get(&doc, 0, "isolated"), false);
	health = object_get(&doc, 0, "network_health");
	if (health >= 0 && doc.tokens[health].type == JSMN_STRING) {
		token_copy(&doc, health, health_status, sizeof(health_status));
		result->network_health = strcmp(health_status, "healthy") == 0;
	} else {
		result->network_health = token_bool(&doc, health, false);
		strcpy(health_status, result->network_health ? "healthy" : "unhealthy");
	}
	interval = token_int(&doc, object_get(&doc, 0, "health_interval_seconds"));
	witness = object_get(&doc, 0, "witness");
	if (witness >= 0 && doc.tokens[witness].type == JSMN_OBJECT) {
		struct buffer witness_out = {0};
		token_copy(&doc, object_get(&doc, witness, "mode"), witness_mode,
			   sizeof(witness_mode));
		witness_quorum = token_bool(&doc,
			object_get(&doc, witness, "quorum_available"), false);
		if (!add_json_token(&witness_out, &doc, witness))
			goto fail;
		result->witness_json = buffer_take(&witness_out);
	} else {
		result->witness_json = strdup("{}");
	}
	if (result->witness_json == NULL)
		goto fail;
	if (isolated) {
		strcpy(result->local_role, "isolated");
	} else {
		bool serviceable = result->service_available &&
			(witness_mode[0] == '\0' || witness_quorum);
		if (result->leader[0] != '\0' &&
		    strcmp(result->leader, result->member_id) == 0)
			strcpy(result->local_role, serviceable ? "leader" : "standby");
		else if (result->leader[0] != '\0')
			strcpy(result->local_role, serviceable ? "follower" : "standby");
		else
			strcpy(result->local_role, "standalone");
	}

	members = object_get(&doc, 0, "members");
	if (members >= 0 && doc.tokens[members].type == JSMN_ARRAY) {
		for (i = members + 1; i < doc.count; i++) {
			struct member_ref ref = {0};
			struct member_ref *grown;
			if (doc.tokens[i].start >= doc.tokens[members].end)
				break;
			if (doc.tokens[i].parent != members ||
			    doc.tokens[i].type != JSMN_OBJECT)
				continue;
			ref.object = i;
			token_copy(&doc, object_get(&doc, i, "member"), ref.id,
				   sizeof(ref.id));
			if (ref.id[0] == '\0')
				token_copy(&doc, object_get(&doc, i, "member_id"), ref.id,
					   sizeof(ref.id));
			ref.priority = token_int(&doc, object_get(&doc, i, "priority"));
			ref.match_index = token_u64(&doc,
				object_get(&doc, i, "match_index"));
			if (ref.match_index > max_match)
				max_match = ref.match_index;
			grown = realloc(refs, (ref_count + 1) * sizeof(*refs));
			if (grown == NULL)
				goto fail;
			refs = grown;
			refs[ref_count++] = ref;
		}
	}
	if (ref_count > 1)
		qsort(refs, ref_count, sizeof(*refs), member_compare);
	if (!append_members(&members_json, &doc, members, refs, ref_count,
			    result->leader, max_match, result))
		goto fail;
	if (!append_health_targets(&targets_json, &doc,
		object_get(&doc, 0, "health_targets"), interval))
		goto fail;

	if (!buffer_addn(&status, "{", 1) ||
	    !add_field_string(&status, "state_dir", state_dir, &first) ||
	    !add_field_string(&status, "cluster_id", result->cluster_id, &first) ||
	    !add_field_string(&status, "primary", result->primary, &first) ||
	    !add_field_string(&status, "member", result->member_id, &first) ||
	    !add_field_string(&status, "leader", result->leader, &first) ||
	    !add_field_string(&status, "local_role", result->local_role, &first) ||
	    !add_field_u64(&status, "term", result->term, &first) ||
	    !add_field_u64(&status, "commit_index", result->commit_index, &first) ||
	    !add_field_u64(&status, "manifest_revision", result->manifest_revision, &first) ||
	    !add_field_string(&status, "digest", result->digest, &first) ||
	    !add_field_bool(&status, "service_available", result->service_available, &first) ||
	    !add_field_bool(&status, "network_health", result->network_health, &first) ||
	    !add_field_string(&status, "network_health_status", health_status, &first) ||
	    !add_field_u64(&status, "health_interval_seconds", (uint64_t)interval, &first) ||
	    !add_field_u64(&status, "health_failure_rounds",
			   token_u64(&doc, object_get(&doc, 0, "health_failure_rounds")), &first) ||
	    !add_field_u64(&status, "health_recovery_rounds",
			   token_u64(&doc, object_get(&doc, 0, "health_recovery_rounds")), &first) ||
	    !add_field_bool(&status, "isolated", isolated, &first) ||
	    !buffer_add(&status, ",\"health_targets\":") ||
	    !buffer_addn(&status, targets_json.data, targets_json.len) ||
	    !buffer_add(&status, ",\"members\":") ||
	    !buffer_addn(&status, members_json.data, members_json.len) ||
	    !buffer_add(&status, ",\"witness\":") ||
	    !buffer_add(&status, result->witness_json) ||
	    !buffer_addn(&status, "}", 1))
		goto fail;
	result->status_json = buffer_take(&status);
	free(refs);
	buffer_free(&members_json);
	buffer_free(&targets_json);
	json_doc_free(&doc);
	return result->status_json != NULL;
fail:
	free(refs);
	buffer_free(&status);
	buffer_free(&members_json);
	buffer_free(&targets_json);
	json_doc_free(&doc);
	cluster_result_free(result);
	return false;
}

struct peer {
	char interface[128];
	char type[32];
	char registration_mode[8];
	char protocol[256];
	char nbma[256];
	char nat[256];
	char flags[512];
	int expires;
};

static char *trim(char *text)
{
	char *end;
	while (isspace((unsigned char)*text)) text++;
	end = text + strlen(text);
	while (end > text && isspace((unsigned char)end[-1])) end--;
	*end = '\0';
	return text;
}

static void peer_field(char *dst, size_t size, const char *src)
{
	if (size == 0) return;
	strncpy(dst, src, size - 1);
	dst[size - 1] = '\0';
}

static int parse_duration(const char *value)
{
	int a = 0, b = 0, c = 0;
	if (sscanf(value, "%d:%d:%d", &a, &b, &c) == 3)
		return a * 3600 + b * 60 + c;
	if (sscanf(value, "%d:%d", &a, &b) == 2)
		return a * 60 + b;
	return atoi(value);
}

static bool append_peer(struct peer **peers, size_t *count,
			const struct peer *current)
{
	struct peer *grown;

	if (current->protocol[0] == '\0' || strcmp(current->type, "local") == 0)
		return true;
	grown = realloc(*peers, (*count + 1) * sizeof(**peers));
	if (grown == NULL)
		return false;
	*peers = grown;
	(*peers)[(*count)++] = *current;
	return true;
}

static char *parse_peers(const char *raw, size_t *peer_count)
{
	char *copy = strdup(raw);
	char *cursor;
	char *line;
	struct peer current = {0};
	struct peer *peers = NULL;
	size_t count = 0;
	struct buffer out = {0};
	size_t i;

	if (copy == NULL)
		return NULL;
	cursor = copy;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		char *colon;
		char *key;
		char *value;
		line = trim(line);
		if (*line == '\0') {
			if (!append_peer(&peers, &count, &current)) goto fail;
			memset(&current, 0, sizeof(current));
			continue;
		}
		colon = strchr(line, ':');
		if (colon == NULL)
			continue;
		*colon = '\0';
		key = trim(line);
		value = trim(colon + 1);
		if (strcasecmp(key, "interface") == 0 || strcasecmp(key, "iface") == 0)
			peer_field(current.interface, sizeof(current.interface), value);
		else if (strcasecmp(key, "type") == 0) {
			peer_field(current.type, sizeof(current.type), value);
			for (char *p = current.type; *p; p++) *p = (char)tolower((unsigned char)*p);
		} else if (strcasecmp(key, "registration-mode") == 0) {
			if (strcasecmp(value, "ha") == 0) strcpy(current.registration_mode, "ha");
			else if (strcasecmp(value, "legacy") == 0) strcpy(current.registration_mode, "legacy");
		} else if (strcasecmp(key, "protocol-address") == 0 || strcasecmp(key, "protocol") == 0)
			peer_field(current.protocol, sizeof(current.protocol), value);
		else if (strcasecmp(key, "nbma-address") == 0 || strcasecmp(key, "nbma") == 0)
			peer_field(current.nbma, sizeof(current.nbma), value);
		else if (strcasecmp(key, "nbma-nat-oa") == 0 ||
			 strcasecmp(key, "nbma-nat-oa-address") == 0 ||
			 strcasecmp(key, "nat-oa") == 0)
			peer_field(current.nat, sizeof(current.nat), value);
		else if (strcasecmp(key, "flags") == 0) {
			char lower[512];
			peer_field(current.flags, sizeof(current.flags), value);
			peer_field(lower, sizeof(lower), value);
			for (char *p = lower; *p; p++) *p = (char)tolower((unsigned char)*p);
			if (strstr(lower, "shadow")) strcpy(current.type, "shadow");
			else if (strstr(lower, "static")) strcpy(current.type, "static");
			else if (current.type[0] == '\0') strcpy(current.type, "direct");
		} else if (strcasecmp(key, "expires-in") == 0 ||
			   strcasecmp(key, "expires") == 0 ||
			   strcasecmp(key, "holding-time") == 0)
			current.expires = parse_duration(value);
	}
	if (!append_peer(&peers, &count, &current)) goto fail;
	if (!buffer_addn(&out, "[", 1)) goto fail;
	for (i = 0; i < count; i++) {
		bool first = true;
		if (i > 0 && !buffer_addn(&out, ",", 1)) goto fail;
		if (!buffer_addn(&out, "{", 1) ||
		    !add_field_string(&out, "protocol_address", peers[i].protocol, &first) ||
		    !add_field_string(&out, "nbma_address", peers[i].nbma, &first)) goto fail;
		if (peers[i].registration_mode[0] &&
		    !add_field_string(&out, "registration_mode", peers[i].registration_mode, &first)) goto fail;
		if (peers[i].nat[0] != '\0' &&
		    !add_field_string(&out, "nat_address", peers[i].nat, &first)) goto fail;
		if (!add_field_string(&out, "interface", peers[i].interface, &first) ||
		    !add_field_string(&out, "type", peers[i].type, &first) ||
		    !add_field_string(&out, "flags", peers[i].flags, &first) ||
		    !add_field_u64(&out, "holding_time", (uint64_t)peers[i].expires, &first) ||
		    !add_field_u64(&out, "expires_in_sec", (uint64_t)peers[i].expires, &first) ||
		    !buffer_addn(&out, "}", 1)) goto fail;
	}
	if (!buffer_addn(&out, "]", 1)) goto fail;
	*peer_count = count;
	free(peers);
	free(copy);
	return buffer_take(&out);
fail:
	free(peers);
	free(copy);
	buffer_free(&out);
	return NULL;
}

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

static bool parse_ws_url(const char *text, struct ws_url *url)
{
	const char *rest;
	const char *authority_end;
	const char *host_start;
	const char *host_end;
	const char *port_start = NULL;
	size_t len;

	memset(url, 0, sizeof(*url));
	if (strncmp(text, "ws://", 5) == 0) {
		rest = text + 5;
		url->tls = false;
		strcpy(url->port, "80");
	} else if (strncmp(text, "wss://", 6) == 0) {
		rest = text + 6;
		url->tls = true;
		strcpy(url->port, "443");
	} else {
		return false;
	}
	authority_end = strpbrk(rest, "/?#");
	if (authority_end == NULL)
		authority_end = rest + strlen(rest);
	if (rest == authority_end || memchr(rest, '@', (size_t)(authority_end - rest)))
		return false;
	host_start = rest;
	if (*host_start == '[') {
		host_start++;
		host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
		if (host_end == NULL)
			return false;
		if (host_end + 1 < authority_end) {
			if (host_end[1] != ':') return false;
			port_start = host_end + 2;
		}
	} else {
		const char *colon = memchr(host_start, ':',
			(size_t)(authority_end - host_start));
		host_end = colon ? colon : authority_end;
		if (colon != NULL)
			port_start = colon + 1;
	}
	len = (size_t)(host_end - host_start);
	if (len == 0 || len >= sizeof(url->host))
		return false;
	memcpy(url->host, host_start, len);
	url->host[len] = '\0';
	if (port_start != NULL) {
		len = (size_t)(authority_end - port_start);
		if (len == 0 || len >= sizeof(url->port))
			return false;
		for (size_t i = 0; i < len; i++)
			if (!isdigit((unsigned char)port_start[i])) return false;
		memcpy(url->port, port_start, len);
		url->port[len] = '\0';
	}
	if (*authority_end == '#' || strchr(authority_end, '#') != NULL)
		return false;
	if (*authority_end == '\0') {
		strcpy(url->path, "/");
	} else {
		const char *fragment = strchr(authority_end, '#');
		len = fragment ? (size_t)(fragment - authority_end) : strlen(authority_end);
		if (len == 0 || len >= sizeof(url->path))
			return false;
		memcpy(url->path, authority_end, len);
		url->path[len] = '\0';
		if (url->path[0] == '?') {
			if (len + 1 >= sizeof(url->path)) return false;
			memmove(url->path + 1, url->path, len + 1);
			url->path[0] = '/';
		}
	}
	return true;
}

static int wait_fd(int fd, short events, int64_t deadline)
{
	struct pollfd pfd = {.fd = fd, .events = events};

	while (!stopping) {
		int64_t left = deadline - monotonic_ms();
		int result;
		if (left <= 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		result = poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left);
		if (result > 0) {
			if (pfd.revents & events)
				return 0;
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				errno = ECONNRESET;
				return -1;
			}
			continue;
		}
		if (result < 0 && errno != EINTR)
			return -1;
	}
	errno = EINTR;
	return -1;
}

static int connect_tcp(const char *host, const char *port, int timeout_ms)
{
	struct addrinfo hints = {0};
	struct addrinfo *addresses = NULL;
	struct addrinfo *address;
	int fd = -1;
	int saved = ECONNREFUSED;
	int result;
	int64_t deadline = monotonic_ms() + timeout_ms;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	result = getaddrinfo(host, port, &hints, &addresses);
	if (result != 0) {
		log_message("ERROR", "resolve %s:%s: %s", host, port,
			    gai_strerror(result));
		errno = EHOSTUNREACH;
		return -1;
	}
	for (address = addresses; address != NULL; address = address->ai_next) {
		int flags;
		int error = 0;
		socklen_t error_len = sizeof(error);

		fd = socket(address->ai_family, address->ai_socktype | SOCK_CLOEXEC,
			    address->ai_protocol);
		if (fd < 0) {
			saved = errno;
			continue;
		}
		flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			saved = errno;
			close(fd);
			fd = -1;
			continue;
		}
		result = connect(fd, address->ai_addr, address->ai_addrlen);
		if (result < 0 && errno != EINPROGRESS) {
			saved = errno;
			close(fd);
			fd = -1;
			continue;
		}
		if (result < 0 && wait_fd(fd, POLLOUT, deadline) < 0) {
			saved = errno;
			close(fd);
			fd = -1;
			continue;
		}
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 ||
		    error != 0) {
			saved = error ? error : errno;
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(addresses);
	if (fd < 0)
		errno = saved;
	return fd;
}

static void transport_close(struct transport *transport)
{
	if (transport->ssl != NULL) {
		SSL_shutdown(transport->ssl);
		SSL_free(transport->ssl);
	}
	if (transport->ctx != NULL)
		SSL_CTX_free(transport->ctx);
	if (transport->fd >= 0)
		close(transport->fd);
	memset(transport, 0, sizeof(*transport));
	transport->fd = -1;
}

static bool transport_connect(struct transport *transport,
			      const struct ws_url *url)
{
	int64_t deadline = monotonic_ms() + 10000;

	memset(transport, 0, sizeof(*transport));
	transport->fd = -1;
	transport->fd = connect_tcp(url->host, url->port, 10000);
	if (transport->fd < 0)
		return false;
	transport->tls = url->tls;
	transport->want_events = POLLIN;
	if (!url->tls)
		return true;
	transport->ctx = SSL_CTX_new(TLS_client_method());
	if (transport->ctx == NULL)
		goto fail;
	SSL_CTX_set_verify(transport->ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(transport->ctx) != 1 ||
	    SSL_CTX_set_min_proto_version(transport->ctx, TLS1_2_VERSION) != 1)
		goto fail;
	transport->ssl = SSL_new(transport->ctx);
	if (transport->ssl == NULL)
		goto fail;
	if (SSL_set_tlsext_host_name(transport->ssl, url->host) != 1)
		goto fail;
	{
		unsigned char ip[sizeof(struct in6_addr)];
		X509_VERIFY_PARAM *param = SSL_get0_param(transport->ssl);
		if (inet_pton(AF_INET, url->host, ip) == 1 ||
		    inet_pton(AF_INET6, url->host, ip) == 1) {
			if (X509_VERIFY_PARAM_set1_ip_asc(param, url->host) != 1)
				goto fail;
		} else {
			X509_VERIFY_PARAM_set_hostflags(param,
				X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
			if (X509_VERIFY_PARAM_set1_host(param, url->host, 0) != 1)
				goto fail;
		}
	}
	if (SSL_set_fd(transport->ssl, transport->fd) != 1)
		goto fail;
	while (!stopping) {
		int result = SSL_connect(transport->ssl);
		int error;
		if (result == 1)
			return true;
		error = SSL_get_error(transport->ssl, result);
		if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
			goto fail;
		if (wait_fd(transport->fd,
			    error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
			    deadline) < 0)
			goto fail;
	}
fail:
	transport_close(transport);
	return false;
}

/* Returns bytes, 0 on EOF, -1 on error, -2 when the nonblocking fd is busy. */
static ssize_t transport_read(struct transport *transport, void *data,
			      size_t size)
{
	ssize_t result;

	if (!transport->tls) {
		do {
			result = read(transport->fd, data, size);
		} while (result < 0 && errno == EINTR && !stopping);
		if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			transport->want_events = POLLIN;
			return -2;
		}
		return result;
	}
	result = SSL_read(transport->ssl, data,
			  size > INT_MAX ? INT_MAX : (int)size);
	if (result > 0)
		return result;
	{
		int error = SSL_get_error(transport->ssl, (int)result);
		if (error == SSL_ERROR_ZERO_RETURN)
			return 0;
		if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
			transport->want_events = error == SSL_ERROR_WANT_READ ?
				POLLIN : POLLOUT;
			return -2;
		}
	}
	return -1;
}

static ssize_t transport_write(struct transport *transport, const void *data,
			       size_t size)
{
	ssize_t result;

	if (!transport->tls) {
		result = write(transport->fd, data, size);
		if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			transport->want_events = POLLOUT;
			return -2;
		}
		return result;
	}
	result = SSL_write(transport->ssl, data,
			   size > INT_MAX ? INT_MAX : (int)size);
	if (result > 0)
		return result;
	{
		int error = SSL_get_error(transport->ssl, (int)result);
		if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
			transport->want_events = error == SSL_ERROR_WANT_READ ?
				POLLIN : POLLOUT;
			return -2;
		}
	}
	return -1;
}

static bool transport_write_all(struct transport *transport, const void *data,
				size_t size, int timeout_ms)
{
	const unsigned char *cursor = data;
	int64_t deadline = monotonic_ms() + timeout_ms;

	while (size > 0 && !stopping) {
		ssize_t written = transport_write(transport, cursor, size);
		if (written > 0) {
			cursor += written;
			size -= (size_t)written;
			continue;
		}
		if (written != -2 ||
		    wait_fd(transport->fd, transport->want_events, deadline) < 0)
			return false;
	}
	return size == 0;
}

static char *base64_encode(const unsigned char *data, size_t len)
{
	size_t size = 4 * ((len + 2) / 3) + 1;
	char *out = malloc(size);
	int result;

	if (out == NULL || len > INT_MAX) {
		free(out);
		return NULL;
	}
	result = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
	if (result < 0) {
		free(out);
		return NULL;
	}
	out[result] = '\0';
	return out;
}

static char *websocket_accept(const char *key)
{
	static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	char *accept = NULL;

	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, key, strlen(key)) != 1 ||
	    EVP_DigestUpdate(ctx, guid, sizeof(guid) - 1) != 1 ||
	    EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1)
		goto out;
	accept = base64_encode(digest, digest_len);
out:
	EVP_MD_CTX_free(ctx);
	return accept;
}

static bool websocket_handshake(struct transport *transport,
				const struct ws_url *url,
				const struct config *config)
{
	unsigned char nonce[16];
	char *key = NULL;
	char *expected = NULL;
	char host_header[300];
	struct buffer request = {0};
	struct buffer response = {0};
	char *copy = NULL;
	char *save = NULL;
	char *line;
	char accept[128] = "";
	bool status_ok = false;
	bool result = false;
	int64_t deadline = monotonic_ms() + 10000;

	if (RAND_bytes(nonce, sizeof(nonce)) != 1)
		goto out;
	key = base64_encode(nonce, sizeof(nonce));
	expected = key ? websocket_accept(key) : NULL;
	if (key == NULL || expected == NULL)
		goto out;
	if (strchr(url->host, ':'))
		snprintf(host_header, sizeof(host_header), "[%s]:%s", url->host,
			 url->port);
	else
		snprintf(host_header, sizeof(host_header), "%s:%s", url->host,
			 url->port);
	if (!buffer_addf(&request,
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\nUser-Agent: opennhrp-agent/%s\r\n"
		"X-Node-ID: %s\r\nX-Node-Type: %s\r\nX-Auth-Token: %s\r\n\r\n",
		url->path, host_header, key, AGENT_VERSION, config->node_id,
		config->node_type, config->token) ||
	    !transport_write_all(transport, request.data, request.len, 10000))
		goto out;
	while (response.len < 65536 && !stopping) {
		char c;
		ssize_t got = transport_read(transport, &c, 1);
		if (got == 1) {
			if (!buffer_addn(&response, &c, 1)) goto out;
			if (response.len >= 4 &&
			    memcmp(response.data + response.len - 4, "\r\n\r\n", 4) == 0)
				break;
			continue;
		}
		if (got != -2 ||
		    wait_fd(transport->fd, transport->want_events, deadline) < 0)
			goto out;
	}
	if (response.len < 4 ||
	    memcmp(response.data + response.len - 4, "\r\n\r\n", 4) != 0)
		goto out;
	copy = strdup(response.data);
	if (copy == NULL)
		goto out;
	line = strtok_r(copy, "\r\n", &save);
	if (line != NULL && strstr(line, " 101 ") != NULL)
		status_ok = true;
	while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
		char *colon = strchr(line, ':');
		char *value;
		if (colon == NULL) continue;
		*colon = '\0';
		value = trim(colon + 1);
		if (strcasecmp(trim(line), "Sec-WebSocket-Accept") == 0)
			peer_field(accept, sizeof(accept), value);
	}
	result = status_ok && strcmp(accept, expected) == 0;
out:
	free(copy);
	free(key);
	free(expected);
	buffer_free(&request);
	buffer_free(&response);
	return result;
}

static bool ws_send_frame(struct websocket *ws, unsigned int opcode,
			  const void *payload, size_t payload_len)
{
	struct buffer frame = {0};
	unsigned char header[14];
	unsigned char mask[4];
	size_t header_len = 0;
	const unsigned char *input = payload;
	bool result = false;

	if (payload_len > MAX_WS_MESSAGE || RAND_bytes(mask, sizeof(mask)) != 1)
		return false;
	header[header_len++] = 0x80U | (unsigned char)(opcode & 0x0fU);
	if (payload_len <= 125) {
		header[header_len++] = 0x80U | (unsigned char)payload_len;
	} else if (payload_len <= 65535) {
		header[header_len++] = 0x80U | 126U;
		header[header_len++] = (unsigned char)(payload_len >> 8);
		header[header_len++] = (unsigned char)payload_len;
	} else {
		header[header_len++] = 0x80U | 127U;
		for (int shift = 56; shift >= 0; shift -= 8)
			header[header_len++] = (unsigned char)((uint64_t)payload_len >> shift);
	}
	memcpy(header + header_len, mask, sizeof(mask));
	header_len += sizeof(mask);
	if (!buffer_addn(&frame, header, header_len) ||
	    !buffer_reserve(&frame, payload_len))
		goto out;
	for (size_t i = 0; i < payload_len; i++)
		frame.data[frame.len + i] = (char)(input[i] ^ mask[i % 4]);
	frame.len += payload_len;
	frame.data[frame.len] = '\0';
	result = transport_write_all(&ws->transport, frame.data, frame.len, 5000);
out:
	buffer_free(&frame);
	return result;
}

static bool ws_send_text(struct websocket *ws, const char *text)
{
	return ws_send_frame(ws, 1, text, strlen(text));
}

static int ws_process_frames(struct websocket *ws)
{
	size_t offset = 0;

	while (ws->input.len - offset >= 2) {
		const unsigned char *data = (unsigned char *)ws->input.data + offset;
		bool fin = (data[0] & 0x80U) != 0;
		unsigned int opcode = data[0] & 0x0fU;
		bool masked = (data[1] & 0x80U) != 0;
		uint64_t payload_len = data[1] & 0x7fU;
		size_t header_len = 2;
		const unsigned char *payload;

		if ((data[0] & 0x70U) != 0 || masked)
			return -1;
		if (payload_len == 126) {
			if (ws->input.len - offset < 4) break;
			payload_len = ((uint64_t)data[2] << 8) | data[3];
			header_len = 4;
		} else if (payload_len == 127) {
			if (ws->input.len - offset < 10) break;
			if (data[2] & 0x80U) return -1;
			payload_len = 0;
			for (int i = 2; i < 10; i++)
				payload_len = (payload_len << 8) | data[i];
			header_len = 10;
		}
		if (payload_len > MAX_WS_MESSAGE ||
		    payload_len > SIZE_MAX - header_len)
			return -1;
		if (ws->input.len - offset < header_len + (size_t)payload_len)
			break;
		payload = data + header_len;
		if (opcode >= 8) {
			if (!fin || payload_len > 125) return -1;
			if (opcode == 8) {
				(void)ws_send_frame(ws, 8, payload, (size_t)payload_len);
				return -1;
			}
			if (opcode == 9 &&
			    !ws_send_frame(ws, 10, payload, (size_t)payload_len))
				return -1;
			if (opcode != 9 && opcode != 10)
				return -1;
		} else if (opcode == 1 || opcode == 2) {
			if (ws->fragment_opcode != 0) return -1;
			ws->fragment_opcode = opcode;
			buffer_reset(&ws->message);
			if (payload_len > 0 && !buffer_addn(&ws->message, payload,
							(size_t)payload_len)) return -1;
			if (fin) {
				if (opcode == 1 &&
				    ((ws->message.len > 0 &&
				      memchr(ws->message.data, '\0', ws->message.len) != NULL) ||
				     !ws->on_message(ws->opaque,
						     ws->message.data ? ws->message.data : "",
						     ws->message.len))) return -1;
				ws->fragment_opcode = 0;
			}
		} else if (opcode == 0) {
			if (ws->fragment_opcode == 0 ||
			    ws->message.len + payload_len > MAX_WS_MESSAGE ||
			    !buffer_addn(&ws->message, payload, (size_t)payload_len))
				return -1;
			if (fin) {
				if (ws->fragment_opcode == 1 &&
				    ((ws->message.len > 0 &&
				      memchr(ws->message.data, '\0', ws->message.len) != NULL) ||
				     !ws->on_message(ws->opaque,
						     ws->message.data ? ws->message.data : "",
						     ws->message.len))) return -1;
				ws->fragment_opcode = 0;
			}
		} else {
			return -1;
		}
		offset += header_len + (size_t)payload_len;
	}
	if (offset > 0) {
		memmove(ws->input.data, ws->input.data + offset, ws->input.len - offset);
		ws->input.len -= offset;
		ws->input.data[ws->input.len] = '\0';
	}
	return 0;
}

/* Drains all currently available transport data. */
static int ws_read_available(struct websocket *ws)
{
	unsigned char data[8192];

	while (!stopping) {
		ssize_t got = transport_read(&ws->transport, data, sizeof(data));
		if (got == -2)
			return ws_process_frames(ws);
		if (got <= 0)
			return -1;
		if (ws->input.len + (size_t)got > MAX_WS_MESSAGE + 14 ||
		    !buffer_addn(&ws->input, data, (size_t)got) ||
		    ws_process_frames(ws) < 0)
			return -1;
		if (ws->transport.tls && SSL_pending(ws->transport.ssl) == 0)
			continue;
	}
	return -1;
}

static bool ws_connect(struct websocket *ws, const struct config *config,
		       ws_message_fn on_message, void *opaque)
{
	struct ws_url url;

	memset(ws, 0, sizeof(*ws));
	ws->transport.fd = -1;
	ws->on_message = on_message;
	ws->opaque = opaque;
	if (!parse_ws_url(config->server, &url) ||
	    !transport_connect(&ws->transport, &url) ||
	    !websocket_handshake(&ws->transport, &url, config)) {
		transport_close(&ws->transport);
		return false;
	}
	return true;
}

static void ws_close(struct websocket *ws)
{
	if (ws->transport.fd >= 0)
		(void)ws_send_frame(ws, 8, "", 0);
	transport_close(&ws->transport);
	buffer_free(&ws->input);
	buffer_free(&ws->message);
}

static int connect_unix(const char *path, int timeout_ms)
{
	struct sockaddr_un address = {0};
	int fd;
	int flags;
	int result;
	int error = 0;
	socklen_t error_len = sizeof(error);

	if (strlen(path) >= sizeof(address.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		goto fail;
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, path);
	result = connect(fd, (struct sockaddr *)&address, sizeof(address));
	if (result < 0 && errno != EINPROGRESS)
		goto fail;
	if (result < 0 && wait_fd(fd, POLLOUT, monotonic_ms() + timeout_ms) < 0)
		goto fail;
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 ||
	    error != 0) {
		errno = error ? error : errno;
		goto fail;
	}
	return fd;
fail:
	close(fd);
	return -1;
}

static bool fd_write_all(int fd, const void *data, size_t size,
			 int64_t deadline)
{
	const unsigned char *cursor = data;
	while (size > 0 && !stopping) {
		ssize_t written = write(fd, cursor, size);
		if (written > 0) {
			cursor += written;
			size -= (size_t)written;
		} else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (wait_fd(fd, POLLOUT, deadline) < 0) return false;
		} else if (written < 0 && errno == EINTR) {
			continue;
		} else {
			return false;
		}
	}
	return size == 0;
}

static bool socket_command(const char *path, const char *command,
			   int timeout_ms, char **output, char **error_text)
{
	int fd = -1;
	struct buffer request = {0};
	struct buffer response = {0};
	int64_t deadline = monotonic_ms() + timeout_ms;
	bool result = false;

	*output = NULL;
	*error_text = NULL;
	fd = connect_unix(path, timeout_ms);
	if (fd < 0) {
		if (asprintf(error_text, "connect %s: %s", path, strerror(errno)) < 0)
			*error_text = NULL;
		goto out;
	}
	if (!buffer_add(&request, command) ||
	    ((request.len == 0 || request.data[request.len - 1] != '\n') &&
	     !buffer_addn(&request, "\n", 1))) {
		*error_text = strdup("out of memory");
		goto out;
	}
	if (!fd_write_all(fd, request.data, request.len, deadline) ||
	    shutdown(fd, SHUT_WR) < 0) {
		if (asprintf(error_text, "write %s: %s", path, strerror(errno)) < 0)
			*error_text = NULL;
		goto out;
	}
	while (!stopping) {
		char data[8192];
		ssize_t got = read(fd, data, sizeof(data));
		if (got > 0) {
			if (response.len + (size_t)got > MAX_WS_MESSAGE ||
			    !buffer_addn(&response, data, (size_t)got)) {
				*error_text = strdup("socket response exceeds 4 MiB");
				goto out;
			}
			continue;
		}
		if (got == 0) {
			*output = buffer_take(&response);
			result = *output != NULL;
			goto out;
		}
		if (errno == EINTR) continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (wait_fd(fd, POLLIN, deadline) == 0) continue;
		}
		if (asprintf(error_text, "read %s: %s", path, strerror(errno)) < 0)
			*error_text = NULL;
		goto out;
	}
	*error_text = strdup("interrupted");
out:
	if (fd >= 0) close(fd);
	buffer_free(&request);
	buffer_free(&response);
	if (!result && *error_text == NULL)
		*error_text = strdup("operation failed");
	return result;
}

static bool read_file_limit(const char *path, char **output, char **error_text)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	struct buffer data = {0};
	bool result = false;

	*output = NULL;
	*error_text = NULL;
	if (fd < 0) {
		if (asprintf(error_text, "open %s: %s", path, strerror(errno)) < 0)
			*error_text = NULL;
		return false;
	}
	while (true) {
		char chunk[8192];
		ssize_t got = read(fd, chunk, sizeof(chunk));
		if (got > 0) {
			if (data.len + (size_t)got > MAX_WS_MESSAGE ||
			    !buffer_addn(&data, chunk, (size_t)got)) {
				*error_text = strdup("file exceeds 4 MiB");
				goto out;
			}
		} else if (got == 0) {
			*output = buffer_take(&data);
			result = *output != NULL;
			goto out;
		} else if (errno != EINTR) {
			if (asprintf(error_text, "read %s: %s", path,
				     strerror(errno)) < 0) *error_text = NULL;
			goto out;
		}
	}
out:
	close(fd);
	buffer_free(&data);
	if (!result && *error_text == NULL)
		*error_text = strdup("operation failed");
	return result;
}

static bool atomic_replace(const char *path, const char *data, size_t len,
			   mode_t mode, char **error_text)
{
	char *path_copy = strdup(path);
	char *slash;
	char *dir;
	char *base;
	char *temporary = NULL;
	int fd = -1;
	int dir_fd = -1;
	bool result = false;

	if (path_copy == NULL) goto memory_error;
	slash = strrchr(path_copy, '/');
	if (slash == NULL) {
		dir = ".";
		base = path_copy;
	} else {
		*slash = '\0';
		dir = path_copy[0] ? path_copy : "/";
		base = slash + 1;
	}
	if (*base == '\0' || asprintf(&temporary, "%s/.%s.tmp-XXXXXX", dir, base) < 0)
		goto memory_error;
	fd = mkstemp(temporary);
	if (fd < 0)
		goto system_error;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 || fchmod(fd, mode) < 0 ||
	    !fd_write_all(fd, data, len, monotonic_ms() + 10000) || fsync(fd) < 0)
		goto system_error;
	if (close(fd) < 0) {
		fd = -1;
		goto system_error;
	}
	fd = -1;
	if (rename(temporary, path) < 0)
		goto system_error;
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd >= 0) {
		(void)fsync(dir_fd);
		close(dir_fd);
		dir_fd = -1;
	}
	result = true;
	goto out;
memory_error:
	*error_text = strdup("out of memory");
	goto out;
system_error:
	if (asprintf(error_text, "write %s: %s", path, strerror(errno)) < 0)
		*error_text = NULL;
out:
	if (fd >= 0) close(fd);
	if (dir_fd >= 0) close(dir_fd);
	if (!result && temporary != NULL) unlink(temporary);
	free(temporary);
	free(path_copy);
	return result;
}

static bool write_config_atomic(const char *path, const char *data, size_t len,
				char **error_text)
{
	struct stat info;
	mode_t mode = 0644;
	char *old = NULL;
	char *read_error = NULL;
	char *backup = NULL;
	bool exists = stat(path, &info) == 0;
	bool result = false;

	*error_text = NULL;
	if (exists) {
		mode = info.st_mode & 0777;
		if (!read_file_limit(path, &old, &read_error)) {
			*error_text = read_error;
			return false;
		}
		if (asprintf(&backup, "%s.bak", path) < 0) {
			*error_text = strdup("out of memory");
			goto out;
		}
		if (!atomic_replace(backup, old, strlen(old), mode, error_text))
			goto out;
	} else if (errno != ENOENT) {
		if (asprintf(error_text, "stat %s: %s", path, strerror(errno)) < 0)
			*error_text = NULL;
		goto out;
	}
	result = atomic_replace(path, data, len, mode, error_text);
out:
	free(old);
	free(backup);
	return result;
}

static bool run_process(char *const argv[], const char *stdin_data,
			char **output, char **error_text)
{
	int output_pipe[2] = {-1, -1};
	int error_pipe[2] = {-1, -1};
	int input_pipe[2] = {-1, -1};
	pid_t pid;
	struct buffer data = {0}, errors = {0};
	int status = 0;
	bool result = false;

	*output = NULL;
	*error_text = NULL;
	if (pipe2(output_pipe, O_CLOEXEC) < 0 ||
	    (stdin_data == NULL && pipe2(error_pipe, O_CLOEXEC) < 0) ||
	    (stdin_data != NULL && pipe2(input_pipe, O_CLOEXEC) < 0))
		goto system_error;
	pid = fork();
	if (pid < 0)
		goto system_error;
	if (pid == 0) {
		int null_fd;
		dup2(output_pipe[1], STDOUT_FILENO);
		dup2(stdin_data != NULL ? output_pipe[1] : error_pipe[1], STDERR_FILENO);
		if (stdin_data != NULL)
			dup2(input_pipe[0], STDIN_FILENO);
		else {
			null_fd = open("/dev/null", O_RDONLY);
			if (null_fd >= 0) {
				dup2(null_fd, STDIN_FILENO);
				close(null_fd);
			}
		}
		close(output_pipe[0]);
		close(output_pipe[1]);
		if (input_pipe[0] >= 0) close(input_pipe[0]);
		if (input_pipe[1] >= 0) close(input_pipe[1]);
		if (error_pipe[0] >= 0) close(error_pipe[0]);
		if (error_pipe[1] >= 0) close(error_pipe[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(output_pipe[1]);
	output_pipe[1] = -1;
	if (error_pipe[1] >= 0) close(error_pipe[1]);
	error_pipe[1] = -1;
	if (input_pipe[0] >= 0) {
		close(input_pipe[0]);
		input_pipe[0] = -1;
		if (!fd_write_all(input_pipe[1], stdin_data, strlen(stdin_data),
				  monotonic_ms() + 5000) ||
		    !fd_write_all(input_pipe[1], "\n", 1, monotonic_ms() + 5000)) {
			close(input_pipe[1]);
			input_pipe[1] = -1;
			kill(pid, SIGTERM);
			(void)waitpid(pid, &status, 0);
			goto system_error;
		}
		close(input_pipe[1]);
		input_pipe[1] = -1;
	}
	while (output_pipe[0] >= 0 || error_pipe[0] >= 0) {
		struct pollfd fds[2] = {{.fd = output_pipe[0], .events = POLLIN},
			{.fd = error_pipe[0], .events = POLLIN}};
		if (poll(fds, 2, -1) < 0) {
			if (errno == EINTR) continue;
			goto child_error;
		}
		for (int i = 0; i < 2; i++) {
			char chunk[8192];
			struct buffer *dest = i == 0 ? &data : &errors;
			int *fd = i == 0 ? &output_pipe[0] : &error_pipe[0];
			if (!fds[i].revents) continue;
			ssize_t got = read(*fd, chunk, sizeof(chunk));
			if (got > 0) {
				if (data.len + errors.len + (size_t)got > MAX_WS_MESSAGE ||
				    !buffer_addn(dest, chunk, (size_t)got)) {
					*error_text = strdup("command output exceeds 4 MiB");
					goto child_error;
				}
			} else if (got == 0) {
				close(*fd);
				*fd = -1;
			} else if (errno != EINTR) goto child_error;
		}
	}
	if (waitpid(pid, &status, 0) < 0)
		goto system_error;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		*output = buffer_take(&data);
		result = *output != NULL;
	} else {
		int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		if (asprintf(error_text, "%s exited with status %d: %s", argv[0],
			     code, stdin_data != NULL ? (data.data ? data.data : "") :
			     (errors.data ? errors.data : "")) < 0)
			*error_text = NULL;
	}
	goto out;
child_error:
	kill(pid, SIGTERM);
	(void)waitpid(pid, &status, 0);
	if (*error_text != NULL) goto out;
system_error:
	if (asprintf(error_text, "%s: %s", argv && argv[0] ? argv[0] : "exec",
		     strerror(errno)) < 0)
		*error_text = NULL;
out:
	for (size_t i = 0; i < 2; i++) {
		if (output_pipe[i] >= 0) close(output_pipe[i]);
		if (input_pipe[i] >= 0) close(input_pipe[i]);
		if (error_pipe[i] >= 0) close(error_pipe[i]);
	}
	buffer_free(&data);
	buffer_free(&errors);
	if (!result && *error_text == NULL)
		*error_text = strdup("command failed");
	return result;
}

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

static void command_request_free(struct command_request *request)
{
	if (request == NULL) return;
	free(request->id);
	free(request->target);
	free(request->command);
	for (size_t i = 0; i < request->argc; i++) free(request->args[i]);
	free(request->args);
	free(request);
}

static struct command_request *parse_command_request(struct agent *agent,
					     const struct json_doc *doc,
					     int root)
{
	int payload = object_get(doc, root, "payload");
	int args;
	struct command_request *request;
	int i;

	if (payload < 0 || doc->tokens[payload].type != JSMN_OBJECT)
		return NULL;
	request = calloc(1, sizeof(*request));
	if (request == NULL)
		return NULL;
	request->agent = agent;
	request->generation = agent->generation;
	request->id = token_string(doc, object_get(doc, root, "id"));
	request->target = token_string(doc, object_get(doc, payload, "target_socket"));
	request->command = token_string(doc, object_get(doc, payload, "command"));
	if (request->id == NULL || request->target == NULL) goto fail;
	if (request->command == NULL) request->command = strdup("");
	if (request->command == NULL) goto fail;
	args = object_get(doc, payload, "args");
	if (args >= 0) {
		if (doc->tokens[args].type != JSMN_ARRAY) goto fail;
		for (i = args + 1; i < doc->count; i++) {
			char *arg;
			char **grown;
			if (doc->tokens[i].start >= doc->tokens[args].end) break;
			if (doc->tokens[i].parent != args) continue;
			if (request->argc >= MAX_COMMAND_ARGS ||
			    doc->tokens[i].type != JSMN_STRING) goto fail;
			arg = token_string(doc, i);
			if (arg == NULL) goto fail;
			grown = realloc(request->args,
					(request->argc + 1) * sizeof(*request->args));
			if (grown == NULL) {
				free(arg);
				goto fail;
			}
			request->args = grown;
			request->args[request->argc++] = arg;
		}
	}
	return request;
fail:
	command_request_free(request);
	return NULL;
}

static void queue_response(struct agent *agent, struct command_response *response)
{
	pthread_mutex_lock(&agent->command_lock);
	if (agent->responses_tail != NULL)
		agent->responses_tail->next = response;
	else
		agent->responses_head = response;
	agent->responses_tail = response;
	pthread_mutex_unlock(&agent->command_lock);
}

static struct command_response *make_response(const struct command_request *request)
{
	struct command_response *response = calloc(1, sizeof(*response));
	if (response == NULL)
		return NULL;
	response->generation = request->generation;
	response->id = strdup(request->id);
	if (response->id == NULL) {
		free(response);
		return NULL;
	}
	return response;
}

static void response_error(struct command_response *response, const char *fmt, ...)
{
	va_list ap;
	char *text = NULL;

	va_start(ap, fmt);
	if (vasprintf(&text, fmt, ap) < 0)
		text = NULL;
	va_end(ap);
	free(response->text);
	response->text = text ? text : strdup("operation failed");
	response->success = false;
}

static void execute_command(const struct command_request *request,
			    struct command_response *response)
{
	const struct config *config = &request->agent->config;
	char *output = NULL;
	char *error_text = NULL;
	bool ok = false;

	if (strcmp(request->target, "opennhrp") == 0) {
		ok = socket_command(config->core_socket, request->command,
				    SOCKET_TIMEOUT_MS, &output, &error_text);
	} else if (strcmp(request->target, "opennhrp-ha") == 0) {
		if (strcmp(config->node_type, "hub") != 0) {
			error_text = strdup("HA socket is unavailable for spoke nodes");
		} else {
			ok = socket_command(config->ha_socket, request->command,
					    SOCKET_TIMEOUT_MS, &output, &error_text);
			if (ok && strncmp(request->command, "ha witness ", 11) == 0 &&
			    strncmp(output, "Status: ok\n", 11) != 0) {
				free(error_text);
				error_text = strdup(trim(output));
				free(output);
				output = NULL;
				ok = false;
			}
		}
	} else if (strcmp(request->target, "cli") == 0 ||
		   strcmp(request->target, "cli-stdin") == 0) {
		char **argv = calloc(request->argc + 2, sizeof(*argv));
		if (argv == NULL) {
			error_text = strdup("out of memory");
		} else {
			argv[0] = (char *)config->ctl_path;
			for (size_t i = 0; i < request->argc; i++)
				argv[i + 1] = request->args[i];
			ok = run_process(argv,
				strcmp(request->target, "cli-stdin") == 0 ?
				request->command : NULL,
				&output, &error_text);
			if (ok && strcmp(request->target, "cli") == 0) {
				char *stripped = trim(output);
				if (stripped != output)
					memmove(output, stripped, strlen(stripped) + 1);
			}
			free(argv);
		}
	} else if (strcmp(request->target, "cli-export-key") == 0) {
		char temporary[] = "/tmp/opennhrp-spoke-key-XXXXXX";
		int fd = mkstemp(temporary);
		if (fd < 0) {
			if (asprintf(&error_text, "create temporary file: %s",
				     strerror(errno)) < 0) error_text = NULL;
		} else {
			char *argv[] = {(char *)config->ctl_path, "ha", "key",
					"export-spoke", temporary, NULL};
			char *ignored = NULL;
			close(fd);
			unlink(temporary);
			ok = run_process(argv, NULL, &ignored, &error_text);
			free(ignored);
			if (ok) {
				ok = read_file_limit(temporary, &output, &error_text);
			}
			unlink(temporary);
		}
	} else if (strcmp(request->target, "fs") == 0) {
		if (strcmp(request->command, "read-config") == 0) {
			ok = read_file_limit(config->config_path, &output, &error_text);
		} else if (strcmp(request->command, "write-config") == 0 &&
			   request->argc > 0) {
			ok = write_config_atomic(config->config_path, request->args[0],
					 strlen(request->args[0]), &error_text);
			if (ok) output = strdup("");
		} else {
			error_text = strdup("unknown fs command");
		}
	} else {
		if (asprintf(&error_text, "unknown target socket: %s",
			     request->target) < 0) error_text = NULL;
	}
	response->success = ok;
	response->text = ok ? output : error_text;
	if (response->text == NULL)
		response->text = strdup(ok ? "" : "operation failed");
	if (ok)
		free(error_text);
	else
		free(output);
}

static void *command_worker(void *opaque)
{
	struct command_request *request = opaque;
	struct agent *agent = request->agent;
	struct command_response *response = make_response(request);

	if (response != NULL)
		execute_command(request, response);
	pthread_mutex_lock(&agent->command_lock);
	if (response != NULL) {
		if (agent->responses_tail != NULL)
			agent->responses_tail->next = response;
		else
			agent->responses_head = response;
		agent->responses_tail = response;
	}
	if (agent->active_commands > 0)
		agent->active_commands--;
	pthread_cond_broadcast(&agent->command_done);
	pthread_mutex_unlock(&agent->command_lock);
	command_request_free(request);
	return NULL;
}

static bool start_command(struct agent *agent, struct command_request *request)
{
	pthread_t thread;
	int error;

	pthread_mutex_lock(&agent->command_lock);
	if (agent->active_commands >= MAX_PENDING_COMMANDS) {
		pthread_mutex_unlock(&agent->command_lock);
		return false;
	}
	agent->active_commands++;
	pthread_mutex_unlock(&agent->command_lock);
	error = pthread_create(&thread, NULL, command_worker, request);
	if (error != 0) {
		pthread_mutex_lock(&agent->command_lock);
		agent->active_commands--;
		pthread_mutex_unlock(&agent->command_lock);
		return false;
	}
	pthread_detach(thread);
	return true;
}

static bool agent_on_message(void *opaque, const char *message, size_t len)
{
	struct agent *agent = opaque;
	struct json_doc doc;
	struct command_request *request;
	char *copy;
	int type;

	copy = malloc(len + 1);
	if (copy == NULL)
		return false;
	memcpy(copy, message, len);
	copy[len] = '\0';
	if (!json_parse(&doc, copy)) {
		free(copy);
		return true;
	}
	if (doc.tokens[0].type != JSMN_OBJECT) {
		json_doc_free(&doc);
		free(copy);
		return true;
	}
	type = object_get(&doc, 0, "type");
	if (!token_equal(&doc, type, "command_request")) {
		json_doc_free(&doc);
		free(copy);
		return true;
	}
	request = parse_command_request(agent, &doc, 0);
	json_doc_free(&doc);
	free(copy);
	if (request == NULL)
		return true;
	if (!start_command(agent, request)) {
		struct command_response *response = make_response(request);
		if (response != NULL) {
			response_error(response, "too many active commands");
			queue_response(agent, response);
		}
		command_request_free(request);
	}
	return true;
}

static void command_response_free(struct command_response *response)
{
	if (response == NULL) return;
	free(response->id);
	free(response->text);
	free(response);
}

static void free_command_responses(struct agent *agent)
{
	while (agent->responses_head != NULL) {
		struct command_response *response = agent->responses_head;
		agent->responses_head = response->next;
		command_response_free(response);
	}
	agent->responses_tail = NULL;
}

static bool flush_command_responses(struct agent *agent)
{
	while (true) {
		struct command_response *response;
		struct buffer json = {0};
		char when[40];
		bool first = true;
		bool sent;

		pthread_mutex_lock(&agent->command_lock);
		response = agent->responses_head;
		if (response != NULL) {
			agent->responses_head = response->next;
			if (agent->responses_head == NULL)
				agent->responses_tail = NULL;
		}
		pthread_mutex_unlock(&agent->command_lock);
		if (response == NULL)
			return true;
		if (response->generation != agent->generation) {
			command_response_free(response);
			continue;
		}
		timestamp(when);
		if (!buffer_addn(&json, "{", 1) ||
		    !add_field_string(&json, "id", response->id, &first) ||
		    !add_field_string(&json, "type", "command_response", &first) ||
		    !add_field_string(&json, "timestamp", when, &first) ||
		    !buffer_add(&json, ",\"payload\":{") ||
		    !buffer_addf(&json, "\"success\":%s", response->success ? "true" : "false") ||
		    !buffer_add(&json, response->success ? ",\"raw_text\":" : ",\"error\":") ||
		    !json_quote(&json, response->text) ||
		    !buffer_add(&json, "}}")) {
			buffer_free(&json);
			command_response_free(response);
			return false;
		}
		sent = ws_send_text(&agent->websocket, json.data);
		buffer_free(&json);
		command_response_free(response);
		if (!sent)
			return false;
	}
}

static bool executable_in_path(const char *name)
{
	const char *path = env_or("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
	char *copy = strdup(path);
	char *cursor;
	char *dir;
	bool found = false;

	if (copy == NULL) return false;
	cursor = copy;
	while ((dir = strsep(&cursor, ":")) != NULL) {
		char candidate[PATH_MAX];
		if (*dir == '\0') dir = ".";
		if (snprintf(candidate, sizeof(candidate), "%s/%s", dir, name) <
		    (int)sizeof(candidate) && access(candidate, X_OK) == 0) {
			found = true;
			break;
		}
	}
	free(copy);
	return found;
}

static bool start_log_reader(struct log_reader *reader)
{
	char *journal_argv[] = {"journalctl", "-f", "-n", "30", "--no-pager", NULL};
	char *logread_argv[] = {"logread", "-f", NULL};
	char *tail_argv[] = {"tail", "-n", "30", "-F", NULL, NULL};
	char **argv = NULL;
	const char *files[] = {"/var/log/syslog", "/var/log/messages",
		"/var/log/opennhrp.log", "/var/log/opennhrp-ha.log"};
	int pipe_fd[2] = {-1, -1};
	pid_t pid;

	if (reader->pid > 0 || monotonic_ms() < reader->retry_at)
		return reader->pid > 0;
	if (executable_in_path("journalctl")) {
		argv = journal_argv;
	} else if (executable_in_path("logread")) {
		argv = logread_argv;
	} else if (executable_in_path("tail")) {
		for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
			if (access(files[i], R_OK) == 0) {
				tail_argv[4] = (char *)files[i];
				argv = tail_argv;
				break;
			}
		}
	}
	if (argv == NULL) {
		reader->retry_at = monotonic_ms() + 5000;
		return false;
	}
	if (pipe2(pipe_fd, O_CLOEXEC | O_NONBLOCK) < 0)
		goto fail;
	pid = fork();
	if (pid < 0)
		goto fail;
	if (pid == 0) {
		int null_fd = open("/dev/null", O_WRONLY);
		fcntl(pipe_fd[1], F_SETFL, fcntl(pipe_fd[1], F_GETFL, 0) & ~O_NONBLOCK);
		dup2(pipe_fd[1], STDOUT_FILENO);
		if (null_fd >= 0) {
			dup2(null_fd, STDERR_FILENO);
			close(null_fd);
		}
		close(pipe_fd[0]);
		close(pipe_fd[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(pipe_fd[1]);
	reader->pid = pid;
	reader->fd = pipe_fd[0];
	reader->retry_at = 0;
	log_message("INFO", "log tailing active via %s", argv[0]);
	return true;
fail:
	if (pipe_fd[0] >= 0) close(pipe_fd[0]);
	if (pipe_fd[1] >= 0) close(pipe_fd[1]);
	reader->retry_at = monotonic_ms() + 5000;
	return false;
}

static void stop_log_reader(struct log_reader *reader)
{
	if (reader->fd >= 0) close(reader->fd);
	if (reader->pid > 0) {
		kill(reader->pid, SIGTERM);
		(void)waitpid(reader->pid, NULL, 0);
	}
	reader->fd = -1;
	reader->pid = 0;
	buffer_free(&reader->partial);
}

static void check_log_reader(struct log_reader *reader)
{
	if (reader->pid > 0) {
		int status;
		pid_t result = waitpid(reader->pid, &status, WNOHANG);
		if (result == reader->pid) {
			if (reader->fd >= 0) close(reader->fd);
			reader->fd = -1;
			reader->pid = 0;
			reader->retry_at = monotonic_ms() + 2000;
		}
	}
	if (reader->pid == 0)
		(void)start_log_reader(reader);
}

static char *lowercase_copy(const char *text)
{
	char *copy = strdup(text);
	if (copy != NULL)
		for (char *p = copy; *p; p++) *p = (char)tolower((unsigned char)*p);
	return copy;
}

static const char *strip_log_prefix(const char *line, const char *lower)
{
	const char *marker = strstr(lower, "opennhrp");
	const char *colon;

	if (marker == NULL || (size_t)(marker - lower) > 160)
		return line;
	colon = strchr(marker, ':');
	if (colon == NULL || (size_t)(colon - marker) > 64)
		return line;
	colon++;
	while (*colon && isspace((unsigned char)*colon)) colon++;
	return line + (colon - lower);
}

static void enqueue_log_json(struct agent *agent, char *json)
{
	struct queued_log *entry = calloc(1, sizeof(*entry));
	if (entry == NULL) {
		free(json);
		return;
	}
	entry->json = json;
	if (agent->logs_tail != NULL)
		agent->logs_tail->next = entry;
	else
		agent->logs_head = entry;
	agent->logs_tail = entry;
	agent->logs_count++;
	if (agent->logs_count > 1000) {
		struct queued_log *old = agent->logs_head;
		agent->logs_head = old->next;
		if (agent->logs_head == NULL) agent->logs_tail = NULL;
		agent->logs_count--;
		free(old->json);
		free(old);
	}
}

static void process_log_line(struct agent *agent, char *line)
{
	char *clean = trim(line);
	char *lower;
	const char *source;
	const char *level = "INFO";
	const char *message;
	struct buffer json = {0};
	char when[40];
	bool first = true;
	char id[64];

	if (*clean == '\0') return;
	lower = lowercase_copy(clean);
	if (lower == NULL) return;
	if (strstr(lower, "opennhrp-ha") || strstr(lower, "opennhrp_ha") ||
	    strstr(lower, "opennhrp ha"))
		source = "ha";
	else if (strstr(lower, "opennhrp") || strstr(lower, "nhrp"))
		source = "core";
	else {
		free(lower);
		return;
	}
	if (strstr(lower, "err") || strstr(lower, "fatal") ||
	    strstr(lower, "failed") || strstr(lower, "panic"))
		level = "ERROR";
	else if (strstr(lower, "warn"))
		level = "WARN";
	else if (strstr(lower, "debug") || strstr(lower, "trace"))
		level = "DEBUG";
	message = strip_log_prefix(clean, lower);
	timestamp(when);
	snprintf(id, sizeof(id), "log-%llu", (unsigned long long)realtime_ns());
	if (!buffer_addn(&json, "{", 1) ||
	    !add_field_string(&json, "id", id, &first) ||
	    !add_field_string(&json, "type", "log_stream", &first) ||
	    !add_field_string(&json, "timestamp", when, &first) ||
	    !buffer_add(&json, ",\"payload\":{") ||
	    !buffer_add(&json, "\"node_id\":") || !json_quote(&json, agent->config.node_id) ||
	    !buffer_add(&json, ",\"source\":") || !json_quote(&json, source) ||
	    !buffer_add(&json, ",\"level\":") || !json_quote(&json, level) ||
	    !buffer_add(&json, ",\"message\":") || !json_quote(&json, message) ||
	    !buffer_add(&json, ",\"timestamp\":") || !json_quote(&json, when) ||
	    !buffer_add(&json, "}}")) {
		buffer_free(&json);
	} else {
		enqueue_log_json(agent, buffer_take(&json));
	}
	free(lower);
}

static void read_logs(struct agent *agent)
{
	struct log_reader *reader = &agent->logs;
	char chunk[8192];

	check_log_reader(reader);
	if (reader->fd < 0) return;
	while (true) {
		ssize_t got = read(reader->fd, chunk, sizeof(chunk));
		if (got > 0) {
			if (reader->partial.len + (size_t)got > 65536) {
				buffer_reset(&reader->partial);
				continue;
			}
			if (!buffer_addn(&reader->partial, chunk, (size_t)got)) return;
			while (reader->partial.data != NULL) {
				char *newline = memchr(reader->partial.data, '\n', reader->partial.len);
				size_t consumed;
				if (newline == NULL) break;
				*newline = '\0';
				process_log_line(agent, reader->partial.data);
				consumed = (size_t)(newline - reader->partial.data) + 1;
				memmove(reader->partial.data,
					reader->partial.data + consumed,
					reader->partial.len - consumed);
				reader->partial.len -= consumed;
				reader->partial.data[reader->partial.len] = '\0';
			}
			continue;
		}
		if (got == 0) {
			(void)waitpid(reader->pid, NULL, 0);
			close(reader->fd);
			reader->fd = -1;
			reader->pid = 0;
			reader->retry_at = monotonic_ms() + 2000;
		}
		break;
	}
}

static bool flush_logs(struct agent *agent)
{
	while (agent->logs_head != NULL) {
		struct queued_log *entry = agent->logs_head;
		bool sent;
		agent->logs_head = entry->next;
		if (agent->logs_head == NULL) agent->logs_tail = NULL;
		agent->logs_count--;
		sent = ws_send_text(&agent->websocket, entry->json);
		free(entry->json);
		free(entry);
		if (!sent) return false;
	}
	return true;
}

static void free_logs(struct agent *agent)
{
	while (agent->logs_head != NULL) {
		struct queued_log *entry = agent->logs_head;
		agent->logs_head = entry->next;
		free(entry->json);
		free(entry);
	}
	agent->logs_tail = NULL;
	agent->logs_count = 0;
}

static char *build_heartbeat(struct agent *agent)
{
	struct cluster_result cluster = {0};
	char *cluster_raw = NULL;
	char *cluster_error = NULL;
	char *core_raw = NULL;
	char *core_error = NULL;
	char *peer_json = NULL;
	bool have_cluster = false;
	bool refreshed_core = false;
	bool first = true;
	struct buffer json = {0};
	char when[40];
	char id[64];
	const char *role = "unknown";
	const char *cluster_id = "";
	const char *member_id = "";
	const char *member_state = "";
	const char *primary = "";
	const char *leader = "";
	const char *advertised = "";
	const char *digest = "";
	const char *witness = "{}";
	uint64_t term = 0;
	uint64_t commit = 0;
	uint64_t revision = 0;
	bool network_health = false;
	bool service_available = false;
	int active_spokes = 0;
	int64_t now = monotonic_ms();

	if (strcmp(agent->config.node_type, "hub") == 0 &&
	    socket_command(agent->config.ha_socket,
			   "ha cluster show --format json\n", 2000,
			   &cluster_raw, &cluster_error)) {
		have_cluster = transform_cluster(cluster_raw, agent->config.node_id,
					 agent->config.state_dir, &cluster);
	}
	free(cluster_error);
	if (now - agent->last_core_refresh >= CORE_REFRESH_MS) {
		size_t count = 0;
		agent->last_core_refresh = now;
		refreshed_core = true;
		agent->core_available = socket_command(agent->config.core_socket,
			"show\n", 2000, &core_raw, &core_error);
		if (agent->core_available) {
			peer_json = parse_peers(core_raw, &count);
			if (peer_json == NULL)
				agent->core_available = false;
			else if (strcmp(agent->config.node_type, "spoke") == 0)
				agent->peer_count = count;
			else
				agent->spoke_count = count;
		}
	}
	free(core_error);
	if (have_cluster) {
		role = cluster.local_role;
		cluster_id = cluster.cluster_id;
		member_id = cluster.member_id;
		member_state = cluster.member_state;
		primary = cluster.primary;
		leader = cluster.leader;
		advertised = cluster.advertised_ip;
		digest = cluster.digest;
		witness = cluster.witness_json;
		term = cluster.term;
		commit = cluster.commit_index;
		revision = cluster.manifest_revision;
		network_health = cluster.network_health;
		service_available = cluster.service_available;
		if (strcmp(role, "leader") == 0 || strcmp(role, "follower") == 0)
			active_spokes = (int)agent->spoke_count;
	} else if (strcmp(agent->config.node_type, "spoke") == 0) {
		role = "spoke";
		network_health = agent->core_available && agent->peer_count > 0;
		service_available = agent->core_available;
	}
	timestamp(when);
	snprintf(id, sizeof(id), "hb-%llu", (unsigned long long)realtime_ns());
	if (!buffer_addn(&json, "{", 1) ||
	    !add_field_string(&json, "id", id, &first) ||
	    !add_field_string(&json, "type", "heartbeat", &first) ||
	    !add_field_string(&json, "timestamp", when, &first) ||
	    !buffer_add(&json, ",\"payload\":{") ||
	    !buffer_add(&json, "\"node_id\":") || !json_quote(&json, agent->config.node_id) ||
	    !buffer_add(&json, ",\"node_type\":") || !json_quote(&json, agent->config.node_type) ||
	    !buffer_add(&json, ",\"cluster_id\":") || !json_quote(&json, cluster_id) ||
	    !buffer_add(&json, ",\"member_id\":") || !json_quote(&json, member_id) ||
	    !buffer_add(&json, ",\"member_state\":") || !json_quote(&json, member_state) ||
	    !buffer_add(&json, ",\"primary\":") || !json_quote(&json, primary) ||
	    !buffer_add(&json, ",\"leader\":") || !json_quote(&json, leader) ||
	    !buffer_add(&json, ",\"advertised_ip\":") || !json_quote(&json, advertised) ||
	    !buffer_add(&json, ",\"local_role\":") || !json_quote(&json, role) ||
	    !buffer_addf(&json,
		",\"term\":%llu,\"commit_index\":%llu,\"manifest_revision\":%llu",
		(unsigned long long)term, (unsigned long long)commit,
		(unsigned long long)revision) ||
	    !buffer_add(&json, ",\"digest\":") || !json_quote(&json, digest) ||
	    !buffer_addf(&json,
		",\"network_health\":%s,\"service_available\":%s,"
		"\"core_available\":%s,\"active_spokes\":%d,\"peer_count\":%zu,"
		"\"uptime_seconds\":0",
		network_health ? "true" : "false",
		service_available ? "true" : "false",
		agent->core_available ? "true" : "false", active_spokes,
		agent->peer_count) ||
	    !buffer_add(&json, ",\"timestamp\":") || !json_quote(&json, when) ||
	    !buffer_add(&json, ",\"witness\":") || !buffer_add(&json, witness))
		goto fail;
	if (have_cluster && (!buffer_add(&json, ",\"cluster_status\":") ||
			     !buffer_add(&json, cluster.status_json)))
		goto fail;
	if (refreshed_core && peer_json != NULL) {
		if (strcmp(agent->config.node_type, "spoke") == 0) {
			if (!buffer_add(&json, ",\"peers\":")) goto fail;
		} else if (!buffer_add(&json, ",\"spokes\":")) {
			goto fail;
		}
		if (!buffer_add(&json, peer_json)) goto fail;
	}
	if (!buffer_add(&json, "}}")) goto fail;
	free(cluster_raw);
	free(core_raw);
	free(peer_json);
	cluster_result_free(&cluster);
	return buffer_take(&json);
fail:
	free(cluster_raw);
	free(core_raw);
	free(peer_json);
	cluster_result_free(&cluster);
	buffer_free(&json);
	return NULL;
}

/* Only the main loop touches WebSocket/TLS; socket sampling runs separately. */
static void *heartbeat_worker(void *opaque)
{
	struct agent *agent = opaque;
	char *heartbeat = build_heartbeat(agent);
	pthread_mutex_lock(&agent->command_lock);
	agent->heartbeat = heartbeat;
	agent->heartbeat_ready = true;
	pthread_mutex_unlock(&agent->command_lock);
	return NULL;
}

static void discard_old_responses(struct agent *agent)
{
	pthread_mutex_lock(&agent->command_lock);
	while (agent->responses_head != NULL &&
	       agent->responses_head->generation != agent->generation) {
		struct command_response *old = agent->responses_head;
		agent->responses_head = old->next;
		if (agent->responses_head == NULL) agent->responses_tail = NULL;
		command_response_free(old);
	}
	pthread_mutex_unlock(&agent->command_lock);
}

static bool service_connection(struct agent *agent)
{
	int64_t next_heartbeat = monotonic_ms();
	pthread_t worker;
	bool sampling = false;
	bool success = false;
	agent->last_core_refresh = 0;
	agent->core_available = false;
	agent->peer_count = agent->spoke_count = 0;

	while (!stopping) {
		struct pollfd fds[2];
		nfds_t count = 1;
		int64_t now;
		int timeout;
		int result;

		read_logs(agent);
		discard_old_responses(agent);
		if (!flush_command_responses(agent) || !flush_logs(agent))
			goto out;
		if (ws_read_available(&agent->websocket) < 0)
			goto out;
		now = monotonic_ms();
		if (sampling) {
			pthread_mutex_lock(&agent->command_lock);
			bool ready = agent->heartbeat_ready;
			pthread_mutex_unlock(&agent->command_lock);
			if (ready) {
				pthread_join(worker, NULL);
				sampling = false;
				if (agent->heartbeat == NULL ||
				    !ws_send_text(&agent->websocket, agent->heartbeat)) goto out;
				free(agent->heartbeat);
				agent->heartbeat = NULL;
			}
		}
		if (!sampling && now >= next_heartbeat) {
			agent->heartbeat_ready = false;
			if (pthread_create(&worker, NULL, heartbeat_worker, agent) != 0) goto out;
			sampling = true;
			next_heartbeat = now + HEARTBEAT_MS;
		}
		/* Bound response latency while a sample or command worker is running. */
		timeout = 50;
		fds[0].fd = agent->websocket.transport.fd;
		fds[0].events = POLLIN | agent->websocket.transport.want_events;
		fds[0].revents = 0;
		if (agent->logs.fd >= 0) {
			fds[1].fd = agent->logs.fd;
			fds[1].events = POLLIN;
			fds[1].revents = 0;
			count = 2;
		}
		result = poll(fds, count, timeout);
		if (result < 0 && errno != EINTR)
			goto out;
		if (result > 0 &&
		    (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)))
			goto out;
	}
	success = true;
out:
	if (sampling) pthread_join(worker, NULL);
	free(agent->heartbeat);
	agent->heartbeat = NULL;
	return success;
}

static void reconnect_wait(struct agent *agent)
{
	int64_t deadline = monotonic_ms() + RECONNECT_MS;
	while (!stopping && monotonic_ms() < deadline) {
		struct pollfd pfd = {.fd = agent->logs.fd, .events = POLLIN};
		int left = (int)(deadline - monotonic_ms());
		if (left > 200) left = 200;
		read_logs(agent);
		if (agent->logs.fd >= 0)
			(void)poll(&pfd, 1, left);
		else
			(void)poll(NULL, 0, left);
	}
}

static void agent_run(struct agent *agent)
{
	(void)start_log_reader(&agent->logs);
	while (!stopping) {
		log_message("INFO", "connecting node %s to %s", agent->config.node_id,
			    agent->config.server);
		agent->generation++;
		if (!ws_connect(&agent->websocket, &agent->config,
				agent_on_message, agent)) {
			log_message("WARN", "connection failed; retrying in 3 seconds");
			reconnect_wait(agent);
			continue;
		}
		log_message("INFO", "connected to Manager");
		if (!service_connection(agent) && !stopping)
			log_message("WARN", "connection lost; retrying in 3 seconds");
		ws_close(&agent->websocket);
		if (!stopping) reconnect_wait(agent);
	}
	stop_log_reader(&agent->logs);
	free_logs(agent);
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [options]\n"
		"  --server URL       Manager WebSocket URL\n"
		"  --node-id ID       unique node ID (default: hostname)\n"
		"  --node-type TYPE   hub or spoke\n"
		"  --token TOKEN      Manager authentication token\n"
		"  --self-test        run parser and protocol checks\n"
		"  --help             show this help\n", program);
}

static bool config_defaults(struct config *config)
{
	char hostname[sizeof(config->node_id)] = "hub-node";
	const char *token;

	memset(config, 0, sizeof(*config));
	(void)gethostname(hostname, sizeof(hostname) - 1);
	hostname[sizeof(hostname) - 1] = '\0';
	if (!copy_setting(config->server, sizeof(config->server),
			env_or("SERVER", "ws://127.0.0.1:8080/api/agent/ws"), "SERVER") ||
	    !copy_setting(config->node_id, sizeof(config->node_id),
			env_or("NODE_ID", hostname), "NODE_ID") ||
	    !copy_setting(config->node_type, sizeof(config->node_type),
			env_or("NODE_TYPE", "hub"), "NODE_TYPE") ||
	    !copy_setting(config->core_socket, sizeof(config->core_socket),
			env_or("OPENNHRP_SOCKET", "/var/run/opennhrp.socket"),
			"OPENNHRP_SOCKET") ||
	    !copy_setting(config->ha_socket, sizeof(config->ha_socket),
			env_or("OPENNHRP_HA_SOCKET", "/var/run/opennhrp-ha.socket"),
			"OPENNHRP_HA_SOCKET") ||
	    !copy_setting(config->ctl_path, sizeof(config->ctl_path),
			env_or("OPENNHRPCTL_PATH", "/usr/sbin/opennhrpctl"),
			"OPENNHRPCTL_PATH") ||
	    !copy_setting(config->config_path, sizeof(config->config_path),
			env_or("OPENNHRP_CONF_PATH", "/etc/opennhrp/opennhrp.conf"),
			"OPENNHRP_CONF_PATH") ||
	    !copy_setting(config->state_dir, sizeof(config->state_dir),
			env_or("OPENNHRP_HA_STATE_DIR", "/var/lib/opennhrp/ha"),
			"OPENNHRP_HA_STATE_DIR"))
		return false;
	token = getenv("TOKEN");
	if (token == NULL || *token == '\0') token = getenv("AUTH_TOKEN");
	if (token != NULL && *token != '\0')
		return copy_setting(config->token, sizeof(config->token), token, "TOKEN");
	if (read_secret_file(config->token, sizeof(config->token),
			     getenv("AUTH_TOKEN_FILE")))
		return true;
	return copy_setting(config->token, sizeof(config->token),
			    "opennhrp-secret-token", "TOKEN");
}

static bool self_test(void)
{
	static const char cluster_fixture[] =
		"prefix {\"cluster_id\":\"cluster\",\"primary\":\"hub-a\","
		"\"leader\":\"hub-a\",\"local_member\":\"hub-b\",\"term\":62,"
		"\"commit_index\":59,\"manifest_revision\":9,\"digest\":\"abc\","
		"\"service_available\":true,\"isolated\":false,"
		"\"network_health\":\"healthy\",\"health_interval_seconds\":10,"
		"\"health_failure_rounds\":2,\"health_recovery_rounds\":3,"
		"\"health_targets\":[{\"address\":\"1.1.1.1\",\"last_success\":true}],"
		"\"witness\":{\"mode\":\"active\",\"quorum_available\":true},"
		"\"members\":[{\"member\":\"hub-a\",\"priority\":100,"
		"\"state\":\"active\",\"connected\":true,\"authenticated\":true,"
		"\"match_index\":60,\"addresses\":[{\"address\":\"10.0.0.1\","
		"\"origin\":\"configured\"}]},{\"member\":\"hub-b\","
		"\"priority\":90,\"state\":\"active\",\"connected\":true,"
		"\"authenticated\":true,\"match_index\":59,\"addresses\":[{"
		"\"address\":\"10.0.0.2\",\"origin\":\"configured\"}]}]}";
	static const char peers_fixture[] =
		"Interface: gre1\nType: dynamic\nProtocol-Address: 10.0.0.2\n"
		"Registration-Mode: HA\nNBMA-Address: 192.0.2.2\nFlags: up\nExpires-In: 01:02\n\n";
	static const char request_fixture[] =
		"{\"id\":\"x\",\"type\":\"command_request\",\"payload\":{"
		"\"target_socket\":\"cli-stdin\",\"command\":\"a\\nb\","
		"\"args\":[\"ha\",\"join\"]}}";
	struct cluster_result cluster = {0};
	struct json_doc doc = {0};
	struct agent agent = {0};
	struct command_request *request = NULL;
	char *peers = NULL;
	char *accept = websocket_accept("dGhlIHNhbXBsZSBub25jZQ==");
	size_t count = 0;
	bool ok = true;

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "self-test failed: %s\n", #x); ok = false; goto out; } } while (0)
	CHECK(accept != NULL && strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
	CHECK(transform_cluster(cluster_fixture, "fallback", "/custom/ha", &cluster));
	CHECK(strstr(cluster.status_json, "\"state_dir\":\"/custom/ha\"") != NULL);
	CHECK(strcmp(cluster.local_role, "follower") == 0);
	CHECK(strcmp(cluster.member_state, "active") == 0);
	CHECK(strcmp(cluster.advertised_ip, "10.0.0.2") == 0);
	CHECK(strstr(cluster.status_json, "\"member_id\":\"hub-b\"") != NULL);
	peers = parse_peers(peers_fixture, &count);
	CHECK(peers != NULL && count == 1);
	CHECK(strstr(peers, "\"registration_mode\":\"ha\"") != NULL);
	CHECK(strstr(peers, "\"expires_in_sec\":62") != NULL);
	agent.generation = 7;
	CHECK(json_parse(&doc, request_fixture));
	request = parse_command_request(&agent, &doc, 0);
	CHECK(request != NULL && request->argc == 2);
	CHECK(strcmp(request->command, "a\nb") == 0);
#undef CHECK
out:
	free(accept);
	free(peers);
	command_request_free(request);
	json_doc_free(&doc);
	cluster_result_free(&cluster);
	if (ok) puts("self-test: ok");
	return ok;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"server", required_argument, NULL, 's'},
		{"node-id", required_argument, NULL, 'i'},
		{"node-type", required_argument, NULL, 'y'},
		{"token", required_argument, NULL, 't'},
		{"self-test", no_argument, NULL, 'T'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	struct agent agent;
	bool run_tests = false;
	int option;
	struct sigaction action = {0};

	memset(&agent, 0, sizeof(agent));
	agent.logs.fd = -1;
	if (!config_defaults(&agent.config))
		return 2;
	while ((option = getopt_long_only(argc, argv, "s:i:y:t:Th", options, NULL)) != -1) {
		const char *name = NULL;
		char *dst = NULL;
		size_t size = 0;
		switch (option) {
		case 's': dst = agent.config.server; size = sizeof(agent.config.server); name = "server"; break;
		case 'i': dst = agent.config.node_id; size = sizeof(agent.config.node_id); name = "node-id"; break;
		case 'y': dst = agent.config.node_type; size = sizeof(agent.config.node_type); name = "node-type"; break;
		case 't': dst = agent.config.token; size = sizeof(agent.config.token); name = "token"; break;
		case 'T': run_tests = true; continue;
		case 'h': usage(stdout, argv[0]); return 0;
		default: usage(stderr, argv[0]); return 2;
		}
		if (!copy_setting(dst, size, optarg, name))
			return 2;
	}
	if (optind != argc) {
		usage(stderr, argv[0]);
		return 2;
	}
	if (agent.config.node_id[0] == '\0') {
		if (gethostname(agent.config.node_id, sizeof(agent.config.node_id) - 1) != 0)
			strcpy(agent.config.node_id, "hub-node");
	}
	if (run_tests)
		return self_test() ? 0 : 1;
	if (strcmp(agent.config.node_type, "hub") != 0 &&
	    strcmp(agent.config.node_type, "spoke") != 0) {
		log_message("ERROR", "node-type must be hub or spoke");
		return 2;
	}
	if (!valid_header_value(agent.config.node_id) ||
	    !valid_header_value(agent.config.node_type) ||
	    !valid_header_value(agent.config.token)) {
		log_message("ERROR", "node identity and token must not contain CR or LF");
		return 2;
	}
	if (!parse_ws_url(agent.config.server, &(struct ws_url){0})) {
		log_message("ERROR", "server must be a valid ws:// or wss:// URL");
		return 2;
	}
	if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
			     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) {
		log_message("ERROR", "OpenSSL initialization failed");
		return 1;
	}
	if (pthread_mutex_init(&agent.command_lock, NULL) != 0 ||
	    pthread_cond_init(&agent.command_done, NULL) != 0) {
		log_message("ERROR", "thread initialization failed");
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	action.sa_handler = on_signal;
	sigemptyset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	log_message("INFO", "OpenNHRP Agent %s (%s, OpenSSL %s)", AGENT_VERSION,
		    agent.config.node_type, OpenSSL_version(OPENSSL_VERSION));
	agent_run(&agent);
	pthread_mutex_lock(&agent.command_lock);
	while (agent.active_commands > 0)
		pthread_cond_wait(&agent.command_done, &agent.command_lock);
	pthread_mutex_unlock(&agent.command_lock);
	free_command_responses(&agent);
	pthread_cond_destroy(&agent.command_done);
	pthread_mutex_destroy(&agent.command_lock);
	return 0;
}
