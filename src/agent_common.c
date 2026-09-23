// SPDX-License-Identifier: MIT
#define OPENNHRP_AGENT_JSMN_IMPLEMENTATION
#include "agent_internal.h"

int64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint64_t realtime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void timestamp(char out[40])
{
	struct timespec ts;
	struct tm tm;
	size_t n;

	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);
	n = strftime(out, 40, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(out + n, 40 - n, ".%09ldZ", ts.tv_nsec);
}

void log_message(const char *level, const char *fmt, ...)
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

bool buffer_reserve(struct buffer *b, size_t extra)
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

bool buffer_addn(struct buffer *b, const void *data, size_t len)
{
	if (!buffer_reserve(b, len))
		return false;
	memcpy(b->data + b->len, data, len);
	b->len += len;
	b->data[b->len] = '\0';
	return true;
}

bool buffer_add(struct buffer *b, const char *text)
{
	return buffer_addn(b, text, strlen(text));
}

bool buffer_addf(struct buffer *b, const char *fmt, ...)
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

void buffer_reset(struct buffer *b)
{
	b->len = 0;
	if (b->data != NULL)
		b->data[0] = '\0';
}

void buffer_free(struct buffer *b)
{
	free(b->data);
	memset(b, 0, sizeof(*b));
}

char *buffer_take(struct buffer *b)
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

bool json_quote(struct buffer *b, const char *text)
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

void json_doc_free(struct json_doc *doc)
{
	free(doc->tokens);
	memset(doc, 0, sizeof(*doc));
}

bool json_parse(struct json_doc *doc, const char *text)
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

bool token_equal(const struct json_doc *doc, int index,
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

int object_get(const struct json_doc *doc, int object,
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

char *token_string(const struct json_doc *doc, int index)
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

bool token_copy(const struct json_doc *doc, int index, char *out,
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

bool token_bool(const struct json_doc *doc, int index, bool fallback)
{
	if (token_equal(doc, index, "true")) return true;
	if (token_equal(doc, index, "false")) return false;
	return fallback;
}

uint64_t token_u64(const struct json_doc *doc, int index)
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

int token_int(const struct json_doc *doc, int index)
{
	uint64_t value = token_u64(doc, index);
	return value > INT_MAX ? INT_MAX : (int)value;
}

bool add_json_token(struct buffer *out, const struct json_doc *doc,
			   int index)
{
	const jsmntok_t *tok;

	if (index < 0 || index >= doc->count)
		return false;
	tok = &doc->tokens[index];
	return buffer_addn(out, doc->text + tok->start,
			   (size_t)(tok->end - tok->start));
}

bool copy_setting(char *dst, size_t size, const char *value,
			 const char *name)
{
	if (value == NULL || strlen(value) >= size) {
		log_message("ERROR", "%s is too long", name);
		return false;
	}
	strcpy(dst, value);
	return true;
}

const char *env_or(const char *name, const char *fallback)
{
	const char *value = getenv(name);
	return value != NULL && *value != '\0' ? value : fallback;
}

bool read_secret_file(char *out, size_t size, const char *path)
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

bool valid_header_value(const char *value)
{
	return value != NULL && strchr(value, '\r') == NULL &&
	       strchr(value, '\n') == NULL;
}

bool add_field_string(struct buffer *out, const char *name,
			     const char *value, bool *first)
{
	if (!*first && !buffer_addn(out, ",", 1)) return false;
	*first = false;
	return json_quote(out, name) && buffer_addn(out, ":", 1) &&
	       json_quote(out, value);
}

bool add_field_bool(struct buffer *out, const char *name, bool value,
			   bool *first)
{
	if (!*first && !buffer_addn(out, ",", 1)) return false;
	*first = false;
	return json_quote(out, name) && buffer_addn(out, ":", 1) &&
	       buffer_add(out, value ? "true" : "false");
}

bool add_field_u64(struct buffer *out, const char *name, uint64_t value,
			  bool *first)
{
	if (!*first && !buffer_addn(out, ",", 1)) return false;
	*first = false;
	return json_quote(out, name) && buffer_addn(out, ":", 1) &&
	       buffer_addf(out, "%llu", (unsigned long long)value);
}

char *trim(char *text)
{
	char *end;
	while (isspace((unsigned char)*text)) text++;
	end = text + strlen(text);
	while (end > text && isspace((unsigned char)end[-1])) end--;
	*end = '\0';
	return text;
}

void peer_field(char *dst, size_t size, const char *src)
{
	if (size == 0) return;
	strncpy(dst, src, size - 1);
	dst[size - 1] = '\0';
}

int wait_fd(int fd, short events, int64_t deadline)
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
