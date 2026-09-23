// SPDX-License-Identifier: MIT
#include "agent_internal.h"

bool parse_ws_url(const char *text, struct ws_url *url)
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

char *websocket_accept(const char *key)
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

bool ws_send_text(struct websocket *ws, const char *text)
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
int ws_read_available(struct websocket *ws)
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

bool ws_connect(struct websocket *ws, const struct config *config,
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

void ws_close(struct websocket *ws)
{
	if (ws->transport.fd >= 0)
		(void)ws_send_frame(ws, 8, "", 0);
	transport_close(&ws->transport);
	buffer_free(&ws->input);
	buffer_free(&ws->message);
}
