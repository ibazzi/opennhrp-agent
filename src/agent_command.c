// SPDX-License-Identifier: MIT
#include "agent_internal.h"

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

bool socket_command(const char *path, const char *command,
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

void command_request_free(struct command_request *request)
{
	if (request == NULL) return;
	free(request->id);
	free(request->target);
	free(request->command);
	for (size_t i = 0; i < request->argc; i++) free(request->args[i]);
	free(request->args);
	free(request);
}

struct command_request *parse_command_request(struct agent *agent,
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

bool agent_on_message(void *opaque, const char *message, size_t len)
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

void command_response_free(struct command_response *response)
{
	if (response == NULL) return;
	free(response->id);
	free(response->text);
	free(response);
}

void free_command_responses(struct agent *agent)
{
	while (agent->responses_head != NULL) {
		struct command_response *response = agent->responses_head;
		agent->responses_head = response->next;
		command_response_free(response);
	}
	agent->responses_tail = NULL;
}

bool flush_command_responses(struct agent *agent)
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
