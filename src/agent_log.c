// SPDX-License-Identifier: MIT
#include "agent_internal.h"

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

bool start_log_reader(struct log_reader *reader)
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

void stop_log_reader(struct log_reader *reader)
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

void read_logs(struct agent *agent)
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

bool flush_logs(struct agent *agent)
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

void free_logs(struct agent *agent)
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
