// SPDX-License-Identifier: MIT
#include "agent_internal.h"

volatile sig_atomic_t stopping;

static void on_signal(int signum)
{
	(void)signum;
	stopping = 1;
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
