// SPDX-License-Identifier: MIT
#include "agent_internal.h"

struct member_ref {
	int object;
	int priority;
	uint64_t match_index;
	char id[256];
};

void cluster_result_free(struct cluster_result *result)
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

bool transform_cluster(const char *raw, const char *default_node_id,
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

char *parse_peers(const char *raw, size_t *peer_count)
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
void *heartbeat_worker(void *opaque)
{
	struct agent *agent = opaque;
	char *heartbeat = build_heartbeat(agent);
	pthread_mutex_lock(&agent->command_lock);
	agent->heartbeat = heartbeat;
	agent->heartbeat_ready = true;
	pthread_mutex_unlock(&agent->command_lock);
	return NULL;
}
