/* SPDX-License-Identifier: MIT */
/* Minimalistic JSON parser, derived from jsmn by Serge Zaitsev. */
#ifndef OPENNHRP_AGENT_JSMN_H
#define OPENNHRP_AGENT_JSMN_H

#include <stddef.h>

typedef enum {
	JSMN_UNDEFINED = 0,
	JSMN_OBJECT = 1,
	JSMN_ARRAY = 2,
	JSMN_STRING = 3,
	JSMN_PRIMITIVE = 4
} jsmntype_t;

enum {
	JSMN_ERROR_NOMEM = -1,
	JSMN_ERROR_INVAL = -2,
	JSMN_ERROR_PART = -3
};

typedef struct {
	jsmntype_t type;
	int start;
	int end;
	int size;
	int parent;
} jsmntok_t;

typedef struct {
	unsigned int pos;
	unsigned int toknext;
	int toksuper;
} jsmn_parser;

#ifdef OPENNHRP_AGENT_JSMN_IMPLEMENTATION
static void jsmn_init(jsmn_parser *parser)
{
	parser->pos = 0;
	parser->toknext = 0;
	parser->toksuper = -1;
}

static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser, jsmntok_t *tokens,
				    size_t count)
{
	jsmntok_t *tok;

	if (parser->toknext >= count)
		return NULL;
	tok = &tokens[parser->toknext++];
	tok->start = tok->end = -1;
	tok->size = 0;
	tok->parent = -1;
	return tok;
}

static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type, int start,
			    int end)
{
	token->type = type;
	token->start = start;
	token->end = end;
	token->size = 0;
}

static int jsmn_parse_primitive(jsmn_parser *parser, const char *js,
				 size_t len, jsmntok_t *tokens,
				 size_t count)
{
	int start = (int)parser->pos;
	jsmntok_t *token;

	for (; parser->pos < len; parser->pos++) {
		switch (js[parser->pos]) {
		case '\t': case '\r': case '\n': case ' ':
		case ',': case ']': case '}':
			goto found;
		default:
			if ((unsigned char)js[parser->pos] < 32 ||
			    (unsigned char)js[parser->pos] >= 127) {
				parser->pos = (unsigned int)start;
				return JSMN_ERROR_INVAL;
			}
		}
	}
found:
	if (tokens == NULL) {
		parser->pos--;
		return 0;
	}
	token = jsmn_alloc_token(parser, tokens, count);
	if (token == NULL) {
		parser->pos = (unsigned int)start;
		return JSMN_ERROR_NOMEM;
	}
	jsmn_fill_token(token, JSMN_PRIMITIVE, start, (int)parser->pos);
	token->parent = parser->toksuper;
	parser->pos--;
	return 0;
}

static int jsmn_parse_string(jsmn_parser *parser, const char *js, size_t len,
			     jsmntok_t *tokens, size_t count)
{
	int start = (int)parser->pos;
	jsmntok_t *token;

	parser->pos++;
	for (; parser->pos < len; parser->pos++) {
		char c = js[parser->pos];

		if (c == '"') {
			if (tokens == NULL)
				return 0;
			token = jsmn_alloc_token(parser, tokens, count);
			if (token == NULL) {
				parser->pos = (unsigned int)start;
				return JSMN_ERROR_NOMEM;
			}
			jsmn_fill_token(token, JSMN_STRING, start + 1,
					(int)parser->pos);
			token->parent = parser->toksuper;
			return 0;
		}
		if (c == '\\') {
			parser->pos++;
			if (parser->pos >= len)
				break;
			switch (js[parser->pos]) {
			case '"': case '/': case '\\': case 'b': case 'f':
			case 'r': case 'n': case 't':
				break;
			case 'u': {
				int i;
				for (i = 0; i < 4 && parser->pos < len; i++) {
					char h = js[++parser->pos];
					if (!((h >= '0' && h <= '9') ||
					      (h >= 'A' && h <= 'F') ||
					      (h >= 'a' && h <= 'f'))) {
						parser->pos = (unsigned int)start;
						return JSMN_ERROR_INVAL;
					}
				}
				parser->pos--;
				break;
			}
			default:
				parser->pos = (unsigned int)start;
				return JSMN_ERROR_INVAL;
			}
		}
	}
	parser->pos = (unsigned int)start;
	return JSMN_ERROR_PART;
}

static int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
		      jsmntok_t *tokens, unsigned int count)
{
	int r;
	int i;
	jsmntok_t *token;

	for (; parser->pos < len; parser->pos++) {
		char c = js[parser->pos];

		switch (c) {
		case '{': case '[':
			token = jsmn_alloc_token(parser, tokens, count);
			if (token == NULL)
				return JSMN_ERROR_NOMEM;
			if (parser->toksuper != -1) {
				tokens[parser->toksuper].size++;
				token->parent = parser->toksuper;
			}
			token->type = c == '{' ? JSMN_OBJECT : JSMN_ARRAY;
			token->start = (int)parser->pos;
			parser->toksuper = (int)parser->toknext - 1;
			break;
		case '}': case ']':
			for (i = (int)parser->toknext - 1; i >= 0; i--) {
				token = &tokens[i];
				if (token->start != -1 && token->end == -1) {
					if ((token->type == JSMN_OBJECT && c == ']') ||
					    (token->type == JSMN_ARRAY && c == '}'))
						return JSMN_ERROR_INVAL;
					token->end = (int)parser->pos + 1;
					parser->toksuper = token->parent;
					break;
				}
			}
			if (i == -1)
				return JSMN_ERROR_INVAL;
			break;
		case '"':
			r = jsmn_parse_string(parser, js, len, tokens, count);
			if (r < 0)
				return r;
			if (parser->toksuper != -1)
				tokens[parser->toksuper].size++;
			break;
		case '\t': case '\r': case '\n': case ' ':
			break;
		case ':':
			parser->toksuper = (int)parser->toknext - 1;
			break;
		case ',':
			if (parser->toksuper != -1 &&
			    tokens[parser->toksuper].type != JSMN_ARRAY &&
			    tokens[parser->toksuper].type != JSMN_OBJECT)
				parser->toksuper = tokens[parser->toksuper].parent;
			break;
		default:
			r = jsmn_parse_primitive(parser, js, len, tokens, count);
			if (r < 0)
				return r;
			if (parser->toksuper != -1)
				tokens[parser->toksuper].size++;
			break;
		}
	}
	for (i = (int)parser->toknext - 1; i >= 0; i--)
		if (tokens[i].start != -1 && tokens[i].end == -1)
			return JSMN_ERROR_PART;
	return (int)parser->toknext;
}
#endif

#endif
