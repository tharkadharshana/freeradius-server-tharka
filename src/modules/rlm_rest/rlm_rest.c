/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_rest.c
 * @brief Integrate FreeRADIUS with RESTfull APIs
 *
 * @copyright 2012-2019,2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <talloc.h>
RCSID("$Id$")

#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/curl/xlat.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_util.h>

#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/tmpl_escape.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/uri.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat.h>

#include "rest.h"

static int rest_uri_part_escape(fr_value_box_t *vb, void *uctx);
static void *rest_uri_part_escape_uctx_alloc(UNUSED request_t *request, void const *uctx);

static fr_uri_part_t const rest_uri_parts[] = {
	{ .name = "scheme", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L(":")), .part_adv = { [':'] = 1 }, .extra_skip = 2 },
	{ .name = "host", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L(":"), L("/")), .part_adv = { [':'] = 1, ['/'] = 2 }, .func = rest_uri_part_escape },
	{ .name = "port", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("/")), .part_adv = { ['/'] = 1 } },
	{ .name = "method", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 }, .func = rest_uri_part_escape },
	{ .name = "param", .safe_for = CURL_URI_SAFE_FOR, .func = rest_uri_part_escape },
	XLAT_URI_PART_TERMINATOR
};

static fr_table_num_sorted_t const http_negotiation_table[] = {

	{ L("1.0"), 		CURL_HTTP_VERSION_1_0 },		//!< Enforce HTTP 1.0 requests.
	{ L("1.1"),		CURL_HTTP_VERSION_1_1 },		//!< Enforce HTTP 1.1 requests.
/*
 *	These are all enum values
 */
#if CURL_AT_LEAST_VERSION(7,49,0)
	{ L("2.0"), 		CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE },	//!< Enforce HTTP 2.0 requests.
#endif
#if CURL_AT_LEAST_VERSION(7,33,0)
	{ L("2.0+auto"),	CURL_HTTP_VERSION_2_0 },		//!< Attempt HTTP 2 requests. libcurl will fall back
									///< to HTTP 1.1 if HTTP 2 can't be negotiated with the
									///< server. (Added in 7.33.0)
#endif
#if CURL_AT_LEAST_VERSION(7,47,0)
	{ L("2.0+tls"),		CURL_HTTP_VERSION_2TLS },		//!< Attempt HTTP 2 over TLS (HTTPS) only.
									///< libcurl will fall back to HTTP 1.1 if HTTP 2
									///< can't be negotiated with the HTTPS server.
									///< For clear text HTTP servers, libcurl will use 1.1.
#endif
	{ L("default"), 	CURL_HTTP_VERSION_NONE }		//!< We don't care about what version the library uses.
									///< libcurl will use whatever it thinks fit.
};
static size_t http_negotiation_table_len = NUM_ELEMENTS(http_negotiation_table);

/** Unique pointer used to determine if we should explicitly disable proxying
 *
 */
char const *rest_no_proxy = "*";

static int rest_proxy_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			    CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	static fr_table_num_sorted_t const disable_proxy_table[] = {
		{ L("no"), 	1 },
		{ L("false"),	1 },
		{ L("none"),	1 }
	};
	static size_t disable_proxy_table_len = NUM_ELEMENTS(disable_proxy_table);
	char const *value = cf_pair_value(cf_item_to_pair(ci));

	if (fr_table_value_by_str(disable_proxy_table, value, 0) == 1) {
		*((char const **)out) = rest_no_proxy;
	} else {
		*((char const **)out) = value;
	}
	return 0;
}

#define SECTION_REQUEST_COMMON \
	{ FR_CONF_OFFSET("body", rlm_rest_section_request_t, body_str), .dflt = "none" }, \
	/* User authentication */ \
	{ FR_CONF_OFFSET_IS_SET("auth", FR_TYPE_VOID, 0, rlm_rest_section_request_t, auth), \
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = http_auth_table, .len = &http_auth_table_len }, .dflt = "none" }, \
	{ FR_CONF_OFFSET("require_auth", rlm_rest_section_request_t, require_auth), .dflt = "no" }, \
	{ FR_CONF_OFFSET("chunk", rlm_rest_section_request_t, chunk), .dflt = "0" } \

static const conf_parser_t section_request_config[] = {
	{ FR_CONF_OFFSET("proxy", rlm_rest_section_request_t, proxy), .func = rest_proxy_parse },
	{ FR_CONF_OFFSET("method", rlm_rest_section_request_t, method_str), .dflt = "GET" },
	SECTION_REQUEST_COMMON,
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t section_response_config[] = {
	{ FR_CONF_OFFSET("force_to", rlm_rest_section_response_t, force_to_str) }, \
	{ FR_CONF_OFFSET_TYPE_FLAGS("max_body_in", FR_TYPE_SIZE, 0, rlm_rest_section_response_t, max_body_in), .dflt = "16k" },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t section_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("request", 0, rlm_rest_section_t, request, section_request_config) },
	{ FR_CONF_OFFSET_SUBSECTION("response", 0, rlm_rest_section_t, response, section_response_config) },

	/* Transfer configuration */
	{ FR_CONF_OFFSET("timeout", rlm_rest_section_t, timeout), .dflt = "4.0" },

	/* TLS Parameters */
	{ FR_CONF_OFFSET_SUBSECTION("tls", 0, rlm_rest_section_t, tls, fr_curl_tls_config) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t xlat_request_config[] = {
	SECTION_REQUEST_COMMON,
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t xlat_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("request", 0, rlm_rest_section_t, request, xlat_request_config) },
	{ FR_CONF_OFFSET_SUBSECTION("response", 0, rlm_rest_section_t, response, section_response_config) },

	/* Transfer configuration */
	{ FR_CONF_OFFSET("timeout", rlm_rest_section_t, timeout), .dflt = "4.0" },

	/* TLS Parameters */
	{ FR_CONF_OFFSET_SUBSECTION("tls", 0, rlm_rest_section_t, tls, fr_curl_tls_config) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_DEPRECATED("connect_timeout", rlm_rest_t, connect_timeout) },
	{ FR_CONF_OFFSET("connect_proxy", rlm_rest_t, connect_proxy), .func = rest_proxy_parse },
	{ FR_CONF_OFFSET("http_negotiation", rlm_rest_t, http_negotiation),
	  .func = cf_table_parse_int,
	  .uctx = &(cf_table_parse_ctx_t){ .table = http_negotiation_table, .len = &http_negotiation_table_len },
	  .dflt = "default" },

	{ FR_CONF_OFFSET_SUBSECTION("connection", 0, rlm_rest_t, conn_config, fr_curl_conn_config) },

#ifdef CURLPIPE_MULTIPLEX
	{ FR_CONF_OFFSET("multiplex", rlm_rest_t, multiplex), .dflt = "yes" },
#endif

#ifndef NDEBUG
	{ FR_CONF_OFFSET("fail_header_decode", rlm_rest_t, fail_header_decode), .dflt = "no" },
	{ FR_CONF_OFFSET("fail_body_decode", rlm_rest_t, fail_body_decode), .dflt = "no" },
#endif

	CONF_PARSER_TERMINATOR
};

#define REST_CALL_ENV_REQUEST_COMMON(_dflt_username, _dflt_password) \
	{ FR_CALL_ENV_OFFSET("header", FR_TYPE_STRING, CALL_ENV_FLAG_MULTI, rlm_rest_call_env_t, request.header) }, \
	{ FR_CALL_ENV_OFFSET("data", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, rlm_rest_call_env_t, request.data) }, \
	{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_SINGLE | CALL_ENV_FLAG_NULLABLE, \
				rlm_rest_call_env_t, request.username), .pair.dflt_quote = T_BARE_WORD, _dflt_username }, \
	{ FR_CALL_ENV_OFFSET("password", FR_TYPE_STRING, CALL_ENV_FLAG_SINGLE | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_SECRET, \
				rlm_rest_call_env_t, request.password), .pair.dflt_quote = T_BARE_WORD, _dflt_password }, \

#define REST_CALL_ENV_RESPONSE_COMMON \
	{ FR_CALL_ENV_PARSE_ONLY_OFFSET("header", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE, rlm_rest_call_env_t, response.header) }, \

#define REST_CALL_ENV_SECTION(_var, _section, _dflt_username, _dflt_password) \
static const call_env_method_t _var = { \
	FR_CALL_ENV_METHOD_OUT(rlm_rest_call_env_t), \
	.env = (call_env_parser_t[]){ \
		{ FR_CALL_ENV_SUBSECTION(_section, NULL, CALL_ENV_FLAG_NONE, \
			((call_env_parser_t[]) { \
				{ FR_CALL_ENV_SUBSECTION("request", NULL, CALL_ENV_FLAG_NONE, \
							((call_env_parser_t[]) { \
								{ FR_CALL_ENV_OFFSET("uri", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT, rlm_rest_call_env_t, request.uri), \
										     .pair.escape = { \
											.func = fr_uri_escape, \
											.mode = TMPL_ESCAPE_PRE_CONCAT, \
											.uctx = { \
												.func = { \
													.alloc = rest_uri_part_escape_uctx_alloc, \
													.uctx = rest_uri_parts \
												} , \
												.type = TMPL_ESCAPE_UCTX_ALLOC_FUNC\
											}, \
											.safe_for = CURL_URI_SAFE_FOR \
										      }, \
										      .pair.literals_safe_for = CURL_URI_SAFE_FOR}, /* Do not concat */ \
								REST_CALL_ENV_REQUEST_COMMON(_dflt_username, _dflt_password) \
								CALL_ENV_TERMINATOR \
							})) }, \
				{ FR_CALL_ENV_SUBSECTION("response", NULL, CALL_ENV_FLAG_NONE, \
							((call_env_parser_t[]) { \
								REST_CALL_ENV_RESPONSE_COMMON \
								CALL_ENV_TERMINATOR \
							})) }, \
				CALL_ENV_TERMINATOR \
			}) \
		) }, \
		CALL_ENV_TERMINATOR \
	} \
}

REST_CALL_ENV_SECTION(rest_call_env_authorize, "authorize",,);
REST_CALL_ENV_SECTION(rest_call_env_authenticate, "authenticate", .pair.dflt = "&User-Name", .pair.dflt = "&User-Password");
REST_CALL_ENV_SECTION(rest_call_env_post_auth, "post-auth",,);
REST_CALL_ENV_SECTION(rest_call_env_accounting, "accounting",,);

/*
 *	xlat call env doesn't have the same set of config items as the other sections
 *	because some values come from the xlat call itself.
 *
 *	If someone can figure out a non-fuggly way of omitting the uri from the
 *	configuration, please do, and use the REST_CALL_ENV_SECTION macro for this
 *	too.
 */
static const call_env_method_t rest_call_env_xlat = { \
	FR_CALL_ENV_METHOD_OUT(rlm_rest_call_env_t), \
	.env = (call_env_parser_t[]){ \
		{ FR_CALL_ENV_SUBSECTION("xlat", NULL, CALL_ENV_FLAG_NONE, \
			((call_env_parser_t[]) { \
				{ FR_CALL_ENV_SUBSECTION("request", NULL, CALL_ENV_FLAG_NONE, \
							((call_env_parser_t[]) { \
								REST_CALL_ENV_REQUEST_COMMON(,) \
								CALL_ENV_TERMINATOR \
							})) }, \
				{ FR_CALL_ENV_SUBSECTION("response", NULL, CALL_ENV_FLAG_NONE, \
							((call_env_parser_t[]) { \
								REST_CALL_ENV_RESPONSE_COMMON \
								CALL_ENV_TERMINATOR \
							})) }, \
				CALL_ENV_TERMINATOR \
			}) \
		) }, \
		CALL_ENV_TERMINATOR \
	} \
};

fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_rest_dict[];
fr_dict_autoload_t rlm_rest_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_rest_http_body;
fr_dict_attr_t const *attr_rest_http_header;
fr_dict_attr_t const *attr_rest_http_status_code;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_rest_dict_attr[];
fr_dict_attr_autoload_t rlm_rest_dict_attr[] = {
	{ .out = &attr_rest_http_body, .name = "REST-HTTP-Body", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_rest_http_header, .name = "REST-HTTP-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_rest_http_status_code, .name = "REST-HTTP-Status-Code", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

extern global_lib_autoinst_t const * const rlm_rest_lib[];
global_lib_autoinst_t const * const rlm_rest_lib[] = {
	&fr_curl_autoinst,
	GLOBAL_LIB_TERMINATOR
};

/** Update the status attribute
 *
 * @param[in] request	The current request.
 * @param[in] handle	rest handle.
 * @return
 *	- 0 if status was updated successfully.
 *	- -1 if status was not updated successfully.
 */
static int rlm_rest_status_update(request_t *request, void *handle)
{
	int		code;
	fr_pair_t	*vp;

	RDEBUG2("Updating result attribute(s)");

	RINDENT();
	code = rest_get_handle_code(handle);
	if (!code) {
		pair_delete_request(attr_rest_http_status_code);
		RDEBUG2("&request.REST-HTTP-Status-Code !* ANY");
		REXDENT();
		return -1;
	}

	RDEBUG2("&request.REST-HTTP-Status-Code := %i", code);

	MEM(pair_update_request(&vp, attr_rest_http_status_code) >= 0);
	vp->vp_uint32 = code;
	REXDENT();

	return 0;
}

static int _rest_uri_part_escape_uctx_free(void *uctx)
{
	return talloc_free(uctx);
}

/** Allocate an escape uctx to pass to fr_uri_escape
 *
 * @param[in] request	UNUSED.
 * @param[in] uctx	pointer to the start of the uri_parts array.
 * @return A new fr_uri_escape_ctx_t.
 */
static void *rest_uri_part_escape_uctx_alloc(UNUSED request_t *request, void const *uctx)
{
	static _Thread_local fr_uri_escape_ctx_t	*t_ctx;

	if (unlikely(t_ctx == NULL)) {
		fr_uri_escape_ctx_t *ctx;

		MEM(ctx = talloc_zero(NULL, fr_uri_escape_ctx_t));
		fr_atexit_thread_local(t_ctx, _rest_uri_part_escape_uctx_free, ctx);
	} else {
		memset(t_ctx, 0, sizeof(*t_ctx));
	}
	t_ctx->uri_part = uctx;
	return t_ctx;
}

/** URL escape a single box forming part of a URL
 *
 * @param[in] vb		to escape
 * @param[in] uctx		UNUSED context containing CURL handle
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
static int rest_uri_part_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	char				*escaped;

	escaped = curl_easy_escape(fr_curl_tmp_handle(), vb->vb_strvalue, vb->vb_length);
	if (!escaped) return -1;

	/*
	 *	Returned string the same length - nothing changed
	 */
	if (strlen(escaped) == vb->vb_length) {
		curl_free(escaped);
		return 0;
	}

	fr_value_box_clear_value(vb);
	fr_value_box_strdup(vb, vb, NULL, escaped, vb->tainted);

	curl_free(escaped);

	return 0;
}

static int rlm_rest_perform(module_ctx_t const *mctx,
			    rlm_rest_section_t const *section, fr_curl_io_request_t *randle,
			    request_t *request)
{
	rlm_rest_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	rlm_rest_call_env_t 	*call_env = talloc_get_type_abort(mctx->env_data, rlm_rest_call_env_t);
	int			ret;

	RDEBUG2("Sending HTTP %s to \"%pV\"",
	        fr_table_str_by_value(http_method_table, section->request.method, NULL), call_env->request.uri);

	/*
	 *  Configure various CURL options, and initialise the read/write
	 *  context data.
	 */
	ret = rest_request_config(mctx, section, request, randle, section->request.method, section->request.body,
				  call_env->request.uri->vb_strvalue,
				  call_env->request.data ? call_env->request.data->vb_strvalue : NULL);
	if (ret < 0) return -1;

	/*
	 *  Send the CURL request, pre-parse headers, aggregate incoming
	 *  HTTP body data into a single contiguous buffer.
	 */
	ret = fr_curl_io_request_enqueue(t->mhandle, request, randle);
	if (ret < 0) return -1;

	return 0;
}

static xlat_action_t rest_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      request_t *request, UNUSED fr_value_box_list_t *in)
{
	rlm_rest_xlat_rctx_t		*rctx = talloc_get_type_abort(xctx->rctx, rlm_rest_xlat_rctx_t);
	int				hcode;
	ssize_t				len;
	char const			*body;
	xlat_action_t			xa = XLAT_ACTION_DONE;

	fr_curl_io_request_t		*handle = talloc_get_type_abort(rctx->handle, fr_curl_io_request_t);
	rlm_rest_section_t		*section = &rctx->section;

	if (section->tls.extract_cert_attrs) fr_curl_response_certinfo(request, handle);

	if (rlm_rest_status_update(request, handle) < 0) {
		xa = XLAT_ACTION_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	switch (hcode) {
	case 404:
	case 410:
	case 403:
	case 401:
	{
		xa = XLAT_ACTION_FAIL;
error:
		rest_response_error(request, handle);
		goto finish;
	}
	case 204:
		goto finish;

	default:
		/*
		 *	Attempt to parse content if there was any.
		 */
		if ((hcode >= 200) && (hcode < 300)) {
			break;
		} else if (hcode < 500) {
			xa = XLAT_ACTION_FAIL;
			goto error;
		} else {
			xa = XLAT_ACTION_FAIL;
			goto error;
		}
	}

finish:
	/*
	 *	Always output the xlat data.
	 *
	 *	The user can check REST-HTTP-Status-Code to figure out what happened.
	 *
	 *	Eventually we should just emit two boxes, one with the response code
	 *	and one with the body.
	 */
	len = rest_get_handle_data(&body, handle);
	if (len > 0) {
		fr_value_box_t *vb;

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_bstrndup(vb, vb, NULL, body, len, true);
		fr_dcursor_insert(out, vb);
	}

	rest_slab_release(handle);

	talloc_free(rctx);

	return xa;
}

static xlat_arg_parser_t const rest_xlat_args[] = {
	{ .required = true, .safe_for = CURL_URI_SAFE_FOR, .type = FR_TYPE_STRING },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Simple xlat to read text data from a URL
 *
 * Example:
@verbatim
%rest(http://example.com/)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t rest_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
			       xlat_ctx_t const *xctx, request_t *request,
			       fr_value_box_list_t *in)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_rest_t);
	rlm_rest_thread_t		*t = talloc_get_type_abort(xctx->mctx->thread, rlm_rest_thread_t);

	fr_curl_io_request_t		*randle = NULL;
	int				ret;
	http_method_t			method;
	fr_value_box_t			*in_vb = fr_value_box_list_pop_head(in), *uri_vb = NULL;

	/* There are no configurable parameters other than the URI */
	rlm_rest_xlat_rctx_t		*rctx;
	rlm_rest_section_t		*section;

	MEM(rctx = talloc(request, rlm_rest_xlat_rctx_t));
	section = &rctx->section;

	/*
	 *	Section gets modified, so we need our own copy.
	 */
	memcpy(&rctx->section, &inst->xlat, sizeof(*section));

	fr_assert(in_vb->type == FR_TYPE_GROUP);

	/*
	 *	If we have more than 1 argument, then the first is the method
	 */
	if  ((fr_value_box_list_head(in))) {
		uri_vb = fr_value_box_list_head(&in_vb->vb_group);
		if (fr_value_box_list_concat_in_place(uri_vb,
						      uri_vb, &in_vb->vb_group, FR_TYPE_STRING,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			REDEBUG("Failed concatenating argument");
			return XLAT_ACTION_FAIL;
		}
		method = fr_table_value_by_substr(http_method_table, uri_vb->vb_strvalue, -1, REST_HTTP_METHOD_UNKNOWN);

		if (method != REST_HTTP_METHOD_UNKNOWN) {
			section->request.method = method;
		/*
	 	 *  If the method is unknown, it's a custom verb
	 	 */
		} else {
			section->request.method = REST_HTTP_METHOD_CUSTOM;
			MEM(section->request.method_str = talloc_bstrndup(rctx, uri_vb->vb_strvalue, uri_vb->vb_length));
		}
		/*
		 *	Move to next argument
		 */
		in_vb = fr_value_box_list_pop_head(in);
	} else {
		section->request.method = REST_HTTP_METHOD_GET;
	}

	/*
	 *	We get a connection from the pool here as the CURL object
	 *	is needed to use curl_easy_escape() for escaping
	 */
	randle = rctx->handle = rest_slab_reserve(t->slab);
	if (!randle) return XLAT_ACTION_FAIL;

	/*
	 *	Walk the incoming boxes, assessing where each is in the URI,
	 *	escaping tainted ones where needed.  Following each space in the
	 *	input a new VB group is started.
	 */

	fr_assert(in_vb->type == FR_TYPE_GROUP);

	randle->request = request;	/* Populate the request pointer for escape callbacks */

	if (fr_uri_escape_list(&in_vb->vb_group, rest_uri_parts, NULL) < 0) {
		RPEDEBUG("Failed escaping URI");

	error:
		rest_slab_release(randle);
		talloc_free(section);

		return XLAT_ACTION_FAIL;
	}

	uri_vb = fr_value_box_list_head(&in_vb->vb_group);
	if (fr_value_box_list_concat_in_place(uri_vb,
					      uri_vb, &in_vb->vb_group, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true,
					      SIZE_MAX) < 0) {
		REDEBUG("Concatenating URI");
		goto error;
	}

	/*
	 *	Any additional arguments are freeform data
	 */
	if ((in_vb = fr_value_box_list_head(in))) {
		if (fr_value_box_list_concat_in_place(in_vb,
						      in_vb, in, FR_TYPE_STRING,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			REDEBUG("Failed to concatenate freeform data");
			goto error;
		}
		section->request.body = REST_HTTP_BODY_CUSTOM;
	}

	RDEBUG2("Sending HTTP %s to \"%pV\"",
	       (section->request.method == REST_HTTP_METHOD_CUSTOM) ?
	       	section->request.method_str : fr_table_str_by_value(http_method_table, section->request.method, NULL),
	        uri_vb);

	/*
	 *  Configure various CURL options, and initialise the read/write
	 *  context data.
	 *
	 *  @todo We could extract the User-Name and password from the URL string.
	 */
	ret = rest_request_config(MODULE_CTX(dl_module_instance_by_data(inst), t, xctx->env_data, NULL),
				  section, request, randle, section->request.method,
				  section->request.body,
				  uri_vb->vb_strvalue, in_vb ? in_vb->vb_strvalue : NULL);
	if (ret < 0) goto error;

	/*
	 *  Send the CURL request, pre-parse headers, aggregate incoming
	 *  HTTP body data into a single contiguous buffer.
	 *
	 * @fixme need to pass in thread to all xlat functions
	 */
	ret = fr_curl_io_request_enqueue(t->mhandle, request, randle);
	if (ret < 0) goto error;

	return unlang_xlat_yield(request, rest_xlat_resume, rest_io_xlat_signal, ~FR_SIGNAL_CANCEL, rctx);
}

static unlang_action_t mod_authorize_result(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_section_t const 	*section = &inst->authenticate;
	fr_curl_io_request_t		*handle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);

	int				hcode;
	rlm_rcode_t			rcode = RLM_MODULE_OK;
	int				ret;

	if (section->tls.extract_cert_attrs) fr_curl_response_certinfo(request, handle);

	if (rlm_rest_status_update(request, handle) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	switch (hcode) {
	case 404:
	case 410:
		rcode = RLM_MODULE_NOTFOUND;
		break;

	case 403:
		rcode = RLM_MODULE_DISALLOW;
		break;

	case 401:
		/*
		 *	Attempt to parse content if there was any.
		 */
		ret = rest_response_decode(inst, section, request, handle);
		if (ret < 0) {
			rcode = RLM_MODULE_FAIL;
			break;
		}

		rcode = RLM_MODULE_REJECT;
		break;

	case 204:
		rcode = RLM_MODULE_OK;
		break;

	default:
		/*
		 *	Attempt to parse content if there was any.
		 */
		if ((hcode >= 200) && (hcode < 300)) {
			ret = rest_response_decode(inst, section, request, handle);
			if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
			else if (ret == 0) rcode = RLM_MODULE_OK;
			else		   rcode = RLM_MODULE_UPDATED;
			break;
		} else if (hcode < 500) {
			rcode = RLM_MODULE_INVALID;
		} else {
			rcode = RLM_MODULE_FAIL;
		}
	}

	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_DISALLOW:
		rest_response_error(request, handle);
		break;

	default:
		rest_response_debug(request, handle);
		break;
	}

finish:
	rest_slab_release(handle);

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_thread_t		*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	rlm_rest_section_t const	*section = &inst->authorize;

	void				*handle;
	int				ret;

	if (!section->name) {
		RDEBUG2("No authorize section configured");
		RETURN_MODULE_NOOP;
	}

	handle = rest_slab_reserve(t->slab);
	if (!handle) RETURN_MODULE_FAIL;

	ret = rlm_rest_perform(mctx, section, handle, request);
	if (ret < 0) {
		rest_slab_release(handle);

		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield(request, mod_authorize_result, rest_io_module_signal, ~FR_SIGNAL_CANCEL, handle);
}

static unlang_action_t mod_authenticate_result(rlm_rcode_t *p_result,
					       module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_section_t const 	*section = &inst->authenticate;
	fr_curl_io_request_t		*handle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);

	int				hcode;
	int				rcode = RLM_MODULE_OK;
	int				ret;

	if (section->tls.extract_cert_attrs) fr_curl_response_certinfo(request, handle);

	if (rlm_rest_status_update(request, handle) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	switch (hcode) {
	case 404:
	case 410:
		rcode = RLM_MODULE_NOTFOUND;
		break;

	case 403:
		rcode = RLM_MODULE_DISALLOW;
		break;

	case 401:
		/*
		 *	Attempt to parse content if there was any.
		 */
		ret = rest_response_decode(inst, section, request, handle);
		if (ret < 0) {
			rcode = RLM_MODULE_FAIL;
			break;
		}

		rcode = RLM_MODULE_REJECT;
		break;

	case 204:
		rcode = RLM_MODULE_OK;
		break;

	default:
		/*
		 *	Attempt to parse content if there was any.
		 */
		if ((hcode >= 200) && (hcode < 300)) {
			ret = rest_response_decode(inst, section, request, handle);
			if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
			else if (ret == 0) rcode = RLM_MODULE_OK;
			else		   rcode = RLM_MODULE_UPDATED;
			break;
		} else if (hcode < 500) {
			rcode = RLM_MODULE_INVALID;
		} else {
			rcode = RLM_MODULE_FAIL;
		}
	}

	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_DISALLOW:
		rest_response_error(request, handle);
		break;

	default:
		rest_response_debug(request, handle);
		break;
	}

finish:
	rest_slab_release(handle);

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	Authenticate the user with the given password.
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_thread_t		*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	rlm_rest_call_env_t 		*call_env = talloc_get_type_abort(mctx->env_data, rlm_rest_call_env_t);
	rlm_rest_section_t const	*section = &inst->authenticate;
	fr_curl_io_request_t		*handle;

	int				ret;

	if (!section->name) {
		RDEBUG2("No authentication section configured");
		RETURN_MODULE_NOOP;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!call_env->request.username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	if (!call_env->request.password) {
		REDEBUG("Attribute \"User-Password\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (call_env->request.password->vb_length == 0) {
		REDEBUG("User-Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &call_env->request.password);
	} else {
		RDEBUG2("Login attempt with password");
	}

	handle = rest_slab_reserve(t->slab);
	if (!handle) RETURN_MODULE_FAIL;

	ret = rlm_rest_perform(mctx, section, handle, request);
	if (ret < 0) {
		rest_slab_release(handle);

		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield(request, mod_authenticate_result, rest_io_module_signal, ~FR_SIGNAL_CANCEL, handle);
}

static unlang_action_t mod_accounting_result(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_section_t const 	*section = &inst->authenticate;
	fr_curl_io_request_t		*handle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);

	int				hcode;
	int				rcode = RLM_MODULE_OK;
	int				ret;

	if (section->tls.extract_cert_attrs) fr_curl_response_certinfo(request, handle);

	if (rlm_rest_status_update(request, handle) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	if (hcode >= 500) {
		rcode = RLM_MODULE_FAIL;
	} else if (hcode == 204) {
		rcode = RLM_MODULE_OK;
	} else if ((hcode >= 200) && (hcode < 300)) {
		ret = rest_response_decode(inst, section, request, handle);
		if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
		else if (ret == 0) rcode = RLM_MODULE_OK;
		else		   rcode = RLM_MODULE_UPDATED;
	} else {
		rcode = RLM_MODULE_INVALID;
	}

	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
		rest_response_error(request, handle);
		break;

	default:
		rest_response_debug(request, handle);
		break;
	}

finish:
	rest_slab_release(handle);

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	Send accounting info to a REST API endpoint
 */
static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_thread_t		*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	rlm_rest_section_t const	*section = &inst->accounting;

	void				*handle;
	int				ret;

	if (!section->name) {
		RDEBUG2("No accounting section configured");
		RETURN_MODULE_NOOP;
	}

	handle = rest_slab_reserve(t->slab);
	if (!handle) RETURN_MODULE_FAIL;

	ret = rlm_rest_perform(mctx, section, handle, request);
	if (ret < 0) {
		rest_slab_release(handle);

		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield(request, mod_accounting_result, rest_io_module_signal, ~FR_SIGNAL_CANCEL, handle);
}

static unlang_action_t mod_post_auth_result(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_section_t const 	*section = &inst->authenticate;
	fr_curl_io_request_t		*handle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);

	int				hcode;
	int				rcode = RLM_MODULE_OK;
	int				ret;

	if (section->tls.extract_cert_attrs) fr_curl_response_certinfo(request, handle);

	if (rlm_rest_status_update(request, handle) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	if (hcode >= 500) {
		rcode = RLM_MODULE_FAIL;
	} else if (hcode == 204) {
		rcode = RLM_MODULE_OK;
	} else if ((hcode >= 200) && (hcode < 300)) {
		ret = rest_response_decode(inst, section, request, handle);
		if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
		else if (ret == 0) rcode = RLM_MODULE_OK;
		else		   rcode = RLM_MODULE_UPDATED;
	} else {
		rcode = RLM_MODULE_INVALID;
	}

	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
		rest_response_error(request, handle);
		break;

	default:
		rest_response_debug(request, handle);
		break;
	}

finish:
	rest_slab_release(handle);

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	Send post-auth info to a REST API endpoint
 */
static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rest_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_rest_t);
	rlm_rest_thread_t		*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	rlm_rest_section_t const	*section = &inst->post_auth;

	void				*handle;
	int				ret;

	if (!section->name) {
		RDEBUG2("No post-auth section configured");
		RETURN_MODULE_NOOP;
	}

	handle = rest_slab_reserve(t->slab);
	if (!handle) RETURN_MODULE_FAIL;

	ret = rlm_rest_perform(mctx, section, handle, request);
	if (ret < 0) {
		rest_slab_release(handle);

		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield(request, mod_post_auth_result, rest_io_module_signal, ~FR_SIGNAL_CANCEL, handle);
}

static int parse_sub_section(rlm_rest_t *inst, CONF_SECTION *parent, conf_parser_t const *config_items,
			     rlm_rest_section_t *config, char const *name)
{
	CONF_SECTION *cs, *request_cs;

	cs = cf_section_find(parent, name, NULL);
	if (!cs) {
		config->name = NULL;
		return 0;
	}

	if (cf_section_rules_push(cs, config_items) < 0) return -1;
	if (cf_section_parse(inst, config, cs) < 0) {
		config->name = NULL;
		return -1;
	}

	/*
	 *  Add section name (Maybe add to headers later?).
	 */
	config->name = name;

	/*
	 *  Convert HTTP method auth and body type strings into their integer equivalents.
	 */
	if ((config->request.auth != REST_HTTP_AUTH_NONE) && !http_curl_auth[config->request.auth]) {
		cf_log_err(cs, "Unsupported HTTP auth type \"%s\", check libcurl version, OpenSSL build "
			   "configuration, then recompile this module",
			   fr_table_str_by_value(http_auth_table, config->request.auth, "<INVALID>"));

		return -1;
	}
	config->request.method = fr_table_value_by_str(http_method_table, config->request.method_str, REST_HTTP_METHOD_CUSTOM);

	/*
	 *  Custom hackery to figure out if data was set we can't do it any other way because we can't
	 *  parse the tmpl_t except within a call_env.
	 *
	 *  We have custom body data so we set REST_HTTP_BODY_CUSTOM, but also need to try and
	 *  figure out what content-type to use. So if they've used the canonical form we
	 *  need to convert it back into a proper HTTP content_type value.
	 */
	if ((strcmp(name, "xlat") == 0) || ((request_cs = cf_section_find(cs, "request", NULL)) && cf_pair_find(request_cs, "data"))) {
		http_body_type_t body;

		config->request.body = REST_HTTP_BODY_CUSTOM;

		body = fr_table_value_by_str(http_body_type_table, config->request.body_str, REST_HTTP_BODY_UNKNOWN);
		if (body != REST_HTTP_BODY_UNKNOWN) {
			config->request.body_str = fr_table_str_by_value(http_content_type_table, body, config->request.body_str);
		}
	/*
	 *  We don't have any custom user data, so we need to select the right encoder based
	 *  on the body type.
	 *
	 *  To make this slightly more/less confusing, we accept both canonical body_types,
	 *  and content_types.
	 */
	} else {
		config->request.body = fr_table_value_by_str(http_body_type_table, config->request.body_str, REST_HTTP_BODY_UNKNOWN);
		if (config->request.body == REST_HTTP_BODY_UNKNOWN) {
			config->request.body = fr_table_value_by_str(http_content_type_table, config->request.body_str, REST_HTTP_BODY_UNKNOWN);
		}

		if (config->request.body == REST_HTTP_BODY_UNKNOWN) {
			cf_log_err(cs, "Unknown HTTP body type '%s'", config->request.body_str);
			return -1;
		}

		switch (http_body_type_supported[config->request.body]) {
		case REST_HTTP_BODY_UNSUPPORTED:
			cf_log_err(cs, "Unsupported HTTP body type \"%s\", please submit patches",
				      config->request.body_str);
			return -1;

		case REST_HTTP_BODY_INVALID:
			cf_log_err(cs, "Invalid HTTP body type.  \"%s\" is not a valid web API data "
				      "markup format", config->request.body_str);
			return -1;

		case REST_HTTP_BODY_UNAVAILABLE:
			cf_log_err(cs, "Unavailable HTTP body type.  \"%s\" is not available in this "
				      "build", config->request.body_str);
			return -1;

		default:
			break;
		}
	}

	if (config->response.force_to_str) {
		config->response.force_to = fr_table_value_by_str(http_body_type_table, config->response.force_to_str, REST_HTTP_BODY_UNKNOWN);
		if (config->response.force_to == REST_HTTP_BODY_UNKNOWN) {
			config->response.force_to = fr_table_value_by_str(http_content_type_table, config->response.force_to_str, REST_HTTP_BODY_UNKNOWN);
		}

		if (config->response.force_to == REST_HTTP_BODY_UNKNOWN) {
			cf_log_err(cs, "Unknown forced response body type '%s'", config->response.force_to_str);
			return -1;
		}

		switch (http_body_type_supported[config->response.force_to]) {
		case REST_HTTP_BODY_UNSUPPORTED:
			cf_log_err(cs, "Unsupported forced response body type \"%s\", please submit patches",
				      config->response.force_to_str);
			return -1;

		case REST_HTTP_BODY_INVALID:
			cf_log_err(cs, "Invalid HTTP forced response body type.  \"%s\" is not a valid web API data "
				      "markup format", config->response.force_to_str);
			return -1;

		default:
			break;
		}
	}

	return 0;
}

static int _mod_conn_free(fr_curl_io_request_t *randle)
{
	curl_easy_cleanup(randle->candle);
	return 0;
}

/** Cleans up after a REST request.
 *
 * Resets all options associated with a CURL handle, and frees any headers
 * associated with it.
 *
 * Calls rest_read_ctx_free and rest_response_free to free any memory used by
 * context data.
 *
 * @param[in] randle to cleanup.
 * @param[in] uctx unused.
 */
static int rest_request_cleanup(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	rlm_rest_curl_context_t *ctx = talloc_get_type_abort(randle->uctx, rlm_rest_curl_context_t);
	CURL			*candle = randle->candle;

	/*
	 *  Clear any previously configured options
	 */
	curl_easy_reset(candle);

	/*
	 *  Free header list
	 */
	if (ctx->headers != NULL) {
		curl_slist_free_all(ctx->headers);
		ctx->headers = NULL;
	}

	/*
	 *  Free response data
	 */
	TALLOC_FREE(ctx->body);
	TALLOC_FREE(ctx->response.buffer);
	TALLOC_FREE(ctx->request.encoder);
	TALLOC_FREE(ctx->response.decoder);
	ctx->response.header = NULL;	/* This is owned by the parsed call env and must not be freed */

	randle->request = NULL;
	return 0;
}

static int rest_conn_alloc(fr_curl_io_request_t *randle, void *uctx)
{
	rlm_rest_t const	*inst = talloc_get_type_abort(uctx, rlm_rest_t);
	rlm_rest_curl_context_t	*curl_ctx = NULL;

	randle->candle = curl_easy_init();
	if (unlikely(!randle->candle)) {
		fr_strerror_printf("Unable to initialise CURL handle");
		return -1;
	}

	MEM(curl_ctx = talloc_zero(randle, rlm_rest_curl_context_t));
	curl_ctx->headers = NULL;
	curl_ctx->request.instance = inst;
	curl_ctx->response.instance = inst;

	randle->uctx = curl_ctx;
	talloc_set_destructor(randle, _mod_conn_free);

	rest_slab_element_set_destructor(randle, rest_request_cleanup, NULL);

	return 0;
}

/** Create a thread specific multihandle
 *
 * Easy handles representing requests are added to the curl multihandle
 * with the multihandle used for mux/demux.
 *
 * @param[in] mctx	Thread instantiation data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_rest_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_rest_t);
	rlm_rest_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	fr_curl_handle_t	*mhandle;

	t->inst = inst;

	if (!(t->slab = rest_slab_list_alloc(t, mctx->el, &inst->conn_config.reuse,
					     rest_conn_alloc, NULL, inst, false, false))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	mhandle = fr_curl_io_init(t, mctx->el, inst->multiplex);
	if (!mhandle) return -1;

	t->mhandle = mhandle;

	return 0;
}

/** Cleanup all outstanding requests associated with this thread
 *
 * Destroys all curl easy handles, and then the multihandle associated
 * with this thread.
 *
 * @param[in] mctx	data to destroy.
 * @return 0
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_rest_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);

	talloc_free(t->mhandle);	/* Ensure this is shutdown before the pool */
	talloc_free(t->slab);

	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int instantiate(module_inst_ctx_t const *mctx)
{
	rlm_rest_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_rest_t);
	CONF_SECTION	*conf = mctx->inst->conf;

	inst->xlat.request.method_str = "GET";
	inst->xlat.request.body = REST_HTTP_BODY_NONE;
	inst->xlat.request.body_str = "application/x-www-form-urlencoded";
	inst->xlat.response.force_to_str = "plain";

	/*
	 *	Parse sub-section configs.
	 */
	if (
		(parse_sub_section(inst, conf, xlat_config, &inst->xlat, "xlat") < 0) ||
		(parse_sub_section(inst, conf, section_config, &inst->authorize,
				   section_type_value[MOD_AUTHORIZE]) < 0) ||
		(parse_sub_section(inst, conf, section_config, &inst->authenticate,
				   section_type_value[MOD_AUTHENTICATE]) < 0) ||
		(parse_sub_section(inst, conf, section_config, &inst->accounting,
				   section_type_value[MOD_ACCOUNTING]) < 0) ||
		(parse_sub_section(inst, conf, section_config, &inst->post_auth,
				   section_type_value[MOD_POST_AUTH]) < 0))
	{
		return -1;
	}

	inst->conn_config.reuse.num_children = 1;
	inst->conn_config.reuse.child_pool_size = sizeof(rlm_rest_curl_context_t);

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_rest_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_rest_t);
	xlat_t		*xlat;

	xlat = xlat_func_register_module(inst, mctx, mctx->inst->name, rest_xlat, FR_TYPE_STRING);
	xlat_func_args_set(xlat, rest_xlat_args);
	xlat_func_call_env_set(xlat, &rest_call_env_xlat);

	return 0;
}

/** Initialises libcurl.
 *
 * Allocates global variables and memory required for libcurl to function.
 * MUST only be called once per module instance.
 *
 * mod_unload must not be called if mod_load fails.
 *
 * @see mod_unload
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_load(void)
{
	/* developer sanity */
	fr_assert((NUM_ELEMENTS(http_body_type_supported)) == REST_HTTP_BODY_NUM_ENTRIES);

#ifdef HAVE_JSON
	fr_json_version_print();
#endif

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_rest;
module_rlm_t rlm_rest = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "rest",
		.flags			= MODULE_TYPE_THREAD_SAFE,
		.inst_size		= sizeof(rlm_rest_t),
		.thread_inst_size	= sizeof(rlm_rest_thread_t),
		.config			= module_config,
		.onload			= mod_load,
		.bootstrap		= mod_bootstrap,
		.instantiate		= instantiate,
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	Hack to support old configurations
		 */
		{ .name1 = "authorize",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,	.method_env = &rest_call_env_authorize		},

		{ .name1 = "recv",		.name2 = "accounting-request",	.method = mod_accounting,	.method_env = &rest_call_env_accounting		},
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,	.method_env = &rest_call_env_authorize		},
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting,	.method_env = &rest_call_env_accounting		},
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate,	.method_env = &rest_call_env_authenticate 	},
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth,	.method_env = &rest_call_env_post_auth		},
		MODULE_NAME_TERMINATOR
	}
};
