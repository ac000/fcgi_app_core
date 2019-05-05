/*
 * common.h
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2014, 2016, 2019	Andrew Clayton
 *		 			<andrew@digital-domain.net>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <fcgiapp.h>

#include <flate.h>

#include <glib.h>

#include "short_types.h"
#include "app_config.h"
#include "db.h"
#include "utils.h"

#define __unused		__attribute__((unused))
#define __maybe_unused		__attribute__((unused))
#define __always_unused		__attribute__((unused))

#define BUF_SIZE	4096
#define SQL_MAX		8192
#define ENTROPY_SIZE	   8

#define TENANT_MAX	64
#define SID_LEN		64
#define CSRF_LEN	64
#define IP_MAX		39
#define SHA1_LEN	40
#define SHA256_LEN	64

enum { SHA1, SHA256, SHA512 };

/*
 * These three define the number of nanoseconds in a second,
 * millisecond and microsecond.
 */
#define NS_SEC		1000000000
#define NS_MSEC		1000000
#define NS_USEC		1000

/* Length of time (seconds) an activation key is valid */
#define KEY_EXP		86400

/* Macro to check if the request method is POST */
#define IS_POST()	(strstr(env_vars.request_method, "POST"))
/* Macro to check if the request method is GET */
#define IS_GET()	(strstr(env_vars.request_method, "GET"))
/* Macro to check if a char *variable is set, i.e a len > 0 */
#define IS_SET(var)	((strlen(var) > 0) ? 1 : 0)

/* Unbreak __func__ by my_global.h */
#ifdef __func__
	#undef __func__
#endif

extern struct env_vars env_vars;
/*
 * Wrapper around fprintf(). It will prepend the text passed it with
 * [datestamp] pid function:
 *
 * e.g if you call it like: d_fprintf(debug, "This is a test\n");
 * You will get:
 *
 * [2013-07-04 00:01:40 +0100] 1843 main: This is a test
 */
#define d_fprintf(stream, fmt, ...) \
	do { \
		time_t secs; \
		struct tm *tm; \
		char ts_buf[32]; \
		char tenant[TENANT_MAX + 1]; \
		if (stream == debug_log && !DEBUG_LEVEL) \
			break; \
		secs = time(NULL); \
		tm = localtime(&secs); \
		get_tenant(env_vars.host, tenant); \
		strftime(ts_buf, sizeof(ts_buf), "%F %T %z", tm); \
		fprintf(stream, "[%s] %d %s %s: " fmt, ts_buf, getpid(), \
				tenant, __func__, ##__VA_ARGS__); \
		fflush(stream); \
	} while (0)

/* Remap some FCGX_ functions for usability/readability */
#define fcgx_p(fmt, ...)	FCGX_FPrintF(fcgx_out, fmt, ##__VA_ARGS__)
#define fcgx_vp(fmt, valist)	FCGX_VFPrintF(fcgx_out, fmt, valist)
#define fcgx_ps(buf, size)	FCGX_PutStr(buf, size, fcgx_out)
#define fcgx_param(name)	FCGX_GetParam(name, fcgx_envp)
#define fcgx_putc(c)		FCGX_PutChar(c, fcgx_out)
#define fcgx_puts(s)		FCGX_PutS(s, fcgx_out)
#define fcgx_gs(buf, size)	FCGX_GetStr(buf, size, fcgx_in)

/* Nicer names for the libflate stuff */
#define lf_set_tmpl		flateSetFile
#define lf_set_var		flateSetVar
#define lf_set_row		flateDumpTableLine
#define lf_send			flatePrint
#define lf_free			flateFreeMem

/*
 * Wrapper around mysql_real_escape_string()
 *
 * Given a string it will return a string, that must be free'd, that is safe
 * to pass to mysql.
 */
static inline char *__make_mysql_safe_string(MYSQL *dbconn, const char *string)
{
	char *safe = malloc(strlen(string)*2 + 1);

	mysql_real_escape_string(dbconn, safe, string, strlen(string));
	return safe;
}

/*
 * Warppaer around __make_mysql_safe_string() using the global db connection.
 */
static inline char *make_mysql_safe_string(const char *string)
{
	return __make_mysql_safe_string(conn, string);
}

/*
 * Warppaer around __make_mysql_safe_string() using the local db connection.
 */
static inline char *make_mysql_safe_stringl(MYSQL *dbconn, const char *string)
{
	return __make_mysql_safe_string(dbconn, string);
}

/*
 * Structure that defines a users session. The session is stored
 * in a tokyocabinet database table inbetween requests.
 */
struct user_session {
	char tenant[TENANT_MAX + 1];
	unsigned long long sid;
	unsigned int uid;
	uint8_t capabilities;
	char *username;
	char *name;
	time_t login_at;
	time_t last_seen;
	char origin_ip[IP_MAX + 1];
	char *client_id;
	char session_id[SID_LEN + 1];
	char csrf_token[CSRF_LEN + 1];
	bool restrict_ip;
	char *user_hdr;
};

/*
 * This structure maps to the environment variable list sent
 * by the application. We don't store every item.
 */
struct env_vars {
	char *request_uri;
	char *request_method;
	char *content_type;
	off_t content_length;
	char *http_cookie;
	char *http_user_agent;
	char *remote_addr;
	int remote_port;
	char *host;
	char *query_string;
};

extern FCGX_Stream *fcgx_in;
extern FCGX_Stream *fcgx_out;
extern FCGX_Stream *fcgx_err;
extern FCGX_ParamArray fcgx_envp;

extern FILE *access_log;
extern FILE *sql_log;
extern FILE *error_log;
extern FILE *debug_log;

extern GList *u_files;
extern GList *avars;
extern GHashTable *qvars;

#endif /* _COMMON_H_ */
