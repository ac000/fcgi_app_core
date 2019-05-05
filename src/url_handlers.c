/*
 * url_handlers.c
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 * 		 2014, 2019	Andrew Clayton <andrew@digital-domain.net>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <stdbool.h>
#include <setjmp.h>

#include <mhash.h>

#include <glib.h>

/* HTML template library */
#include <flate.h>

#include "common.h"
#include "utils.h"
#include "audit.h"
#include "csrf.h"

struct user_session user_session;

/*
 * /login/
 *
 * HTML is in templates/login.tmpl
 *
 * Display the login screen.
 */
static void login(void)
{
	int ret = 1;
	Flate *f = NULL;

	if (qvars) {
		ret = check_auth();
		if (ret == 0) {
			unsigned long long sid = log_login();

			create_session(sid);
			fcgx_p("Location: //\r\n\r\n");
			return; /* Successful login */
		}
	}

	lf_set_tmpl(&f, "templates/login.tmpl");
	if (ret == -1)
		lf_set_var(f, "auth_fail", "", NULL);
	if (ret == -2)
		lf_set_var(f, "acc_disab", "", NULL);
	if (ret == -3)
		lf_set_var(f, "ipacl_deny", "", NULL);
	lf_set_var(f, "rip", env_vars.remote_addr, de_xss);

	send_template(f);
	lf_free(f);
}

/*
 * /logout/
 *
 * HTML is in templates/logout.tmpl
 *
 * Clean up a users session. Remove their entry from the sessions db and
 * set the session_id browser cookie to expired.
 */
static void logout(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	int rsize;
	const char *rbuf;

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ,
					user_session.session_id);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	/* Immediately expire the session cookies */
	fcgx_p("Set-Cookie: session_id=deleted; "
				"expires=Thu, 01 Jan 1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	send_page("templates/logout.tmpl");
}

static char *request_uri;
/*
 * Given a URI we are checking for against request_uri
 * Return:
 *     true for a match and
 *     false for no match.
 */
static bool match_uri(const char *uri)
{
	size_t rlen;
	size_t mlen = strlen(uri);
	const char *request;
	char *req = strdupa(request_uri);

	/*
	 * Handle URLs in the form /something/?key=value by stripping
	 * everything from the ? onwards and matching on the initial part.
	 */
	if (strchr(request_uri, '?'))
		request = strtok(req, "?");
	else
		request = request_uri;

	rlen = strlen(request);

	/*
	 * The image URLs are a bit different, we only want to match on
	 * the first /.../ part and they don't contain a ?.
	 */
	if ((strstr(request, "/get_image/") && strstr(uri, "/get_image/")) ||
	    (strncmp(request, uri, mlen) == 0 && rlen == mlen))
		return true;

	return false;
}

static jmp_buf env;
/*
 * This is the main URI mapping/routing function.
 *
 * Takes a URI string to match and the function to run if it matches
 * request_uri.
 */
static inline void uri_map(const char *uri, void (uri_handler)(void))
{
	if (match_uri(uri)) {
		uri_handler();
		longjmp(env, 1);
	}
}

/*
 * Main application. This is where the requests come in and routed.
 */
void handle_request(void)
{
	bool logged_in = false;
	struct timespec stp;
	struct timespec etp;

	clock_gettime(CLOCK_REALTIME, &stp);

	qvars = NULL;
	avars = NULL;
	u_files = NULL;

	set_env_vars();
	set_vars();
	request_uri = strdupa(env_vars.request_uri);

	/* Initialise the database connection */
	conn = db_conn();
	if (!conn)
		goto out2;

	/* Return from non-authenticated URIs and goto 'out2' */
	if (setjmp(env))
		goto out2;

	/*
	 * Some routes need to come before the login / session stuff as
	 * they can't be logged in and have no session.
	 */
	uri_map("/login/", login);

	logged_in = is_logged_in();
	if (!logged_in) {
		fcgx_p("Location: /login/\r\n\r\n");
		goto out2;
	}

	/* Logged in, set-up the user_session structure */
	set_user_session();

	/* Return from authenticated URIs and goto 'out' */
	if (setjmp(env))
		goto out;

	/* Add new url handlers after here */
	uri_map("/logout/", logout);

	/* Default location */
	fcgx_p("Location: /login/\r\n\r\n");

out:
	free_user_session();

out2:
	free_vars(qvars);
	free_avars();
	free_u_files();
	clock_gettime(CLOCK_REALTIME, &etp);
	d_fprintf(access_log, "Got request from %s for %s (%s), %ums\n",
				env_vars.remote_addr,
				request_uri,
				env_vars.request_method,
				(unsigned int)((etp.tv_sec * 1000 +
				etp.tv_nsec / NS_MSEC) -
				(stp.tv_sec * 1000 + stp.tv_nsec / NS_MSEC)));
	free_env_vars();
	mysql_close(conn);
}
