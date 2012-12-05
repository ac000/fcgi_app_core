/*
 * url_handlers.c
 *
 * Copyright (C) 2012		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <alloca.h>
#include <netdb.h>
#include <stdbool.h>

#include <mhash.h>

#include <glib.h>

/* HTML template library */
#include <ctemplate.h>

#include "common.h"
#include "utils.h"
#include "url_helpers.h"
#include "audit.h"

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
	unsigned long long sid;
	TMPL_varlist *vl = NULL;

	if (qvars) {
		ret = check_auth();
		if (ret == 0) {
			sid = log_login();
			create_session(sid);
			printf("Location: //\r\n\r\n");
			return; /* Successful login */
		}
	}

	if (ret == -1)
		vl = add_html_var(vl, "logged_in", "no");
	if (ret == -2)
		vl = add_html_var(vl, "enabled", "no");

	send_template("templates/login.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	printf("Set-Cookie: session_id=deleted; "
				"expires=Thu, 01 Jan 1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	send_template("templates/logout.tmpl", NULL, NULL);
}

/*
 * Main application. This is where the requests come in and routed.
 */
void handle_request(void)
{
	bool logged_in = false;
	char *request_uri;
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

	/*
	 * Some routes need to come before the login / session stuff as
	 * they can't be logged in and have no session.
	 */
	if (match_uri(request_uri, "//")) {
		/* function call goes here */
		goto out2;
	}

	if (match_uri(request_uri, "/login/")) {
		login();
		goto out2;
	}

	logged_in = is_logged_in();
	if (!logged_in) {
		printf("Location: /login/\r\n\r\n");
		goto out2;
	}

	/* Logged in, set-up the user_session structure */
	set_user_session();

	/* Add new url handlers after here */

	if (match_uri(request_uri, "/logout/")) {
		logout();
		goto out;
	}

	/* Default location */
	printf("Location: /login/\r\n\r\n");

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
