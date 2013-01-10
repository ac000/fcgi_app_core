/*
 * csrf.c - CSRF mitigation functions
 *
 * Copyright (C) 2012		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 *
 * Released under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ctemplate.h>

#include "common.h"
#include "utils.h"

/*
 * This will create a token for use in forms to help prevent against
 * CSRF attacks.
 */
static void generate_csrf_token(char *csrf_token)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int primary_key_size;
	char pkbuf[256];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[21];
	char restrict_ip[2];
	char capabilities[4];
	const char *rbuf;

	/*
	 * We want to set a new CSRF token in the users session.
	 * This entails removing the old session first then storing
	 * the new updated session.
	 */
	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ,
			user_session.session_id);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(login_at, sizeof(login_at), "%ld", user_session.login_at);
	snprintf(last_seen, sizeof(last_seen), "%ld",
			user_session.last_seen);
	snprintf(uid, sizeof(uid), "%u", user_session.uid);
	snprintf(sid, sizeof(sid), "%llu", user_session.sid);
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
			user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
			user_session.capabilities);
	generate_hash(csrf_token, SHA1);
	cols = tcmapnew3("tenant", user_session.tenant,
			"sid", sid,
			"uid", uid,
			"username", user_session.username,
			"name", user_session.name,
			"login_at", login_at,
			"last_seen", last_seen,
			"origin_ip", user_session.origin_ip,
			"client_id", user_session.client_id,
			"session_id", user_session.session_id,
			"csrf_token", csrf_token,
			"restrict_ip", restrict_ip,
			"capabilities", capabilities,
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Given a template varlist, this will add a csrf token variable.
 */
void add_csrf_token(TMPL_varlist *varlist)
{
	char csrf_token[CSRF_LEN + 1];

	generate_csrf_token(csrf_token);
	varlist = TMPL_add_var(varlist, "csrf_token", csrf_token,
			(char *)NULL);
}

/*
 * Checks if a valid csrf token has been presented.
 *
 * Returns:
 * 	true, for yes
 * 	false, for no
 */
bool valid_csrf_token(void)
{
	if (strcmp(get_var(qvars, "csrf_token"),
				user_session.csrf_token) == 0)
		return true;
	else
		return false;
}
