/*
 * url_helpers.c
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>

/* Hashing algorithms */
#include <mhash.h>

/* HTML template library */
#include <ctemplate.h>

#include <glib.h>

#include "common.h"
#include "utils.h"
#include "audit.h"

/*
 * Given a username return the real name, which should be free'd.
 */
char *username_to_name(const char *username)
{
	char *who;
	char *name;
	MYSQL_RES *res;
	MYSQL_ROW row;

	who = make_mysql_safe_string(username);
	res = sql_query("SELECT name FROM passwd WHERE username = '%s'", who);
	row = mysql_fetch_row(res);

	name = strdup(row[0]);

	mysql_free_result(res);
	free(who);

	return name;
}

/*
 * This checks if a user is currently logged in. It is called at the start
 * of each request.
 *
 * There are upto three checks performed:
 *
 * 1) The session_id cookie from the browser is checked with the stored
 *    session_id generated at login.
 * 2) The client_id from the browser (currently the user agent string) is
 *    checked against the stored client_id.
 *
 * 4) Optionally (enabled by default on the login screen) a check is made
 *    on the requesting ip address against the stored origin_ip that was
 *    used at login.
 *
 * If any of these checks fail, the request is denied and the user is
 * punted to the login screen.
 */
bool is_logged_in(void)
{
	char session_id[65];
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	const char *rbuf;
	bool login_ok = false;

	if (!env_vars.http_cookie)
		goto out3;

	snprintf(session_id, sizeof(session_id), "%s",
						env_vars.http_cookie + 11);

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
	res = tctdbqrysearch(qry);
	if (tclistnum(res) == 0)
		goto out2;

	rbuf = tclistval(res, 0, &rsize);
	cols = tctdbget(tdb, rbuf, rsize);
	tcmapiterinit(cols);

	/* restrict_ip */
	if (atoi(tcmapget2(cols, "restrict_ip")) == 1) {
		/* origin_ip */
		if (strcmp(tcmapget2(cols, "origin_ip"),
					env_vars.remote_addr) != 0)
			goto out;
	}
	/* client_id */
	if (strcmp(tcmapget2(cols, "client_id"),
					env_vars.http_user_agent) != 0)
		goto out;

	/* We got here, all checks are OK */
	login_ok = true;

out:
	tcmapdel(cols);
out2:
	tctdbqrydel(qry);
	tclistdel(res);
	tctdbclose(tdb);
	tctdbdel(tdb);
out3:
	return login_ok;
}

/*
 * Authenticates the user. Takes their password, crypt()'s it using
 * the salt from their password entry and compares the result with
 * their stored password.
 */
int check_auth(void)
{
	int ret = -1;
	char *username;
	char *enc_passwd;
	MYSQL_RES *res;
	MYSQL_ROW row;

	username = make_mysql_safe_string(get_var(qvars, "username"));
	res = sql_query("SELECT password, enabled FROM passwd WHERE "
			"username = '%s'", username);
	if (mysql_num_rows(res) < 1)
		goto out;

	row = mysql_fetch_row(res);
	if (atoi(row[1]) == 0) {
		ret = -2;
		goto out;
	}

	enc_passwd = crypt(get_var(qvars, "password"), row[0]);
	if (strcmp(enc_passwd, row[0]) == 0)
		ret = 0;

out:
	mysql_free_result(res);
	free(username);

	return ret;
}

/*
 * Sets up the user_session structure. This contains various bits of
 * information pertaining to the users session.
 */
void set_user_session(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int primary_key_size;
	char pkbuf[256];
	char session_id[65];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[21];
	char restrict_ip[2];
	char capabilities[4];
	char user_hdr[1025];
	char *xss_string;
	const char *rbuf;

	/*
	 * Don't assume the order we get the cookies back is the
	 * same order as we sent them.
	 */
	if (strncmp(env_vars.http_cookie, "session_id", 10) == 0)
		snprintf(session_id, sizeof(session_id), "%s",
						env_vars.http_cookie + 11);
	else
		snprintf(session_id, sizeof(session_id), "%s",
						env_vars.http_cookie + 88);

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	/* Get the users stored session */
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
	res = tctdbqrysearch(qry);

	rbuf = tclistval(res, 0, &rsize);
	cols = tctdbget(tdb, rbuf, rsize);
	tcmapiterinit(cols);

	memset(&user_session, 0, sizeof(user_session));
	user_session.tenant = strdup(tcmapget2(cols, "tenant"));
	user_session.sid = strtoull(tcmapget2(cols, "sid"), NULL, 10);
	user_session.uid = atoi(tcmapget2(cols, "uid"));
	user_session.username = strdup(tcmapget2(cols, "username"));
	user_session.name = strdup(tcmapget2(cols, "name"));
	user_session.login_at = atol(tcmapget2(cols, "login_at"));
	user_session.last_seen = time(NULL);
	user_session.origin_ip = strdup(tcmapget2(cols, "origin_ip"));
	user_session.client_id = strdup(tcmapget2(cols, "client_id"));
	user_session.session_id = strdup(tcmapget2(cols, "session_id"));
	user_session.csrf_token = strdup(tcmapget2(cols, "csrf_token"));
	user_session.restrict_ip = atoi(tcmapget2(cols, "restrict_ip"));
	user_session.capabilities = atoi(tcmapget2(cols, "capabilities"));

	tcmapdel(cols);
	tclistdel(res);
	tctdbqrydel(qry);

	/*
	 * Set the user header banner, which displays the users name, uid and
	 * whether they are an Approver and or Admin.
	 */
	xss_string = xss_safe_string(user_session.name);
	snprintf(user_hdr, sizeof(user_hdr), "<big><big> %s</big></big><small>"
				"<span class = \"lighter\"> (%d) </span>"
				"</small>", xss_string, user_session.uid);
	free(xss_string);
	strncat(user_hdr, "&nbsp;", 1024 - strlen(user_hdr));
	user_session.user_hdr = strdup(user_hdr);

	/*
	 * We want to update the last_seen timestamp in the users session.
	 * This entails removing the old session first then storing the new
	 * updated session.
	 */
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
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
			"csrf_token", user_session.csrf_token,
			"restrict_ip", restrict_ip,
			"capabilities", capabilities,
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Generate a session_id used to identify a users session.
 * It generates a SHA-256 from random data.
 */
char *create_session_id(void)
{
	int fd;
	int i;
	int hbs;
	ssize_t bytes_read;
	char buf[1024];
	char shash[65];
	unsigned char *hash;
	char ht[3];
	MHASH td;

	fd = open("/dev/urandom", O_RDONLY);
	bytes_read = read(fd, buf, sizeof(buf));
	close(fd);
	/*
	 * If we couldn't read the required amount, something is
	 * seriously wrong. Log it and exit.
	 */
	if (bytes_read < sizeof(buf)) {
		d_fprintf(error_log, "Couldn't read sufficient data from "
							"/dev/urandom\n");
		_exit(EXIT_FAILURE);
	}

	td = mhash_init(MHASH_SHA256);
	mhash(td, &buf, sizeof(buf));
	hash = mhash_end(td);

	memset(shash, 0, sizeof(shash));
	hbs = mhash_get_block_size(MHASH_SHA256);
	for (i = 0; i < hbs; i++) {
		sprintf(ht, "%.2x", hash[i]);
		strncat(shash, ht, 2);
	}
	free(hash);

	return strdup(shash);
}

/*
 * This will create a SHA-256 token for use in forms to help prevent
 * against CSRF attacks.
 */
char *generate_csrf_token(void)
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
	char *csrf_token = create_session_id();

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

	return csrf_token;
}

/*
 * Given a template varlist, this will add a csrf token variable.
 */
void add_csrf_token(TMPL_varlist *varlist)
{
	char *csrf_token;

	csrf_token = generate_csrf_token();
	varlist = TMPL_add_var(varlist, "csrf_token", csrf_token,
							(char *)NULL);
	free(csrf_token);
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

/*
 * Adds last login information to the page. Time and location of
 * last login.
 *
 * If this is the users first login, then "First login" is simply
 * displayed.
 */
void display_last_login(TMPL_varlist *varlist)
{
	char host[NI_MAXHOST];
	time_t login;

	login = get_last_login(host);
	if (login > 0) {
		char tbuf[32];

		strftime(tbuf, 32, "%a %b %e %H:%M %Y", localtime(&login));
		varlist = add_html_var(varlist, "last_login", tbuf);
		varlist = add_html_var(varlist, "last_login_from", host);
	} else {
		varlist = add_html_var(varlist, "last_login", "First login");
	}
}

/*
 * Create a new user session. This is done upon each successful login.
 */
void create_session(unsigned long long sid)
{
	char *session_id;
	char restrict_ip[2] = "0\0";
	char pkbuf[256];
	char timestamp[21];
	char ssid[21];
	char tenant[NI_MAXHOST];
	char *username;
	int primary_key_size;
	MYSQL_RES *res;
	TCTDB *tdb;
	TCMAP *cols;
	GHashTable *db_row = NULL;

	username = make_mysql_safe_string(get_var(qvars, "username"));
	res = sql_query("SELECT uid, name, capabilities FROM passwd WHERE "
			"username = '%s'", username);
	db_row = get_dbrow(res);

	get_tenant(env_vars.host, tenant);
	session_id = create_session_id();

	if (strcmp(get_var(qvars, "restrict_ip"), "true") == 0) {
		d_fprintf(debug_log, "Restricting session to origin ip "
								"address\n");
		restrict_ip[0] = '1';
	}

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER | TDBOCREAT);
	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));
	snprintf(ssid, sizeof(ssid), "%llu", sid);
	cols = tcmapnew3("tenant", tenant,
			"sid", ssid,
			"uid", get_var(db_row, "uid"),
			"username", get_var(qvars, "username"),
			"name", get_var(db_row, "name"),
			"login_at", timestamp,
			"last_seen", timestamp,
			"origin_ip", env_vars.remote_addr,
			"client_id", env_vars.http_user_agent,
			"session_id", session_id,
			"csrf_token", "\0",
			"restrict_ip", restrict_ip,
			"capabilities", get_var(db_row, "capabilities"),
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);
	tcmapdel(cols);
	tctdbclose(tdb);
	tctdbdel(tdb);

	printf("Set-Cookie: session_id=%s; path=/; httponly\r\n", session_id);

	mysql_free_result(res);
	free_vars(db_row);
	free(username);
	free(session_id);
}

/*
 * Send the specified template to the user.
 */
void send_template(const char *template, TMPL_varlist *varlist,
						TMPL_fmtlist *fmtlist)
{
	printf("Cache-Control: private\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write(template, NULL, fmtlist, varlist, stdout, error_log);
	fflush(error_log);
}

/*
 * Given a request URI and the URI we are checking for.
 * Return:
 *     true for a match and
 *     false for no match.
 */
bool match_uri(const char *request_uri, const char *match)
{
	size_t rlen;
	size_t mlen = strlen(match);
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
	if (strstr(request, "/get_image/") && strstr(match, "/get_image/"))
		return true;
	else if (strncmp(request, match, mlen) == 0 && rlen == mlen)
		return true;
	else
		return false;
}
