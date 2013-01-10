/*
 * url_helpers.h
 *
 * Copyright (C) 2012		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#ifndef _URL_HELPERS_H_
#define _URL_HELPERS_H_

bool is_logged_in(void);
int check_auth(void);
void set_user_session(void);
void add_csrf_token(TMPL_varlist *varlist);
bool valid_csrf_token(void);
void display_last_login(TMPL_varlist *varlist);
void create_session(unsigned long long sid);
bool match_uri(const char *request_uri, const char *match);

#endif /* _URL_HELPERS_H_ */
