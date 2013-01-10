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

void add_csrf_token(TMPL_varlist *varlist);
bool valid_csrf_token(void);

#endif /* _URL_HELPERS_H_ */
