/*
 * csrf.h - CSRF mitigation functions
 *
 * Copyright (C) 2012		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 *
 * Released under the GNU Affero General Public License version 3
 * See AGPL-3.0.txt
 */

#ifndef _CSRF_H_
#define _CSRF_H_

void add_csrf_token(TMPL_varlist *varlist);
bool valid_csrf_token(void);

#endif /* _CSRF_H_ */
