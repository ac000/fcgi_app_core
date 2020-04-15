/*
 * csrf.h - CSRF mitigation functions
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2014, 2016, 2020	Andrew Clayton
 *					<andrew@digital-domain.net>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#ifndef _CSRF_H_
#define _CSRF_H_

#include <stdbool.h>

#include <flate.h>

extern void add_csrf_token(Flate *f);
extern bool valid_csrf_token(void);

#endif /* _CSRF_H_ */
