/*
 * db.h
 *
 * Copyright (C) 2012		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#ifndef _DB_H_
#define _DB_H_

/* For Tokyocabinet (user sessions) */
#include <tcutil.h>
#include <tctdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <libgen.h>

/* MySQL */

/*
 * The FCGI printf function seemed to be causing a conflict here, under F16
 * with GCC 4.6.2
 *
 * Just undef printf for the my_global stuff and then define it back again,
 */
#undef printf
#include <my_global.h>
#define printf FCGI_printf

#include <mysql.h>
#include <mysqld_error.h>

/*
 * Wrapper around mysql_real_query(), it uses __sql_query() to do the
 * actual work. It takes a mysql connection and a query string and passes
 * that to __sql_query() along with the function name of the caller for the
 * sql log.
 */
#define sql_query(conn, fmt, ...) \
	__sql_query((const char *)__func__, conn, fmt, ##__VA_ARGS__)

MYSQL *db_conn(void);
MYSQL_RES *__sql_query(const char *func, MYSQL *conn, char *fmt, ...);

#endif /* _DB_H_ */
