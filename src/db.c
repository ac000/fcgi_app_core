/*
 * db.c
 *
 * Copyright (C) 2012		OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2014		Andrew Clayton <andrew@digital-domain.net>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "app_config.h"
#include "utils.h"
#include "db.h"

/* Global MySQL connection handle */
MYSQL *conn;

char *db_host = "localhost";
char *db_socket_name = NULL;
unsigned int db_port_num = 3306;
unsigned int db_flags = 0;

/*
 * Opens up a MySQL connection and returns the connection handle.
 */
MYSQL *db_conn(void)
{
	MYSQL *ret;

	if (MULTI_TENANT) {
		char tenant[TENANT_MAX + 1];
		char db[sizeof(tenant) + 3] = "rm_";

		get_tenant(env_vars.host, tenant);
		strncat(db, tenant, TENANT_MAX);
		free(db_name);
		db_name = strdup(db);
	}
	conn = mysql_init(NULL);
	ret = mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME,
			DB_PORT_NUM, DB_SOCKET_NAME, DB_FLAGS);

	if (!ret) {
		d_fprintf(error_log, "Failed to connect to database. Error: "
				"%s\n", mysql_error(conn));
		switch (mysql_errno(conn)) {
		case ER_BAD_DB_ERROR:	/* unknown database */
			send_template("templates/invalid.tmpl", NULL, NULL);
			break;
		}
		conn = NULL;
	}

	return conn;
}

/*
 * This takes a sql query and returns the result set.
 * It also takes __func__ to get the name of the calling function. It also
 * logs the query into the sql log.
 *
 * This function should not be called directly and should instead be used via
 * the sql_query() macro.
 *
 * This function will either return a result set or NULL. Note that some
 * queries don't return result sets by design.
 */
MYSQL_RES *__sql_query(const char *func, const char *fmt, ...)
{
	va_list args;
	char sql[SQL_MAX];
	int len;

	va_start(args, fmt);
	len = vsnprintf(sql, sizeof(sql), fmt, args);
	va_end(args);

	if (DEBUG_LEVEL) {
		char tenant[TENANT_MAX + 1];
		char ts_buf[32];
		time_t secs = time(NULL);
		struct tm *tm = localtime(&secs);

		get_tenant(env_vars.host, tenant);
		strftime(ts_buf, sizeof(ts_buf), "%F %T %z", tm);
		fprintf(sql_log, "[%s] %d %s %s: %s\n", ts_buf,  getpid(),
				tenant, func, sql);
		fflush(sql_log);
	}

	mysql_real_query(conn, sql, len);
	return mysql_store_result(conn);
}
