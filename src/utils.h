/*
 * utils.h
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2014		Andrew Clayton <andrew@digital-domain.net>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#ifndef _UTILS_H_
#define _UTILS_H_

/* Pagination macro's */
#define IS_MULTI_PAGE(nr_pages)		(((nr_pages) > 1) ? 1 : 0)
#define IS_FIRST_PAGE(page)		(((page) == 1) ? 1 : 0)
#define IS_LAST_PAGE(page, nr_pages)	(((page) == (nr_pages)) ? 1 : 0)

char *get_tenant(const char *host, char *tenant);
char *username_to_name(const char *username);
char *generate_hash(char *hash, int type);
void free_avars(void);
void free_vars(GHashTable *vars);
void free_u_files(void);
void set_vars(void);
GHashTable *get_dbrow(MYSQL_RES *res);
const char *get_avar(int index, const char *key);
const char *get_var(GHashTable *vars, const char *key);
void free_env_vars(void);
void free_user_session(void);
void set_env_vars(void);
void send_activation_mail(const char *name, const char *address,
			  const char *key);
char *generate_password_hash(int hash_type, const char *password);
void delete_user_session(unsigned int uid);
bool user_already_exists(const char *username);
void get_page_pagination(const char *req_page_no, int rpp, int *page_no,
			 int *from);
void do_pagination(Flate *f, int page, int nr_pages);
void do_zebra(Flate *f, unsigned long row, char *zebra);
char *de_xss(const char *value);
void send_template(Flate *f);
void send_page(char *file);

#endif /* _UTILS_H_ */
