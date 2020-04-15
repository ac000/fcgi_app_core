/*
 * utils.h
 *
 * Copyright (C) 2012 - 2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2014, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * This software is released under the MIT License (MIT-LICENSE.txt)
 * and the GNU Affero General Public License version 3 (AGPL-3.0.txt)
 */

#ifndef _UTILS_H_
#define _UTILS_H_

/*
 * Macro to simplify creating paginated table row data
 *
 * i      - The loop index
 * pn     - The pagination structure
 * datums - The _total_ number of items being displayed across _all_ pages
 */
#define for_each_table_row(i, pn, datums) \
	for (i = pn.from; i < pn.from + pn.rows_per_page && i < datums; i++)

/* Pagination macro's */
#define IS_MULTI_PAGE(nr_pages)		(((nr_pages) > 1) ? 1 : 0)
#define IS_FIRST_PAGE(page)		(((page) == 1) ? 1 : 0)
#define IS_LAST_PAGE(page, nr_pages)	(((page) == (nr_pages)) ? 1 : 0)

struct pagination {
	int requested_page;	/* Page requested by client */
	int page_no;		/* Page being returned to client */
	int rows_per_page;	/* Rows to show on each page */
	int nr_pages;		/* Number of pages across result set */
	int from;		/* Index into the result set to start from */
};

extern char *get_tenant(const char *host, char *tenant);
extern char *username_to_name(const char *username);
extern char *generate_hash(char *hash, int type);
extern void free_avars(void);
extern void free_vars(GHashTable *vars);
extern void free_u_files(void);
extern void set_vars(void);
extern GHashTable *get_dbrow(MYSQL_RES *res);
extern const char *get_avar(int index, const char *key);
extern const char *get_var(GHashTable *vars, const char *key);
extern void free_env_vars(void);
extern void free_user_session(void);
extern void set_env_vars(void);
extern void send_activation_mail(const char *name, const char *address,
				 const char *key);
extern char *generate_password_hash(int hash_type, const char *password);
extern void delete_user_session(unsigned int uid);
extern bool user_already_exists(const char *username);
extern void get_page_pagination(struct pagination *pn);
extern void do_pagination(Flate *f, const struct pagination *pn);
extern void do_zebra(Flate *f, unsigned long row, char *zebra);
extern char *de_xss(const char *value);
extern void send_template(Flate *f);
extern void send_page(char *file);

#endif /* _UTILS_H_ */
