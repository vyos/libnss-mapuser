/*
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * All rights reserved.
 * Author: Dave Olson <olson@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 */

/*
 * This is the header file for the common code used by the nss_mapuser and
 * nss_mapuid NSS plugin library.   None of it's symbols are public, they are
 * stripped during the linking phase (made internal only).
 */

#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <errno.h>
#include <ctype.h>
#include <nss.h>

/*
 * pwbuf is used to reduce number of arguments passed around; the strings in
 * the passwd struct need to point into this buffer.
 */
struct pwbuf {
	char *name;
	char *buf;
	struct passwd *pw;
	int *errnop;
	size_t buflen;
};

/* configuration variables. */
extern char *exclude_users;
extern char *mappeduser;
extern char *mapped_priv_user;
extern uid_t map_min_uid;
extern int map_debug;

extern int nss_mapuser_config(int *errnop, const char *lname);
extern uint32_t get_sessionid(void);
extern int skip_program(void);
extern int find_mappingfile(struct pwbuf *pb, uid_t uid);
extern int find_mapped_name(struct pwbuf *pb, uid_t uid, uint32_t session);
extern int make_mapuser(struct pwbuf *pb, const char *name);
extern int map_init_common(int *errnop, const char *plugname);
extern char **fixup_gr_mem(const char *name, const char **gr_in, char *buf,
			   size_t * lp, int *err, unsigned privbits);
extern void cleanup_gr_mem(void);

#define PRIV_MATCH 2
#define UNPRIV_MATCH 1
