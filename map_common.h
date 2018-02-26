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
extern uid_t min_uid;
extern int debug;

extern int nss_mapuser_config(int *errnop, const char *lname);
extern int pwcopy(char *buf, size_t len, struct passwd *srcpw, struct passwd *destpw,
       const char *usename);
extern int get_pw_mapuser(const char *name, struct pwbuf *pb);

