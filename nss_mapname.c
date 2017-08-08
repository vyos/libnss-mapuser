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
 * This plugin implements getpwnam_r for NSS to map any user
 * name to a fixed account (from the configuration file).  The
 * fixed account is used to get the base of the home directory,
 * and for the uid and gid.  All other fields are replaced, and
 * the password is always returned as 'x' (disabled).  The assumption
 * is that any authentication and authorization will be done via PAM
 * using some mechanism other than the local password file.
 *
 * Because it will match any account, this should always be the
 * last module in /etc/nsswitch.conf for the passwd entry
 *
 * The home dir returned is the mapped user homedir with the last component
 * replaced with the username being looked up.
 *
 * See nss_mapuid.c for the matching getpwuid_r for UIDs.
 */


#include "map_common.h"


static const char *nssname = "nss_mapuser"; /* for syslogs */

/*
 * If you aren't using glibc or a variant that supports this,
 * and you have a system that supports the BSD getprogname(),
 * you can replace this use with getprogname()
 */
extern const char *__progname;

/*
 * This is an NSS entry point.
 * We map any username given to the account listed in the configuration file
 * We only fail if we can't read the configuration file, or the username
 * in the configuration file can't be found in the /etc/passwd file.
 * Because we always have a positive reply, it's important that this
 * be the last NSS module for passwd lookups.
 */
__attribute__ ((visibility ("default")))
enum nss_status _nss_mapname_getpwnam_r(const char *name, struct passwd *pw,
    char *buffer, size_t buflen, int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    struct pwbuf pbuf;

    /*
     * the useradd family will not add/mod/del users correctly with
     * the mapuid functionality, so return immediately if we are
     * running as part of those processes.
     */
    if (__progname && (!strcmp(__progname, "useradd") || 
        !strcmp(__progname, "usermod") || 
        !strcmp(__progname, "userdel")))
        return status;

    if (nss_mapuser_config(errnop, nssname) == 1) {
         syslog(LOG_NOTICE, "%s: bad configuration", nssname);
         return status;
    }

    /* marshal the args for the lower level functions */
    pbuf.name = (char *)name;
    pbuf.pw = pw;
    pbuf.buf = buffer;
    pbuf.buflen = buflen;
    pbuf.errnop = errnop;

    if(!get_pw_mapuser(name, &pbuf))
        status = NSS_STATUS_SUCCESS;

    return status;
}
