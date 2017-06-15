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
 * This plugin implements getpwuid_r for NSS to map a UID back to
 * a mapped username account, set up via nss_mapuser.
 *
 * A fixed account is used to get the base of the home directory,
 * and for the uid and gid.  All other fields are replaced, and
 * the password is always returned as 'x' (disabled).  The assumption
 * is that any authentication and authorization will be done via PAM
 * using some mechanism other than the local password file.
 *
 * Since this should match first whenever a mapped user's UID is being
 * looked up, this module should appear first in in nsswitch.conf for
 * the passwd database.
 *
 * It implements getpwuid_r for UIDs if and only if a mapped user is currently
 * logged in This means that if you do, e.g.:
 *     ls -ld ~SomeUserName
 * you will sometimes get a mapped username, and other times get the name of the
 * fixed account in the configuration file, depending on whether a mapped user
 * is logged in or not.
 *
 * See nss_mapuser.c for the matching getpwnam_r for UIDs.
 */

#include "map_common.h"
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>


static const char *nssname = "nss_mapuid"; /* for syslogs */
static const char dbdir[] = "/run/mapuser/";

/*
 * Read the requested session file (in the dbdir by intent), verify the
 * uid matches, and setup the passwd structure with the username found
 * in the file.
 */
static int chk_session_file(char *sfile, uid_t uid, struct pwbuf *pb)
{
    char rbuf[256], user[64];
    FILE *mapf;
    uid_t auid = 0;
    int ret = 1;

    mapf = fopen(sfile, "r");
    if (!mapf) {
        if( debug)
            syslog(LOG_DEBUG, "%s:  session map file %s open fails: %m",
                nssname, sfile);
        return ret;
    }
    user[0] = '\0';
    while(fgets(rbuf, sizeof rbuf, mapf)) {
        strtok(rbuf, " \t\n\r\f"); /* terminate buffer at first whitespace */
        if(!strncmp("user=", rbuf, 5)) { /* should precede auid */
            snprintf(user, sizeof user, "%s", rbuf+5);
            if (auid) /* found out of order, but now have both */
                break;
        }
        else if(!strncmp("auid=", rbuf, 5)) {
            uid_t fuid = (uid_t)strtoul(rbuf+5, NULL, 10);
            if (fuid && uid == fuid) {
                auid = fuid;
                if (user[0])
                    break; /*  normal ordering, else keep looking for user */
            }
        }
    }
    fclose(mapf);

    if (auid && user[0]) /*  otherwise not a match */
        ret = get_pw_mapuser(user, pb); /* should always succeed */

    return ret;
}

/* find mapping for this sessionid */
static int
find_mapped_name(struct pwbuf *pb, uid_t uid, uint32_t session)
{
    char sessfile[sizeof dbdir + 11];

    snprintf(sessfile, sizeof sessfile, "%s%u", dbdir, session);
    return chk_session_file(sessfile, uid, pb);
}

static int find_mappingfile(struct pwbuf *pb, uid_t uid)
{
    DIR *dir;
    struct dirent *ent;
    int ret = 1;

    dir = opendir(dbdir);
    if (!dir) { /*  can happen if no mapped users logged in */
        if (debug > 1)
            syslog(LOG_DEBUG, "%s: Unable to open mapping directory %s: %m",
                nssname, dbdir);
        return 1;
    }

    /* Loop through all numeric files in dbdir, check for matching uid */
    while (ret && (ent = readdir(dir))) {
        char sessfile[sizeof dbdir + 11];
        if (!isdigit(ent->d_name[0])) /* sanity check on session file */
            continue;
        snprintf(sessfile, sizeof sessfile, "%s%s", dbdir, ent->d_name);
        ret = chk_session_file(sessfile, uid, pb);
    }
    if (ret && debug)
        syslog(LOG_DEBUG, "%s: uid %u mapping not found in map files",
            nssname, uid);
    closedir(dir);
    return ret;
}

static uint32_t
get_sessionid(void)
{
    int fd = -1, cnt;
    uint32_t id = 0U;
    static char buf[12];

    fd = open("/proc/self/sessionid", O_RDONLY);
    if(fd != -1) {
        cnt = read(fd, buf, sizeof(buf));
        close(fd);
    }
    if(fd != -1 && cnt > 0) {
        id = strtoul(buf, NULL, 0);
    }
    return id;
}

/*
 * This is an NSS entry point.
 * We implement getpwuid(), for anything that wants to get the original
 * login name from the uid.
 * If it matches an entry in the map, we use that data to replace
 * the data from the local passwd file (not via NSS).
 * locally from the map.
 *
 * This can be made to work 2 different ways, and we need to choose
 * one, or make it configurable.
 *
 * 1) Given a valid session id, and a mapped user logged in,
 * we'll match only that user.   That is, we can only do the lookup
 * successfully for child processes of the mapped login, and
 * only while still logged in (map entry is valid).
 *
 * For now, if session are set, I try them, and if that lookup
 * fails, try the wildcard.
 *
 * Only works while the UID is in use for a mapped user, and only
 * for processes invoked from that session.  Other callers will
 * just get the files, ldap, etc. entry for the UID
 * Returns the first match if multiple mapped users.
 */
__attribute__ ((visibility ("default")))
enum nss_status _nss_mapuid_getpwuid_r(uid_t uid, struct passwd *pw,
    char *buffer, size_t buflen, int *errnop)
{
    struct pwbuf pb;
    enum nss_status status = NSS_STATUS_NOTFOUND;
    uint32_t session;

    /*  this can happen for permission reasons, do don't complain except
     *  at debug */
    if (nss_mapuser_config(errnop, nssname) == 1) {
         return status; /* syslog already done */
    }


    if (min_uid != ~0U && uid < min_uid) {
        if(debug > 1)
            syslog(LOG_DEBUG, "%s: uid %u < min_uid %u, don't lookup",
                nssname, uid, min_uid);
        return status;
    }
    
    /* marshal the args for the lower level functions */
    pb.pw = pw;
    pb.buf = buffer;
    pb.buflen = buflen;
    pb.errnop = errnop;
    pb.name = NULL;

    /* session needs to be set to lookup this user.  May also be set
     * for other users.
     */
    session = get_sessionid();
    if(session && !find_mapped_name(&pb, uid, session))
        status = NSS_STATUS_SUCCESS;
    if(status != NSS_STATUS_SUCCESS) {
        /* lookup by some other user or unrelated process, try dir lookup */
        if (!find_mappingfile(&pb, uid))
            status = NSS_STATUS_SUCCESS;
    }
    return status;
}
