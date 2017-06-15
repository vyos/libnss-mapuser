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
 * This is common code used by the nss_mapuser and nss_mapuid NSS
 * plugin library.   None of it's symbols are public, they are stripped
 * during the linking phase (made internal only).
 */


#include "map_common.h"
#include <sys/stat.h>

static const char config_file[] = "/etc/mapuser_nss.conf";

#define DEF_MIN_UID 1001 /*  fail lookups on uid's below this value */

/* set from configuration file parsing; stripped from exported symbols
 * in build, so local to the shared lib. */
char *exclude_users; /*  don't lookup these users */
char *mappeduser;
uid_t min_uid = DEF_MIN_UID;
int debug;

static int conf_parsed = 0;
static const char *libname; /* for syslogs, set in each library */

/*  reset all config variables when we are going to re-parse */
static void
reset_config(void)
{
    /*  reset the config variables that we use, freeing memory where needed */
    if(exclude_users) {
        (void)free(exclude_users);
        exclude_users = NULL;
    }
    if(mappeduser) {
        (void)free(mappeduser);
        mappeduser = NULL;
    }
    debug = 0;
    min_uid = DEF_MIN_UID;
}

/*
 * return 0 on succesful parsing (at least no hard errors), 1 if
 *  an error, and 2 if already parsed and no change to config file
 */
int
nss_mapuser_config(int *errnop, const char *lname)
{
    FILE *conf;
    char lbuf[256];
    static struct stat lastconf;

    if(conf_parsed) {
        struct stat st, *lst = &lastconf;
        /*
         *  check to see if the config file(s) have changed since last time,
         *  in case we are part of a long-lived daemon.  If any changed,
         *  reparse.  If not, return the appropriate status (err or OK)
         */
        if (stat(config_file, &st) && st.st_ino == lst->st_ino &&
            st.st_mtime == lst->st_mtime && st.st_ctime == lst->st_ctime)
            return 2; /*  nothing to reparse */
        reset_config();
        conf_parsed = 0;
        if (debug && conf_parsed)
            syslog(LOG_DEBUG, "%s: Configuration file changed, re-initializing",
                libname);
    }

    libname = lname;

    conf = fopen(config_file, "r");
    if(conf == NULL) {
        *errnop = errno;
        syslog(LOG_NOTICE, "%s: can't open config file %s: %m",
            libname, config_file);
        return 1;
    }
    if (fstat(fileno(conf), &lastconf) != 0)
        memset(&lastconf, 0, sizeof lastconf); /*  avoid stale data, no warning */

    while(fgets(lbuf, sizeof lbuf, conf)) {
        if(*lbuf == '#' || isspace(*lbuf))
            continue; /* skip comments, white space lines, etc. */
        strtok(lbuf, " \t\n\r\f"); /* terminate buffer at first whitespace */
        if(!strncmp(lbuf, "debug=", 6))
            debug = strtoul(lbuf+6, NULL, 0);
        else if(!strncmp(lbuf, "exclude_users=", 14)) {
            /*
             * Don't lookup users in this comma-separated list for both
             * robustness and performnce.  Typically root and other commonly
             * used local users.  If set, we also look up the uids
             * locally, and won't do remote lookup on those uids either.
             */
            exclude_users = strdup(lbuf+14);
        }
        else if(!strncmp(lbuf, "mapped_user=", 12)) {
            /*  the user we are mapping to */
            mappeduser = strdup(lbuf+12);
        }
        else if(!strncmp(lbuf, "min_uid=", 8)) {
            /*
             * Don't lookup uids that are local, typically set to either
             * 0 or smallest always local user's uid
             */
            unsigned long uid;
            char *valid;
            uid = strtoul(lbuf+8, &valid, 0);
            if (valid > (lbuf+8))
                min_uid = (uid_t)uid;
        }
        else if(debug) /* ignore unrecognized lines, unless debug on */
            syslog(LOG_WARNING, "%s: unrecognized parameter: %s",
                libname, lbuf);
    }
    fclose(conf);
    conf_parsed = 1;

    return mappeduser ? 0 : 1; /*  can't do anything without this */
}

/*
 * copy a passwd structure and it's strings, using the provided buffer
 * for the strings.
 * usename is used for the new pw_name, the last part of the homedir,
 * and the GECOS field.
 * For strings, if pointer is null, use an empty string.
 * Returns 0 if everything fit, otherwise 1.
 */
int
pwcopy(char *buf, size_t len, struct passwd *srcpw, struct passwd *destpw,
       const char *usename)
{
    int needlen, cnt, origlen = len;
    char *shell;

    if(!mappeduser) {
        if(debug)
            syslog(LOG_DEBUG, "%s: empty mapped_user, failing", libname);
        return 1;
    }
    if(!usename) { /*  this should never happen */
        if(debug)
            syslog(LOG_DEBUG, "%s: empty username, failing", libname);
        return 1;
    }

    needlen = 2 * strlen(usename) + 2 + /*  pw_name and pw_gecos */
        srcpw->pw_dir ? strlen(srcpw->pw_dir) + 1 : 1 +
        srcpw->pw_shell ? strlen(srcpw->pw_shell) + 1 : 1 +
        2 + /*  for 'x' in the passwd field */
        12; /*  for the "Mapped user" in the gecos field */
    if(needlen > len) {
        if(debug)
            syslog(LOG_DEBUG, "%s provided password buffer too small (%ld<%d)",
                libname, (long)len, needlen);
        return 1;
    }

    destpw->pw_uid = srcpw->pw_uid;
    destpw->pw_gid = srcpw->pw_gid;

    cnt = snprintf(buf, len, "%s", usename);
    destpw->pw_name = buf;
    cnt++; /* allow for null byte also */
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", "x");
    destpw->pw_passwd = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", srcpw->pw_shell ? srcpw->pw_shell : "");
    destpw->pw_shell = buf;
    shell = strrchr(buf, '/');
    shell = shell ? shell+1 : buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s mapped user", usename);
    destpw->pw_gecos = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    if (usename) {
        char *slash, dbuf[strlen(srcpw->pw_dir) + strlen(usename)];
        snprintf(dbuf, sizeof dbuf, "%s", srcpw->pw_dir ? srcpw->pw_dir : "");
        slash = strrchr(dbuf, '/');
        if (slash) {
            slash++;
            snprintf(slash, sizeof dbuf - (slash-dbuf), "%s", usename);
        }
        cnt = snprintf(buf, len, "%s", dbuf);
    }
    else
        cnt = snprintf(buf, len, "%s", srcpw->pw_dir ? srcpw->pw_dir : "");
    destpw->pw_dir = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    if(len < 0) {
        if(debug)
            syslog(LOG_DEBUG, "%s provided password buffer too small (%ld<%d)",
                libname, (long)origlen, origlen-(int)len);
        return 1;
    }

    return 0;
}

/*
 * This passes in a fixed
 * name for UID lookups, where we have the mapped name from the
 * map file.
 * returns 0 on success
 */
int
get_pw_mapuser(const char *name, struct pwbuf *pb)
{
    FILE *pwfile;
    struct passwd *ent;
    int ret = 1;


    pwfile = fopen("/etc/passwd", "r");
    if(!pwfile) {
        syslog(LOG_WARNING, "%s: failed to open /etc/passwd: %m",
            libname);
        return 1;
    }

    pb->pw->pw_name = NULL; /* be paranoid */
    for(ret = 1; ret && (ent = fgetpwent(pwfile)); ) {
        if(!ent->pw_name)
            continue; /* shouldn't happen */
        if(!strcmp(ent->pw_name, mappeduser)) {
            ret = pwcopy(pb->buf, pb->buflen, ent, pb->pw, name);
            break;
        }
    }
    fclose(pwfile);
    if(ret)
       *pb->errnop = ERANGE;

    return ret;
}
