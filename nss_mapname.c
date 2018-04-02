/*
 * Copyright (C) 2017, 2018 Cumulus Networks, Inc.
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
 * name to one of two account (from the configuration file).
 * The base mapping is done if no shell:prv-lvl attribute is
 * received, or if the value is less than 15.  If the attribute
 * is present with the value 15, then we map to the privileged
 * mapping account, which typically has the ability to run
 * configuration commands.
 * The fixed account is used to get the base of the home directory,
 * and for the uid and gid.  All other fields are replaced, and
 * the password is always returned as 'x' (disabled).  The assumption
 * is that any authentication and authorization will be done via PAM
 * using some mechanism other than the local password file, such as
 * RADIUS
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
#include <stdbool.h>
#include <fcntl.h>
#include <grp.h>

static const char *nssname = "nss_mapuser";	/* for syslogs */

/*
 * This is an NSS entry point.
 * We map any username given to the account listed in the configuration file
 * We only fail if we can't read the configuration file, or the username
 * in the configuration file can't be found in the /etc/passwd file.
 * Because we always have a positive reply, it's important that this
 * be the last NSS module for passwd lookups.
 */
__attribute__ ((visibility("default")))
enum nss_status _nss_mapname_getpwnam_r(const char *name, struct passwd *pw,
					char *buffer, size_t buflen,
					int *errnop)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;
	struct pwbuf pbuf;
	bool islocal = 0;
	unsigned session;

	if (map_init_common(errnop, nssname))
		return errnop
		    && *errnop == ENOENT ? NSS_STATUS_UNAVAIL : status;

	/*
	 * Ignore any name starting with tacacs[0-9] in case a
	 * tacplus client is installed.  Cleaner than listing
	 * all 16 in the exclude_users list or implementing
	 * some form of wildcard.  Also ignore our own mappeduser
	 * and mapped_priv_user names if set.
	 */
	if ((mappeduser && !strcmp(mappeduser, name)) ||
	    (mapped_priv_user && !strcmp(mapped_priv_user, name)))
		islocal = 1;
	else if (!strncmp("tacacs", name, 6) && isdigit(name[6]))
		islocal = 1;
	else if (exclude_users) {
		char *user, *list;
		list = strdup(exclude_users);
		if (list) {
			static const char *delim = ", \t\n";
			user = strtok(list, delim);
			list = NULL;
			while (user) {
				if (!strcmp(user, name)) {
					islocal = 1;
					break;
				}
				user = strtok(NULL, delim);
			}
			free(list);
		}
	}
	if (islocal) {
		if (map_debug > 1)
			syslog(LOG_DEBUG, "%s: skipped excluded user: %s",
			       nssname, name);
		return 2;
	}

	/* marshal the args for the lower level functions */
	pbuf.name = (char *)name;
	pbuf.pw = pw;
	pbuf.buf = buffer;
	pbuf.buflen = buflen;
	pbuf.errnop = errnop;

	session = get_sessionid();
	if (session && !find_mapped_name(&pbuf, (uid_t) - 1, session))
		status = NSS_STATUS_SUCCESS;
	if (status != NSS_STATUS_SUCCESS) {
		/* lookup by some unrelated process, try dir lookup */
		if (!find_mappingfile(&pbuf, (uid_t) - 1))
			status = NSS_STATUS_SUCCESS;
		else if (!make_mapuser(&pbuf, name))
			status = NSS_STATUS_SUCCESS;
	}

	return status;
}

/*
 * The group routines are here so we can substitute mappings for radius_user
 * and radius_priv_user when reading /etc/group, so that we can make
 * users members of the appropriate groups for various privileged
 * (and unprivileged) tasks.
 * Ideally, we'd be able to use the getgr* routines specifying compat,
 * but the NSS plugin infrastructure doesn't support that, so we have to
 * read /etc/group directly, and then do our substitutions.
 *
 * This won't work if the RADIUS users are in LDAP group and/or password
 * files, but that's the way it goes.
 *
 * For the intended purpose, it works well enough.
 *
 * We need getgrent() for this one, because initgroups needs it, unlike
 * the password file.
 */

static FILE *grent;

__attribute__ ((visibility("default")))
enum nss_status _nss_mapname_setgrent(void)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;
	static const char *grpname = "/etc/group";
	int error, *errnop = &error;

	if (map_init_common(errnop, nssname))
		return errnop
		    && *errnop == ENOENT ? NSS_STATUS_UNAVAIL : status;

	if (grent) {
		rewind(grent);
		status = NSS_STATUS_SUCCESS;
		goto done;
	}

	grent = fopen(grpname, "r");
	if (!grent) {
		syslog(LOG_WARNING, "%s: failed to open %s: %m",
		       nssname, grpname);
		status = NSS_STATUS_UNAVAIL;
	} else {
		status = NSS_STATUS_SUCCESS;
		/*  don't leave fd open across execs */
		(void)fcntl(fileno(grent), F_SETFD, FD_CLOEXEC);
	}
 done:
	return status;
}

__attribute__ ((visibility("default")))
enum nss_status _nss_mapname_endgrent(void)
{
	if (grent) {
		FILE *f = grent;
		grent = NULL;
		(void)fclose(f);
	}
	return NSS_STATUS_SUCCESS;
}

/*
 * do the fixups and copies, using the passed in buffer.  result must
 * have been checked to be sure it's non-NULL before calling.
 */
static int fixup_grent(struct group *entry, struct group *result, char *buf,
		       size_t lenbuf, int *errp)
{
	char **grusr, **new_grmem = NULL;
	struct group *newg;
	long long l, len;	/* size_t unsigned on some systems */
	int err, members, memlen;
	int ret = NSS_STATUS_NOTFOUND;
	unsigned pmatch = 0;
	char *nm = entry->gr_name ? entry->gr_name : "(nil)";

	if (!result)		/* should always be non-NULL, just cautious */
		return ret;

	len = lenbuf;
	if (!errp)		/*  to reduce checks below */
		errp = &err;
	*errp = 0;

	newg = (struct group *)buf;
	len -= sizeof *newg;
	buf += sizeof *newg;
	if (len < 0) {
		*errp = ENOMEM;
		return ret;
	}
	newg->gr_gid = entry->gr_gid;
	l = snprintf(buf, len, "%s", entry->gr_name);
	newg->gr_name = buf;
	len -= l + 1;
	buf += l + 1;
	if (len > 0) {
		l = snprintf(buf, len, "%s", entry->gr_passwd);
		newg->gr_passwd = buf;
		len -= l + 1;
		buf += l + 1;
	}
	if (len < 0) {
		*errp = ENOMEM;
		return NSS_STATUS_TRYAGAIN;
	}

	for (memlen = members = 0, grusr = entry->gr_mem; grusr && *grusr;
	     grusr++) {
		if (mapped_priv_user && !strcmp(mapped_priv_user, *grusr))
			pmatch |= PRIV_MATCH;
		else if (mappeduser && !strcmp(mappeduser, *grusr))
			pmatch |= UNPRIV_MATCH;
		members++;
		memlen += strlen(*grusr) + 1;
	}
	if (pmatch) {		/* one or both mapped users are in gr_mem */
		size_t usedbuf = len;
		new_grmem = fixup_gr_mem(nm, (const char **)entry->gr_mem,
					 buf, &usedbuf, errp, pmatch);
		buf += usedbuf;
		len -= usedbuf;
		if (errp) {
			if (*errp == ERANGE)
				ret = NSS_STATUS_TRYAGAIN;
			else if (*errp == ENOENT)
				ret = NSS_STATUS_UNAVAIL;

		} else if (len < 0) {
			*errp = ERANGE;
			ret = NSS_STATUS_TRYAGAIN;
		}
	}
	if (*errp)
		goto done;
	*result = *newg;
	if (new_grmem)
		result->gr_mem = new_grmem;
	else {
		char **sav, **entgr, *usrbuf;
		len -= (members + 1) * sizeof *new_grmem;
		len -= memlen;
		if (len < 0) {
			*errp = ERANGE;
			ret = NSS_STATUS_TRYAGAIN;
			goto done;
		}
		sav = result->gr_mem = (char **)buf;
		buf += (members + 1) * sizeof *new_grmem;
		usrbuf = buf;

		for (entgr = entry->gr_mem; entgr && *entgr; entgr++, sav++) {
			*sav = usrbuf;
			usrbuf += strlen(*entgr) + 1;
			strcpy(*sav, *entgr);
		}

		*sav = NULL;
	}
	ret = NSS_STATUS_SUCCESS;
 done:
	return ret;
}

/*
 * No locking needed because our only global is the dirent * for
 * the runuser directory, and our use of that should be thread safe
 */
__attribute__ ((visibility("default")))
enum nss_status _nss_mapname_getgrent_r(struct group *gr_result,
					char *buffer, size_t buflen,
					int *errnop)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;
	struct group *ent;
	int ret = 1;

	if (!gr_result) {
		if (errnop)
			*errnop = EFAULT;
		return status;
	}

	if (map_init_common(errnop, nssname))
		return errnop
		    && *errnop == ENOENT ? NSS_STATUS_UNAVAIL : status;

	if (!grent) {
		status = _nss_mapname_setgrent();
		if (status != NSS_STATUS_SUCCESS)
			return status;
	}

	ent = fgetgrent(grent);
	if (!ent) {
		int e = errno;
		if (ferror(grent)) {
			syslog(LOG_WARNING,
			       "%s: error reading group information: %m",
			       nssname);
			errno = e;
		} else
			errno = 0;
		return status;
	}
	ret = fixup_grent(ent, gr_result, buffer, buflen, errnop);
	return ret;
}

__attribute__ ((visibility("default")))
enum nss_status _nss_mapname_getgrnam_r(const char *name, struct group *gr,
					char *buffer, size_t buflen,
					int *errnop)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;
	struct group *ent;

	if (!gr) {
		if (errnop)
			*errnop = EFAULT;
		return status;
	}

	if (map_init_common(errnop, nssname))
		return errnop
		    && *errnop == ENOENT ? NSS_STATUS_UNAVAIL : status;

	if (_nss_mapname_setgrent() != NSS_STATUS_SUCCESS)
		return status;

	for (ent = fgetgrent(grent); ent; ent = fgetgrent(grent)) {
		if (!strcmp(ent->gr_name, name)) {
			status = fixup_grent(ent, gr, buffer, buflen, errnop);
			break;
		}
	}

	return status;
}

__attribute__ ((visibility("default")))
enum nss_status _nss_mapname_getgrgid_r(gid_t gid, struct group *gr,
					char *buffer, size_t buflen,
					int *errnop)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;
	struct group *ent;

	if (!gr) {
		if (errnop)
			*errnop = EFAULT;
		return status;
	}

	if (map_init_common(errnop, nssname))
		return errnop
		    && *errnop == ENOENT ? NSS_STATUS_UNAVAIL : status;

	if (_nss_mapname_setgrent() != NSS_STATUS_SUCCESS)
		return status;

	for (ent = fgetgrent(grent); ent; ent = fgetgrent(grent)) {
		if (ent->gr_gid == gid) {
			status = fixup_grent(ent, gr, buffer, buflen, errnop);
			break;
		}
	}

	return status;
}
