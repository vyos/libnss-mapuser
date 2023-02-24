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
#include <stddef.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <libaudit.h>

static const char config_file[] = "/etc/nss_mapuser.conf";

#define DEF_MIN_UID 1001	/*  fail lookups on uid's below this value */

/* set from configuration file parsing; stripped from exported symbols
 * in build, so local to the shared lib. */
char *exclude_users;		/*  don't lookup these users */
char *mappeduser;
char *mapped_priv_user;
uid_t map_min_uid = DEF_MIN_UID;
int map_debug;

static int conf_parsed = 0;
static const char *libname;	/* for syslogs, set in each library */
static const char dbdir[] = "/run/mapuser/";

/*
 * If you aren't using glibc or a variant that supports this,
 * and you have a system that supports the BSD getprogname(),
 * you can replace this use with getprogname()
 */
extern const char *__progname;

/*  reset all config variables when we are going to re-parse */
static void reset_config(void)
{
	void *p;

	/*  reset the config variables that we use, freeing memory where needed */
	if (exclude_users) {
		p = exclude_users;
		exclude_users = NULL;
		(void)free(p);
	}
	if (mappeduser) {
		p = mappeduser;
		mappeduser = NULL;
		(void)free(p);
	}
	if (mapped_priv_user) {
		p = mapped_priv_user;
		mapped_priv_user = NULL;
		(void)free(p);
	}
	map_debug = 0;
	map_min_uid = DEF_MIN_UID;
}

/*
 * return 0 on succesful parsing (at least no hard errors), 1 if
 *  an error, and 2 if already parsed and no change to config file
 */
int nss_mapuser_config(int *errnop, const char *lname)
{
	FILE *conf;
	char lbuf[256];
	static struct stat lastconf;

	if (conf_parsed) {
		struct stat st, *lst = &lastconf;
		/*
		 *  check to see if the config file(s) have changed since last time,
		 *  in case we are part of a long-lived daemon.  If any changed,
		 *  reparse.  If not, return the appropriate status (err or OK)
		 */
		if (stat(config_file, &st) && st.st_ino == lst->st_ino &&
		    st.st_mtime == lst->st_mtime
		    && st.st_ctime == lst->st_ctime)
			return 2;	/*  nothing to reparse */
		reset_config();
		conf_parsed = 0;
		if (map_debug && conf_parsed)
			syslog(LOG_DEBUG,
			       "%s: Configuration file changed, re-initializing",
			       libname);
	}

	libname = lname;

	conf = fopen(config_file, "r");
	if (conf == NULL) {
		*errnop = errno;
		syslog(LOG_NOTICE, "%s: can't open config file %s: %m",
		       libname, config_file);
		return 1;
	}
	if (fstat(fileno(conf), &lastconf) != 0)
		memset(&lastconf, 0, sizeof lastconf);	/*  avoid stale data, no warning */

	while (fgets(lbuf, sizeof lbuf, conf)) {
		if (*lbuf == '#' || isspace(*lbuf))
			continue;	/* skip comments, white space lines, etc. */
		strtok(lbuf, " \t\n\r\f");	/* terminate buffer at first whitespace */
		if (!strncmp(lbuf, "debug=", 6)) {
			map_debug = strtoul(lbuf + 6, NULL, 0);
		} else if (!strncmp(lbuf, "exclude_users=", 14)) {
			/*
			 * Don't lookup users in this comma-separated list for both
			 * robustness and performnce.  Typically root and other commonly
			 * used local users.  If set, we also look up the uids
			 * locally, and won't do remote lookup on those uids either.
			 */
			exclude_users = strdup(lbuf + 14);
		} else if (!strncmp(lbuf, "mapped_user=", 12)) {
			/*  the user we are mapping to */
			mappeduser = strdup(lbuf + 12);
		} else if (!strncmp(lbuf, "mapped_priv_user=", 17)) {
			/*  the user we are mapping to */
			mapped_priv_user = strdup(lbuf + 17);
		} else if (!strncmp(lbuf, "min_uid=", 8)) {
			/*
			 * Don't lookup uids that are local, typically set to either
			 * 0 or smallest always local user's uid
			 */
			unsigned long uid;
			char *valid;
			uid = strtoul(lbuf + 8, &valid, 0);
			if (valid > (lbuf + 8))
				map_min_uid = (uid_t) uid;
		} else if (map_debug)	/* ignore unrecognized lines, unless map_debug on */
			syslog(LOG_WARNING, "%s: unrecognized parameter: %s",
			       libname, lbuf);
	}
	fclose(conf);
	conf_parsed = 1;

	/*  can't do anything without at least one of these */
	return (mappeduser || mapped_priv_user) ? 0 : 1;
}

uint32_t get_sessionid(void)
{
	int fd = -1, cnt;
	uint32_t id = 0U;
	static char buf[12];

	fd = open("/proc/self/sessionid", O_RDONLY);
	if (fd != -1) {
		cnt = read(fd, buf, sizeof(buf));
		close(fd);
	}
	if (fd != -1 && cnt > 0) {
		id = strtoul(buf, NULL, 0);
	}
	return id;
}

/*
 * copy a passwd structure and it's strings, using the provided buffer
 * for the strings.
 * user name is used for the new pw_name, the last part of the homedir,
 * and the GECOS field.
 * For strings, if pointer is null, use an empty string.
 * Returns 0 if everything fit, otherwise 1.
 */
int
pwcopy(char *buf, size_t len, const char *usename, struct passwd *srcpw,
       struct passwd *destpw)
{
	int needlen, cnt, origlen = len;
	char *shell;

	if (!usename) {		/*  this should never happen */
		if (map_debug)
			syslog(LOG_DEBUG, "%s: empty username, failing",
			       libname);
		return 1;
	}

	needlen = 2 * strlen(usename) + 2 +	/*  pw_name and pw_gecos */
	    srcpw->pw_dir ? strlen(srcpw->pw_dir) + 1 : 1 + srcpw->pw_shell ?
		strlen(srcpw->pw_shell) + 1 : 1 + 2 +	/*  for 'x' in passwd */
		12;			/*  for the "Mapped user" in gecos */
	if (needlen > len) {
		if (map_debug)
			syslog(LOG_DEBUG,
			       "%s provided password buffer too small (%ld<%d)",
			       libname, (long)len, needlen);
		return 1;
	}

	destpw->pw_uid = srcpw->pw_uid;
	destpw->pw_gid = srcpw->pw_gid;

	cnt = snprintf(buf, len, "%s", usename);
	destpw->pw_name = buf;
	cnt++;			/* allow for null byte also */
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
	shell = shell ? shell + 1 : buf;
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
		snprintf(dbuf, sizeof dbuf, "%s",
			 srcpw->pw_dir ? srcpw->pw_dir : "");
		slash = strrchr(dbuf, '/');
		if (slash) {
			slash++;
			snprintf(slash, sizeof dbuf - (slash - dbuf), "%s",
				 usename);
		}
		cnt = snprintf(buf, len, "%s", dbuf);
	} else
		cnt =
		    snprintf(buf, len, "%s",
			     srcpw->pw_dir ? srcpw->pw_dir : "");
	destpw->pw_dir = buf;
	cnt++;
	buf += cnt;
	len -= cnt;
	if (len < 0) {
		if (map_debug)
			syslog(LOG_DEBUG,
			       "%s provided password buffer too small (%ld<%d)",
			       libname, (long)origlen, origlen - (int)len);
		return 1;
	}

	return 0;
}

/*
 * pb->name is non-NULL when we have the name and want to look it up
 * from the mapping.  mapuid will be the auid if we found it in the
 * files, otherwise will be what was passed down, which should
 * be the UID we are looking up when pb->name is NULL, when it's
 * the uid lookup, and otherwise should be -1 when pb->name is not NULL.
 * Returns 0 on success, 1 if uid not found in mapping files (even if
 * uid matches the radius mapping users; let nss_files handle that).
 */
static int
get_pw_mapuser(const char *name, struct pwbuf *pb, uid_t mapuid, int privileged)
{
	FILE *pwfile;
	struct passwd *ent;
	int ret = 1;

	pwfile = fopen("/etc/passwd", "r");
	if (!pwfile) {
		syslog(LOG_WARNING, "%s: failed to open /etc/passwd: %m",
		       libname);
		return 1;
	}

	for (ret = 1; ret && (ent = fgetpwent(pwfile));) {
		if (!ent->pw_name)
			continue;	/* shouldn't happen */
		if (!strcmp(ent->pw_name, name) || /*  added locally */
		    !strcmp(ent->pw_name, privileged ? mapped_priv_user :
			    mappeduser) || ent->pw_uid == mapuid) {
			ret =
			    pwcopy(pb->buf, pb->buflen, pb->name, ent, pb->pw);
			break;
		}
	}
	fclose(pwfile);
	if (ret) {
		*pb->errnop = ERANGE;
	}

	return ret;
}

/*
 * Read the requested session file (in the dbdir by intent), verify the
 * uid matches, and setup the passwd structure with the username found
 * in the file.
 */
static int chk_session_file(char *session, uid_t uid, struct pwbuf *pb)
{
	char rbuf[256], user[64], sessfile[sizeof dbdir + 12];
	FILE *mapf;
	uid_t auid = 0;
	int ret = 1, privileged = 0;;

	snprintf(sessfile, sizeof sessfile, "%s%s", dbdir, session);

	mapf = fopen(sessfile, "r");
	if (!mapf) {
		if (map_debug > 2)
			syslog(LOG_DEBUG,
			       "%s:  session map file %s open fails: %m",
			       libname, sessfile);
		return ret;
	}
	user[0] = '\0';
	while (fgets(rbuf, sizeof rbuf, mapf)) {
		/* terminate buffer at first whitespace */
		strtok(rbuf, " \t\n\r\f");
		if (!strncmp("user=", rbuf, 5)) {
			if (pb->name && strcmp(rbuf + 5, pb->name))
				break;
			snprintf(user, sizeof user, "%s", rbuf + 5);
		} else if (!strncmp("pid=", rbuf, 4)) {
			char *ok;
			unsigned pid = (unsigned) strtoul(rbuf + 4, &ok, 10);
			if (ok != (rbuf + 4) && pid > 0 && kill(pid, 0) &&
			    errno == ESRCH) {
				/*  ESRCH instead of any error because perms as
				 *  non-root.  Try to unlink, since we often
				 *  run as root; report as DEBUG if we unlink,
				 *  report as INFO if not */
				if (unlink(sessfile) == 0)
					syslog(LOG_DEBUG, "session file %s"
					       " PID=%u no longer active,"
					       " removed", sessfile, pid);
				else
					syslog(LOG_INFO, "session file %s"
					       " PID=%u no longer active, skip",
					       sessfile, pid);
				auid = 0; /*  force fail */
				break;
			}
		} else if (!strncmp("auid=", rbuf, 5)) {
			char *ok;
			uid_t fuid = (uid_t) strtoul(rbuf + 5, &ok, 10);
			if (ok != (rbuf + 5)) {
				if (uid != -1 && fuid != uid) {
					/*  getpwuid call but mismatch, nogo */
					break;
				} else
					auid = fuid;
			}
		} else if (!strcasecmp("privileged=yes", rbuf)) {
			privileged = 1;
		} else if (!strcasecmp("privileged=no", rbuf)) {
			privileged = 0;
		} else if (!strncmp("session=", rbuf, 8)) {
			/*  structural problem, so log warning */
			if (strcmp(session, rbuf + 8)) {
				syslog(LOG_WARNING,
				       "%s: session \"%s\" mismatch in %s",
				       libname, rbuf, sessfile);
				auid = 0; /*  force a skip */
			}
		}
	}
	fclose(mapf);

	if (auid && (uid == (uid_t)-1 || auid == uid) && user[0]) {
		if (!pb->name)
			pb->name = user;	/*  uid lookups */
		ret = get_pw_mapuser(user, pb, auid, privileged);
	}
	/*  otherwise not a match */

	return ret;
}

/*
 * find mapping for this sessionid; if uid == -1, we are doing name lookup
 * and will find in uid; else we are doing name lookup.
 */
int find_mapped_name(struct pwbuf *pb, uid_t uid, uint32_t session)
{
	char sess[11];

	snprintf(sess, sizeof sess, "%u", session);
	return chk_session_file(sess, uid, pb);
}

/*
 * Called when we don't have a sessionid, or the sessionid we have
 * doesn't match a mapped user (from find_mapped_name() above),
 * so we need to look through all the mapping files.
 * As with find_mapped_name(), if uid == -1, we are looking up from
 * the name, otherwise we are looking up from the uid.
 */
int find_mappingfile(struct pwbuf *pb, uid_t uid)
{
	DIR *dir;
	struct dirent *ent;
	int ret = 1;

	dir = opendir(dbdir);
	if (!dir) {		/*  can happen if no mapped users logged in */
		if (map_debug > 1)
			syslog(LOG_DEBUG,
			       "%s: Unable to open mapping directory %s: %m",
			       libname, dbdir);
		return 1;
	}

	/* Loop through all numeric files in dbdir, check for matching uid */
	while (ret && (ent = readdir(dir))) {
		if (!isdigit(ent->d_name[0]) || ent->d_type != DT_REG)
			continue;	/* sanity check on session file */
		ret = chk_session_file(ent->d_name, uid, pb);
	}
	closedir(dir);
	return ret;
}

/*
 * Used when there are no mapping entries, just create an entry from
 * the default radius user
 * This is needed so that ssh and login accept the username, and continue.
 */
int make_mapuser(struct pwbuf *pb, const char *name)
{
	int ret;
	ret = get_pw_mapuser(mappeduser, pb, (uid_t)-1, 0);
	return ret;
}

static char
*_getcmdname(void)
{
	static char buf[64];
	char *rv = NULL;
	int ret, fd;

	if (*buf)
		return buf;

	fd = open("/proc/self/comm", O_RDONLY);
	if (fd == -1) {
		if (map_debug)
			syslog(LOG_DEBUG,
			       "%s: failed to open /proc/self/comm: %m",
			       libname);
	} else {
		ret = read(fd, buf, sizeof buf);
		if (ret <= 0) {
			if (map_debug)
				syslog(LOG_DEBUG,
				       "%s: read /proc/self/comm ret %d: %m",
				       libname, ret);
		} else {
			(void)strtok(buf, "\n\r ");
			rv = buf;
		}
	}

	return rv;
}

static int chk_progs(const char *pname)
{
	static const char *progs[] =
	    { "useradd", "usermod", "userdel", "adduser",
		"deluser", NULL
	};
	const char **prog;
	int ret = 0;

	for (prog = &progs[0]; pname && *prog && !ret; prog++) {
		if (!strcmp(pname, *prog)) {
			if (map_debug > 1)
				syslog(LOG_DEBUG,
				       "%s: running from %s, skip lookup",
				       libname, *prog);
			ret = 1;
		}
	}
	return ret;
}

/*
 * the useradd family will not add/mod/del users correctly with
 * the mapuid functionality, so return immediately if we are
 * running as part of those processes.  Same for adduser, deluser
 * adduser and deluser are often perl scripts, so check for "comm"
 * name from /proc, also, unless already matched from progname.
 */
int skip_program(void)
{
	return chk_progs(__progname) || chk_progs(_getcmdname());
}

/*
 * All the entry points have this same common prolog, so put it here
 */
int map_init_common(int *errnop, const char *plugname)
{
	if (skip_program())
		return 1;

	if (nss_mapuser_config(errnop, plugname) == 1) {
		*errnop = ENOENT;
		syslog(LOG_NOTICE, "%s: bad configuration", plugname);
		return 1;
	}
	return 0;
}

/*  Open a session file, get the username and the privilege level,
 *  and if the privilege level matches, fill in usrbuf with name.
 *  0 on errors or no match, 1 if match and usrbuf is valid
 */
int get_priv_usr(const char *fname, unsigned prbits, char *usrbuf)
{
	char buf[256], user[64], sessfile[sizeof dbdir + 12];
	FILE *map;
	int privmatch = 0;

	snprintf(sessfile, sizeof sessfile, "%s%s", dbdir, fname);

	map = fopen(sessfile, "r");
	if (!map) {
		syslog(LOG_WARNING, "%s:  session map file %s open fails: %m",
		       libname, sessfile);
		return 0;
	}
	user[0] = '\0';
	while (fgets(buf, sizeof buf, map)) {
		strtok(buf, " \t\n\r\f");	/* terminate buffer at first whitespace */
		if (!strncmp("user=", buf, 5)) {
			snprintf(user, sizeof user, "%s", buf + 5);
		} else if (!strcasecmp("privileged=yes", buf)) {
			if (prbits & PRIV_MATCH)
				privmatch = 1;
		} else if (!strcasecmp("privileged=no", buf)) {
			if (prbits & UNPRIV_MATCH)
				privmatch = 1;
		}
	}
	fclose(map);
	if (privmatch && user[0] && usrbuf)
		strcpy(usrbuf, user);
	return privmatch == 1;
}


/*
* Return a char ** list of strings of usernames from the mapping files
* that match priviliged=yes|no, for replacing the gr_mem field for
* getgrent(), etc.
* Makes one sanity check to be sure the listed PID is still active
* before adding the username to the list.
* Passed the original gr_mem array, which will
* include the mappeduser or mapped_priv_user (or both).
* All strings go into buf, and we return ERANGE in *err if there
* isn't enough room.
* The allocated memory will leak, but it's re-used on each call, so
* not too signficant, and if endgrent() gets called, we'll clean up.
*/
char **fixup_gr_mem(const char *grnam, const char **gr_in, char *buf,
		    size_t * lenp, int *err, unsigned privbits)
{
	DIR *dir = NULL;
	struct dirent *ent;
	int ret = 1, nmemb, nadded = 0, midx, j;
	const int nmax = 64; /* max members we'll add per group */
	long long l = 0, len = *lenp;	/* size_t unsigned on some systems */
	const char **in;
	char **out, *mem = buf;
	char **gr_mem;
	char newmembers[nmax][128];
	const unsigned align = sizeof(void *) - 1;

	*err = 0;
	if (!gr_in)
		goto done;

	dir = opendir(dbdir);
	if (!dir) {
		/*
		 * Usually because no mapped users logged in.  Could
		 * return ENOENT, but may as well just act like compat
		 */
		goto done;
	}

	/* Loop through all numeric files in dbdir, check for matching uid */
	while (ret && nadded < nmax && (ent = readdir(dir))) {
		char usr[64];
		if (!isdigit(ent->d_name[0]) || ent->d_type != DT_REG)
			continue;	/* sanity check on session file */
		if (get_priv_usr(ent->d_name, privbits, usr)) {
			int n;
			int dup = 0;
			for (n=0; n < nadded; n++) {
				if (!strcmp(newmembers[n], usr)) {
					dup++;
					break;
				}
			}
			if (dup)
				continue;
			l = snprintf(newmembers[nadded++], sizeof newmembers[0],
				 "%s", usr);
			if (l >= sizeof newmembers[0])
				syslog(LOG_WARNING,
				       "%s: group %s, member %s truncated to"
				       " %ld characters", libname, grnam, usr,
				       sizeof newmembers[0]);
		}
	}

	if (!nadded)
		goto done;

	if (nadded == nmax && ent) {
		syslog(LOG_WARNING,
		       "%s: Only adding %d members to"
		       " group %s", libname, nmax, grnam);
	}
	for (nmemb=0, in=gr_in; in && *in; in++)
		nmemb++;

	/* copy the original list first; maybe make a common routine later */
	l = (((ptrdiff_t)mem + align) & align);
	len -= align;
	mem += align;
	gr_mem = (char **)mem;
	l = sizeof *gr_mem * (nmemb+nadded+1);
	len -= l;
	mem += l;

	for (midx=0, in=gr_in; in && *in; in++) {
		l = strlen(*in) + 1;
		len -= l;
		if (len < 0) {
			*err = ERANGE;
			goto done;
		}
		gr_mem[midx] = mem;
		mem += l;
		strcpy(gr_mem[midx++], *in);
	}
	/* now same for users we are adding */
	for(j=0; j<nadded; j++) {
		l = strlen(newmembers[j]) + 1;
		len -= l;
		if (len < 0) {
			*err = ERANGE;
			goto done;
		}
		gr_mem[midx] = mem;
		mem += l;
		strcpy(gr_mem[midx++], newmembers[j]);
	}
	gr_mem[midx] = NULL; /*  terminate the list */
 done:

	if (dir)
		closedir(dir);
	if (*err || !nadded) {
		out = NULL;
		*lenp = 0;
	} else {
		out = gr_mem;
		*lenp = mem - buf;
	}
	return out;
}
